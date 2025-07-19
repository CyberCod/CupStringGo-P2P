// -----------------BEGIN FILE-------------main.go

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	ircmsg "github.com/ergochat/irc-go/ircmsg"
	ircreader "github.com/ergochat/irc-go/ircreader"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

type IRCClient struct {
	conn          net.Conn
	nick          string
	channel       string
	display       *widget.Label
	scrollDisplay *container.Scroll
	input         *widget.Entry
	connectBtn    *widget.Button
	disconnectBtn *widget.Button
	tabs          *container.AppTabs
	mu            sync.Mutex
	connected     bool
	reconnect     time.Duration
}

var (
	logChan       chan string
	p2pShutdown   func()
	configPath    = "mysetup.json"
	logFilePath   = "current_log.txt"
	currentConfig *Config
	configMu      sync.Mutex
	logFile       *os.File
	logFileMutex  sync.Mutex
	allLogText    strings.Builder // Keep all log text in memory for display
	allLogMutex   sync.RWMutex
)

func main() {
	// Check if admin is required and restart if needed
	checkAdminRequirements()

	// Initialize log file first thing
	initializeLogFile()

	// Set up logging redirection for GUI application
	logChan = make(chan string, 1000)
	
	// FIXED: For GUI applications, only use channel writer (no os.Stdout)
	log.SetOutput(&chanWriter{ch: logChan})
	log.SetFlags(0) // No default timestamps, use TimestampLog

	a := app.New()
	w := a.NewWindow("CupStringGO-P2P")

	client := &IRCClient{
		display:   widget.NewLabel(""),
		input:     widget.NewEntry(),
		reconnect: time.Second,
	}

	// Check if we need initial setup
	
	// Start P2P only if config exists and is complete
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// No config file exists - create defaults but don't start P2P/IRC
		currentConfig = createDefaultConfig()
		log.Println("=== FIRST TIME SETUP REQUIRED ===")
		log.Println("Welcome to CupStringGO-P2P!")
		log.Println("")
		log.Println("Before the program can start, please fill out the Config tab:")
		log.Println("1. Your Username - your identifier (letters/numbers/underscore only)")
		log.Println("2. Recipient Username - who you want to connect to")
		log.Println("3. Channel Name - IRC channel for discovery (optional, default is fine)")
		log.Println("4. Pairing Secret - shared secret both users must know")
		log.Println("5. Export/Import folders - where files are sent from/received to")
		log.Println("")
		log.Println("After filling these out, click 'Save Config' to start the P2P system.")
		log.Println("=== CONFIGURATION REQUIRED ===")
	} else {
		// Config exists - try to load it
		var err error
		currentConfig, err = LoadConfig(configPath)
		if err != nil {
			log.Printf("Failed to load config: %v", err)
			currentConfig = createDefaultConfig()
		} else if !isConfigComplete(currentConfig) {
			log.Println("=== CONFIGURATION INCOMPLETE ===")
			log.Println("Your configuration is missing required fields.")
			log.Println("Please check the Config tab and ensure these are filled:")
			if currentConfig.YourUsername == "" {
				log.Println("- Your Username")
			}
			if currentConfig.RecipientUsername == "" {
				log.Println("- Recipient Username") 
			}
			if currentConfig.PairingSecret == "" {
				log.Println("- Pairing Secret")
			}
			log.Println("Then click 'Save Config' to start the P2P system.")
			log.Println("=== CONFIGURATION REQUIRED ===")
		} else {
			// Config is complete - start P2P/IRC
			forceSetup := false
			p2pShutdown, err = RunP2P(configPath, forceSetup)
			if err != nil {
				log.Fatalf("P2P startup failed: %v", err)
			}
		}
	}

	// FIXED: Proper cleanup on window close instead of defer
	w.SetCloseIntercept(func() {
		log.Println("Application closing...")
		if p2pShutdown != nil {
			p2pShutdown()
		}
		closeLogFile()
		w.Close()
	})

	// Access loaded config
	configMu.Lock()
	if currentConfig == nil {
		log.Fatal("Config initialization failed")
	}
	configMu.Unlock()

	// Config tab content
	serverEntry := widget.NewEntry()
	serverEntry.SetText(fmt.Sprintf("%s:%d", currentConfig.IRCServer, currentConfig.IRCPort))
	nickEntry := widget.NewEntry()
	nickEntry.SetText(currentConfig.YourUsername)
	channelEntry := widget.NewEntry()
	channelEntry.SetText(currentConfig.ChannelName)
	exportEntry := widget.NewEntry()
	exportEntry.SetText(currentConfig.ExportFolder)
	importEntry := widget.NewEntry()
	importEntry.SetText(currentConfig.ImportFolder)
	recipientEntry := widget.NewEntry()
	recipientEntry.SetText(currentConfig.RecipientUsername)
	secretEntry := widget.NewEntry()
	secretEntry.SetText(currentConfig.PairingSecret)
	localPortEntry := widget.NewEntry() // Make it editable
	localPortEntry.SetText(strconv.Itoa(currentConfig.LocalPort))
	externalIPEntry := widget.NewEntry()
	externalIPEntry.SetText(currentConfig.ExternalIP)
	tlsCheck := widget.NewCheck("TLS Enabled", nil)
	tlsCheck.SetChecked(currentConfig.TLSEnabled)
	
	adminCheck := widget.NewCheck("Run with Administrator privileges", nil)
	adminCheck.SetChecked(currentConfig.RequireAdmin)
	
	// Network mode selector
	networkModeSelect := widget.NewSelect([]string{"LAN", "Internet"}, func(value string) {
		// Auto-detect appropriate IP when mode changes
		if value == "LAN" {
			detectedIP := detectLocalIP()
			externalIPEntry.SetText(detectedIP)
			log.Printf("LAN mode: detected IP %s", detectedIP)
		} else if value == "Internet" {
			// For Internet mode, detect WAN IP in background
			go func() {
				log.Println("Internet mode: detecting external IP...")
				detectedIP := detectWanIPNonInteractive()
				// Update UI on main thread
				fyne.Do(func() {
					if detectedIP != "" {
						externalIPEntry.SetText(detectedIP)
						log.Printf("Internet mode: detected external IP %s", detectedIP)
					} else {
						log.Println("Internet mode: could not detect external IP - please enter manually")
					}
				})
			}()
		}
	})
	networkModeSelect.SetSelected(currentConfig.NetworkMode)

	saveBtn := widget.NewButton("Save Config", func() {
		go saveConfigChanges(serverEntry.Text, nickEntry.Text, channelEntry.Text, exportEntry.Text, importEntry.Text, recipientEntry.Text, secretEntry.Text, localPortEntry.Text, externalIPEntry.Text, tlsCheck.Checked, adminCheck.Checked, networkModeSelect.Selected)
	})

	form := container.New(layout.NewFormLayout(),
		widget.NewLabel("Server:"), serverEntry,
		widget.NewLabel("Nick:"), nickEntry,
		widget.NewLabel("Channel:"), channelEntry,
		widget.NewLabel("Export Folder:"), exportEntry,
		widget.NewLabel("Import Folder:"), importEntry,
		widget.NewLabel("Recipient User:"), recipientEntry,
		widget.NewLabel("Pairing Secret:"), secretEntry,
		widget.NewLabel("Local Port:"), localPortEntry,
		widget.NewLabel("External IP:"), externalIPEntry,
		widget.NewLabel("TLS:"), tlsCheck,
		widget.NewLabel("Network Mode:"), networkModeSelect,
		widget.NewLabel("Admin Mode:"), adminCheck,
	)
	configContent := container.NewVBox(form, saveBtn)

	// Chat tab content
	client.scrollDisplay = container.NewScroll(client.display)
	client.scrollDisplay.SetMinSize(fyne.NewSize(400, 300))
	client.display.Wrapping = fyne.TextWrapWord

	client.input.SetPlaceHolder("Type message...")
	client.input.Disable() // Start disabled
	client.input.OnSubmitted = func(msg string) {
		if client.connected && strings.TrimSpace(msg) != "" {
			client.send(fmt.Sprintf("PRIVMSG %s :%s", client.channel, msg))
			client.appendDisplaySafe(fmt.Sprintf("You: %s", msg))
			client.input.SetText("")
		}
	}
	client.connectBtn = widget.NewButton("Connect", func() {
		client.connect(serverEntry.Text, nickEntry.Text, channelEntry.Text, w)
	})
	client.disconnectBtn = widget.NewButton("Disconnect", func() {
		client.disconnect()
	})
	client.disconnectBtn.Disable()
	chatTop := container.NewHBox(client.connectBtn, client.disconnectBtn)
	chatContent := container.NewBorder(chatTop, client.input, nil, nil, client.scrollDisplay)

	// Logs tab content - ENHANCED with selectable text and buttons
	logDisplay := widget.NewRichTextFromMarkdown("") // RichText instead of Label for selectability
	logDisplay.Wrapping = fyne.TextWrapWord
	logScroll := container.NewScroll(logDisplay)
	logScroll.SetMinSize(fyne.NewSize(400, 300))
	
	// Add buttons for log operations
	openEditorBtn := widget.NewButton("Open in Editor", func() {
		go openLogInEditor() // Run in goroutine to avoid blocking
	})
	saveLogBtn := widget.NewButton("Save Log", func() {
		go saveCurrentLog() // Run in goroutine to avoid blocking
	})
	clearLogBtn := widget.NewButton("Clear Display", func() {
		clearLogDisplay(logDisplay) // This one can be immediate
	})
	
	logButtons := container.NewHBox(openEditorBtn, saveLogBtn, clearLogBtn)
	
	// Log display goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Log display panic recovered: %v\n", r)
			}
		}()
		
		for msg := range logChan {
			// Write to file immediately
			writeToLogFile(msg)
			
			// Update in-memory log text
			allLogMutex.Lock()
			allLogText.WriteString(msg)
			allLogMutex.Unlock()
			
			// FIXED: Use fyne.Do instead of fyne.DoAndWait to avoid threading issues
			fyne.Do(func() {
				// Get current content
				allLogMutex.RLock()
				fullText := allLogText.String()
				allLogMutex.RUnlock()
				
				// Limit display size to prevent memory issues
				displayText := fullText
				if len(displayText) > 100000 { // Keep last 100KB of logs in display
					lines := strings.Split(displayText, "\n")
					if len(lines) > 500 {
						displayText = strings.Join(lines[len(lines)-500:], "\n")
					}
				}
				
				// Update the RichText widget
				logDisplay.ParseMarkdown("```\n" + displayText + "\n```")
				logDisplay.Refresh()
				logScroll.ScrollToBottom()
			})
		}
	}()
	
	logsContent := container.NewBorder(logButtons, nil, nil, nil, logScroll)

	// Tabs
	client.tabs = container.NewAppTabs(
		container.NewTabItem("Config", configContent),
		container.NewTabItem("Chat", chatContent),
		container.NewTabItem("Logs", logsContent),
	)

	w.SetContent(client.tabs)
	w.Resize(fyne.NewSize(500, 500))
	w.ShowAndRun()
}

// Log file management functions

func initializeLogFile() {
	logFileMutex.Lock()
	defer logFileMutex.Unlock()
	
	// Close existing file if open
	if logFile != nil {
		logFile.Close()
	}
	
	// Create/truncate the log file
	var err error
	logFile, err = os.Create(logFilePath)
	if err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
		return
	}
	
	// Write session header
	header := fmt.Sprintf("=== CupStringGO-P2P Log Session Started: %s ===\n", 
		time.Now().Format("2006-01-02 15:04:05"))
	logFile.WriteString(header)
	logFile.Sync()
	
	// Initialize the in-memory log builder
	allLogMutex.Lock()
	allLogText.Reset()
	allLogText.WriteString(header)
	allLogMutex.Unlock()
}

func writeToLogFile(message string) {
	logFileMutex.Lock()
	defer logFileMutex.Unlock()
	
	if logFile != nil {
		logFile.WriteString(message)
		logFile.Sync() // Ensure it's written to disk immediately
	}
}

func closeLogFile() {
	logFileMutex.Lock()
	defer logFileMutex.Unlock()
	
	if logFile != nil {
		footer := fmt.Sprintf("\n=== Session Ended: %s ===\n", 
			time.Now().Format("2006-01-02 15:04:05"))
		logFile.WriteString(footer)
		logFile.Close()
		logFile = nil
	}
}

// Button action functions

func openLogInEditor() {
	// Ensure log file is up to date
	logFileMutex.Lock()
	if logFile != nil {
		logFile.Sync()
	}
	logFileMutex.Unlock()
	
	// Get absolute path to the log file
	absPath, err := filepath.Abs(logFilePath)
	if err != nil {
		log.Printf("Failed to get absolute path for log file: %v", err)
		return
	}
	
	// Try to open with default editor (Windows)
	cmd := exec.Command("notepad.exe", absPath)
	err = cmd.Start()
	if err != nil {
		// Fallback: try to open with default associated program
		cmd = exec.Command("cmd", "/C", "start", "", absPath)
		err = cmd.Start()
		if err != nil {
			log.Printf("Failed to open log in editor: %v", err)
			return
		}
	}
	
	log.Printf("Opened log file in editor: %s", absPath)
}

func saveCurrentLog() {
	// The log is already being saved in real-time to current_log.txt
	// This function could create a timestamped backup copy
	
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("log_backup_%s.txt", timestamp)
	
	allLogMutex.RLock()
	logContent := allLogText.String()
	allLogMutex.RUnlock()
	
	err := os.WriteFile(backupPath, []byte(logContent), 0644)
	if err != nil {
		log.Printf("Failed to save log backup: %v", err)
		return
	}
	
	log.Printf("Log saved to backup file: %s", backupPath)
}

func clearLogDisplay(logDisplay *widget.RichText) {
	// Clear only the display, not the actual log file or memory
	fyne.Do(func() {
		logDisplay.ParseMarkdown("```\nLog display cleared (file logging continues)\n```")
		logDisplay.Refresh()
	})
	log.Println("Log display cleared by user")
}

func saveConfigChanges(server string, nick string, channel string, exportFolder string, importFolder string, recipient string, secret string, localPort string, externalIP string, tlsEnabled bool, requireAdmin bool, networkMode string) {
	configMu.Lock()
	oldConfig := *currentConfig
	configMu.Unlock()

	// Parse server and port
	host, portStr := server, "6667"
	if strings.Contains(server, ":") {
		parts := strings.Split(server, ":")
		host, portStr = parts[0], parts[1]
	}
	ircPortInt, _ := strconv.Atoi(portStr)
	
	// Parse local port
	localPortInt, err := strconv.Atoi(localPort)
	if err != nil {
		log.Printf("Invalid local port '%s', keeping existing: %v", localPort, err)
		localPortInt = oldConfig.LocalPort
	}

	newConfig := Config{
		IRCServer:         host,
		IRCPort:           ircPortInt,
		YourUsername:      nick,
		ChannelName:       channel,
		ExportFolder:      exportFolder,
		ImportFolder:      importFolder,
		RecipientUsername: recipient,
		PairingSecret:     secret,
		LocalPort:         localPortInt, // Now editable
		ExternalIP:        externalIP,
		TLSEnabled:        tlsEnabled,
		RequireAdmin:      requireAdmin,
		NetworkMode:       networkMode,
	}

	// Check if this is the first complete config
	wasIncomplete := !isConfigComplete(&oldConfig)
	isNowComplete := isConfigComplete(&newConfig)

	// Check if restart needed (server/port/TLS/IP/export/import/recipient/secret/channel/localport/admin/networkmode changed)
	needsRestart := newConfig.IRCServer != oldConfig.IRCServer ||
		newConfig.IRCPort != oldConfig.IRCPort ||
		newConfig.ChannelName != oldConfig.ChannelName ||
		newConfig.TLSEnabled != oldConfig.TLSEnabled ||
		newConfig.ExportFolder != oldConfig.ExportFolder ||
		newConfig.ImportFolder != oldConfig.ImportFolder ||
		newConfig.RecipientUsername != oldConfig.RecipientUsername ||
		newConfig.PairingSecret != oldConfig.PairingSecret ||
		newConfig.ExternalIP != oldConfig.ExternalIP ||
		newConfig.YourUsername != oldConfig.YourUsername ||
		newConfig.LocalPort != oldConfig.LocalPort || // Add local port change detection
		newConfig.RequireAdmin != oldConfig.RequireAdmin || // Add admin mode change detection
		newConfig.NetworkMode != oldConfig.NetworkMode // Add network mode change detection

	configMu.Lock()
	*currentConfig = newConfig
	configMu.Unlock()

	if err := SaveConfig(configPath, &newConfig); err != nil {
		log.Printf("Failed to save config: %v", err)
		return
	}

	log.Println("Config saved successfully")

	// Check if admin privileges changed and handle accordingly
	if newConfig.RequireAdmin != oldConfig.RequireAdmin {
		if newConfig.RequireAdmin && !isRunningAsAdmin() {
			log.Println("Admin mode enabled but not running as admin - restarting with admin privileges...")
			restartAsAdmin()
			return
		} else if !newConfig.RequireAdmin && isRunningAsAdmin() {
			log.Println("Admin mode disabled - changes will take effect on next restart")
		}
	}

	// If admin is required and we're not running as admin, restart
	if newConfig.RequireAdmin && !isRunningAsAdmin() {
		log.Println("Admin privileges required but not running as admin - restarting...")
		restartAsAdmin()
		return
	}

	// Start P2P for the first time if config is now complete
	if wasIncomplete && isNowComplete {
		log.Println("=== STARTING P2P SYSTEM ===")
		log.Println("Configuration is now complete! Starting P2P and IRC systems...")
		
		var err error
		p2pShutdown, err = RunP2P(configPath, false)
		if err != nil {
			log.Printf("P2P startup failed: %v", err)
		} else {
			log.Println("P2P system started successfully!")
			log.Println("You can now send/receive files and the system will auto-discover peers.")
		}
	} else if isNowComplete && needsRestart && p2pShutdown != nil {
		// Restart existing P2P system
		log.Println("Configuration changed, restarting P2P system...")
		p2pShutdown()
		var err error
		p2pShutdown, err = RunP2P(configPath, false)
		if err != nil {
			log.Printf("P2P restart failed: %v", err)
		} else {
			log.Println("P2P system restarted with new configuration")
		}
	} else if !isNowComplete {
		log.Println("Configuration saved but still incomplete. Please fill all required fields.")
	}
}

// Helper functions for config management

func createDefaultConfig() *Config {
	// Get current directory for default folders
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = "."
	}

	return &Config{
		IRCServer:         "irc.libera.chat",
		IRCPort:           6697,
		ChannelName:       "cupandstring",
		TLSEnabled:        true,
		YourUsername:      "", // User must fill
		RecipientUsername: "", // User must fill
		LocalPort:         4200,
		ExternalIP:        detectLocalIP(), // Auto-detect
		PairingSecret:     "", // User must fill or use default
		ExportFolder:      filepath.Join(currentDir, "export"),
		ImportFolder:      filepath.Join(currentDir, "import"),
		RequireAdmin:      false, // Default to not requiring admin
		NetworkMode:       "LAN", // Default to LAN mode
	}
}

func isConfigComplete(config *Config) bool {
	// Check required fields
	return config.YourUsername != "" &&
		config.RecipientUsername != "" &&
		config.PairingSecret != "" &&
		config.ExportFolder != "" &&
		config.ImportFolder != ""
}

// detectLocalIP finds the best local network IP address (simplified version for GUI)
func detectLocalIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.To4() == nil {
				continue
			}

			ipStr := ip.String()
			if strings.HasPrefix(ipStr, "192.168.") {
				return ipStr
			}
		}
	}

	return "127.0.0.1"
}

// Windows admin privilege functions

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	openProcessToken  = advapi32.NewProc("OpenProcessToken")
	getTokenInfo      = advapi32.NewProc("GetTokenInformation")
)

// checkAdminRequirements checks if admin is required and restarts if needed
func checkAdminRequirements() {
	// Try to load config to see if admin is required
	if config, err := LoadConfig(configPath); err == nil {
		if config.RequireAdmin && !isRunningAsAdmin() {
			log.Println("Admin privileges required, restarting as admin...")
			restartAsAdmin()
			return
		}
	}
	// If config doesn't exist or doesn't require admin, continue normally
}

// isRunningAsAdmin checks if the current process is running with admin privileges
func isRunningAsAdmin() bool {
	var token syscall.Handle
	var isAdmin bool

	// Get current process handle
	process, _, _ := getCurrentProcess.Call()

	// Open process token
	ret, _, _ := openProcessToken.Call(
		process,
		syscall.TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return false
	}
	defer syscall.CloseHandle(token)

	// Get token elevation information
	var elevation uint32
	var returnLength uint32
	const TokenElevation = 20

	ret, _, _ = getTokenInfo.Call(
		uintptr(token),
		TokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		return false
	}

	isAdmin = elevation != 0
	log.Printf("Admin status check: %t", isAdmin)
	return isAdmin
}

// restartAsAdmin restarts the application with admin privileges
func restartAsAdmin() {
	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("Failed to get executable path: %v", err)
		return
	}

	// Get current working directory
	workDir, err := os.Getwd()
	if err != nil {
		log.Printf("Failed to get working directory: %v", err)
		workDir = filepath.Dir(execPath)
	}

	log.Printf("Restarting as admin: %s in %s", execPath, workDir)

	// Use PowerShell to start with admin privileges
	cmd := exec.Command("powershell", "-Command", 
		fmt.Sprintf("Start-Process '%s' -WorkingDirectory '%s' -Verb RunAs", execPath, workDir))
	
	err = cmd.Start()
	if err != nil {
		log.Printf("Failed to restart as admin: %v", err)
		return
	}

	// Exit current process
	log.Println("Exiting current process...")
	os.Exit(0)
}
type chanWriter struct {
	ch chan string
}

func (cw *chanWriter) Write(p []byte) (n int, err error) {
	if cw.ch == nil {
		return len(p), nil // Safety check
	}
	
	message := string(p)
	select {
	case cw.ch <- message:
		// Message sent successfully
	default:
		// Channel full - this prevents blocking but loses the message
		// In GUI mode, we prioritize not hanging the application
	}
	return len(p), nil
}

// IRCClient methods (unchanged)

func (c *IRCClient) connect(server, nick, channel string, w fyne.Window) {
	if c.conn != nil {
		c.appendDisplay("Already connected!")
		return
	}

	// Parse server:port, default 6667
	host, portStr := server, "6667"
	if strings.Contains(server, ":") {
		parts := strings.Split(server, ":")
		host, portStr = parts[0], parts[1]
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		c.appendDisplay("Invalid port: " + err.Error())
		return
	}
	tlsEnabled := portInt == 6697
	addr := fmt.Sprintf("%s:%s", host, portStr)

	// Random nick suffix
	rnd := make([]byte, 4)
	rand.Read(rnd)
	c.nick = fmt.Sprintf("%s_%s", nick, hex.EncodeToString(rnd))
	c.channel = strings.ToLower("#" + strings.TrimPrefix(channel, "#")) // Lowercase channel

	var conn net.Conn
	if tlsEnabled {
		conn, err = tls.Dial("tcp", addr, &tls.Config{})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		c.appendDisplay("Connection error: " + err.Error())
		return
	}
	c.conn = conn
	c.connected = true
	c.connectBtn.Disable()
	c.disconnectBtn.Enable()
	c.input.Enable()
	c.appendDisplay("Connecting as " + c.nick + "...")

	// Send registration
	c.send("NICK " + c.nick)
	c.send("USER " + c.nick + " 0 * :" + c.nick)
	c.send("JOIN " + c.channel)

	go c.readLoop()

	// Switch to chat tab on connect
	c.tabs.SelectIndex(1)
}

func (c *IRCClient) disconnect() {
	if c.conn != nil {
		c.send("QUIT :Bye")
		c.conn.Close()
		c.conn = nil
		c.connected = false
		c.connectBtn.Enable()
		c.disconnectBtn.Disable()
		c.input.Disable()
		c.appendDisplay("Disconnected.")
	}
}

func (c *IRCClient) readLoop() {
	reader := ircreader.NewIRCReader(c.conn)
	for c.conn != nil {
		line, err := reader.ReadLine()
		if err != nil {
			fyne.DoAndWait(func() {
				c.appendDisplay("Read error: " + err.Error())
				c.disconnect()
				time.Sleep(c.reconnect)
				c.reconnect *= 2
				if c.reconnect > time.Minute {
					c.reconnect = time.Minute
				}
			})
			return
		}

		msg, err := ircmsg.ParseLine(string(line))
		if err != nil {
			continue
		}
		fyne.DoAndWait(func() {
			c.handleLine(msg)
		})
	}
}

func (c *IRCClient) handleLine(msg ircmsg.Message) {
	if msg.Command == "PING" {
		c.send("PONG :" + msg.Params[0])
		return
	}

	// Extract user from source
	user := ""
	if msg.Source != "" {
		user = strings.Split(msg.Source, "!")[0]
	}

	switch msg.Command {
	case "001":
		c.appendDisplay("Connected to server.")
	case "433": // Nick in use
		c.appendDisplay("Nick in use; regenerating...")
		rnd := make([]byte, 4)
		rand.Read(rnd)
		newNick := fmt.Sprintf("%s_%s", strings.Split(c.nick, "_")[0], hex.EncodeToString(rnd))
		c.send("NICK " + newNick)
		c.nick = newNick
	case "JOIN":
		if user == c.nick {
			c.appendDisplay("Joined " + c.channel)
		} else {
			c.appendDisplay(user + " joined.")
		}
	case "PRIVMSG":
		if len(msg.Params) < 2 {
			return
		}
		target, text := strings.ToLower(msg.Params[0]), msg.Params[1]
		if target == strings.ToLower(c.channel) || target == strings.ToLower(c.nick) {
			c.appendDisplay(fmt.Sprintf("%s: %s", user, text))
		}
	default:
		// Other: MOTD, etc.
		c.appendDisplay(msg.Command + " " + strings.Join(msg.Params, " "))
	}
}

func (c *IRCClient) send(cmd string) {
	if c.conn == nil {
		return
	}
	fmt.Fprintf(c.conn, "%s\r\n", cmd)
}

func (c *IRCClient) appendDisplay(text string) {
	c.display.SetText(c.display.Text + text + "\n")
	c.display.Refresh()
	c.scrollDisplay.ScrollToBottom()
}

func (c *IRCClient) appendDisplaySafe(text string) {
	fyne.Do(func() {
		c.appendDisplay(text)
	})
}

// -----------------END OF FILE-------------main.go