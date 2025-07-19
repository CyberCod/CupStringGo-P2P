// -----------------BEGIN FILE-------------setup.go

package main

import (
	"bufio"
	"fmt"
	"log"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Windows API structures and functions for firewall management
var (
	firewallRuleName   = "CupAndString_P2P"
	upnpManager        *UPnPManager // Global UPnP manager for cleanup
)

// detectLanIP finds the best local network IP address
func detectLanIP() string {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		TimestampLog(fmt.Sprintf("Failed to get network interfaces: %v", err))
		return "127.0.0.1"
	}

	var ip192, ip10, ipOther string

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
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

			// Only consider IPv4 addresses
			if ip == nil || ip.To4() == nil {
				continue
			}

			ipStr := ip.String()
			
			// Skip loopback
			if strings.HasPrefix(ipStr, "127.") {
				continue
			}

			// Prioritize 192.168.* addresses
			if strings.HasPrefix(ipStr, "192.168.") && ip192 == "" {
				ip192 = ipStr
			} else if strings.HasPrefix(ipStr, "10.") && ip10 == "" {
				ip10 = ipStr
			} else if ipOther == "" {
				ipOther = ipStr
			}
		}
	}

	// Return in priority order
	if ip192 != "" {
		return ip192
	}
	if ip10 != "" {
		return ip10
	}
	if ipOther != "" {
		return ipOther
	}

	TimestampLog("No suitable local IP found, using localhost")
	return "127.0.0.1"
}


// detectWanIPNonInteractive attempts to detect the public IP address without user interaction
func detectWanIPNonInteractive() string {
	// HTTP and HTTPS services for IP detection
	services := []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://ipinfo.io/ip",
		"https://api.ipsimple.org/ipv4",
		"http://ipecho.net/plain",
		"http://icanhazip.com",
		"http://ifconfig.me",
		"https://ipapi.co/ip",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		TimestampLog(fmt.Sprintf("Trying IP detection service: %s", service))
		
		resp, err := client.Get(service)
		if err != nil {
			TimestampLog(fmt.Sprintf("Failed to connect to %s: %v", service, err))
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if err != nil {
			TimestampLog(fmt.Sprintf("Failed to read response from %s: %v", service, err))
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		TimestampLog(fmt.Sprintf("Received from %s: '%s' (Status: %d)", service, ipStr, resp.StatusCode))

		// Validate IP address
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil && ipStr != "0.0.0.0" && ipStr != "127.0.0.1" {
			TimestampLog(fmt.Sprintf("Detected WAN IP using %s: %s", service, ipStr))
			return ipStr
		} else {
			TimestampLog(fmt.Sprintf("Invalid IP from %s: %s", service, ipStr))
		}
	}

	TimestampLog("WARNING: All automatic WAN IP detection services failed.")
	return "" // Return empty string instead of prompting user
}

// detectWanIP attempts to detect the public IP address using multiple services
func detectWanIP() string {
	// HTTP and HTTPS services for IP detection
	services := []string{
		"http://ipecho.net/plain",
		"http://icanhazip.com",
		"http://ifconfig.me",
		"https://api.ipsimple.org/ipv4",
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://ipinfo.io/ip",
		"https://ipapi.co/ip",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		TimestampLog(fmt.Sprintf("Trying IP detection service: %s", service))
		
		resp, err := client.Get(service)
		if err != nil {
			TimestampLog(fmt.Sprintf("Failed to connect to %s: %v", service, err))
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if err != nil {
			TimestampLog(fmt.Sprintf("Failed to read response from %s: %v", service, err))
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		TimestampLog(fmt.Sprintf("Received from %s: '%s' (Status: %d)", service, ipStr, resp.StatusCode))

		// Validate IP address
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil && ipStr != "0.0.0.0" && ipStr != "127.0.0.1" {
			TimestampLog(fmt.Sprintf("Detected WAN IP using %s: %s", service, ipStr))
			return ipStr
		} else {
			TimestampLog(fmt.Sprintf("Invalid IP from %s: %s", service, ipStr))
		}
	}

	// All automatic detection failed, ask user for manual input
	TimestampLog("WARNING: All automatic WAN IP detection services failed.")
	log.Println("Visit https://whatismyipaddress.com or similar to find your public IP.")
	
	scanner := bufio.NewScanner(os.Stdin)
	for {
		log.Print("Enter your public IP manually: ")
		scanner.Scan()
		manualIP := strings.TrimSpace(scanner.Text())
		
		// Validate manually entered IP
		ip := net.ParseIP(manualIP)
		if ip != nil && ip.To4() != nil && manualIP != "0.0.0.0" && manualIP != "127.0.0.1" {
			TimestampLog(fmt.Sprintf("Using manually entered WAN IP: %s", manualIP))
			return manualIP
		} else {
			log.Println("ERROR: Invalid IP format. Please try again.")
		}
	}
}

// findFreeListenPort finds an available port starting from basePort
func findFreeListenPort(basePort int) int {
	maxPort := basePort + 100 // Search up to basePort + 100
	
	for port := basePort; port <= maxPort; port++ {
		// Try to bind to the port
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			continue // Port is busy, try next
		}
		
		// Port is available, close the listener and return
		listener.Close()
		
		if port != basePort {
			TimestampLog(fmt.Sprintf("Port %d busy, using %d", basePort, port))
		} else {
			TimestampLog(fmt.Sprintf("Port %d available", port))
		}
		return port
	}

	// No free port found in range
	TimestampLog(fmt.Sprintf("ERROR: No free port in range %d-%d!", basePort, maxPort))
	log.Printf("ERROR: No free port in range %d-%d!\n", basePort, maxPort)
	log.Println("Press Enter to exit...")
	bufio.NewScanner(os.Stdin).Scan()
	os.Exit(1)
	return 0
}

// createFirewallRule creates a Windows firewall rule for the specified port
func createFirewallRule(port int) error {
	// Remove existing rule first to avoid duplicates
	removeCmd := fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, firewallRuleName)
	exec.Command("cmd", "/C", removeCmd).Run() // Ignore errors for remove

	// Create new rule
	addCmd := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=%d`, 
		firewallRuleName, port)
	
	err := exec.Command("cmd", "/C", addCmd).Run()
	
	if err == nil {
		TimestampLog(fmt.Sprintf("OK: Firewall rule created/updated for port %d", port))
		return nil
	} else {
		TimestampLog(fmt.Sprintf("WARNING: Failed to create firewall rule for port %d", port))
		log.Printf("WARNING: Failed to create firewall rule for port %d\n", port)
		log.Println("Application may not receive connections. Check if running as admin.")
		return fmt.Errorf("firewall rule creation failed")
	}
}

// removeFirewallRule removes the Windows firewall rule
func removeFirewallRule() {
	removeCmd := fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, firewallRuleName)
	err := exec.Command("cmd", "/C", removeCmd).Run()
	
	if err == nil {
		TimestampLog("OK: Firewall rule removed")
	} else {
		TimestampLog("WARNING: Failed to remove firewall rule")
	}
}

// validateName checks if a name contains only valid characters (letters, numbers, underscores)
func validateName(name, fieldName string) bool {
	if name == "" {
		return true // Empty names are allowed for optional fields
	}
	
	// Only allow letters, numbers, and underscores
	validName := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validName.MatchString(name) {
		log.Printf("ERROR: %s cannot contain spaces, hyphens, or special characters. Use underscores instead.\n", fieldName)
		return false
	}
	return true
}

// testNetworkConnectivity tests basic network connectivity
func testNetworkConnectivity() {
	TimestampLog("Testing network connectivity...")
	
	// Try to connect to Google DNS
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		TimestampLog("WARNING: No internet connectivity detected")
		log.Println("WARNING: No internet connectivity detected")
		log.Println("IRC connection may fail")
		return
	}
	conn.Close()
	
	TimestampLog("OK: Network connectivity confirmed")
	log.Println("OK: Network connectivity confirmed")
}

// testDirectoryPermissions tests if we can write to a directory
func testDirectoryPermissions(dir string) error {
	testFile := filepath.Join(dir, "writetest.tmp")
	
	// Try to create and write to test file
	file, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("cannot create file in directory: %v", err)
	}
	
	_, err = file.WriteString("test")
	file.Close()
	
	if err != nil {
		os.Remove(testFile)
		return fmt.Errorf("cannot write to file: %v", err)
	}
	
	// Clean up test file
	err = os.Remove(testFile)
	if err != nil {
		return fmt.Errorf("cannot remove test file: %v", err)
	}
	
	return nil
}

// runInteractiveSetup runs the interactive setup wizard
func runInteractiveSetup() *Config {
	log.Println("===============================================================")
	log.Println("                    CUP AND STRING P2P FILE SYNC")
	log.Println("===============================================================")
	log.Println()

	// Default values
	config := &Config{
		IRCServer:         "irc.libera.chat",
		IRCPort:           6697,
		ChannelName:       "cupandstring",
		TLSEnabled:        true,
		LocalPort:         4200,
		ExternalIP:        "127.0.0.1",
		PairingSecret:     "Practice",
	}

	// Get current directory for default folders
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = "."
	}
	config.ExportFolder = filepath.Join(currentDir, "export")
	config.ImportFolder = filepath.Join(currentDir, "import")

	scanner := bufio.NewScanner(os.Stdin)

	log.Println("Enter configuration (press Enter for defaults):")
	log.Println()
	log.Println("WARNING: Names are CASE SENSITIVE. Use only letters, numbers, and underscores.")
	log.Println("Do NOT use spaces, hyphens, or special characters like @#$%^&*")
	log.Println()

	// Network type selection
	log.Println("Are you connecting to the recipient on the same local network or over the Internet?")
	log.Println("  1 = Same local network (LAN) - faster, more reliable")
	log.Println("  2 = Over the Internet (WAN) - works anywhere but slower")
	log.Print("Enter choice [1]: ")
	scanner.Scan()
	networkInput := strings.TrimSpace(scanner.Text())
	
	networkType := "LAN"
	if networkInput == "2" {
		networkType = "WAN"
		config.ExternalIP = detectWanIP()
	} else {
		config.ExternalIP = detectLanIP()
	}
	log.Printf("Detected IP: %s\n", config.ExternalIP)

	// IRC server
	log.Printf("IRC server [%s]: ", config.IRCServer)
	scanner.Scan()
	if input := strings.TrimSpace(scanner.Text()); input != "" {
		config.IRCServer = input
	}

	// IRC port
	log.Printf("IRC port [%d]: ", config.IRCPort)
	scanner.Scan()
	if input := strings.TrimSpace(scanner.Text()); input != "" {
		if port, err := strconv.Atoi(input); err == nil {
			config.IRCPort = port
		}
	}

	// TLS
	log.Print("Use TLS (secure connection)? (Y/N) [Y]: ")
	scanner.Scan()
	tlsInput := strings.ToLower(strings.TrimSpace(scanner.Text()))
	config.TLSEnabled = !(tlsInput == "n" || tlsInput == "no")

	// Local port
	log.Printf("Local listen port [%d]: ", config.LocalPort)
	scanner.Scan()
	if input := strings.TrimSpace(scanner.Text()); input != "" {
		if port, err := strconv.Atoi(input); err == nil {
			config.LocalPort = port
		}
	}

	// Find free port
	config.LocalPort = findFreeListenPort(config.LocalPort)

	// Export folder
	log.Printf("Export folder [%s]: ", config.ExportFolder)
	scanner.Scan()
	if input := strings.TrimSpace(scanner.Text()); input != "" {
		config.ExportFolder = input
	}

	// Import folder
	log.Printf("Import folder [%s]: ", config.ImportFolder)
	scanner.Scan()
	if input := strings.TrimSpace(scanner.Text()); input != "" {
		config.ImportFolder = input
	}

	log.Println()
	log.Println("IRC Channel Configuration:")
	log.Println("(Use only letters, numbers, and underscores - NO spaces or special chars)")
	log.Println()

	// Channel name
	for {
		log.Printf("IRC channel name [%s]: ", config.ChannelName)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			break // Use default
		}
		if validateName(input, "Channel name") {
			config.ChannelName = input
			break
		}
	}

	// Your username
	for {
		log.Print("Your username []: ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			break // Empty is allowed
		}
		if validateName(input, "Username") {
			config.YourUsername = input
			break
		}
	}

	// Recipient username
	for {
		log.Print("Recipient username []: ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			break // Empty is allowed
		}
		if validateName(input, "Username") {
			config.RecipientUsername = input
			break
		}
	}

	// Pairing secret
	for {
		log.Printf("What are we talking about? [%s]: ", config.PairingSecret)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			break // Use default
		}
		if validateName(input, "Pairing secret") {
			config.PairingSecret = input
			break
		}
	}

	// Display configuration summary
	TimestampLog("Configuration set:")
	TimestampLog(fmt.Sprintf("  Network Type: %s", networkType))
	TimestampLog(fmt.Sprintf("  Your IP: %s", config.ExternalIP))
	TimestampLog(fmt.Sprintf("  IRC Server: %s", config.IRCServer))
	TimestampLog(fmt.Sprintf("  IRC Port: %d", config.IRCPort))
	TimestampLog(fmt.Sprintf("  TLS Enabled: %t", config.TLSEnabled))
	TimestampLog(fmt.Sprintf("  Listen Port: %d", config.LocalPort))
	TimestampLog(fmt.Sprintf("  Export Folder: %s", config.ExportFolder))
	TimestampLog(fmt.Sprintf("  Import Folder: %s", config.ImportFolder))
	TimestampLog(fmt.Sprintf("  Channel: %s", config.ChannelName))
	TimestampLog(fmt.Sprintf("  Your Username: %s", config.YourUsername))
	TimestampLog(fmt.Sprintf("  Recipient: %s", config.RecipientUsername))
	TimestampLog(fmt.Sprintf("  Pairing Secret: %s", config.PairingSecret))

	return config
}

// setupDirectories creates and tests the export and import directories
func setupDirectories(config *Config) error {
	TimestampLog("[2/5] Setting up directories...")

	// Create export folder
	if _, err := os.Stat(config.ExportFolder); os.IsNotExist(err) {
		TimestampLog(fmt.Sprintf("Creating directory: %s", config.ExportFolder))
		if err := os.MkdirAll(config.ExportFolder, 0755); err != nil {
			return fmt.Errorf("failed to create export folder: %v", err)
		}
	} else {
		TimestampLog(fmt.Sprintf("OK: Directory exists: %s", config.ExportFolder))
	}

	// Create import folder
	if _, err := os.Stat(config.ImportFolder); os.IsNotExist(err) {
		TimestampLog(fmt.Sprintf("Creating directory: %s", config.ImportFolder))
		if err := os.MkdirAll(config.ImportFolder, 0755); err != nil {
			return fmt.Errorf("failed to create import folder: %v", err)
		}
	} else {
		TimestampLog(fmt.Sprintf("OK: Directory exists: %s", config.ImportFolder))
	}

	// Test write permissions for export folder
	if err := testDirectoryPermissions(config.ExportFolder); err != nil {
		return fmt.Errorf("no write permission for export folder %s: %v", config.ExportFolder, err)
	}
	TimestampLog("OK: Write permissions confirmed for export folder")

	// Test write permissions for import folder
	if err := testDirectoryPermissions(config.ImportFolder); err != nil {
		return fmt.Errorf("no write permission for import folder %s: %v", config.ImportFolder, err)
	}
	TimestampLog("OK: Write permissions confirmed for import folder")

	return nil
}

// saveConfiguration saves the configuration to mysetup.json
func saveConfiguration(config *Config) error {
	TimestampLog("[3/5] Saving configuration...")
	TimestampLog("Saving configuration to mysetup.json...")

	// Convert Windows paths to JSON format (forward slashes)
	config.ExportFolder = filepath.ToSlash(config.ExportFolder)
	config.ImportFolder = filepath.ToSlash(config.ImportFolder)

	TimestampLog(fmt.Sprintf("EXPORT_JSON = %s", config.ExportFolder))
	TimestampLog(fmt.Sprintf("IMPORT_JSON = %s", config.ImportFolder))

	// Save configuration using the SaveConfig function from config.go
	if err := SaveConfig("mysetup.json", config); err != nil {
		return fmt.Errorf("failed to save configuration: %v", err)
	}

	TimestampLog("OK: Configuration saved to mysetup.json")
	return nil
}

// performSystemChecks performs pre-flight system checks
func performSystemChecks(config *Config) error {
	TimestampLog("[4/5] Pre-flight system check...")

	// Test network connectivity
	testNetworkConnectivity()

	// Check UPnP support
	TimestampLog("Checking UPnP support for automatic port opening...")
	if checkUPnPSupport() {
		TimestampLog("OK: UPnP support detected")
		
		// Optionally show available devices for debugging
		discoverUPnPDevices()
	} else {
		TimestampLog("WARNING: No UPnP support detected")
		TimestampLog("You may need to manually configure port forwarding on your router")
	}

	// Create firewall rule
	TimestampLog(fmt.Sprintf("Setting up firewall rule for port %d...", config.LocalPort))
	createFirewallRule(config.LocalPort)

	return nil
}

// RunSetup runs the complete setup process
func RunSetup() *Config {
	TimestampLog("[1/5] Loading configuration...")

	var config *Config

	// Check if config file exists
	if _, err := os.Stat("mysetup.json"); err == nil {
		TimestampLog("Found existing configuration file")
		TimestampLog("Auto-loading saved configuration...")
		TimestampLog("TO RECONFIGURE SOFTWARE")
		TimestampLog("DELETE OR RENAME mysetup.json")

		// Load existing config
		var err error
		config, err = LoadConfig("mysetup.json")
		if err != nil {
			TimestampLog(fmt.Sprintf("Failed to load existing config: %v", err))
			TimestampLog("Running interactive setup...")
			config = runInteractiveSetup()
		} else {
			// Re-detect IP and port for existing config
			if strings.Contains(config.ExternalIP, "192.168.") || strings.Contains(config.ExternalIP, "10.") {
				// Assume LAN
				config.ExternalIP = detectLanIP()
			} else {
				// Assume WAN
				config.ExternalIP = detectWanIP()
			}
			TimestampLog(fmt.Sprintf("Detected IP: %s", config.ExternalIP))

			// Find free listen port
			config.LocalPort = findFreeListenPort(config.LocalPort)
			TimestampLog("Configuration loaded successfully")
		}
	} else {
		TimestampLog("No existing configuration found, will create new one")
		config = runInteractiveSetup()
	}

	// Setup directories
	if err := setupDirectories(config); err != nil {
		TimestampLog(fmt.Sprintf("Directory setup failed: %v", err))
		os.Exit(1)
	}

	// Save configuration
	if err := saveConfiguration(config); err != nil {
		TimestampLog(fmt.Sprintf("Configuration save failed: %v", err))
		os.Exit(1)
	}

	// Perform system checks
	if err := performSystemChecks(config); err != nil {
		TimestampLog(fmt.Sprintf("System checks failed: %v", err))
		// Don't exit on system check failures, just warn
	}

	TimestampLog("[5/5] Starting Cup and String P2P File Sync...")
	TimestampLog("Setup completed, starting P2P file sync")

	return config
}

// CleanupSetup performs cleanup operations (like removing firewall rules and UPnP mappings)
func CleanupSetup() {
	// Add panic recovery to prevent crashes during cleanup
	defer func() {
		if r := recover(); r != nil {
			TimestampLog(fmt.Sprintf("Cleanup panic recovered: %v", r))
		}
	}()
	
	TimestampLog("Performing setup cleanup...")
	
	// Remove UPnP port mapping using the global manager
	if upnpManager != nil {
		TimestampLog("Cleaning up UPnP manager...")
		if err := upnpManager.Close(); err != nil {
			TimestampLog(fmt.Sprintf("UPnP cleanup error: %v", err))
		}
		upnpManager = nil
	}
	
	// Remove UPnP port mapping using the global variable (fallback)
	if activePortMapping != nil {
		TimestampLog("Cleaning up global UPnP mapping...")
		if err := removeUPnPPortMapping(activePortMapping); err != nil {
			TimestampLog(fmt.Sprintf("UPnP cleanup error: %v", err))
		}
		activePortMapping = nil
	}
	
	// Remove firewall rule
	removeFirewallRule()
	
	TimestampLog("Cleanup completed")
}

// -----------------END OF FILE-------------setup.go