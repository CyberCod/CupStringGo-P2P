// -----------------BEGIN FILE-------------p2p_main.go

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
)

var globalConfig *Config
var activePortMapping *UPnPPortMapping // Global variable for UPnP port mapping

// RunP2P starts the P2P file sync process
// Returns a shutdown function and any error
func RunP2P(configPath string, forceSetup bool) (func(), error) {
	ctx, cancel := context.WithCancel(context.Background())

	var config *Config
	var err error

	// Check if we need to run setup
	needsSetup := forceSetup || !configFileExists(configPath)

	if needsSetup {
		// Run interactive setup
		config = RunSetup()
		globalConfig = config
	} else {
		// Load existing configuration
		config, err = LoadConfig(configPath)
		if err != nil {
			log.Printf("Failed to load config, running setup: %v", err)
			config = RunSetup()
		}

		// Re-detect IP and port for existing config (like PowerShell script does)
		TimestampLog("Re-detecting network settings...")
		
		// Determine if this looks like a LAN or WAN IP to decide detection method
		if isLanIP(config.ExternalIP) {
			config.ExternalIP = detectLanIP()
		} else {
			config.ExternalIP = detectWanIPNonInteractive()
		}
		TimestampLog("Detected IP: " + config.ExternalIP)

		// Find free listen port
		config.LocalPort = findFreeListenPort(config.LocalPort)
		
		// Create firewall rule for existing config
		createFirewallRule(config.LocalPort)
		
		globalConfig = config
	}

	// REMOVED: defer CleanupSetup() - cleanup now happens in shutdown function

	// Monitor goroutine count for debugging
	initialGoroutines := runtime.NumGoroutine()
	TimestampLog(fmt.Sprintf("Initial goroutine count: %d", initialGoroutines))

	// Initialize networking sequentially to prevent resource conflicts
	p2pHost, multiAddr, err := initializeNetworkingSequentially(globalConfig)
	if err != nil {
		return nil, fmt.Errorf("Network initialization failed: %v", err)
	}
	// REMOVED: defer p2pHost.Close() - this was closing the host immediately!

	var wg sync.WaitGroup
	triggerChan := make(chan bool, 1) // For watcher to IRC trigger

	// Start IRC bot
	wg.Add(1)
	go func() {
		defer wg.Done()
		StartBot(globalConfig, multiAddr, p2pHost, triggerChan)
	}()

	// Start file watchers
	wg.Add(1)
	go func() {
		defer wg.Done()
		StartWatchers(globalConfig, triggerChan)
	}()

	finalGoroutines := runtime.NumGoroutine()
	TimestampLog(fmt.Sprintf("Final goroutine count: %d (started with %d)", finalGoroutines, initialGoroutines))
	TimestampLog("Cup and String P2P File Sync started successfully")

	// Goroutine to wait for context cancel and shutdown
	go func() {
		<-ctx.Done()
		log.Println("Shutting down...")
		TimestampLog("Received shutdown signal")
		
		// Properly close P2P host on shutdown
		if p2pHost != nil {
			TimestampLog("Closing P2P host...")
			p2pHost.Close()
		}
		
		wg.Wait()
		log.Println("Done.")
		TimestampLog("Shutdown complete")
	}()

	// Return the shutdown function with cleanup included
	return func() {
		cancel()
		CleanupSetup() // Cleanup happens here when shutdown is called
	}, nil
}

func initializeNetworkingSequentially(config *Config) (host.Host, string, error) {
	TimestampLog("=== Starting Sequential Network Initialization ===")
	
	// Phase 1: UPnP setup with proper resource management
	TimestampLog("Phase 1: Setting up UPnP with resource management...")
	beforeUPnP := runtime.NumGoroutine()
	
	upnpManager, err := setupUPnPWithResourceManagement(config)
	if err != nil {
		TimestampLog(fmt.Sprintf("UPnP setup failed (non-fatal): %v", err))
		log.Printf("WARNING: UPnP automatic port opening failed: %v", err)
		log.Println("You may need to manually configure port forwarding on your router")
	} else {
		activePortMapping = upnpManager.GetMapping()
		TimestampLog("UPnP setup completed successfully")
	}
	
	afterUPnP := runtime.NumGoroutine()
	TimestampLog(fmt.Sprintf("Goroutines: before UPnP %d, after UPnP %d", beforeUPnP, afterUPnP))
	
	// Phase 2: Allow network stack to stabilize and cleanup resources
	TimestampLog("Phase 2: Stabilizing network resources...")
	time.Sleep(1 * time.Second)
	
	// Force garbage collection to clean up any leaked resources
	runtime.GC()
	afterGC := runtime.NumGoroutine()
	TimestampLog(fmt.Sprintf("Goroutines after GC: %d", afterGC))
	
	// Phase 3: Create P2P host only after UPnP cleanup
	TimestampLog("Phase 3: Creating P2P host...")
	p2pHost, multiAddr, err := NewHostWithRetry(config)
	if err != nil {
		return nil, "", fmt.Errorf("P2P host creation failed: %v", err)
	}
	
	log.Printf("Started. Multiaddr: %s", multiAddr)
	TimestampLog("=== Network Initialization Complete ===")
	
	return p2pHost, multiAddr, nil
}

// setupUPnPWithResourceManagement handles UPnP setup with proper cleanup
func setupUPnPWithResourceManagement(config *Config) (*UPnPManager, error) {
	// Skip UPnP entirely for LAN mode
	if config.NetworkMode == "LAN" {
		TimestampLog("LAN mode detected - UPnP not needed, skipping")
		return nil, fmt.Errorf("UPnP not needed for LAN connections")
	}
	
	TimestampLog("Internet mode detected - setting up UPnP...")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	manager := NewUPnPManager()
	
	if err := manager.DiscoverAndSetupPortMapping(ctx, config.LocalPort); err != nil {
		manager.Close()
		return nil, err
	}
	
	return manager, nil
}

// NewHostWithRetry creates P2P host with retry logic for better reliability
func NewHostWithRetry(config *Config) (host.Host, string, error) {
	maxRetries := 3
	baseDelay := 1 * time.Second
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		TimestampLog(fmt.Sprintf("P2P host creation attempt %d/%d", attempt, maxRetries))
		
		// Try to create host
		h, addr, createErr := NewHost(config)
		if createErr == nil {
			TimestampLog("P2P host created successfully")
			return h, addr, nil
		}
		
		TimestampLog(fmt.Sprintf("P2P host creation attempt %d failed: %v", attempt, createErr))
		
		if attempt < maxRetries {
			delay := time.Duration(attempt) * baseDelay
			TimestampLog(fmt.Sprintf("Retrying in %v...", delay))
			time.Sleep(delay)
		} else {
			return nil, "", fmt.Errorf("P2P host creation failed after %d attempts: %v", maxRetries, createErr)
		}
	}
	
	return nil, "", fmt.Errorf("unexpected error in retry logic")
}

// configFileExists checks if the configuration file exists
func configFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

// isLanIP determines if an IP address appears to be a local network IP
func isLanIP(ip string) bool {
	return ip == "127.0.0.1" || 
		   ip == "localhost" ||
		   (len(ip) >= 8 && ip[:8] == "192.168.") ||
		   (len(ip) >= 3 && ip[:3] == "10.") ||
		   (len(ip) >= 8 && ip[:8] == "172.16.") ||
		   (len(ip) >= 8 && ip[:8] == "172.17.") ||
		   (len(ip) >= 8 && ip[:8] == "172.18.") ||
		   (len(ip) >= 8 && ip[:8] == "172.19.") ||
		   (len(ip) >= 7 && ip[:7] == "172.2") ||
		   (len(ip) >= 7 && ip[:7] == "172.3")
}

// -----------------END OF FILE-------------p2p_main.go