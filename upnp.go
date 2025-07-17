// -----------------BEGIN FILE-------------upnp.go
package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

// UPnPPortMapping represents an active port mapping
type UPnPPortMapping struct {
	ExternalPort int
	InternalPort int
	InternalIP   string
	Protocol     string
	Description  string
	clientV1     *internetgateway1.WANIPConnection1
	clientV2     *internetgateway2.WANIPConnection1
	clientType   string // "v1" or "v2"
}

// UPnPManager handles UPnP operations with proper resource management
type UPnPManager struct {
	clients    []interface{}
	cleanup    []func()
	mapping    *UPnPPortMapping
	mu         sync.Mutex
	closed     bool
}

// NewUPnPManager creates a new UPnP manager with resource tracking
func NewUPnPManager() *UPnPManager {
	return &UPnPManager{
		clients: make([]interface{}, 0),
		cleanup: make([]func(), 0),
	}
}

// DiscoverAndSetupPortMapping discovers devices and sets up port mapping
func (m *UPnPManager) DiscoverAndSetupPortMapping(ctx context.Context, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return fmt.Errorf("manager is closed")
	}
	
	TimestampLog("=== UPnP Manager: Starting Discovery ===")
	
	// Get local IP address first
	localIP, err := getLocalIPWithTimeout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local IP: %v", err)
	}
	TimestampLog(fmt.Sprintf("Local IP detected: %s", localIP))
	
	// Try IGDv2 first
	if mapping, err := m.tryIGDv2WithContext(ctx, port, localIP); err == nil {
		m.mapping = mapping
		TimestampLog("UPnP port mapping successful using IGDv2")
		return nil
	} else {
		TimestampLog(fmt.Sprintf("IGDv2 failed: %v", err))
	}
	
	// Try IGDv1 as fallback
	if mapping, err := m.tryIGDv1WithContext(ctx, port, localIP); err == nil {
		m.mapping = mapping
		TimestampLog("UPnP port mapping successful using IGDv1")
		return nil
	} else {
		TimestampLog(fmt.Sprintf("IGDv1 failed: %v", err))
	}
	
	return fmt.Errorf("UPnP port mapping failed with both IGDv1 and IGDv2")
}

// tryIGDv2WithContext attempts IGDv2 port mapping with proper resource management
func (m *UPnPManager) tryIGDv2WithContext(ctx context.Context, port int, localIP string) (*UPnPPortMapping, error) {
	TimestampLog("  IGDv2: Starting context-aware discovery...")
	
	// Use context-aware discovery
	clients, errors, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("IGDv2 discovery failed: %v", err)
	}
	
	TimestampLog(fmt.Sprintf("  IGDv2: Found %d devices, %d errors", len(clients), len(errors)))
	
	// Log any query errors separately
	for i, e := range errors {
		if e != nil {
			TimestampLog(fmt.Sprintf("  IGDv2: Query error for device %d: %v", i, e))
		}
	}
	
	if len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv2 devices found")
	}
	
	// Try port mapping with each client
	for i, client := range clients {
		if client == nil {
			TimestampLog(fmt.Sprintf("  IGDv2: Client %d is nil", i))
			continue
		}
		
		// Check if there is an error for this client
		if i < len(errors) && errors[i] != nil {
			TimestampLog(fmt.Sprintf("  IGDv2: Skipping client %d due to error: %v", i, errors[i]))
			continue
		}
		
		// Register client for cleanup
		m.clients = append(m.clients, client)
		m.cleanup = append(m.cleanup, func() {
			TimestampLog("Cleaning up IGDv2 client")
		})
		
		TimestampLog(fmt.Sprintf("  IGDv2: Trying port mapping with device %d", i))
		
		mapping, err := m.createPortMappingV2(ctx, client, port, localIP)
		if err != nil {
			TimestampLog(fmt.Sprintf("  IGDv2: Device %d mapping failed: %v", i, err))
			continue
		}
		
		return mapping, nil
	}
	
	return nil, fmt.Errorf("no IGDv2 devices could create port mapping")
}

// tryIGDv1WithContext attempts IGDv1 port mapping with proper resource management
func (m *UPnPManager) tryIGDv1WithContext(ctx context.Context, port int, localIP string) (*UPnPPortMapping, error) {
	TimestampLog("  IGDv1: Starting context-aware discovery...")
	
	// Use context-aware discovery
	clients, errors, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("IGDv1 discovery failed: %v", err)
	}
	
	TimestampLog(fmt.Sprintf("  IGDv1: Found %d devices, %d errors", len(clients), len(errors)))
	
	// Log any query errors separately
	for i, e := range errors {
		if e != nil {
			TimestampLog(fmt.Sprintf("  IGDv1: Query error for device %d: %v", i, e))
		}
	}
	
	if len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv1 devices found")
	}
	
	// Try port mapping with each client
	for i, client := range clients {
		if client == nil {
			TimestampLog(fmt.Sprintf("  IGDv1: Client %d is nil", i))
			continue
		}
		
		// Check if there is an error for this client
		if i < len(errors) && errors[i] != nil {
			TimestampLog(fmt.Sprintf("  IGDv1: Skipping client %d due to error: %v", i, errors[i]))
			continue
		}
		
		// Register client for cleanup
		m.clients = append(m.clients, client)
		m.cleanup = append(m.cleanup, func() {
			TimestampLog("Cleaning up IGDv1 client")
		})
		
		TimestampLog(fmt.Sprintf("  IGDv1: Trying port mapping with device %d", i))
		
		mapping, err := m.createPortMappingV1(ctx, client, port, localIP)
		if err != nil {
			TimestampLog(fmt.Sprintf("  IGDv1: Device %d mapping failed: %v", i, err))
			continue
		}
		
		return mapping, nil
	}
	
	return nil, fmt.Errorf("no IGDv1 devices could create port mapping")
}

// createPortMappingV2 creates a port mapping using IGDv2
func (m *UPnPManager) createPortMappingV2(ctx context.Context, client *internetgateway2.WANIPConnection1, port int, localIP string) (*UPnPPortMapping, error) {
	description := "CupAndString P2P File Sync"
	
	// Add timeout for port mapping operation
	mappingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	// Create a channel to handle the result
	resultChan := make(chan error, 1)
	
	go func() {
		err := client.AddPortMapping(
			"",                    // RemoteHost (empty for any)
			uint16(port),          // ExternalPort
			"TCP",                 // Protocol
			uint16(port),          // InternalPort
			localIP,               // InternalClient
			true,                  // Enabled
			description,           // Description
			uint32(3600),          // LeaseDuration (1 hour)
		)
		resultChan <- err
	}()
	
	select {
	case err := <-resultChan:
		if err != nil {
			return nil, fmt.Errorf("IGDv2 AddPortMapping failed: %v", err)
		}
	case <-mappingCtx.Done():
		return nil, fmt.Errorf("IGDv2 port mapping timeout")
	}
	
	TimestampLog(fmt.Sprintf("  IGDv2: Port mapping successful! External:%d -> %s:%d", port, localIP, port))
	
	return &UPnPPortMapping{
		ExternalPort: port,
		InternalPort: port,
		InternalIP:   localIP,
		Protocol:     "TCP",
		Description:  description,
		clientV2:     client,
		clientType:   "v2",
	}, nil
}

// createPortMappingV1 creates a port mapping using IGDv1
func (m *UPnPManager) createPortMappingV1(ctx context.Context, client *internetgateway1.WANIPConnection1, port int, localIP string) (*UPnPPortMapping, error) {
	description := "CupAndString P2P File Sync"
	
	// Add timeout for port mapping operation
	mappingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	// Create a channel to handle the result
	resultChan := make(chan error, 1)
	
	go func() {
		err := client.AddPortMapping(
			"",                    // RemoteHost (empty for any)
			uint16(port),          // ExternalPort
			"TCP",                 // Protocol
			uint16(port),          // InternalPort
			localIP,               // InternalClient
			true,                  // Enabled
			description,           // Description
			uint32(3600),          // LeaseDuration (1 hour)
		)
		resultChan <- err
	}()
	
	select {
	case err := <-resultChan:
		if err != nil {
			return nil, fmt.Errorf("IGDv1 AddPortMapping failed: %v", err)
		}
	case <-mappingCtx.Done():
		return nil, fmt.Errorf("IGDv1 port mapping timeout")
	}
	
	TimestampLog(fmt.Sprintf("  IGDv1: Port mapping successful! External:%d -> %s:%d", port, localIP, port))
	
	return &UPnPPortMapping{
		ExternalPort: port,
		InternalPort: port,
		InternalIP:   localIP,
		Protocol:     "TCP",
		Description:  description,
		clientV1:     client,
		clientType:   "v1",
	}, nil
}

// GetMapping returns the current port mapping
func (m *UPnPManager) GetMapping() *UPnPPortMapping {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mapping
}

// Close cleans up all resources
func (m *UPnPManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return nil
	}
	
	m.closed = true
	
	TimestampLog("UPnP Manager: Starting cleanup...")
	
	// Remove port mapping if it exists
	if m.mapping != nil {
		if err := m.removePortMapping(m.mapping); err != nil {
			TimestampLog(fmt.Sprintf("Failed to remove port mapping: %v", err))
		}
	}
	
	// Execute all cleanup functions
	for i, cleanup := range m.cleanup {
		TimestampLog(fmt.Sprintf("Executing cleanup %d/%d", i+1, len(m.cleanup)))
		cleanup()
	}
	
	TimestampLog("UPnP Manager: Cleanup completed")
	return nil
}

// removePortMapping removes a port mapping
func (m *UPnPManager) removePortMapping(mapping *UPnPPortMapping) error {
	if mapping == nil {
		return nil
	}
	
	TimestampLog("Removing UPnP port mapping...")
	
	var err error
	if mapping.clientType == "v2" && mapping.clientV2 != nil {
		err = mapping.clientV2.DeletePortMapping(
			"",                           // RemoteHost
			uint16(mapping.ExternalPort), // ExternalPort
			mapping.Protocol,             // Protocol
		)
	} else if mapping.clientType == "v1" && mapping.clientV1 != nil {
		err = mapping.clientV1.DeletePortMapping(
			"",                           // RemoteHost
			uint16(mapping.ExternalPort), // ExternalPort
			mapping.Protocol,             // Protocol
		)
	}
	
	if err != nil {
		return fmt.Errorf("failed to remove UPnP mapping: %v", err)
	}
	
	TimestampLog("UPnP port mapping removed successfully")
	return nil
}

// getLocalIPWithTimeout gets the local IP address with timeout
func getLocalIPWithTimeout(ctx context.Context) (string, error) {
	type result struct {
		ip  string
		err error
	}
	
	resultChan := make(chan result, 1)
	
	go func() {
		ip, err := getLocalIP()
		resultChan <- result{ip: ip, err: err}
	}()
	
	select {
	case res := <-resultChan:
		return res.ip, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// getLocalIP gets the local IP address of this machine
func getLocalIP() (string, error) {
	// Connect to a remote address to determine which local interface is used
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// Legacy functions for compatibility (now use UPnPManager internally)
func setupUPnPPortMapping(port int) (*UPnPPortMapping, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	manager := NewUPnPManager()
	defer manager.Close()
	
	if err := manager.DiscoverAndSetupPortMapping(ctx, port); err != nil {
		return nil, err
	}
	
	return manager.GetMapping(), nil
}

func removeUPnPPortMapping(mapping *UPnPPortMapping) error {
	if mapping == nil {
		return nil
	}
	
	manager := NewUPnPManager()
	defer manager.Close()
	
	return manager.removePortMapping(mapping)
}

// checkUPnPSupport tests if UPnP is available and working
func checkUPnPSupport() bool {
	TimestampLog("=== UPnP Support Check ===")
	
	// Try a quick discovery to see if UPnP is available
	devices, err := goupnp.DiscoverDevices("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
	if err != nil {
		TimestampLog(fmt.Sprintf("UPnP discovery failed: %v", err))
		return false
	}
	
	TimestampLog(fmt.Sprintf("Found %d UPnP Internet Gateway Device(s)", len(devices)))
	
	if len(devices) == 0 {
		TimestampLog("No UPnP Internet Gateway Devices found")
		return false
	}
	
	// List found devices for debugging
	for i, device := range devices {
		TimestampLog(fmt.Sprintf("  Device %d: %s", i+1, device.Location))
	}
	
	TimestampLog("UPnP support detected")
	return true
}

// discoverUPnPDevices lists available UPnP devices for debugging
func discoverUPnPDevices() {
	TimestampLog("Discovering UPnP devices...")
	
	// Discover all UPnP devices on network
	devices, err := goupnp.DiscoverDevices("upnp:rootdevice")
	if err != nil {
		TimestampLog(fmt.Sprintf("UPnP discovery error: %v", err))
		return
	}
	
	TimestampLog(fmt.Sprintf("Found %d UPnP devices:", len(devices)))
	for i, device := range devices {
		TimestampLog(fmt.Sprintf("  Device %d: %s", i+1, device.Location))
	}
}

// renewUPnPMapping periodically renews the UPnP port mapping (disabled for now)
func renewUPnPMapping(mapping *UPnPPortMapping) {
	// Disabled to prevent goroutine leaks
	TimestampLog("UPnP renewal disabled to prevent resource leaks")
}

// -----------------END OF FILE-------------upnp.go