// -----------------BEGIN FILE-------------config.go
package main

import (
	"encoding/json"
	"errors"
	"os"
)

type Config struct {
	ExportFolder      string `json:"export_folder"`
	ImportFolder      string `json:"import_folder"`
	IRCServer         string `json:"irc_server"`
	IRCPort           int    `json:"irc_port"`
	ChannelName       string `json:"channel_name"`
	TLSEnabled        bool   `json:"tls"`
	YourUsername      string `json:"your_username"`
	RecipientUsername string `json:"recipient_username"`
	LocalPort         int    `json:"local_port"`
	ExternalIP        string `json:"external_ip"`
	PairingSecret     string `json:"pairing_secret"`
	RequireAdmin      bool   `json:"require_admin"`
	NetworkMode       string `json:"network_mode"` // "LAN" or "Internet"
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filePath string) (*Config, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	
	// Apply defaults for missing fields
	if c.IRCServer == "" {
		c.IRCServer = "irc.libera.chat"
	}
	if c.IRCPort == 0 {
		c.IRCPort = 6697
	}
	if c.ChannelName == "" {
		c.ChannelName = "cupandstring"
	}
	if !c.TLSEnabled {
		c.TLSEnabled = true
	}
	if c.LocalPort == 0 {
		c.LocalPort = 4200
	}
	if c.ExternalIP == "" {
		c.ExternalIP = "127.0.0.1"
	}
	if c.PairingSecret == "" {
		c.PairingSecret = "Practice"
	}
	if c.NetworkMode == "" {
		c.NetworkMode = "LAN" // Default to LAN mode
	}
	// RequireAdmin defaults to false (no default needed since bool zero value is false)
	
	// Validate required fields
	if c.ExportFolder == "" || c.ImportFolder == "" || c.YourUsername == "" || c.RecipientUsername == "" {
		return nil, errors.New("missing required config fields")
	}
	return &c, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(filePath string, config *Config) error {
	// Convert config to JSON with proper formatting
	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	// Write to file
	return os.WriteFile(filePath, jsonData, 0644)
}

// -----------------END OF FILE-------------config.go