// -----------------BEGIN FILE-------------utils.go

// Package declaration: Part of the main package, holds helper functions.
package main

// Imports: For hashing, logging with time, error handling, and formatting.
import (
	"crypto/sha256" // For SHA256 hashing.
	"fmt"           // For string formatting.
	"io"            // For reading files in hashing.
	"log"           // For basic logging.
	"os"            // For file operations in hashing.
	"time"          // For timestamped logs and durations.
)

// SHA256File function: Computes the SHA256 hash of a file and returns it as hex string.
func SHA256File(filePath string) (string, error) {
	fileHandle, openErr := os.Open(filePath)
	if openErr != nil {
		return "", openErr // Return error if can't open.
	}
	defer fileHandle.Close() // Close file when done.

	hasher := sha256.New() // Create new SHA256 hasher.
	_, copyErr := io.Copy(hasher, fileHandle) // Copy file contents to hasher.
	if copyErr != nil {
		return "", copyErr // Return error on copy fail.
	}

	hashBytes := hasher.Sum(nil) // Get the hash bytes.
	hashHexString := fmt.Sprintf("%x", hashBytes) // Convert to hex string.

	return hashHexString, nil // Return the hash.
}

// TimestampLog function: Logs a message with a timestamp prefix.
func TimestampLog(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05") // Standard time format.
	log.Printf("[%s] %s", timestamp, message) // Log with prefix.
}

// ErrorWrap function: Wraps an error with context string for better debugging.
func ErrorWrap(originalErr error, contextMessage string) error {
	if originalErr == nil {
		return nil // No error, return nil.
	}
	return fmt.Errorf("%s: %v", contextMessage, originalErr) // Wrapped error.
}

// AverageBitrate: Computes average bitrate in KB/s as string.
func AverageBitrate(bytesTransferred int64, duration time.Duration) string {
	seconds := duration.Seconds()
	if seconds <= 0 {
		return "N/A"
	}
	bitrate := float64(bytesTransferred) / seconds / 1024 // KB/s
	return fmt.Sprintf("%.2f KB/s", bitrate)
}

// GenerateTempName: Generates nondescript temp name from hash.
func GenerateTempName(hash string) string {
	shortHash := hash[:8]
	return fmt.Sprintf("data_%s.bin", shortHash)
}

// -----------------END OF FILE-------------utils.go