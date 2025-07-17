// -----------------BEGIN FILE-------------file_watcher.go

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type FileInfo struct {
	Name         string
	FullPath     string
	OriginalPath string
	Size         int64
	Hash         string
}

var exportFileQueue chan FileInfo
var recentlyProcessed = make(map[string]time.Time) // Track recently processed files
var recentlyProcessedMutex sync.RWMutex

// cleanupRecentlyProcessed removes old entries from the recently processed map
func cleanupRecentlyProcessed() {
	recentlyProcessedMutex.Lock()
	defer recentlyProcessedMutex.Unlock()
	
	cutoff := time.Now().Add(-30 * time.Second) // Remove entries older than 30 seconds
	for path, timestamp := range recentlyProcessed {
		if timestamp.Before(cutoff) {
			delete(recentlyProcessed, path)
		}
	}
}

// wasRecentlyProcessed checks if a file was recently processed to avoid duplicates
func wasRecentlyProcessed(path string) bool {
	recentlyProcessedMutex.RLock()
	defer recentlyProcessedMutex.RUnlock()
	
	lastProcessed, exists := recentlyProcessed[path]
	if !exists {
		return false
	}
	
	// Consider it recently processed if it was processed within the last 5 seconds
	return time.Since(lastProcessed) < 5*time.Second
}

// markAsRecentlyProcessed marks a file as recently processed
func markAsRecentlyProcessed(path string) {
	recentlyProcessedMutex.Lock()
	defer recentlyProcessedMutex.Unlock()
	recentlyProcessed[path] = time.Now()
}

func StartWatchers(loadedConfig *Config, triggerChan chan<- bool) {
	exportFileQueue = make(chan FileInfo, 1000)

	// Start cleanup routine for recently processed files
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			cleanupRecentlyProcessed()
		}
	}()

	TimestampLog("Cleaning up partial files in import folder")
	cleanupPartialFiles(loadedConfig.ImportFolder)
	TimestampLog("Cleaning up temp dir in export folder")
	cleanupTempDir(filepath.Join(loadedConfig.ExportFolder, ".temp"))

	TimestampLog("Starting initial scan of export folder")
	initialScanError := scanAndQueueFiles(loadedConfig.ExportFolder, loadedConfig)
	if initialScanError != nil {
		TimestampLog(fmt.Sprintf("Initial scan failed: %v", initialScanError))
	}
	triggerScanIfNeeded(triggerChan)

	exportWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		TimestampLog(fmt.Sprintf("Failed to create export watcher: %v", err))
		log.Fatalf("Export watcher failed: %v", err)
	}
	defer exportWatcher.Close()

	err = exportWatcher.Add(loadedConfig.ExportFolder)
	if err != nil {
		TimestampLog(fmt.Sprintf("Failed to watch export folder: %v", err))
		log.Fatalf("Watch export failed: %v", err)
	}
	TimestampLog(fmt.Sprintf("Watching export folder: %s", loadedConfig.ExportFolder))

	importWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		TimestampLog(fmt.Sprintf("Failed to create import watcher: %v", err))
		log.Fatalf("Import watcher failed: %v", err)
	}
	defer importWatcher.Close()

	err = importWatcher.Add(loadedConfig.ImportFolder)
	if err != nil {
		TimestampLog(fmt.Sprintf("Failed to watch import folder: %v", err))
		log.Fatalf("Watch import failed: %v", err)
	}
	TimestampLog(fmt.Sprintf("Watching import folder: %s", loadedConfig.ImportFolder))

	go func() {
		for {
			select {
			case event := <-exportWatcher.Events:
				TimestampLog(fmt.Sprintf("Export event: %s - %s", event.Name, event.Op))
				if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					if isValidFile(event.Name) {
						// Check if we recently processed this file to avoid duplicates
						if wasRecentlyProcessed(event.Name) {
							TimestampLog(fmt.Sprintf("Skipping recently processed file: %s", event.Name))
							continue
						}
						
						// Wait a moment to ensure file is fully written
						time.Sleep(500 * time.Millisecond)
						
						fileInfo, err := getFileInfo(event.Name, loadedConfig)
						if err == nil {
							markAsRecentlyProcessed(event.Name)
							exportFileQueue <- fileInfo
							TimestampLog(fmt.Sprintf("Queued export file: %s", fileInfo.Name))
							triggerScanIfNeeded(triggerChan)
						} else {
							TimestampLog(fmt.Sprintf("Failed to get file info for %s: %v", event.Name, err))
						}
					} else {
						TimestampLog(fmt.Sprintf("Ignored invalid file: %s", event.Name))
					}
				}
			case err := <-exportWatcher.Errors:
				TimestampLog(fmt.Sprintf("Export watcher error: %v", err))
				if strings.Contains(err.Error(), "overflow") {
					TimestampLog("Recovering from watcher overflow: Recreating watcher and rescanning")
					exportWatcher.Close()
					exportWatcher, _ = fsnotify.NewWatcher()
					exportWatcher.Add(loadedConfig.ExportFolder)
					scanAndQueueFiles(loadedConfig.ExportFolder, loadedConfig)
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case event := <-importWatcher.Events:
				TimestampLog(fmt.Sprintf("Import event: %s - %s", event.Name, event.Op))
			case err := <-importWatcher.Errors:
				TimestampLog(fmt.Sprintf("Import watcher error: %v", err))
			}
		}
	}()

	select {}
}

func cleanupPartialFiles(importFolder string) {
	files, err := os.ReadDir(importFolder)
	if err != nil {
		TimestampLog(fmt.Sprintf("Failed to read import folder for cleanup: %v", err))
		return
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".part") {
			removePath := filepath.Join(importFolder, file.Name())
			removeErr := os.Remove(removePath)
			if removeErr != nil {
				TimestampLog(fmt.Sprintf("Failed to remove partial file %s: %v", removePath, removeErr))
			} else {
				TimestampLog(fmt.Sprintf("Cleaned up partial file: %s", removePath))
			}
		}
	}
}

func cleanupTempDir(tempDir string) {
	if err := os.RemoveAll(tempDir); err != nil {
		TimestampLog(fmt.Sprintf("Failed to remove temp dir: %v", err))
	}
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		TimestampLog(fmt.Sprintf("Failed to create temp dir: %v", err))
	}
}

func scanAndQueueFiles(folderPath string, config *Config) error {
	queuedCount := 0
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() && isValidFile(path) {
			fileInfo, infoErr := getFileInfo(path, config)
			if infoErr == nil {
				select {
				case exportFileQueue <- fileInfo:
					queuedCount++
					TimestampLog(fmt.Sprintf("Queued during scan: %s", fileInfo.Name))
				default:
					TimestampLog(fmt.Sprintf("Queue full, skipping queue during scan: %s", fileInfo.Name))
				}
			} else {
				TimestampLog(fmt.Sprintf("Failed to get file info during scan for %s: %v", path, infoErr))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	TimestampLog(fmt.Sprintf("Scan completed, queued %d files", queuedCount))
	return nil
}

func isValidFile(filePath string) bool {
	baseName := filepath.Base(filePath)
	if strings.HasPrefix(baseName, ".") || strings.HasSuffix(baseName, "~") || strings.Contains(baseName, ".tmp") {
		return false
	}
	return true
}

func getFileInfo(originalPath string, config *Config) (FileInfo, error) {
	fileStat, statErr := os.Stat(originalPath)
	if statErr != nil {
		return FileInfo{}, statErr
	}

	// Wait a moment for the file to be fully written (especially for large files)
	time.Sleep(100 * time.Millisecond)

	tempDir := filepath.Join(config.ExportFolder, ".temp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return FileInfo{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	tempName := fmt.Sprintf("%s_%d", filepath.Base(originalPath), time.Now().UnixNano())
	tempPath := filepath.Join(tempDir, tempName)
	
	// Try to copy with retries for file locking issues
	var copyErr error
	for retries := 0; retries < 3; retries++ {
		copyErr = copyFile(originalPath, tempPath)
		if copyErr == nil {
			break
		}
		TimestampLog(fmt.Sprintf("Copy attempt %d failed for %s: %v", retries+1, originalPath, copyErr))
		time.Sleep(time.Duration(retries+1) * 200 * time.Millisecond)
	}
	
	if copyErr != nil {
		return FileInfo{}, fmt.Errorf("failed to copy to temp after retries: %v", copyErr)
	}

	fileHandle, openErr := os.Open(tempPath)
	if openErr != nil {
		os.Remove(tempPath) // Cleanup on error.
		return FileInfo{}, openErr
	}
	defer fileHandle.Close()

	hash := sha256.New()
	_, hashErr := io.Copy(hash, fileHandle)
	if hashErr != nil {
		os.Remove(tempPath)
		return FileInfo{}, hashErr
	}
	hashHex := fmt.Sprintf("%x", hash.Sum(nil))

	TimestampLog(fmt.Sprintf("Successfully processed file: %s (size: %d, hash: %s)", filepath.Base(originalPath), fileStat.Size(), hashHex[:8]))

	return FileInfo{
		Name:         filepath.Base(originalPath),
		FullPath:     tempPath,
		OriginalPath: originalPath,
		Size:         fileStat.Size(),
		Hash:         hashHex,
	}, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func triggerScanIfNeeded(triggerChan chan<- bool) {
	queueSize := len(exportFileQueue)
	TimestampLog(fmt.Sprintf("Trigger check: queue size %d", queueSize))
	if queueSize > 0 {
		triggerChan <- true
	} else {
		triggerChan <- false
	}
}

// -----------------END OF FILE-------------file_watcher.go