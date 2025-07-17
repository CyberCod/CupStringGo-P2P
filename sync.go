// -----------------BEGIN FILE-------------sync.go

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

const chunkSize = 64 * 1024
const batchSize = 5
const receiveTimeout = 30 * time.Second

type ManifestEntry struct {
	Original string `json:"original"`
	Renamed  string `json:"renamed"`
	Hash     string `json:"hash"`
}

// HandleSyncStream handles bidirectional file sync on a stream
func HandleSyncStream(stream network.Stream, config *Config, isSender bool, p2pHost host.Host) {
	defer stream.Close()

	TimestampLog(fmt.Sprintf("Handling stream, isSender=%t", isSender))

	// Exchange file counts for logging
	myCount := countExportFiles(config)
	peerCount, err := exchangeFileCounts(stream, myCount)
	if err != nil {
		TimestampLog(fmt.Sprintf("Count exchange failed: %v", err))
		return
	}
	TimestampLog(fmt.Sprintf("Peer has %d files queued", peerCount))

	manifest := make(map[string]string)

	// Determine actual roles based on who has files
	shouldSend := len(exportFileQueue) > 0
	shouldReceive := peerCount > 0

	if shouldSend && shouldReceive {
		// Both sides have files - handle based on initial isSender flag
		if isSender {
			TimestampLog("Both sides have files, I'll send first then receive")
			// Send first, then receive
			if err := sendAllFiles(stream, config); err != nil {
				TimestampLog(fmt.Sprintf("Send phase failed: %v", err))
				return
			}
			stream.CloseWrite()
			if err := receiveAllFiles(stream, config.ImportFolder, manifest); err != nil {
				TimestampLog(fmt.Sprintf("Receive phase failed: %v", err))
				return
			}
		} else {
			TimestampLog("Both sides have files, I'll receive first then send")
			// Receive first, then send
			if err := receiveAllFiles(stream, config.ImportFolder, manifest); err != nil {
				TimestampLog(fmt.Sprintf("Receive phase failed: %v", err))
				return
			}
			// Open reverse stream for sending
			if len(exportFileQueue) > 0 {
				TimestampLog("Opening reverse stream for my files")
				ctx := context.Background()
				peerID := stream.Conn().RemotePeer()
				reverseStream, err := p2pHost.NewStream(ctx, peerID, "/sync/1.0.0")
				if err != nil {
					TimestampLog(fmt.Sprintf("Reverse stream failed: %v", err))
					return
				}
				go HandleSyncStream(reverseStream, config, true, p2pHost)
			}
		}
	} else if shouldSend {
		// Only I have files to send
		TimestampLog("Only I have files, sending...")
		if err := sendAllFiles(stream, config); err != nil {
			TimestampLog(fmt.Sprintf("Send failed: %v", err))
		}
		stream.CloseWrite()
	} else if shouldReceive {
		// Only peer has files to send
		TimestampLog("Only peer has files, receiving...")
		if err := receiveAllFiles(stream, config.ImportFolder, manifest); err != nil {
			TimestampLog(fmt.Sprintf("Receive failed: %v", err))
		}
	} else {
		// Neither side has files
		TimestampLog("Neither side has files, closing stream")
		return
	}
}

// sendAllFiles sends all files in the export queue
func sendAllFiles(stream network.Stream, config *Config) error {
	TimestampLog("Starting send phase")
	for len(exportFileQueue) > 0 {
		err := sendBatch(stream, config)
		if err != nil {
			TimestampLog(fmt.Sprintf("Send batch error: %v", err))
			// Retry logic
			for retries := 1; retries <= 3; retries++ {
				time.Sleep(time.Second * time.Duration(retries))
				err = sendBatch(stream, config)
				if err == nil {
					break
				}
			}
			if err != nil {
				return fmt.Errorf("send failed after retries: %v", err)
			}
		}
	}
	TimestampLog("Send phase completed")
	return nil
}

// receiveAllFiles receives all files from the peer
func receiveAllFiles(stream network.Stream, importFolder string, manifest map[string]string) error {
	TimestampLog("Starting receive phase")
	timer := time.NewTimer(receiveTimeout)
	defer timer.Stop()
	
	for {
		select {
		case <-timer.C:
			TimestampLog("Receive timeout")
			return fmt.Errorf("receive timeout")
		default:
			err := receiveFromStream(stream, importFolder, manifest)
			if err == io.EOF {
				TimestampLog("End of receive stream")
				return nil
			}
			if err != nil {
				TimestampLog(fmt.Sprintf("Receive error: %v", err))
				// Retry logic
				for retries := 1; retries <= 3; retries++ {
					time.Sleep(time.Second * time.Duration(retries))
					err = receiveFromStream(stream, importFolder, manifest)
					if err == nil {
						break
					}
				}
				if err != nil {
					return fmt.Errorf("receive failed after retries: %v", err)
				}
			}
			timer.Reset(receiveTimeout)
		}
	}
}

func exchangeFileCounts(stream network.Stream, myCount int) (int, error) {
	TimestampLog("Exchanging file counts")
	countMsg := struct{ Count int }{myCount}
	encoder := json.NewEncoder(stream)
	if err := encoder.Encode(countMsg); err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(stream)
	var peerCountMsg struct{ Count int }
	if err := decoder.Decode(&peerCountMsg); err != nil {
		return 0, err
	}
	return peerCountMsg.Count, nil
}

func sendBatch(stream network.Stream, config *Config) error {
	TimestampLog("Starting send batch")
	var batch []FileInfo
	
	TimestampLog("About to enter batch collection loop")
	for len(batch) < batchSize {
		TimestampLog(fmt.Sprintf("Batch collection loop: current batch size %d, target %d", len(batch), batchSize))
		select {
		case fi, ok := <-exportFileQueue:
			TimestampLog(fmt.Sprintf("Received file from queue: %s (ok=%t)", fi.Name, ok))
			if !ok {
				TimestampLog("Queue closed")
				return nil
			}
			batch = append(batch, fi)
			TimestampLog(fmt.Sprintf("Added to batch: %s, new batch size: %d", fi.Name, len(batch)))
		default:
			TimestampLog("No files available in queue, checking batch size")
			if len(batch) == 0 {
				TimestampLog("No files for batch")
				return nil
			}
			TimestampLog("Breaking from batch collection loop")
			goto batchComplete  // Use goto to exit the for loop
		}
	}
	
batchComplete:
	TimestampLog(fmt.Sprintf("Batch collection complete. Final batch size: %d", len(batch)))
	TimestampLog(fmt.Sprintf("Batch size %d", len(batch)))

	var entries []ManifestEntry
	for _, fi := range batch {
		tempName := GenerateTempName(fi.Hash)
		entries = append(entries, ManifestEntry{
			Original: fi.Name,
			Renamed:  tempName,
			Hash:     fi.Hash,
		})
	}
	manifest := struct{ Files []ManifestEntry }{entries}
	mJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	mHash := fmt.Sprintf("%x", sha256.Sum256(mJSON))
	mMeta := struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	}{"manifest.json", int64(len(mJSON)), mHash}
	encoder := json.NewEncoder(stream)
	TimestampLog("Sending manifest meta")
	if err := encoder.Encode(mMeta); err != nil {
		return err
	}
	TimestampLog("Sending manifest data")
	if err := sendDataOverStream(stream, mJSON); err != nil {
		return err
	}
	ack, err := readAck(stream)
	if err != nil || ack != "success" {
		return fmt.Errorf("manifest ack: %s %v", ack, err)
	}
	TimestampLog("Manifest ack success")

	var totalBytes int64
	start := time.Now()
	for _, fi := range batch {
		tempName := GenerateTempName(fi.Hash)
		meta := struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			Hash string `json:"hash"`
		}{tempName, fi.Size, fi.Hash}
		TimestampLog(fmt.Sprintf("Sending meta for %s", fi.Name))
		if err := encoder.Encode(meta); err != nil {
			TimestampLog(fmt.Sprintf("Meta send %s: %v", fi.Name, err))
			continue
		}
		fStart := time.Now()
		err := sendFileData(stream, fi)
		for retries := 1; err != nil && retries <= 3; retries++ {
			time.Sleep(time.Second * time.Duration(retries))
			TimestampLog(fmt.Sprintf("Retrying send %s attempt %d", fi.Name, retries))
			err = sendFileData(stream, fi)
		}
		if err != nil {
			TimestampLog(fmt.Sprintf("Send gave up %s: %v", fi.Name, err))
			exportFileQueue <- fi // Requeue
			os.Remove(fi.FullPath)
			continue
		}
		ack, err := readAck(stream)
		if err != nil {
			TimestampLog(fmt.Sprintf("Ack %s: %v", fi.Name, err))
			continue
		}
		TimestampLog(fmt.Sprintf("Ack for %s: %s", fi.Name, ack))
		switch ack {
		case "success":
			os.Remove(fi.FullPath)
			os.Remove(fi.OriginalPath)
			TimestampLog(fmt.Sprintf("Sent/deleted %s", fi.Name))
			TimestampLog(fmt.Sprintf("Bitrate %s: %s", fi.Name, AverageBitrate(fi.Size, time.Since(fStart))))
			totalBytes += fi.Size
		case "decline":
			TimestampLog(fmt.Sprintf("Decline duplicate %s", fi.Name))
			os.Remove(fi.FullPath)
		case "fail":
			TimestampLog(fmt.Sprintf("Fail %s; requeuing", fi.Name))
			os.Remove(fi.FullPath)
			exportFileQueue <- fi
		default:
			TimestampLog(fmt.Sprintf("Unexpected ack %s: %s", fi.Name, ack))
			os.Remove(fi.FullPath)
			exportFileQueue <- fi
		}
	}
	TimestampLog(fmt.Sprintf("Batch bitrate: %s (%d bytes)", AverageBitrate(totalBytes, time.Since(start)), totalBytes))
	return nil
}

func sendFileData(stream network.Stream, fi FileInfo) error {
	TimestampLog(fmt.Sprintf("Sending data for %s", fi.Name))
	f, err := os.Open(fi.FullPath)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, chunkSize)
	for {
		n, err := f.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		data := buf[:n]
		for len(data) > 0 {
			w, err := stream.Write(data)
			if err != nil {
				return err
			}
			data = data[w:]
		}
	}
	return nil
}

func sendDataOverStream(stream network.Stream, data []byte) error {
	TimestampLog("Sending data over stream")
	for len(data) > 0 {
		n, err := stream.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func readAck(stream network.Stream) (string, error) {
	TimestampLog("Waiting for ack")
	buf := make([]byte, 32)
	n, err := stream.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func receiveFromStream(stream network.Stream, importFolder string, manifest map[string]string) error {
	TimestampLog("Waiting for metadata")
	decoder := json.NewDecoder(stream)
	var meta struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	}
	if err := decoder.Decode(&meta); err != nil {
		return err
	}
	TimestampLog(fmt.Sprintf("Received meta: %s size %d", meta.Name, meta.Size))

	isManifest := meta.Name == "manifest.json"

	if !isManifest {
		if dup, _ := checkDuplicateByHash(importFolder, meta.Hash); dup {
			// Still need to consume the file data to keep stream synchronized
			TimestampLog(fmt.Sprintf("Duplicate detected %s, consuming data to maintain sync", meta.Name))
			discardBuf := make([]byte, chunkSize)
			received := int64(0)
			for received < meta.Size {
				n, err := stream.Read(discardBuf)
				if err != nil && err != io.EOF {
					return err
				}
				if n == 0 {
					break
				}
				received += int64(n)
			}
			stream.Write([]byte("decline"))
			TimestampLog(fmt.Sprintf("Declined duplicate %s", meta.Name))
			return nil
		}
	}

	var mw io.Writer
	hasher := sha256.New()
	var partFile *os.File
	var buf *bytes.Buffer
	if isManifest {
		buf = new(bytes.Buffer)
		mw = io.MultiWriter(buf, hasher)
	} else {
		partPath := filepath.Join(importFolder, meta.Name+".part")
		var err error
		partFile, err = os.Create(partPath)
		if err != nil {
			return err
		}
		mw = io.MultiWriter(partFile, hasher)
	}

	TimestampLog("Receiving data")
	received := int64(0)
	rbuf := make([]byte, chunkSize)
	for received < meta.Size {
		n, err := stream.Read(rbuf)
		if err != nil && err != io.EOF {
			if !isManifest {
				os.Remove(partFile.Name())
			}
			return err
		}
		if n == 0 {
			break
		}
		if _, err := mw.Write(rbuf[:n]); err != nil {
			if !isManifest {
				os.Remove(partFile.Name())
			}
			return err
		}
		received += int64(n)
	}

	if !isManifest {
		partFile.Close()
	}

	compHash := fmt.Sprintf("%x", hasher.Sum(nil))
	TimestampLog(fmt.Sprintf("Computed hash %s, expected %s", compHash, meta.Hash))
	if compHash != meta.Hash {
		if !isManifest {
			os.Remove(partFile.Name())
		}
		stream.Write([]byte("fail"))
		return fmt.Errorf("hash mismatch: %s vs %s", compHash, meta.Hash)
	}

	if isManifest {
		var mStruct struct {
			Files []struct {
				Original string `json:"original"`
				Renamed  string `json:"renamed"`
				Hash     string `json:"hash"`
			} `json:"files"`
		}
		if err := json.Unmarshal(buf.Bytes(), &mStruct); err != nil {
			stream.Write([]byte("fail"))
			return err
		}
		for _, e := range mStruct.Files {
			manifest[e.Renamed] = e.Original
		}
		TimestampLog("Parsed manifest")
		stream.Write([]byte("success"))
		return nil
	}

	finalName := meta.Name
	if orig, ok := manifest[meta.Name]; ok && orig != "" {
		finalName = orig
	}
	partPath := partFile.Name()
	finalPath := filepath.Join(importFolder, finalName)
	if err := os.Rename(partPath, finalPath); err != nil {
		os.Remove(partPath)
		stream.Write([]byte("fail"))
		return err
	}

	stream.Write([]byte("success"))
	TimestampLog(fmt.Sprintf("Received/saved %s as %s", meta.Name, finalName))
	return nil
}

func checkDuplicateByHash(folder, hash string) (bool, error) {
	TimestampLog(fmt.Sprintf("Checking dup for hash %s", hash))
	files, err := os.ReadDir(folder)
	if err != nil {
		return false, err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		path := filepath.Join(folder, f.Name())
		fHash, err := SHA256File(path)
		if err != nil {
			continue
		}
		if fHash == hash {
			return true, nil
		}
	}
	return false, nil
}

func countExportFiles(config *Config) int {
	count := len(exportFileQueue) // Chan len for approx
	TimestampLog(fmt.Sprintf("Count export files: %d", count))
	return count
}

// -----------------END OF FILE-------------sync.go