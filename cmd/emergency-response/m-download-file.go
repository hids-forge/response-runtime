//go:build danger_emergencies

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	chunkSize  = 10240 // 10KB chunks
	maxInQueue = 50    // Max message wating ACK
	ackTimeout = 5     // ACK seconds
	maxRetries = 2     // Max retries publish
)

type FileRequest struct {
	FilePath string `json:"file_path"`
	ClientID string `json:"client_id"`
}

type FileResponse struct {
	// FileName    string `json:"file_name"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Data        []byte `json:"data"`
	Hash        string `json:"hash,omitempty"`
	Error       string `json:"error,omitempty"`
}

type ChunkAck struct {
	ChunkIndex int    `json:"chunk_index"`
	FilePath   string `json:"file_path"`
}

type TransferSession struct {
	filePath    string
	clientID    string
	totalChunks int
	chunks      [][]byte
	hash        string
	ackReceived map[int]bool
	mu          sync.Mutex
	stopChan    chan bool
}

var (
	topicResponse = ""
	sessions      = make(map[string]*TransferSession)
	sessionsMu    sync.RWMutex
)

func handleDownloadFile(prefix, sessionID string, params json.RawMessage) error {
	log.Printf("Start handle download file\n")
	var req FileRequest
	if err := json.Unmarshal(params, &req); err != nil {
		log.Printf("error parse request: %v\n", err)
		return err
	}

	topicResponse = fmt.Sprintf("%s/download/%s/response", prefix, sessionID)

	if req.ClientID != "" {
		topicResponse = req.ClientID
	}

	log.Printf("Request download file '%s' to '%s'\n", req.FilePath, topicResponse)
	go sendFile(req.FilePath, topicResponse)
	return nil
}

func handleChunkAck(client mqtt.Client, msg mqtt.Message) {
	var ack ChunkAck
	if err := json.Unmarshal(msg.Payload(), &ack); err != nil {
		return
	}

	sessionKey := getSessionKey(ack.FilePath, topicResponse)

	log.Printf("Chunk ack session: %s - received: %s\n", sessionKey, string(msg.Payload()))

	sessionsMu.RLock()
	session, exists := sessions[sessionKey]
	sessionsMu.RUnlock()

	if !exists {
		return
	}

	session.mu.Lock()
	session.ackReceived[ack.ChunkIndex] = true
	session.mu.Unlock()
}

func getSessionKey(fileName, clientID string) string {
	return fmt.Sprintf("%s:%s", clientID, fileName)
}

func sendFile(filePath, topicResponse string) {
	// Check file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		sendError(topicResponse, fmt.Sprintf("File not exist: %v", err))
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		sendError(topicResponse, fmt.Sprintf("Error open file: %v", err))
		return
	}
	defer file.Close()

	// Hash file
	hash, err := calculateFileHash(filePath)
	if err != nil {
		sendError(topicResponse, fmt.Sprintf("Error calculate hash: %v", err))
		return
	}

	// Number chunks
	totalChunks := int(fileInfo.Size() / chunkSize)
	if fileInfo.Size()%chunkSize != 0 {
		totalChunks++
	}

	chunks := make([][]byte, totalChunks)
	buffer := make([]byte, chunkSize)
	chunkIndex := 0

	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			sendError(topicResponse, fmt.Sprintf("error read file: %v", err))
			return
		}

		chunks[chunkIndex] = make([]byte, n)
		copy(chunks[chunkIndex], buffer[:n])
		chunkIndex++
	}

	log.Printf("Start send file '%s' (%d bytes, %d chunks) to '%s'\n", filePath, fileInfo.Size(), totalChunks, topicResponse)

	// Tạo session
	session := &TransferSession{
		filePath:    filePath,
		clientID:    topicResponse,
		totalChunks: totalChunks,
		chunks:      chunks,
		hash:        hash,
		ackReceived: make(map[int]bool),
		stopChan:    make(chan bool),
	}

	sessionKey := getSessionKey(filePath, topicResponse)
	sessionsMu.Lock()
	sessions[sessionKey] = session
	sessionsMu.Unlock()

	sendChunksWithFlowControl(session, topicResponse)

	// Wait and retry missing chunks
	// retryMissingChunks(session)

	// Cleanup
	sessionsMu.Lock()
	delete(sessions, sessionKey)
	sessionsMu.Unlock()

	log.Printf("Done '%s'\n", filePath) // Done send file
}

func sendError(topicResponse, errorMsg string) {
	response := FileResponse{
		Error: errorMsg,
	}
	data, _ := json.Marshal(response)
	token := mqttClient.Publish(topicResponse, 1, false, data)
	if token.Wait() && token.Error() != nil {
		log.Println("error", token.Error())
	}
	log.Printf("%s\n", errorMsg)
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sendChunksWithFlowControl(session *TransferSession, topicResponse string) {
	log.Println("Flow control total chunks:", session.totalChunks)

	for i := 0; i < session.totalChunks; i++ {

		response := FileResponse{
			// FilePath:    session.filePath,
			ChunkIndex:  i,
			TotalChunks: session.totalChunks,
			Data:        session.chunks[i],
		}

		if i == session.totalChunks-1 {
			response.Hash = session.hash
		}

		data, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshaling response: %v\n", err)
		}
		token := mqttClient.Publish(topicResponse, 1, false, data)
		if token.Error() != nil {
			log.Println("send chunk error", token.Error())
		}
		token.Wait()

		if (i%100 == 0) || (i == session.totalChunks-1) {
			log.Printf("Send %d/%d chunks\n", i+1, session.totalChunks)
		}
	}

	log.Printf("Send all %d chunks\n", session.totalChunks)
}

func retryMissingChunks(session *TransferSession) {
	for retry := 0; retry < maxRetries; retry++ {
		time.Sleep(time.Duration(ackTimeout) * time.Second)

		session.mu.Lock()
		missingChunks := []int{}
		for i := 0; i < session.totalChunks; i++ {
			if !session.ackReceived[i] {
				missingChunks = append(missingChunks, i)
			}
		}
		session.mu.Unlock()

		if len(missingChunks) == 0 {
			log.Printf("All chunks confirmed!\n")
			return
		}

		log.Printf("Retry %d: %d missing chunks\n", retry+1, len(missingChunks))

		for _, idx := range missingChunks {
			response := FileResponse{
				// FileName:    session.fileName,
				ChunkIndex:  idx,
				TotalChunks: session.totalChunks,
				Data:        session.chunks[idx],
			}

			if idx == session.totalChunks-1 {
				response.Hash = session.hash
			}

			data, _ := json.Marshal(response)
			token := mqttClient.Publish(topicResponse, 1, false, data)
			if token.Error() != nil {
				log.Println("send missing chunk error", token.Error())
			}
			token.Wait()
		}
	}

	session.mu.Lock()
	totalReceived := len(session.ackReceived)
	session.mu.Unlock()

	log.Printf("Received ACK for %d/%d chunks after %d retry\n", totalReceived, session.totalChunks, maxRetries)
}
