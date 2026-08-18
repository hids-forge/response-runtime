package main

import (
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type RansomwareInfo struct {
	MqttURL       string `json:"mqtt-url"`      // MQTT broker URL (tcp:// or ssl://)
	MqttUsername  string `json:"mqtt-username"` // MQTT username
	MqttPassword  string `json:"mqtt-password"` // MQTT password
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	CorrelationID string `json:"correlation_id"`
	ReplyTo       string `json:"reply_to"`

	FilePath string `json:"file_path"`
	Action   string `json:"action"` // kill process or remove file
}

var filePath string = ""
var processName string = ""
var messageKillRSParts = []string{""}

func handleKillRamsomware(payload helper.Payload) {
	log.Println("Start kill ramsomeware")
	var infoData RansomwareInfo
	json.Unmarshal(payload.Parameters.Alert.Data, &infoData)

	filePath = infoData.FilePath
	if filePath == "" {
		log.Println("File path is empty")
	}
	processName = filepath.Base(filePath)

	brokerUrl = infoData.MqttURL
	username = infoData.MqttUsername
	password = infoData.MqttPassword
	agentName = infoData.Agent
	managerName = infoData.Manager
	correlationID = infoData.CorrelationID
	if infoData.ReplyTo != "" {
		publishTopic = infoData.ReplyTo
	}

	action := infoData.Action

	ch := make(chan mqtt.Message)
	mqttClient = MqttClient(ch)

	if processName != "" {
		if action == "" || action == "kill-process" {
			killProcess(processName)
		}
	}

	if filePath != "" {
		if action == "" || action == "remove-file" {
			removePath(filePath)
		}
	}

	messageKillRS := strings.Join(messageKillRSParts, "\n")
	sendBackResponseStr(messageKillRS)
}

func killProcess(processName string) {
	goos := runtime.GOOS

	switch goos {
	case "windows":
		// Windows
		checkCmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", processName))
		checkOutput, checkErr := checkCmd.CombinedOutput()

		if checkErr != nil {
			log.Printf("KILL_PROCESS_CHECK_FAILED: %s - Error: %s", processName, checkErr.Error())
			return
		}

		if !strings.Contains(string(checkOutput), processName) {
			log.Printf("PROCESS_NOT_RUNNING: %s - Process not found", processName)
			messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Process %s not running", processName))
			return
		}

		log.Printf("Attempting to kill process: %s", processName)
		cmd := exec.Command("taskkill", "/F", "/IM", processName)
		_, err := cmd.CombinedOutput()

		if err != nil {
			helper.WriteStructuredLog("CRITICAL", "Killed process failed", processName)
			log.Printf("Failed to kill process %s: %v", processName, err)
			messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Failed to kill process %s: %v", processName, err))
		} else {
			helper.WriteStructuredLog("WARN", "Killed process successfully", processName)
			log.Printf("Successfully killed process %s", processName)
			messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Successfully killed process %s", processName))
		}
	case "linux", "darwin": // Linux and macOS
		checkCmd := exec.Command("pgrep", "-f", processName)
		checkOutput, checkErr := checkCmd.CombinedOutput()

		if checkErr != nil {
			if len(checkOutput) == 0 {
				log.Printf("PROCESS_NOT_RUNNING: %s - Process not found", processName)
				messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Process %s not running", processName))
				return
			}
			log.Printf("KILL_PROCESS_CHECK_FAILED: %s - Error: %s", processName, checkErr.Error())
			return
		}

		if len(strings.TrimSpace(string(checkOutput))) == 0 {
			log.Printf("PROCESS_NOT_RUNNING: %s - Process not found", processName)
			messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Process %s not running", processName))
			return
		}

		log.Printf("Attempting to kill process: %s", processName)
		cmd := exec.Command("pkill", "-f", processName)
		_, err := cmd.CombinedOutput()
		if err != nil {
			helper.WriteStructuredLog("CRITICAL", "Killed process failed", processName)
			messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Failed to kill process %s: %v", processName, err))
		} else {
			helper.WriteStructuredLog("WARN", "Killed process successfully", processName)
			messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Successfully killed process %s", processName))
		}
	default:
		log.Printf("Unsupported operating system: %s", goos)
		messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Unsupported operating system: %s", goos))
	}
}

func removePath(filePath string) {
	err := removeThreatPath(filePath)
	if err != nil {
		helper.WriteStructuredLog("CRITICAL", "Deleted file failed", filePath)
		messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Failed to delete file %s: %v", filePath, err))
		return
	}

	helper.WriteStructuredLog("WARN", "Deleted file successfully", filePath)
	messageKillRSParts = append(messageKillRSParts, fmt.Sprintf("Successfully deleted file %s", filePath))

	// Check for file regeneration 2 times with 1 second interval
	for i := 1; i <= 2; i++ {
		time.Sleep(1 * time.Second)

		log.Printf("Checking file regeneration (attempt %d/2): %s", i, filePath)

		if _, err := os.Stat(filePath); err == nil {
			// File regenerated, kill process and delete again
			processName := filepath.Base(filePath)
			log.Printf("FILE_REGENERATED: %s detected, killing process %s", filePath, processName)

			killProcess(processName)

			// Delete file again
			err := removeThreatPath(filePath)
			if err != nil {
				helper.WriteStructuredLog("CRITICAL", "Deleted regenerated file failed", filePath)
			} else {
				helper.WriteStructuredLog("WARN", "Deleted regenerated file successfully", filePath)
			}
		} else {
			log.Printf("FILE_NOT_REGENERATED: %s (check %d/2)", filePath, i)
		}
	}

	log.Printf("File monitoring completed for: %s", filePath)
}
