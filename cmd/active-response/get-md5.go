package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"io"
	"log"
	"os"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type Md5Data struct {
	MqttURL       string `json:"mqtt-url"`      // MQTT broker URL (tcp:// or ssl://)
	MqttUsername  string `json:"mqtt-username"` // MQTT username
	MqttPassword  string `json:"mqtt-password"` // MQTT password
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	FilePath      string `json:"file_path"`
	CorrelationID string `json:"correlation_id"`
	ReplyTo       string `json:"reply_to"`
}

type ResultResponse struct {
	UserId        string `json:"user_id"`
	Category      string `json:"category"`
	Manager       string `json:"manager"`
	CorrelationID string `json:"correlation_id"`
	Response      string `json:"response"`
}

var correlationID string = ""

func handleGetMd5(payload helper.Payload) {
	log.Println("Start get MD5.")
	publishTopic = ""

	var md5Data Md5Data
	json.Unmarshal(payload.Parameters.Alert.Data, &md5Data)
	if md5Data.MqttURL == "" || md5Data.MqttUsername == "" || md5Data.MqttPassword == "" {
		log.Println("Missing MQTT configuration parameters")
		return
	}

	if md5Data.FilePath == "" {
		log.Println("File need check md5 is required")
		return
	}

	brokerUrl = md5Data.MqttURL
	username = md5Data.MqttUsername
	password = md5Data.MqttPassword
	agentName = md5Data.Agent
	managerName = md5Data.Manager
	filePath = md5Data.FilePath
	correlationID = md5Data.CorrelationID
	if md5Data.ReplyTo != "" {
		publishTopic = md5Data.ReplyTo
	}

	ch := make(chan mqtt.Message)
	mqttClient = MqttClient(ch)

	getMd5()
}

func getMd5() {
	var md5File string = ""

	// Get md5 file from file path
	if filePath != "" {
		md5File = getMd5File(filePath)
	}

	response := ResultResponse{
		UserId:        "999",
		Category:      "getMd5File",
		Manager:       managerName,
		CorrelationID: correlationID,
		Response:      md5File,
	}

	// Convert data to JSON
	jsonData, err := json.Marshal(response)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}

	sendBackResponse(jsonData)
}

func getMd5File(filePath string) string {
	// Get md5 file from file path
	md5File := ""
	file, err := os.Open(filePath)
	if err != nil {
		log.Println("Error opening file:", err)
		return "Error opening file"
	}
	defer file.Close()
	// Create a new hasher
	hasher := md5.New()
	// Read the file and hash the contents
	if _, err := io.Copy(hasher, file); err != nil {
		log.Println("Error reading file:", err)
		return "Error reading file"
	}
	// Get the hash value as a string
	md5File = hex.EncodeToString(hasher.Sum(nil))
	return md5File
}
