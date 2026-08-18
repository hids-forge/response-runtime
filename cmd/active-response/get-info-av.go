package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"log"
	"os"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type InfoData struct {
	MqttURL      string `json:"mqtt-url"`      // MQTT broker URL (tcp:// or ssl://)
	MqttUsername string `json:"mqtt-username"` // MQTT username
	MqttPassword string `json:"mqtt-password"` // MQTT password
	Agent        string `json:"agent"`
	Manager      string `json:"manager"`
	ReplyTo      string `json:"reply_to"`
}

type InputData struct {
	UserId      string `json:"user_id"`
	Category    string `json:"category"`
	Manager     string `json:"manager"`
	Response    string `json:"response"`
	RunOnServer string `json:"run_on_server"` // soc or worker-soc or client
}

type UpdateInfo struct {
	Version  string `json:"version"`
	Type     string `json:"type"`
	Level    string `json:"level"`
	Platform string `json:"platform"`
	Build    string `json:"build"`
	File     string `json:"file"`
	Size     string `json:"size"`
}

type NOD32EngineSettings struct {
	XMLName         xml.Name `xml:"NOD32EngineSettings"`
	ProductVersion  string   `xml:"ProductVersion"`
	ScannerVersion  string   `xml:"ScannerVersion"`
	SoftwareVersion string   `xml:"SoftwareVersion"`
}

func handlePublishAVInfo(payload helper.Payload) {
	log.Println("Start get info AV")
	subscribeTopic = ""
	publishTopic = ""

	var infoData InfoData
	json.Unmarshal(payload.Parameters.Alert.Data, &infoData)

	if infoData.MqttURL == "" || infoData.MqttUsername == "" || infoData.MqttPassword == "" {
		log.Println("Missing configuration parameters")
		return
	}

	brokerUrl = infoData.MqttURL
	username = infoData.MqttUsername
	password = infoData.MqttPassword
	agentName = infoData.Agent
	managerName = infoData.Manager
	if infoData.ReplyTo != "" {
		publishTopic = infoData.ReplyTo
	}

	ch := make(chan mqtt.Message)
	mqttClient = MqttClient(ch)

	publishAVInfo()
	log.Println("Finish get info.")
}

func publishAVInfo() {
	// Get ESET version
	esetVersion := getESETVersion()
	fmt.Println(esetVersion)

	// Get SentinelAV version
	sentinelAVVersion := getSentinelAVVersion()
	fmt.Println(sentinelAVVersion)

	// Get GTSentinel
	nod32Setting := getNODSetting()
	fmt.Println(nod32Setting)

	// Create a map to store the version information
	versionInfo := map[string]string{
		"ESET":       esetVersion,
		"SentinelAV": sentinelAVVersion,
		"NODSetting": nod32Setting,
		"agent":      agentName,
		"manager":    managerName,
	}

	// Convert the map to JSON
	jsonVersion, err := json.Marshal(versionInfo)
	if err != nil {
		fmt.Println("Error converting version info to JSON:", err)
		return
	}

	inputData := InputData{
		UserId:      "999",
		Category:    "getinfoav",
		Manager:     managerName,
		RunOnServer: "client",
		Response:    string(jsonVersion),
	}

	// Convert data to JSON
	jsonData, err := json.Marshal(inputData)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}

	sendBackResponse(jsonData)
}

func getESETVersion() string {
	// Define the full path
	// iniPath := "C:/Program Files/ESET/ESET Security/SecurityProductInformation.ini"
	iniPath := os.Getenv("EsetProductInformation")
	// iniPath = "SecurityProductInformation.ini"

	// Check if file exists
	if _, err := os.Stat(iniPath); os.IsNotExist(err) {
		fmt.Println("INI file not found at:", iniPath)
		return ""
	}

	// Read the INI file
	content, err := os.ReadFile(iniPath)
	if err != nil {
		fmt.Println("Error reading INI file:", err)
		return ""
	}

	// Parse the INI content to get Version and Company
	lines := strings.Split(string(content), "\n")
	version := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "Version=") {
			version = strings.TrimPrefix(line, "Version=")
			version = strings.TrimSpace(version)
			break
		}
		// if strings.HasPrefix(line, "Company=") {
		// 	company = strings.TrimPrefix(line, "Company=")
		// 	company = strings.TrimSpace(company)
		// }
	}

	// response := map[string]string{
	// 	"Company": company,
	// 	"Version": version,
	// }

	return version
}

func getSentinelAVVersion() string {
	// updatePath := "C:/SentinelAV/NOD32/dll/update.ver"
	// updatePath = "update.ver"
	updatePath := os.Getenv("NodUpdateVer")

	// Check if file exists
	if _, err := os.Stat(updatePath); os.IsNotExist(err) {
		log.Println("Update file not found at:", updatePath)
		return ""
	}

	// Read update.ver file
	content, err := os.ReadFile(updatePath)
	if err != nil {
		log.Println("Error reading update.ver file:", err)
		return ""
	}

	// Parse sections from update.ver
	sections := strings.Split(string(content), "[")
	var updates []UpdateInfo

	for _, section := range sections {
		if section == "" {
			continue
		}

		lines := strings.Split(section, "\n")
		var info UpdateInfo

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "version=") {
				info.Version = strings.TrimPrefix(line, "version=")
				continue
			}
			if strings.HasPrefix(line, "build=") {
				info.Build = strings.TrimPrefix(line, "build=")
				continue
			}
			if strings.HasPrefix(line, "type=") {
				info.Type = strings.TrimPrefix(line, "type=")
				continue
			}
			if strings.HasPrefix(line, "level=") {
				info.Level = strings.TrimPrefix(line, "level=")
				continue
			}
			if strings.HasPrefix(line, "platform=") {
				info.Platform = strings.TrimPrefix(line, "platform=")
				continue
			}
			if strings.HasPrefix(line, "size=") {
				info.Size = strings.TrimPrefix(line, "size=")
				continue
			}
			if strings.HasPrefix(line, "file=") {
				info.File = strings.TrimPrefix(line, "file=")
			}
		}

		if info.Version != "" {
			updates = append(updates, info)
		}
	}

	// Convert to JSON
	jsonData, err := json.Marshal(updates)
	if err != nil {
		log.Println("Error marshalling to JSON:", err)
		return ""
	}

	return string(jsonData)
}

func getNODSetting() string {
	// Define the full path
	// settingPath := "C:/SentinelAV/NOD32EngineSettings.xml"
	// settingPath = "NOD32EngineSettings.xml"
	settingPath := os.Getenv("NodEngineSettings")

	// Check if file exists
	if _, err := os.Stat(settingPath); os.IsNotExist(err) {
		fmt.Println("INI file not found at:", settingPath)
		return ""
	}

	// Read the INI file
	file, err := os.ReadFile(settingPath)
	if err != nil {
		fmt.Println("Error read file:", err)
		return ""
	}

	var settings NOD32EngineSettings
	err = xml.Unmarshal(file, &settings)
	if err != nil {
		fmt.Println("Error parse XML:", err)
		return ""
	}

	response := map[string]string{
		"ProductVersion":  settings.ProductVersion,
		"ScannerVersion":  settings.ScannerVersion,
		"SoftwareVersion": settings.SoftwareVersion,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Println("Error marshalling to JSON:", err)
		return ""
	}

	return string(jsonData)
}
