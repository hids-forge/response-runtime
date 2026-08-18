//go:build unsafe_features

package main

import (
	"context"
	"encoding/json"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"log"
	"os/exec"
	"runtime"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type RunCommandData struct {
	MqttURL       string `json:"mqtt-url"`      // MQTT broker URL (tcp:// or ssl://)
	MqttUsername  string `json:"mqtt-username"` // MQTT username
	MqttPassword  string `json:"mqtt-password"` // MQTT password
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	CorrelationID string `json:"correlation_id"`
	ReplyTo       string `json:"reply_to"`

	Command string `json:"command"`
}

func handleRunCommand(payload helper.Payload) {
	log.Println("Start run command.")
	publishTopic = ""

	var runcmdData RunCommandData
	json.Unmarshal(payload.Parameters.Alert.Data, &runcmdData)
	if runcmdData.MqttURL == "" || runcmdData.MqttUsername == "" || runcmdData.MqttPassword == "" {
		log.Println("Missing configuration parameters")
		return
	}

	if runcmdData.Command == "" {
		log.Println("Command is required")
		return
	}

	brokerUrl = runcmdData.MqttURL
	username = runcmdData.MqttUsername
	password = runcmdData.MqttPassword
	agentName = runcmdData.Agent
	managerName = runcmdData.Manager
	command := runcmdData.Command
	correlationID = runcmdData.CorrelationID
	if runcmdData.ReplyTo != "" {
		publishTopic = runcmdData.ReplyTo
	}

	ch := make(chan mqtt.Message)
	mqttClient = MqttClient(ch)

	runCommand(command)
}

func runCommand(command string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // limit runtime
	defer cancel()

	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "cmd", "/C", command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Println(err)
		}
		sendBackResponse(output)
	} else {
		cmd := exec.Command("bash", "-c", command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Println(err)
		}
		sendBackResponse(output)
	}
}
