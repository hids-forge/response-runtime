package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var agentName string = ""
var managerName string = ""
var mqttClient mqtt.Client

var (
	brokerUrl      = ""
	username       = ""
	password       = ""
	subscribeTopic = ""
	publishTopic   = ""
)

// mqttConfig carries optional MQTT connection details provided in the alert payload.
type mqttConfig struct {
	MqttURL       string `json:"mqtt-url"`
	MqttUsername  string `json:"mqtt-username"`
	MqttPassword  string `json:"mqtt-password"`
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	ReplyTo       string `json:"reply_to"`
	CorrelationID string `json:"correlation_id"`
	ProgressTo    string `json:"progress_to"`
	DebugTo       string `json:"debug_to"`
}

func MqttClient(mqchan chan mqtt.Message) mqtt.Client {
	if brokerUrl == "" || username == "" {
		return nil
	}

	opts := mqtt.NewClientOptions().AddBroker(brokerUrl)
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetClientID(fmt.Sprintf("subscribe-%d", time.Now().UnixNano()))
	opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(1 * time.Minute)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetConnectTimeout(15 * time.Second)
	opts.SetWriteTimeout(10 * time.Second)

	opts.SetOnConnectHandler(func(client mqtt.Client) { // auto subscribe topic
		if subscribeTopic != "" {
			client.Subscribe(subscribeTopic, 1, nil)
		}
	})
	opts.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
		mqchan <- msg
	})

	// mqtt connect
	mq := mqtt.NewClient(opts)
	token := mq.Connect()
	if ok := token.WaitTimeout(10 * time.Second); !ok {
		log.Println("MQTT connect timeout")
		os.Exit(1)
	}

	if err := token.Error(); err != nil {
		log.Println("Error connecting to MQTT broker:", err)
		os.Exit(1)
	}
	return mq
}

func sendBackResponse(jsonData []byte) {
	if mqttClient != nil && publishTopic != "" {
		token := mqttClient.Publish(publishTopic, 1, false, jsonData)
		token.Wait()
		log.Println("Publish successful.")
	}
}

// configureMQTT sets global MQTT connection details from the provided config and connects.
// Returns true if a client was created.
func configureMQTT(cfg mqttConfig) bool {
	if cfg.MqttURL == "" || cfg.MqttUsername == "" || cfg.MqttPassword == "" {
		return false
	}
	brokerUrl = cfg.MqttURL
	username = cfg.MqttUsername
	password = cfg.MqttPassword
	agentName = cfg.Agent
	managerName = cfg.Manager
	correlationID = cfg.CorrelationID
	if cfg.ReplyTo != "" {
		publishTopic = cfg.ReplyTo
	}

	ch := make(chan mqtt.Message)
	mqttClient = MqttClient(ch)
	return mqttClient != nil
}

func sendBackResponseStr(message string) {
	if mqttClient != nil && publishTopic != "" {
		token := mqttClient.Publish(publishTopic, 1, false, message)
		token.Wait()
		log.Println("Publish successful.")
	}
}
