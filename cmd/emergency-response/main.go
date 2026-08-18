package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/logging"
	"github.com/hids-forge/response-runtime/pkg/helper"
	versionpkg "github.com/hids-forge/response-runtime/pkg/version"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type EmergencyResponseData struct {
	// MQTT configuration
	MqttURL      string `json:"mqtt-url"`      // MQTT broker URL (tcp:// or ssl://)
	MqttUsername string `json:"mqtt-username"` // MQTT username for RPC channel
	MqttPassword string `json:"mqtt-password"` // MQTT password for RPC channel
	TLSCertFP    string `json:"tls_cert_fp"`   // TLS certificate fingerprint for broker verification
	SessionID    string `json:"session_id"`    // Session ID for openShell or RPC method (sensorName-agentID)
}

var msg helper.Message
var mqttClient mqtt.Client
var topicAck string
var defaultActiveResponseBin = "active-response"

func main() {
	helper.GetConfig()
	logFile := logging.SetupLogging(helper.LOG_FILE)
	defer logFile.Close()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "version":
			fmt.Println(versionpkg.Version)
			return
		}
	}

	if len(os.Args) > 1 && os.Args[1] == "--child" {
		// Process child
		handleEmergencyResponse()
		return
	}

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	// log.Println(input)

	var payload helper.Payload
	if err := json.Unmarshal([]byte(input), &payload); err != nil {
		log.Fatalf("json unmarshal error: %v", err)
	}

	// Make pipe to send json to child
	r, w, err := os.Pipe()
	if err != nil {
		log.Fatalf("pipe error: %v", err)
	}

	// Fork and detach
	cmd := exec.Command(os.Args[0], "--child")
	cmd.Stdin = r
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = newSysProcAttr()

	// Send json to pipe
	go func() {
		defer w.Close()
		w.Write([]byte(input))
	}()

	// Start child process
	if err := cmd.Start(); err != nil {
		log.Fatalf("fork failed: %v", err)
	}
	cmd.Process.Release()
	log.Printf("F-PID %d\n", cmd.Process.Pid)
	time.Sleep(1 * time.Second)
}

func handleEmergencyResponse() {
	log.Println("Start running emergency-response...")

	// Read input from stdin and parse message
	msg = helper.SetupAndCheckMessage()
	if msg.Command < 0 {
		os.Exit(helper.OS_INVALID)
	}

	var emergencyData EmergencyResponseData
	json.Unmarshal(msg.Payload.Parameters.Alert.Data, &emergencyData)

	if emergencyData.MqttURL == "" || emergencyData.MqttUsername == "" || emergencyData.MqttPassword == "" {
		log.Println("Missing configuration parameters")
		return
	}
	if emergencyData.SessionID == "" {
		log.Println("Missing session_id parameter")
		return
	}

	err := runEmergencyResponse(emergencyData)
	if err != nil {
		log.Fatalf("emergency-response error: %s\n", err.Error())
	}
}

func runEmergencyResponse(emergencyData EmergencyResponseData) error {
	url := emergencyData.MqttURL
	user := emergencyData.MqttUsername
	pass := emergencyData.MqttPassword
	sessionID := emergencyData.SessionID
	certFp := emergencyData.TLSCertFP

	prefix := "response-runtime/rpc"
	// log.Printf("Emergency-response session ID: %s\n", sessionID)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	if certFp != "" {
		log.Printf("Using TLS fingerprint: %s\n", certFp)
	}

	opts := mqtt.NewClientOptions().AddBroker(url)
	opts.SetUsername(user)
	opts.SetPassword(pass)
	opts.SetClientID(fmt.Sprintf("response-runtime-%d", time.Now().UnixNano()))
	opts.SetTLSConfig(tlsConfig)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(1 * time.Minute)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetOnConnectHandler(func(client mqtt.Client) { // auto subscribe topic
		reqTopic := prefix + "/request/" + sessionID
		respTopicBase := prefix + "/response/" + sessionID
		topicAck = prefix + "/download/ack/" + sessionID
		log.Println("Connected.")

		token := client.Subscribe(reqTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
			var req struct {
				JSONRPC string          `json:"jsonrpc"`
				Method  string          `json:"method"`
				Params  json.RawMessage `json:"params"`
				ID      string          `json:"id"`
			}
			if err := json.Unmarshal(msg.Payload(), &req); err != nil {
				log.Printf("Invalid parse request: %v\n", err)
				return
			}

			// log.Println("Received request:", string(msg.Payload()))

			// prepare result and error variables
			var result interface{}
			var rpcErr error
			switch req.Method {
			case "downloadFile":
				rpcErr = handleDownloadFile(prefix, sessionID, req.Params)
				if rpcErr == nil {
					result = map[string]string{"session": sessionID}
				}
			case "openShell":
				// spawn PTY and wire I/O over MQTT topics
				rpcErr = serveShell(client, prefix, sessionID)
				if rpcErr == nil {
					result = map[string]string{"session": sessionID}
				}
			default:
				result, rpcErr = dispatchRPC(req.Method, req.Params)
			}

			resp := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
			if rpcErr != nil {
				resp["error"] = map[string]string{"message": rpcErr.Error()}
			} else {
				resp["result"] = result
			}
			out, _ := json.Marshal(resp)
			client.Publish(respTopicBase, 1, false, out)
		})
		token.WaitTimeout(30 * time.Second)
		<-token.Done()
		if token.Error() != nil {
			log.Printf("handle request error: %v", token.Error())
		}

		// log.Println("topicAck", topicAck)
		// if token := mqttClient.Subscribe(topicAck, 1, handleChunkAck); token.Wait() && token.Error() != nil {
		// 	log.Println("handle ack error", token.Error())
		// }
	})

	mqttClient = mqtt.NewClient(opts)
	if tok := mqttClient.Connect(); !tok.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("connect timeout")
	} else if tok.Error() != nil {
		return fmt.Errorf("connect error: %v", tok.Error())
	}
	defer mqttClient.Disconnect(250)

	// Keep running 20 minute
	time.AfterFunc(20*time.Minute, func() {
		log.Println("Session timeout, exiting")
		mqttClient.Disconnect(250)
		os.Exit(0)
	})

	select {}
}

// dispatchRPC routes JSON-RPC methods to local handlers in emergency-response mode.
func dispatchRPC(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "runSubcommand":
		return handleRunSubcommand(params)
	case "uploadScript":
		return handleUploadScript(params)
	case "runJS":
		return handleRunJS(params)

	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

// handleRunSubcommand invokes a subcommand locally.
func handleRunSubcommand(params json.RawMessage) (interface{}, error) {
	_ = params
	return nil, fmt.Errorf("runSubcommand is disabled in this build")
}

// handleUploadScript is a stub for script upload RPC.
func handleUploadScript(params json.RawMessage) (interface{}, error) {
	_ = params
	return nil, fmt.Errorf("uploadScript is disabled in this build")
}

func handleRunJS(params json.RawMessage) (interface{}, error) {
	var alertCtx map[string]interface{}
	if err := json.Unmarshal(params, &alertCtx); err != nil {
		return nil, err
	}
	script, _ := alertCtx["script"].(string)
	if script == "" {
		return nil, fmt.Errorf("runJS requires a script field")
	}

	companionBin := os.Getenv("RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN")
	if companionBin == "" {
		exePath, err := os.Executable()
		if err != nil {
			return nil, err
		}
		binName := defaultActiveResponseBin
		if filepath.Ext(exePath) == ".exe" && filepath.Ext(binName) != ".exe" {
			binName += ".exe"
		}
		companionBin = filepath.Join(filepath.Dir(exePath), binName)
	}

	inputPayload := map[string]interface{}{
		"script": script,
		"alert":  alertCtx,
	}
	tmp, err := os.CreateTemp("", "response-runtime-js-*.json")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := json.NewEncoder(tmp).Encode(inputPayload); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	cmd := exec.Command(companionBin, "exec-js-payload", "--input", tmpPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("runJS via companion active-response failed: %w (%s)", err, string(out))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("invalid runJS output: %w", err)
	}
	return result, nil
}
