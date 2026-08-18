//go:build !danger_emergencies

package main

import (
	"encoding/json"
	"fmt"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func handleDownloadFile(prefix, sessionID string, params json.RawMessage) error {
	_ = prefix
	_ = sessionID
	_ = params
	return fmt.Errorf("downloadFile is disabled in this build")
}

func serveShell(client mqtt.Client, prefix, sessionID string) error {
	_ = client
	_ = prefix
	_ = sessionID
	return fmt.Errorf("openShell is disabled in this build")
}
