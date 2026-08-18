//go:build danger_emergencies && !windows
// +build danger_emergencies,!windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/creack/pty"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// serveShell sets up a PTY for the given session and wires I/O over MQTT topics.
func serveShell(client mqtt.Client, prefix, sessionID string) error {
	log.Println("Starting session " + sessionID)
	shellCmd := "/bin/sh"

	cmd := exec.Command(shellCmd)
	ptyFile, err := pty.Start(cmd)
	if err != nil {
		log.Printf("failed to start pty: %v\n", err)
		return err
	}

	inTopic := fmt.Sprintf("%s/shell/%s/input", prefix, sessionID)
	outTopic := fmt.Sprintf("%s/shell/%s/output", prefix, sessionID)
	resizeTopic := fmt.Sprintf("%s/shell/%s/resize", prefix, sessionID)
	// log.Println("PTY started, subscribing to " + inTopic + " and " + resizeTopic)

	// subscribe to input
	client.Subscribe(inTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		if len(msg.Payload()) > 0 {
			ptyFile.Write(msg.Payload())
		}
	})

	if err := pty.InheritSize(os.Stdin, ptyFile); err != nil {
		_ = pty.Setsize(ptyFile, &pty.Winsize{Rows: 30, Cols: 120})
	}

	// subscribe to resize events
	client.Subscribe(resizeTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		var dims struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if err := json.Unmarshal(msg.Payload(), &dims); err != nil {
			return
		}
		pty.Setsize(ptyFile, &pty.Winsize{Cols: uint16(dims.Cols), Rows: uint16(dims.Rows)})
	})

	// Read output from PTY and publish to MQTT
	go func() {
		defer func() {
			ptyFile.Close()
			cmd.Process.Kill()
		}()

		buf := make([]byte, 4096)
		// log.Println("[Shell Output] Starting to read from PTY")
		for {
			n, err := ptyFile.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				tok := client.Publish(outTopic, 1, false, buf[:n])
				tok.Wait()
			}
		}
	}()

	// Wait for shell process to exit
	go func() {
		cmd.Wait()
	}()
	return nil
}
