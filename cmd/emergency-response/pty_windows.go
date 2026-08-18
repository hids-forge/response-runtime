//go:build danger_emergencies && windows
// +build danger_emergencies,windows

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/iamacarpet/go-winpty"
)

func serveShell(client mqtt.Client, prefix, sessionID string) error {
	log.Println("Starting session " + sessionID)
	// shellCmd := "powershell.exe -NoLogo -NoProfile"
	shellCmd := "cmd.exe"

	pty, err := winpty.OpenDefault("", shellCmd)
	if err != nil {
		log.Printf("failed to create win pty: %v\n", err)
		return err
	}

	pty.SetSize(120, 24)
	time.Sleep(1 * time.Second)

	inTopic := fmt.Sprintf("%s/shell/%s/input", prefix, sessionID)
	outTopic := fmt.Sprintf("%s/shell/%s/output", prefix, sessionID)
	resizeTopic := fmt.Sprintf("%s/shell/%s/resize", prefix, sessionID)

	// subscribe to input
	token := client.Subscribe(inTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		if len(msg.Payload()) > 0 {
			pty.StdIn.Write(msg.Payload())
		}
	})
	if token.Wait() && token.Error() != nil {
		log.Fatalf("Error subscribe %s: %v", inTopic, token.Error())
	}

	// subscribe to resize events
	client.Subscribe(resizeTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		var dims struct {
			Cols uint32 `json:"cols"`
			Rows uint32 `json:"rows"`
		}
		if err := json.Unmarshal(msg.Payload(), &dims); err != nil {
			return
		}
		pty.SetSize(dims.Cols, dims.Rows)
		time.Sleep(1 * time.Second)
	})

	// Read output from PTY and publish to MQTT
	go func() {
		defer func() {
			pty.Close()
		}()

		buf := make([]byte, 4096)
		log.Println("[Output] Starting to read from PTY")
		for {
			n, err := pty.StdOut.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Println("PTY closed")
					return
				}
				log.Printf("Error read from PTY: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			if n > 0 {
				tok := client.Publish(outTopic, 1, false, buf[:n])
				tok.Wait()
			}
		}
	}()
	return nil
}
