package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type BlockIPData struct {
	IP            string `json:"ip"`
	MqttURL       string `json:"mqtt-url"`
	MqttUsername  string `json:"mqtt-username"`
	MqttPassword  string `json:"mqtt-password"`
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	CorrelationID string `json:"correlation_id"`
	ReplyTo       string `json:"reply_to"`
}

func handleBlockIP(payload helper.Payload) {
	publishTopic = ""
	log.Println("Start running block IP.")
	var blockIPData BlockIPData
	json.Unmarshal(payload.Parameters.Alert.Data, &blockIPData)
	if blockIPData.IP == "" {
		log.Println("IP is empty")
	} else {
		log.Printf("Block IP: %s", blockIPData.IP)
	}

	configureMQTT(mqttConfig{
		MqttURL:       blockIPData.MqttURL,
		MqttUsername:  blockIPData.MqttUsername,
		MqttPassword:  blockIPData.MqttPassword,
		Agent:         blockIPData.Agent,
		Manager:       blockIPData.Manager,
		ReplyTo:       blockIPData.ReplyTo,
		CorrelationID: blockIPData.CorrelationID,
	})

	result := blockIP(blockIPData.IP)
	if result != "" {
		sendBackResponse([]byte(result))
	}
	log.Println("Done block IP.")

}

func blockIP(ip string) string {
	// check if ip is valid
	if net.ParseIP(ip) == nil {
		log.Println("IP is not valid")
		return "block-ip: invalid IP"
	}

	system := runtime.GOOS
	var messages []string
	switch system {
	case "windows":
		netshPath, err := exec.LookPath("netsh")
		if err != nil {
			return "block-ip: netsh not found"
		}

		inboundCmd := exec.Command(netshPath, "advfirewall", "firewall", "add", "rule",
			"name=BlockIP", "dir=in", "interface=any", "action=block", fmt.Sprintf("remoteip=%s", ip))
		outboundCmd := exec.Command(netshPath, "advfirewall", "firewall", "add", "rule",
			"name=BlockIP", "dir=out", "interface=any", "action=block", fmt.Sprintf("remoteip=%s", ip))

		if err := inboundCmd.Run(); err != nil {
			messages = append(messages, fmt.Sprintf("inbound rule error: %v", err))
		} else {
			messages = append(messages, "inbound rule added")
		}
		if err := outboundCmd.Run(); err != nil {
			messages = append(messages, fmt.Sprintf("outbound rule error: %v", err))
		} else {
			messages = append(messages, "outbound rule added")
		}
	case "linux":
		commands := [][]string{
			{"iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"},
			{"iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"},
		}

		for _, cmdArgs := range commands {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				log.Printf("Error run command %v: %v", cmdArgs, err)
			} else {
				log.Printf("Iptables rule Added for IP: %s\n", ip)
			}
		}
	case "darwin":
		exec.Command("/sbin/pfctl", "-e").Run()
		addIPRule(ip)

		cmd := exec.Command("/sbin/pfctl", "-f", "/etc/pf.conf")
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Println("Error run pfctl:", err)
			log.Println(string(out))
		}

		log.Printf("Updated rule - IP: %s has been chained by MacOS Firewall\n", ip)
		messages = append(messages, "pf rule updated")
	default:
		return fmt.Sprintf("block-ip: unsupported OS %s", system)
	}

	log.Println("Done block IP.")
	if len(messages) == 0 {
		return fmt.Sprintf("block-ip: %s processed", ip)
	}
	return fmt.Sprintf("block-ip %s: %s", ip, strings.Join(messages, "; "))
}

func addIPRule(ip string) {
	// Context with timeout 5 s
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		if strings.TrimSpace(ip) == "" {
			done <- fmt.Errorf("Invalid IP address")
			return
		}

		rule := fmt.Sprintf("block in from any to %s\nblock out from any to %s\n", ip, ip)

		// Write to /etc/pf.conf
		f, err := os.OpenFile("/etc/pf.conf", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			done <- fmt.Errorf("Can not open file pf.conf: %v", err)
			return
		}
		defer f.Close()

		if _, err := f.WriteString(rule); err != nil {
			done <- fmt.Errorf("Can not write rule: %v", err)
			return
		}

		log.Printf("Added rule to block inbound and outbound traffic to %s\n", ip)
		done <- nil
	}()

	select {
	case <-ctx.Done():
		log.Println("Function timed out")
	case err := <-done:
		if err != nil {
			log.Println("Error:", err)
		}
	}
}
