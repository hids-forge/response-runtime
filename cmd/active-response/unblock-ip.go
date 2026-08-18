package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type UnBlockIPData struct {
	IP            string `json:"ip"`
	MqttURL       string `json:"mqtt-url"`
	MqttUsername  string `json:"mqtt-username"`
	MqttPassword  string `json:"mqtt-password"`
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	CorrelationID string `json:"correlation_id"`
	ReplyTo       string `json:"reply_to"`
}

func handleUnBlockIP(payload helper.Payload) {
	publishTopic = ""
	log.Println("Start running un block IP.")
	var unBlockIPData UnBlockIPData
	json.Unmarshal(payload.Parameters.Alert.Data, &unBlockIPData)
	if unBlockIPData.IP == "" {
		log.Println("IP is empty")
	} else {
		log.Printf("UnBlock IP: %s", unBlockIPData.IP)
	}

	configureMQTT(mqttConfig{
		MqttURL:       unBlockIPData.MqttURL,
		MqttUsername:  unBlockIPData.MqttUsername,
		MqttPassword:  unBlockIPData.MqttPassword,
		Agent:         unBlockIPData.Agent,
		Manager:       unBlockIPData.Manager,
		ReplyTo:       unBlockIPData.ReplyTo,
		CorrelationID: unBlockIPData.CorrelationID,
	})

	result := unBlockIP(unBlockIPData.IP)
	if result != "" {
		sendBackResponse([]byte(result))
	}
	log.Println("Done un block IP.")
}

func unBlockIP(ip string) string {
	// check if ip is valid
	if net.ParseIP(ip) == nil {
		log.Println("IP is not valid")
		return "unblock-ip: invalid IP"
	}

	system := runtime.GOOS
	var messages []string
	switch system {
	case "windows":

		netshPath, err := exec.LookPath("netsh")
		if err != nil {
			return "unblock-ip: netsh not found"
		}

		cmd := exec.Command(netshPath, "advfirewall", "firewall", "delete", "rule", "name=BlockIP", fmt.Sprintf("remoteip=%s", ip))
		if err := cmd.Run(); err != nil {
			messages = append(messages, fmt.Sprintf("delete rule error: %v", err))
		} else {
			messages = append(messages, "rule removed")
		}
	case "linux":
		commands := [][]string{
			{"iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"},
			{"iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"},
		}

		for _, cmdArgs := range commands {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				log.Printf("Error run command %v: %v", cmdArgs, err)
			} else {
				log.Printf("Iptables rule removed for IP: %s\n", ip)
			}
		}
	case "darwin":
		removeIPRule(ip)
		exec.Command("/sbin/pfctl", "-f", "/etc/pf.conf").Run()
		log.Printf("IP: %s has been untied by MacOS Firewall\n", ip)
		messages = append(messages, "pf rule removed")
	default:
		return fmt.Sprintf("unblock-ip: unsupported OS %s", system)
	}

	log.Println("Finish running un block IP.")
	if len(messages) == 0 {
		return fmt.Sprintf("unblock-ip: %s processed", ip)
	}
	return fmt.Sprintf("unblock-ip %s: %s", ip, strings.Join(messages, "; "))
}

func removeIPRule(ip string) {
	if strings.TrimSpace(ip) == "" {
		fmt.Println("Invalid IP address")
		return
	}

	// Read all file /etc/pf.conf
	filePath := "/etc/pf.conf"
	lines := []string{}

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Can not open pf.conf:", err)
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, fmt.Sprintf("block in from any to %s", ip)) &&
			!strings.HasPrefix(line, fmt.Sprintf("block out from any to %s", ip)) {
			lines = append(lines, line)
		}
	}
	file.Close()

	// Write to file pf.conf
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Can not write file pf.conf:", err)
		return
	}

	writer := bufio.NewWriter(f)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	writer.Flush()
	f.Close()

	log.Println("IP rule removed from pf.conf")

	// Reload pfctl
	cmd := exec.Command("/sbin/pfctl", "-f", "/etc/pf.conf")
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error run pfctl:", err)
		fmt.Println(string(cmdOutput))
		return
	}

	fmt.Println("pfctl command executed successfully")
}
