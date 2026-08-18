package helper

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	ADD_COMMAND      = 0
	DELETE_COMMAND   = 1
	CONTINUE_COMMAND = 2
	ABORT_COMMAND    = 3
	OS_SUCCESS       = 0
	OS_INVALID       = -1
)

type Message struct {
	Payload Payload
	Command int
}

type Payload struct {
	Command    string     `json:"command"`
	Parameters Parameters `json:"parameters"`
}

type Parameters struct {
	ExtraArgs []string `json:"extra_args"`
	Alert     Alert    `json:"alert"`
}

type Alert struct {
	Data json.RawMessage `json:"data"`
}

type Config struct {
	SelectOs *SelectOs
}

type SelectOs struct {
	Os        string
	OssecConf string
	ARPath    string
	ArLogs    string
}

var (
	CONFIG   *Config
	SELEC_OS map[string]*SelectOs
	LOG_FILE = "active-response/active-responses.log"
)

func GetConfig() {
	SELEC_OS = make(map[string]*SelectOs)
	SELEC_OS["windows"] = &SelectOs{
		Os:        "windows",
		OssecConf: "ossec.conf",
		ARPath:    "active-response/bin",
		ArLogs:    "active-response/active-responses.log",
	}
	SELEC_OS["linux"] = &SelectOs{
		Os:        "linux",
		OssecConf: "/var/ossec/etc/ossec.conf",
		ARPath:    "/var/ossec/active-response/bin",
		ArLogs:    "/var/ossec/logs/active-responses.log",
	}
	SELEC_OS["darwin"] = &SelectOs{
		Os:        "macos",
		OssecConf: "/Library/Ossec/etc/ossec.conf",
		ARPath:    "/Library/Ossec/active-response/bin",
		ArLogs:    "/Library/Ossec/logs/active-responses.log",
	}
	SELEC_OS["debug"] = &SelectOs{
		Os:        "linux",
		OssecConf: "./test/test.xml", //"/var/ossec/etc/ossec.conf",
		ARPath:    "./test/bin",      // "/var/ossec/active-response/bin",
		ArLogs:    "./test/test.log", //"/var/ossec/logs/active-responses.log",
	}

	CONFIG = &Config{
		SelectOs: SELEC_OS[runtime.GOOS],
	}

	LOG_FILE = CONFIG.SelectOs.ArLogs
}

func SetupAndCheckMessage() Message {
	var msg Message
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	// log.Println(input)

	var payload Payload
	if err := json.Unmarshal([]byte(input), &payload); err != nil {
		log.Printf("Error while decoding JSON: %s", input)
		msg.Command = OS_INVALID
		return msg
	}

	msg.Payload = payload
	switch payload.Command {
	case "add":
		msg.Command = ADD_COMMAND
	case "delete":
		msg.Command = DELETE_COMMAND
	default:
		msg.Command = OS_INVALID
	}

	return msg
}

func WriteLog(arName, msg string) {
	file, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Could not find the active-responses.log file!")
		return
	}
	defer file.Close()

	arNamePosix := filepath.ToSlash(arName)
	logMsg := fmt.Sprintf("%s %s: %s\r\n", time.Now().Format("2006/01/02 15:04:05"), arNamePosix, msg)
	file.WriteString(logMsg)
}

func WriteStructuredLog(level, action, filePath string) {
	file, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Could not find the active-responses.log file!")
		return
	}
	defer file.Close()

	logMsg := fmt.Sprintf("%s response-runtime: %s - %s: %s\r\n",
		time.Now().Format("2006/01/02 15:04:05"), level, action, filePath)
	file.WriteString(logMsg)
}

func WriteCheckUpgradeLog(message, version string) {
	file, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Could not find the active-responses.log file!")
		return
	}
	defer file.Close()

	// Tue Feb 24 07:43:24 AM UTC 2026 response-runtime: success, version 1.1
	logMsg := fmt.Sprintf("%s response-runtime: %s, version %s\r\n", time.Now().UTC().Format("Mon Jan 02 15:04:05 PM MST 2006"), message, version)
	file.WriteString(logMsg)
}
