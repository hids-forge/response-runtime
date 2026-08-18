//go:build enable_remote_updates

package main

import (
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
)

type ArUpdaterData struct {
	mqttConfig
}

func handleArUpdater(payload helper.Payload) {
	publishTopic = ""
	helper.WriteLog(os.Args[0], "Start running ar-updater")

	var arData ArUpdaterData
	if len(payload.Parameters.Alert.Data) > 0 {
		_ = json.Unmarshal(payload.Parameters.Alert.Data, &arData)
	}
	configureMQTT(arData.mqttConfig)

	var urlStr, destPath string
	for _, arg := range payload.Parameters.ExtraArgs {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "url":
			urlStr = strings.TrimSpace(parts[1])
		case "path":
			destPath = strings.TrimSpace(parts[1])
		}
	}
	if urlStr == "" || destPath == "" {
		helper.WriteLog(os.Args[0], "both url and path parameters are required")
		sendBackResponse([]byte("ar-updater failed: missing url or path"))
		return
	}

	if !strings.Contains(destPath, "/") || !strings.Contains(destPath, "\\") {
		destPath = helper.CONFIG.SelectOs.ARPath + "/" + destPath
	}

	// fmt.Println("Downloading from", urlStr, "to", destPath)

	resp, err := http.Get(urlStr)
	if err != nil {
		helper.WriteLog(os.Args[0], fmt.Sprintf("download failed: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		helper.WriteLog(os.Args[0], fmt.Sprintf("download failed: %s", resp.Status))
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		helper.WriteLog(os.Args[0], fmt.Sprintf("read body failed: %v", err))
		return
	}

	if _, err := os.Stat(destPath); err == nil {
		for i := 0; i < 3; i++ {
			suf := rand.Intn(100) + 1
			bak := fmt.Sprintf("%s.%d", destPath, suf)
			if err := os.Rename(destPath, bak); err != nil {
				if os.IsExist(err) {
					os.Remove(bak)
					if err2 := os.Rename(destPath, bak); err2 == nil {
						break
					}
				}
				continue
			}
			break
		}
	}

	if err := os.WriteFile(destPath, body, 0755); err != nil {
		helper.WriteLog(os.Args[0], fmt.Sprintf("write file failed: %v", err))
		sendBackResponse([]byte(fmt.Sprintf("ar-updater failed: %v", err)))
		return
	}
	helper.WriteLog(os.Args[0], fmt.Sprintf("downloaded file successful to %s (%d bytes)", destPath, len(body)))
	sendBackResponse([]byte(fmt.Sprintf("ar-updater downloaded to %s (%d bytes)", destPath, len(body))))
}
