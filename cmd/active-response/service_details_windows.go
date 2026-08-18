//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func helperWindowsServiceDetails(limit int, maxHashBytes int64) ([]map[string]interface{}, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	var res []map[string]interface{}
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		cfg, _ := s.Config()
		st, _ := s.Query()
		entry := map[string]interface{}{
			"name":        name,
			"startType":   startTypeString(cfg.StartType),
			"state":       svcStateString(st.State),
			"display":     cfg.DisplayName,
			"binPath":     cfg.BinaryPathName,
			"serviceType": cfg.ServiceType,
		}
		path := cfg.BinaryPathName
		if path != "" {
			trimmed := strings.Trim(path, "\"")
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				trimmed = fields[0]
			}
			if _, err := os.Stat(trimmed); err == nil {
				if _, sha, hErr := computeFileHashes(trimmed, maxHashBytes); hErr == nil {
					entry["hash"] = sha
				}
				sig := winSigInfoWintrust(trimmed)
				entry["signed"] = sig["signed"]
				entry["sigStatus"] = sig["status"]
			}
			entry["path"] = trimmed
		}
		if cfg.ServiceType&windows.SERVICE_KERNEL_DRIVER != 0 || cfg.ServiceType&windows.SERVICE_FILE_SYSTEM_DRIVER != 0 {
			entry["driver"] = true
		}
		res = append(res, entry)
		s.Close()
		if len(res) >= limit {
			break
		}
	}
	return res, nil
}
