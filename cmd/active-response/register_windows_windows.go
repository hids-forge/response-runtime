//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"github.com/dop251/goja"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modversion        = windows.NewLazySystemDLL("version.dll")
	procVerQueryValue = modversion.NewProc("VerQueryValueW")
)

type vsFixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

func hiWord(val uint32) uint16 { return uint16(val >> 16) }
func loWord(val uint32) uint16 { return uint16(val & 0xffff) }

func syscallStringToUTF16Ptr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func startTypeString(st uint32) string {
	switch st {
	case windows.SERVICE_AUTO_START:
		return "automatic"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	default:
		return fmt.Sprintf("%d", st)
	}
}

func svcStateString(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("%d", state)
	}
}

func winMutexExists(name string) bool {
	if name == "" {
		return false
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, windows.StringToUTF16Ptr(name))
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return false
}

func winNamedPipeExists(name string) (bool, string) {
	if name == "" {
		return false, "empty name"
	}
	path := `\\.\pipe\` + strings.TrimPrefix(name, `\\.\pipe\`)
	// Try opening with short timeout (non-blocking); ERROR_PIPE_BUSY indicates it exists but busy.
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), 0, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		windows.CloseHandle(handle)
		return true, ""
	}
	if err == windows.ERROR_PIPE_BUSY {
		return true, "pipe busy"
	}
	return false, err.Error()
}

func winServiceInfo(name string) map[string]interface{} {
	info := map[string]interface{}{"present": false}
	m, err := mgr.Connect()
	if err != nil {
		info["error"] = err.Error()
		return info
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		info["error"] = err.Error()
		return info
	}
	defer s.Close()
	cfg, err := s.Config()
	if err == nil {
		info["startType"] = startTypeString(cfg.StartType)
		info["description"] = cfg.Description
		info["serviceType"] = cfg.ServiceType
	}
	st, err := s.Query()
	if err == nil {
		info["state"] = svcStateString(st.State)
	}
	info["present"] = true
	return info
}

func winDriverInfo(name string) map[string]interface{} {
	info := winServiceInfo(name)
	if present, ok := info["present"].(bool); !ok || !present {
		return info
	}
	if st, ok := info["serviceType"].(uint32); ok {
		if st&windows.SERVICE_KERNEL_DRIVER != 0 || st&windows.SERVICE_FILE_SYSTEM_DRIVER != 0 {
			info["driver"] = true
		} else {
			info["driver"] = false
		}
	}
	return info
}

func winFileVersion(path string) map[string]interface{} {
	res := map[string]interface{}{}
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["error"] = "empty version info"
		}
		return res
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		res["error"] = err.Error()
		return res
	}
	var block *byte
	var blen uint32
	r, _, _ := procVerQueryValue.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(syscallStringToUTF16Ptr(`\`))), uintptr(unsafe.Pointer(&block)), uintptr(unsafe.Pointer(&blen)))
	if r == 0 || blen == 0 {
		res["error"] = "VerQueryValue failed"
		return res
	}
	v := (*vsFixedFileInfo)(unsafe.Pointer(block))
	if v.Signature != 0xfeef04bd {
		res["error"] = "invalid version signature"
		return res
	}
	fileVer := fmt.Sprintf("%d.%d.%d.%d", hiWord(v.FileVersionMS), loWord(v.FileVersionMS), hiWord(v.FileVersionLS), loWord(v.FileVersionLS))
	prodVer := fmt.Sprintf("%d.%d.%d.%d", hiWord(v.ProductVersionMS), loWord(v.ProductVersionMS), hiWord(v.ProductVersionLS), loWord(v.ProductVersionLS))
	res["fileVersion"] = fileVer
	res["productVersion"] = prodVer
	return res
}

func winSigInfoCmd(path string) map[string]interface{} {
	res := map[string]interface{}{}
	// Deprecated in favor of winSigInfoWintrust, kept as fallback.
	cmd := exec.Command("powershell", "-NoLogo", "-NonInteractive", "-Command",
		"Get-AuthenticodeSignature -FilePath '"+path+"' | Select-Object Status,StatusMessage,SignerCertificate | ConvertTo-Json -Compress")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		res["signed"] = false
		res["error"] = err.Error()
		return res
	}
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		res["error"] = err.Error()
		return res
	}
	if status, ok := res["Status"].(string); ok && strings.EqualFold(status, "Valid") {
		res["signed"] = true
	} else {
		res["signed"] = false
	}
	return res
}

// registerWindowsHelpers provides real Windows implementations.
func registerWindowsHelpers(vm *goja.Runtime) {
	vm.Set("winIsMutexExist", func(name string) bool {
		return winMutexExists(name)
	})
	vm.Set("winIsServicePresent", func(name string) map[string]interface{} {
		return winServiceInfo(name)
	})
	vm.Set("winIsDriverPresent", func(name string) map[string]interface{} {
		return winDriverInfo(name)
	})
	vm.Set("winCheckNamedPipe", func(name string) map[string]interface{} {
		exists, errStr := winNamedPipeExists(name)
		res := map[string]interface{}{"exists": exists}
		if errStr != "" {
			res["error"] = errStr
		}
		return res
	})
	vm.Set("winFileVersionInfo", func(path string) map[string]interface{} {
		return winFileVersion(path)
	})
	vm.Set("winSigInfo", func(path string) map[string]interface{} {
		res := winSigInfoWintrust(path)
		if signed, ok := res["signed"].(bool); !ok || !signed {
			// fallback to Powershell for richer error text
			res = winSigInfoCmd(path)
		}
		if _, ok := res["timestamp"]; !ok {
			res["timestamp"] = time.Now()
		}
		return res
	})
}
