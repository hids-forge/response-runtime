//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWintrust         = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust  = modWintrust.NewProc("WinVerifyTrust")
	wintrustActionGUID  = windows.GUID{Data1: 0xaac56b, Data2: 0xcd44, Data3: 0x11d0, Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
	wtUIChoiceNone      = uint32(2)
	wtRevocationNone    = uint32(0)
	wtChoiceFile        = uint32(1)
	wtStateActionVerify = uint32(0x00000001)
	wtStateActionClose  = uint32(0x00000002)
	wtProvFlagSafer     = uint32(0x00000100) // WTD_SAFER_FLAG
	wtProvFlagRevNone   = uint32(0x00000010) // WTD_REVOCATION_CHECK_NONE
	wtProvFlagCacheOnly = uint32(0x00000020) // WTD_CACHE_ONLY_URL_RETRIEVAL
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               uintptr
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
}

func winSigInfoWintrust(path string) map[string]interface{} {
	res := map[string]interface{}{"signed": false}
	if path == "" {
		res["error"] = "empty path"
		return res
	}
	utfPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		res["error"] = err.Error()
		return res
	}
	finfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: utfPath,
		hFile:         0,
	}
	data := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtUIChoiceNone,
		fdwRevocationChecks: wtRevocationNone,
		dwUnionChoice:       wtChoiceFile,
		pFile:               uintptr(unsafe.Pointer(&finfo)),
		dwStateAction:       wtStateActionVerify,
		dwProvFlags:         wtProvFlagRevNone | wtProvFlagCacheOnly | wtProvFlagSafer,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&wintrustActionGUID)),
		uintptr(unsafe.Pointer(&data)),
	)
	// Always close state data to avoid leaks.
	data.dwStateAction = wtStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&wintrustActionGUID)), uintptr(unsafe.Pointer(&data)))

	if ret == 0 {
		res["signed"] = true
		res["status"] = 0
		return res
	}
	res["signed"] = false
	res["status"] = ret
	if ret != 0 {
		res["error"] = fmt.Sprintf("WinVerifyTrust status 0x%x (%s)", ret, windows.Errno(ret).Error())
	}
	return res
}
