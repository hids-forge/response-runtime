//go:build windows

package main

import "golang.org/x/sys/windows"

func newSysProcAttr() *windows.SysProcAttr {
	return &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
}
