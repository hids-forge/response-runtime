//go:build !linux

package main

import "github.com/shirou/gopsutil/v4/process"

// memoryMapToMap stub for non-Linux platforms.
func memoryMapToMap(m process.MemoryMapsStat) (map[string]interface{}, bool) {
	return nil, false
}
