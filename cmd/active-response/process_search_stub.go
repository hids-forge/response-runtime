//go:build windows || darwin

package main

import "fmt"

func processSearchTextLinux(pid int64, needle string, maxTotal int, maxHits int, caseInsensitive bool) (map[string]interface{}, error) {
	return nil, fmt.Errorf("processSearchText not supported on this platform")
}
