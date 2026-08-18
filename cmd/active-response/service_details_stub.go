//go:build !windows

package main

import "fmt"

func helperWindowsServiceDetails(limit int, maxHashBytes int64) ([]map[string]interface{}, error) {
	return nil, fmt.Errorf("windows service details not available on this platform")
}
