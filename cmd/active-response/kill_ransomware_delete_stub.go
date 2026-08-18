//go:build !unsafe_features

package main

import "fmt"

func removeThreatPath(filePath string) error {
	return fmt.Errorf("file deletion is disabled in this build")
}
