//go:build unsafe_features

package main

import "os"

func removeThreatPath(filePath string) error {
	return os.Remove(filePath)
}
