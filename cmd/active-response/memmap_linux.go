//go:build linux

package main

import "github.com/shirou/gopsutil/v4/process"

// memoryMapToMap converts gopsutil MemoryMapsStat to a map; linux implementation.
func memoryMapToMap(m process.MemoryMapsStat) (map[string]interface{}, bool) {
	return map[string]interface{}{
		"path":         m.Path,
		"rss":          m.Rss,
		"size":         m.Size,
		"pss":          m.Pss,
		"sharedClean":  m.SharedClean,
		"sharedDirty":  m.SharedDirty,
		"privateClean": m.PrivateClean,
		"privateDirty": m.PrivateDirty,
		"swap":         m.Swap,
	}, true
}
