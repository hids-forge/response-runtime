package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
)

func TestPidHelpersCurrentProcess(t *testing.T) {
	pid := os.Getpid()
	info, err := getPidStatsHelper(int64(pid))
	if err != nil {
		t.Fatalf("getPidStatsHelper: %v", err)
	}
	if info.Pid != int64(pid) || info.Name == "" {
		t.Fatalf("unexpected info: %+v", info)
	}
	ptp, err := pathToPidHelper(filepath.Base(os.Args[0]))
	if err != nil {
		t.Fatalf("pathToPidHelper: %v", err)
	}
	if len(ptp) == 0 {
		t.Fatalf("expected at least current pid in pathToPidHelper")
	}
}

// helpers to call unexported logic safely in tests
func getPidStatsHelper(pid int64) (*pidStats, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}
	return getPidStats(p)
}

func pathToPidHelper(path string) ([]int64, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		exe, err := p.Exe()
		if err != nil {
			continue
		}
		if matchPathInsensitive(filepath.Base(exe), path) {
			out = append(out, int64(pid))
		}
	}
	return out, nil
}
