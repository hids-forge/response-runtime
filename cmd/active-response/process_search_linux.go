//go:build !windows && !darwin

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func processSearchTextLinux(pid int64, needle string, maxTotal int, maxHits int, caseInsensitive bool) (map[string]interface{}, error) {
	needleB := []byte(needle)
	if len(needleB) == 0 {
		return nil, fmt.Errorf("needle cannot be empty")
	}
	if caseInsensitive {
		needleB = []byte(strings.ToLower(needle))
	}
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	mapsFile, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer mapsFile.Close()
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, err
	}
	defer memFile.Close()

	type region struct {
		start, end int64
		perms      string
	}
	var regions []region
	sc := bufio.NewScanner(mapsFile)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addrs := strings.Split(fields[0], "-")
		if len(addrs) != 2 {
			continue
		}
		start, err1 := strconv.ParseInt(addrs[0], 16, 64)
		end, err2 := strconv.ParseInt(addrs[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		perms := fields[1]
		if !strings.Contains(perms, "r") {
			continue
		}
		regions = append(regions, region{start: start, end: end, perms: perms})
	}
	var hits []map[string]interface{}
	totalRead := 0
	buf := make([]byte, 4096)
	for _, r := range regions {
		if totalRead >= maxTotal || len(hits) >= maxHits {
			break
		}
		segSize := r.end - r.start
		if segSize <= 0 {
			continue
		}
		if segSize > int64(maxTotal-totalRead) {
			segSize = int64(maxTotal - totalRead)
		}
		section := io.NewSectionReader(memFile, r.start, segSize)
		readBytes, err := io.ReadFull(section, buf[:min(len(buf), int(segSize))])
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			continue
		}
		data := buf[:readBytes]
		if caseInsensitive {
			data = []byte(strings.ToLower(string(data)))
		}
		idx := bytes.Index(data, needleB)
		if idx != -1 {
			hits = append(hits, map[string]interface{}{
				"address": fmt.Sprintf("0x%x", r.start+int64(idx)),
				"perms":   r.perms,
				"match":   needle,
			})
		}
		totalRead += readBytes
		if len(hits) >= maxHits {
			break
		}
	}
	return map[string]interface{}{"hits": hits, "totalRead": totalRead}, nil
}
