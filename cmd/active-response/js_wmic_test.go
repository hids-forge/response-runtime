package main

import (
	"strings"
	"testing"
)

func TestParseWmicList(t *testing.T) {
	lines := strings.Split(`Caption=CPU0
DeviceID=CPU0

Caption=CPU1
DeviceID=CPU1
`, "\n")
	out := parseWmicList(lines)
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d", len(out))
	}
	if out[0]["Caption"] != "CPU0" || out[1]["DeviceID"] != "CPU1" {
		t.Fatalf("unexpected parsed content: %+v", out)
	}
}
