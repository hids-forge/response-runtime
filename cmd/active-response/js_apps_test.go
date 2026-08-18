package main

import (
	"strings"
	"testing"
)

func TestParseInstalledTabLines(t *testing.T) {
	lines := strings.Split("pkg1\t1.0\npkg-two 2.0\n\n", "\n")
	out := parseInstalledTabLines(lines, "dpkg")
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if out[0].Name != "pkg1" || out[0].Version != "1.0" || out[0].Source != "dpkg" {
		t.Fatalf("unexpected first entry: %+v", out[0])
	}
	if out[1].Name != "pkg-two" || out[1].Version != "2.0" {
		t.Fatalf("unexpected second entry: %+v", out[1])
	}
}
