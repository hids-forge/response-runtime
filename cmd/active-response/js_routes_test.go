package main

import (
	"strings"
	"testing"
)

func TestParseIPRouteJSON(t *testing.T) {
	jsonStr := `[{"dst":"default","gateway":"192.168.0.1","dev":"eth0","protocol":"dhcp","metric":100,"family":2}]`
	out := parseIPRouteJSON([]byte(jsonStr))
	if len(out) != 1 || out[0].Gateway != "192.168.0.1" || out[0].Dev != "eth0" || out[0].Family != "inet" {
		t.Fatalf("unexpected route parse: %+v", out)
	}
}

func TestParseNetstatRoute(t *testing.T) {
	lines := strings.Split(`Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.0.1     0.0.0.0         UG        0 0          0 eth0
`, "\n")
	out := parseNetstatRoute(lines)
	if len(out) == 0 || out[0].Gateway != "192.168.0.1" || out[0].Dev != "eth0" {
		t.Fatalf("unexpected netstat parse: %+v", out)
	}
}
