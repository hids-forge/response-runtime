package main

import (
	"strings"
	"testing"
)

func TestParseTracerouteOutputUnix(t *testing.T) {
	lines := strings.Split(`traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  192.168.0.1 (192.168.0.1)  1.234 ms  1.111 ms  1.002 ms
 2  10.0.0.1 (10.0.0.1)  5.111 ms  5.222 ms  5.333 ms
 3  * * *
`, "\n")
	hops := parseTracerouteOutput(lines)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}
	if hops[0].Hop != 1 || hops[0].IP != "192.168.0.1" || hops[0].Host != "192.168.0.1" {
		t.Fatalf("unexpected hop0: %+v", hops[0])
	}
	if len(hops[0].TimesMs) != 3 {
		t.Fatalf("expected times parsed")
	}
	if hops[2].Host != "" && len(hops[2].TimesMs) != 0 {
		t.Fatalf("expected star hop to be mostly empty: %+v", hops[2])
	}
}

func TestParseTracerouteOutputWindows(t *testing.T) {
	lines := strings.Split(`Tracing route to 8.8.8.8 over a maximum of 30 hops:
  1     1 ms     1 ms     1 ms  192.168.0.1
  2    10 ms    11 ms    12 ms  example.com [93.184.216.34]
  3     *        *        *     Request timed out.
`, "\n")
	hops := parseTracerouteOutput(lines)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}
	if hops[1].IP != "93.184.216.34" || hops[1].Host != "example.com" {
		t.Fatalf("unexpected hop1: %+v", hops[1])
	}
	if len(hops[1].TimesMs) != 3 {
		t.Fatalf("expected times on hop1")
	}
}
