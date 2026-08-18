package main

import (
	"strings"
	"testing"
)

func TestParsePingOutputUnix(t *testing.T) {
	lines := strings.Split(`PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=11.3 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.9 ms
`, "\n")
	res := parsePingOutput(lines)
	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}
	if res[0].Addr != "8.8.8.8" || res[0].Bytes != 64 || res[0].Seq != 0 || res[0].TTL != 117 {
		t.Fatalf("unexpected first result: %+v", res[0])
	}
	if res[0].TimeMs <= 0 {
		t.Fatalf("expected time > 0")
	}
}

func TestParsePingOutputWindows(t *testing.T) {
	lines := strings.Split(`Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=10ms TTL=115
Reply from 8.8.8.8: bytes=32 time=9ms TTL=115
`, "\n")
	res := parsePingOutput(lines)
	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}
	if res[0].Bytes != 32 || res[0].TTL != 115 || res[0].Addr != "8.8.8.8" {
		t.Fatalf("unexpected first result: %+v", res[0])
	}
	if res[1].TimeMs <= 0 {
		t.Fatalf("expected time > 0")
	}
}
