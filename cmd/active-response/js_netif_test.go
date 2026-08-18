package main

import (
	"strings"
	"testing"
)

func TestParseIPAddrJSON(t *testing.T) {
	jsonStr := `[{"ifindex":1,"ifname":"lo","mtu":65536,"flags":["LOOPBACK"],"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}],"address":"00:00:00:00:00:00"}]`
	out := parseIPAddrJSON([]byte(jsonStr))
	if len(out) != 1 || out[0].Name != "lo" || out[0].Addr != "127.0.0.1" {
		t.Fatalf("unexpected parse: %+v", out)
	}
}

func TestParseIfconfig(t *testing.T) {
	lines := strings.Split(`lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 65536
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128 
	ether aa:bb:cc:dd:ee:ff
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255
	ether 11:22:33:44:55:66
`, "\n")
	out := parseIfconfig(lines)
	if len(out) == 0 || out[0].Name != "lo0" || out[0].Addr != "127.0.0.1" {
		t.Fatalf("unexpected parse length or first entry: %+v", out)
	}
	found := false
	for _, ni := range out {
		if ni.Name == "en0" && ni.Addr == "192.168.0.10" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected en0 entry for 192.168.0.10, got %+v", out)
	}
}

func TestParseIpconfig(t *testing.T) {
	lines := strings.Split(`Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   IPv4 Address. . . . . . . . . . . : 10.0.0.5
`, "\n")
	out := parseIpconfig(lines)
	if len(out) == 0 {
		t.Fatalf("unexpected empty parse")
	}
	foundIP := false
	foundMac := false
	for _, ni := range out {
		if ni.Addr == "10.0.0.5" {
			foundIP = true
		}
		if ni.Mac == "00:11:22:33:44:55" {
			foundMac = true
		}
	}
	if !foundIP || !foundMac {
		t.Fatalf("expected IP and MAC parsed, got %+v", out)
	}
}
