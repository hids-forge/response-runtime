package main

import "testing"

func TestParseIptablesSave(t *testing.T) {
	out := `-A INPUT -s 1.2.3.4/32 -m comment --comment "response-runtime:BLOCK_1.2.3.4" -j DROP
-A INPUT -s 5.6.7.8/32 -m comment --comment "response-runtime:BLOCK_5.6.7.8" -j DROP`
	ips := parseIptablesSave(out, "comment \"response-runtime:BLOCK_", 10)
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Fatalf("unexpected ips: %v", ips)
	}
}

func TestParseNetshFirewall(t *testing.T) {
	out := `
Rule Name:                            response-runtime:BLOCK_9.9.9.9
    Enabled:                          Yes
Rule Name:                            OtherRule
`
	ips := parseNetshFirewall(out, 5)
	if len(ips) != 1 || ips[0] != "9.9.9.9" {
		t.Fatalf("unexpected ips: %v", ips)
	}
}

func TestParsePfctlTable(t *testing.T) {
	out := "1.1.1.1\n2.2.2.2 3.3.3.3\n"
	ips := parsePfctlTable(out, 10)
	if len(ips) != 3 || ips[2] != "3.3.3.3" {
		t.Fatalf("unexpected pfctl entries: %v", ips)
	}
	ips2 := parsePfctlTable(out, 2)
	if len(ips2) != 2 {
		t.Fatalf("expected limit respected, got %v", ips2)
	}
}
