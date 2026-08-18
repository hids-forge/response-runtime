package main

import "testing"

func TestParseHostsContent(t *testing.T) {
	data := `
# comment
127.0.0.1 localhost # loopback
10.0.0.1 host1 host1.local;note
; ignored
`
	res := parseHostsContent(data, 10)
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res))
	}
	if res[0]["ip"] != "127.0.0.1" || res[0]["comment"] != "loopback" {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
	if res[1]["ip"] != "10.0.0.1" || res[1]["comment"] != "note" {
		t.Fatalf("unexpected second entry: %+v", res[1])
	}
}
