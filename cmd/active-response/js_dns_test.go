package main

import (
	"errors"
	"net"
	"testing"
)

func TestDnsTraceStructured(t *testing.T) {
	origNS := lookupNS
	origHost := lookupHost
	t.Cleanup(func() {
		lookupNS = origNS
		lookupHost = origHost
	})

	lookupNS = func(name string) ([]*net.NS, error) {
		return []*net.NS{
			{Host: "ns1.example.com."},
			{Host: "ns2.example.com."},
		}, nil
	}
	lookupHost = func(name string) ([]string, error) {
		return []string{"1.1.1.1", "2.2.2.2"}, nil
	}

	out, err := dnsTrace("example.com")
	if err != nil {
		t.Fatalf("dnsTrace error: %v", err)
	}
	if len(out) != 4 { // 2 resolvers * 2 record types
		t.Fatalf("expected 4 entries, got %d", len(out))
	}
	for _, e := range out {
		if e["resolver"] == "" || e["type"] == "" {
			t.Fatalf("missing resolver/type in entry: %+v", e)
		}
		if e["error"] == nil {
			if _, ok := e["records"]; !ok {
				t.Fatalf("expected records field in %+v", e)
			}
		}
	}
}

func TestDnsTraceWithError(t *testing.T) {
	origNS := lookupNS
	origHost := lookupHost
	t.Cleanup(func() {
		lookupNS = origNS
		lookupHost = origHost
	})

	lookupNS = func(name string) ([]*net.NS, error) {
		return nil, errors.New("ns failure")
	}
	lookupHost = func(name string) ([]string, error) {
		return nil, errors.New("lookup failure")
	}

	out, err := dnsTrace("bad.example")
	if err != nil {
		t.Fatalf("dnsTrace error: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected entries even on error")
	}
	for _, e := range out {
		if e["error"] == nil {
			t.Fatalf("expected error field in %+v", e)
		}
	}
}
