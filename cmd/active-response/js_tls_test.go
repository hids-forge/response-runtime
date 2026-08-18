package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Integration-light: ensure tlsFingerprint handles unreachable hosts without panic.
func TestTlsFingerprintUnreachable(t *testing.T) {
	_, err := tlsFingerprintInternal("127.0.0.1", 1, 500)
	if err == nil {
		t.Fatalf("expected error for unreachable TLS target")
	}
}

// Smoke test for httpFingerprint body hash on a local string via httptest.
func TestHttpFingerprintLocal(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	res, err := httpFingerprintInternal(srv.URL, 1024)
	if err != nil {
		t.Fatalf("httpFingerprint error: %v", err)
	}
	if res["status"] != 200 {
		t.Fatalf("expected 200, got %v", res["status"])
	}
	if hash, ok := res["bodyHash"].(string); !ok || len(hash) == 0 {
		t.Fatalf("expected bodyHash, got %v", res["bodyHash"])
	}
}

// helper to start a small test server.
func newTestServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	})
	srv := httptest.NewServer(handler)
	// avoid leaking goroutines if tests hang
	srv.Config.ReadTimeout = 1 * time.Second
	srv.Config.WriteTimeout = 1 * time.Second
	return srv
}
