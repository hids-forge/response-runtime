package main

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashFileSha1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	data := []byte("hello world")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	h, err := hashFileWith(path, "sha1")
	if err != nil {
		t.Fatalf("hashFileWith error: %v", err)
	}
	expect := sha1.Sum(data)
	if h != hex.EncodeToString(expect[:]) {
		t.Fatalf("unexpected sha1 hash: %s", h)
	}
}

func TestPEInfo(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "hello.go")
	if err := os.WriteFile(src, []byte(`package main
func main() {}
`), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	exe := filepath.Join(dir, "hello.exe")
	cmd := exec.Command("go", "build", "-o", exe, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("skipping peInfo test, windows cross-compile failed: %v: %s", err, out)
	}

	info, err := peInfo(exe)
	if err != nil {
		t.Fatalf("peInfo error: %v", err)
	}
	if info["machine"] != "amd64" {
		t.Fatalf("expected machine amd64, got %v", info["machine"])
	}
	sections, ok := info["sections"].([]map[string]interface{})
	if !ok || len(sections) == 0 {
		t.Fatalf("expected sections slice, got %#v", info["sections"])
	}
	dlls, ok := info["dlls"].([]string)
	if !ok || len(dlls) == 0 {
		t.Fatalf("expected dlls slice, got %#v", info["dlls"])
	}
	foundKernel := false
	for _, d := range dlls {
		if strings.Contains(strings.ToLower(d), "kernel32") {
			foundKernel = true
			break
		}
	}
	if !foundKernel {
		t.Fatalf("expected at least kernel32 dll in imports, got %v", dlls)
	}
	symbols, ok := info["symbols"].([]string)
	if !ok || len(symbols) == 0 {
		t.Fatalf("expected symbols slice, got %#v", info["symbols"])
	}
}
