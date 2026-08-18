package jsonio

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadJSONInput_JSON(t *testing.T) {
	input := `  {"key": "value"}`
	data, isJSON, err := ReadJSONInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isJSON {
		t.Errorf("expected JSON detection, got false")
	}
	if !bytes.HasPrefix(data, []byte(input)) {
		t.Errorf("expected data to match input, got %q", data)
	}
}

func TestReadJSONInput_NonJSON(t *testing.T) {
	input := "not a json"
	data, isJSON, err := ReadJSONInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isJSON {
		t.Errorf("expected non-JSON detection, got true")
	}
	if string(data) != input {
		t.Errorf("expected data to match input, got %q", data)
	}
}
