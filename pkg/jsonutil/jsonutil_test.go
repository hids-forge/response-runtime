package jsonutil

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	buf := new(bytes.Buffer)
	err := WriteJSON(buf, map[string]string{"foo": "bar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"foo":"bar"`) {
		t.Errorf("unexpected output: %s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output not newline-terminated: %s", out)
	}
}

func TestWriteJSONSuccess(t *testing.T) {
	buf := new(bytes.Buffer)
	data := []int{1, 2, 3}
	if err := WriteJSONSuccess(buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"success":true`) {
		t.Errorf("expected success:true, got %s", out)
	}
	if !strings.Contains(out, `"data":[1,2,3]`) {
		t.Errorf("expected data field, got %s", out)
	}
}

func TestWriteJSONError(t *testing.T) {
	buf := new(bytes.Buffer)
	errMsg := "fail"
	if err := WriteJSONError(buf, errors.New(errMsg)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"success":false`) {
		t.Errorf("expected success:false, got %s", out)
	}
	if !strings.Contains(out, `"error":"fail"`) {
		t.Errorf("expected error field, got %s", out)
	}
}
