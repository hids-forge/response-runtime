package jsonio

import (
	"bytes"
	"io"
	"unicode"
)

// ReadJSONInput reads all data from r, detects if it is JSON (starting with '{' or '[' after trimming whitespace),
// and returns the raw data, a boolean indicating JSON input, and any error.
func ReadJSONInput(r io.Reader) ([]byte, bool, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, false, err
	}
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return data, true, nil
	}
	return data, false, nil
}
