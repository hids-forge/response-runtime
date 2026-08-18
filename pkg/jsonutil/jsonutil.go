package jsonutil

import (
	"encoding/json"
	"io"
)

// Response is a standard wrapper for JSON output.
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// WriteJSON writes v as JSON to w, followed by a newline.
func WriteJSON(w io.Writer, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// WriteJSONSuccess writes a successful Response with the given data.
func WriteJSONSuccess(w io.Writer, data interface{}) error {
	res := Response{Success: true, Data: data}
	return WriteJSON(w, res)
}

// WriteJSONError writes an error Response with the given error message.
func WriteJSONError(w io.Writer, err error) error {
	res := Response{Success: false, Error: err.Error()}
	return WriteJSON(w, res)
}
