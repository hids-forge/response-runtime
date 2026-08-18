package main

import (
	"testing"
)

func TestWhoisSummaryHandlesFailure(t *testing.T) {
	_, _ = whoisSummary("invalid.invalid")
}
