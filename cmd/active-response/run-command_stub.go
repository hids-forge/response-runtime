//go:build !unsafe_features

package main

import "github.com/hids-forge/response-runtime/pkg/helper"

func handleRunCommand(payload helper.Payload) {
	_ = payload
	sendBackResponse([]byte("run-command disabled: unsafe features are not enabled in this build"))
}
