//go:build !enable_remote_updates

package main

import (
	"github.com/hids-forge/response-runtime/pkg/helper"
)

func handleArUpdater(payload helper.Payload) {
	_ = payload
	sendBackResponse([]byte("ar-updater disabled: remote update support is not enabled in this build"))
}
