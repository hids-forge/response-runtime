//go:build enable_remote_updates

package main

import (
	"github.com/hids-forge/response-runtime/cmd/active-response/internal/updateclient"
	"github.com/spf13/cobra"
)

func registerUpdateCommands(rootCmd *cobra.Command) {
	updateclient.EnableUpdateSubCommand(rootCmd)
}
