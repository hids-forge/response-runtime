//go:build !enable_remote_updates

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func registerUpdateCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(&cobra.Command{
		Use:    "update",
		Short:  "Remote update support is disabled in this build",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("remote update support is disabled in this build")
		},
	})
}
