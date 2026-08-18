package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/nacl/box"
)

// keygenCmd is the parent for key generation subcommands.
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate encryption keys for AES-GCM or NaCl Box",
}

// aesGcmCmd generates a random 256-bit key for AES-GCM (hex encoded).
var aesGcmCmd = &cobra.Command{
	Use:   "aes-gcm",
	Short: "Generate a 256-bit AES-GCM key (hex)",
	RunE: func(cmd *cobra.Command, args []string) error {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(key))
		return nil
	},
}

// naclBoxCmd generates a Curve25519 key pair for NaCl box (base64 encoded).
var naclBoxCmd = &cobra.Command{
	Use:   "nacl-box",
	Short: "Generate a NaCl Curve25519 key pair (base64)",
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Printf("Public Key: %s\n", base64.StdEncoding.EncodeToString(pub[:]))
		fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(priv[:]))
		return nil
	},
}

func init() {
	keygenCmd.AddCommand(aesGcmCmd, naclBoxCmd)
	// rootCmd.AddCommand(keygenCmd)
}
