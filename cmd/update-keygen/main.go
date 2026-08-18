package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	outDir := flag.String("out-dir", "build/update-keys", "directory to write generated update signing keys")
	bits := flag.Int("bits", 4096, "RSA key size")
	prefix := flag.String("prefix", "response-runtime_update", "output filename prefix")
	flag.Parse()

	if *bits < 2048 {
		fmt.Fprintln(os.Stderr, "bits must be >= 2048")
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	priv, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}

	privPath := filepath.Join(*outDir, *prefix+"_private.pem")
	pubPath := filepath.Join(*outDir, *prefix+"_public.pem")

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write private key: %v\n", err)
		os.Exit(1)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal public key: %v\n", err)
		os.Exit(1)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated private key: %s\n", privPath)
	fmt.Printf("Generated public key:  %s\n", pubPath)
	fmt.Println("Do not commit the private key.")
}
