package main

import (
	"crypto/sha256"
	"encoding/pem"
	"os"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p256"
)

func main() {
	// Generate a nist P256 Elliptic Curve
	k, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	pub := k.Public()

	msg := []byte("Secret message.")

	// encrypt message using AES256_GCM with SHA256 and a 128bit nonce
	ciphertext, err := pub.Encrypt(msg, rome.CipherAES_GCM, sha256.New())
	if err != nil {
		panic(err)
	}

	// Encode in PEM format (not required, but human readable)
	pem.Encode(os.Stdout, &pem.Block{
		Type: "ECIES MESSAGE",
		Headers: map[string]string{
			"kdf":    "sha256",
			"cipher": "AES_GCM",
		},
		Bytes: ciphertext,
	})
}
