package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/argon2"
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

	encryptArgon2()
}

// Argon2 encrypt example
func encryptArgon2() {
	// Generate a nist P256 Elliptic Curve
	k, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	pub := k.Public()

	msg := []byte("Secret message.")

	// generate salt for Argon2
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		panic(err)
	}

	// encrypt message using AES256_GCM with ARGON2id and a 94bit nonce
	ciphertext, err := pub.Encrypt(msg, rome.CipherAES_GCM, argon2.ID(salt))
	if err != nil {
		panic(err)
	}

	ciphertext = append(salt, ciphertext...)

	fmt.Printf("AES256_GCM_Argon2 Ciphertext: %X\n", ciphertext)
	decryptArgon2(k, ciphertext)
}

func decryptArgon2(k rome.PrivateKey, ciphertext []byte) {
	salt := ciphertext[:16]

	plaintext, err := k.Decrypt(ciphertext[16:], rome.CipherAES_GCM, argon2.ID(salt))
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Plaintext:", string(plaintext))
}
