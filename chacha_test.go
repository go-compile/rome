package rome_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p224"
)

func TestECIESChaCha(t *testing.T) {
	const cipher = rome.CipherChacha20

	k, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.ECPublic().Encrypt(msg, cipher, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := k.Decrypt(ciphertext, cipher, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatal("plain text is not equal")
	}
}

func TestECIESChaChaSHA256(t *testing.T) {
	const cipher = rome.CipherChacha20_SHA256

	k, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.ECPublic().Encrypt(msg, cipher, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := k.Decrypt(ciphertext, cipher, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatal("plain text is not equal")
	}
}
