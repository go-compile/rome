package rome_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p224"
)

func TestECIES(t *testing.T) {
	k, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.ECPublic().Encrypt(msg, rome.CipherAES_GCM, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := k.Decrypt(ciphertext, rome.CipherAES_GCM, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatal("plain text is not equal")
	}
}
