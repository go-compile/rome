package rome_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome"
)

func TestParsePrivateKeyRSA(t *testing.T) {
	key, err := rome.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}

	p, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := rome.ParseRSAPrivate(p)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(priv.PrivateRaw(), key.PrivateRaw()) || !bytes.Equal(priv.Public().Fingerprint(sha256.New()), key.Public().Fingerprint(sha256.New())) {
		t.Fatal("keys don't match")
	}
}

func TestRSAEncrypt(t *testing.T) {
	k, err := rome.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.RSAPublic().Encrypt(msg, rome.Cipher(0), sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := k.Decrypt(ciphertext, rome.Cipher(0), sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatal("plain text is not equal")
	}
}

func TestRSAEncryptCipherOptions(t *testing.T) {
	k, err := rome.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	_, err = k.RSAPublic().Encrypt(msg, rome.CipherAES_GCM, sha256.New())
	if err == nil {
		t.Fatal("expected failure")
	}
}

func TestRSADecryptCipherOptions(t *testing.T) {
	k, err := rome.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.RSAPublic().Encrypt(msg, rome.Cipher(0), sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	_, err = k.Decrypt(ciphertext, rome.CipherAES_GCM, sha256.New())
	if err == nil {
		t.Fatal("expected failure")
	}
}
