package rome_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
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

func TestECIESHKDF(t *testing.T) {
	k, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.ECPublic().Encrypt(msg, rome.CipherAES_GCM, nil, rome.NewHKDF(sha512.New, 32, nil))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := k.Decrypt(ciphertext, rome.CipherAES_GCM, nil, rome.NewHKDF(sha512.New, 32, nil))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatal("plain text is not equal")
	}
}

func TestECIESModifyLength(t *testing.T) {
	k, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.ECPublic().Encrypt(msg, rome.CipherAES_GCM, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	ciphertext_bak := ciphertext

	for {
		if len(ciphertext) == 0 {
			break
		}

		fmt.Print(".")

		ciphertext = ciphertext[1:]
		_, err := k.Decrypt(ciphertext, rome.CipherAES_GCM, sha256.New())
		if err == nil {
			t.Fatal("input was manipulated but decrypt was falsy a success")
		}
	}

	fmt.Println()
	ciphertext = ciphertext_bak
	for {
		if len(ciphertext) == 0 {
			break
		}

		fmt.Print("+")

		ciphertext = ciphertext[:len(ciphertext)-1]
		_, err := k.Decrypt(ciphertext, rome.CipherAES_GCM, sha256.New())
		if err == nil {
			t.Fatal("input was manipulated but decrypt was falsy a success")
		}
	}
}

func TestECIESModifyLengthChaChaSHA512(t *testing.T) {
	k, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is the secret message 123.")
	ciphertext, err := k.ECPublic().Encrypt(msg, rome.CipherChacha20_SHA512, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	ciphertext_bak := ciphertext

	for {
		if len(ciphertext) == 0 {
			break
		}

		fmt.Print(".")

		ciphertext = ciphertext[1:]
		_, err := k.Decrypt(ciphertext, rome.CipherChacha20_SHA512, sha256.New())
		if err == nil {
			t.Fatal("input was manipulated but decrypt was falsy a success")
		}
	}

	fmt.Println()
	ciphertext = ciphertext_bak
	for {
		if len(ciphertext) == 0 {
			break
		}

		fmt.Print("+")

		ciphertext = ciphertext[:len(ciphertext)-1]
		_, err := k.Decrypt(ciphertext, rome.CipherChacha20_SHA512, sha256.New())
		if err == nil {
			t.Fatal("input was manipulated but decrypt was falsy a success")
		}
	}
}
