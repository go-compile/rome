package rome_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome/p224"
	"github.com/go-compile/rome/p256"
	"github.com/go-compile/rome/p384"
)

func TestP256ECDH(t *testing.T) {
	alice, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	bob, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	a := alice.Public()
	b := bob.Public()
	// START OF BOB'S VIEW

	// generate ephemeral Bob's key
	secret, err := a.DH(sha256.New(), bob)
	if err != nil {
		t.Fatal(err)
	}

	// END OF BOB'S VIEW

	// START OF ALICE'S VIEW

	// perform same ECDH
	secret2, err := b.DH(sha256.New(), alice)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, secret2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestP224ECDH(t *testing.T) {
	alice, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	bob, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	a := alice.Public()
	b := bob.Public()
	// START OF BOB'S VIEW

	// generate ephemeral Bob's key
	secret, err := a.DH(sha256.New(), bob)
	if err != nil {
		t.Fatal(err)
	}

	// END OF BOB'S VIEW

	// START OF ALICE'S VIEW

	// perform same ECDH
	secret2, err := b.DH(sha256.New(), alice)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, secret2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestP384ECDH(t *testing.T) {
	alice, err := p384.Generate()
	if err != nil {
		t.Fatal(err)
	}

	bob, err := p384.Generate()
	if err != nil {
		t.Fatal(err)
	}

	a := alice.Public()
	b := bob.Public()
	// START OF BOB'S VIEW

	// generate ephemeral Bob's key
	secret, err := a.DH(sha256.New(), bob)
	if err != nil {
		t.Fatal(err)
	}

	// END OF BOB'S VIEW

	// START OF ALICE'S VIEW

	// perform same ECDH
	secret2, err := b.DH(sha256.New(), alice)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, secret2) {
		t.Fatal("shared secrets do not match")
	}
}
