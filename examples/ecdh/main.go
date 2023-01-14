package main

import (
	"fmt"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p256"
	"golang.org/x/crypto/sha3"
)

var bobPrivate rome.PrivateKey

func main() {
	// Both Alice and Bob are separated in this code example,
	// illustrating that Alice only needs Bob's public key and
	// Bob only needs Alice's public key plus their own private
	// keys to generate the same shared secret.
	alice()
}

func bobGenerate() rome.PublicKey {
	// Generate a nist P256 Elliptic Curve
	bob, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	bobPrivate = bob
	return bob.Public()
}

// Alice is the client in this example
func alice() {
	// transfer bob's public key to Alice over a insecure channel
	bobPub := bobGenerate()

	// Generate a ephemeral P256 Elliptic Curve
	// this key will only be used once
	alice, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	// Use SHA3-385 to generate the shared secret.
	// Any hash function can be used to derive a shared secret and
	// it is upto you to pick one.
	secret, err := bobPub.DH(sha3.New384(), alice)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Alice's shared secret: %x\n", secret)

	bob(alice.Public())
}

// Bob is the server
func bob(alicePub rome.PublicKey) {
	secret, err := alicePub.DH(sha3.New384(), bobPrivate)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Bob's shared secret:   %x\n", secret)
}
