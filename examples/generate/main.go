package main

import (
	"fmt"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/ed25519"
	"github.com/go-compile/rome/p224"
	"github.com/go-compile/rome/p256"
	"github.com/go-compile/rome/p384"
	"github.com/go-compile/rome/p521"
)

func main() {
	// Generate a nist P256 Elliptic Curve
	k, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	printKey("P256", k)

	// Generate a nist P224 Elliptic Curve
	k, err = p224.Generate()
	if err != nil {
		panic(err)
	}

	printKey("P224", k)

	// Generate a nist P384 Elliptic Curve
	k, err = p384.Generate()
	if err != nil {
		panic(err)
	}

	printKey("P384", k)

	// Generate a nist P521 Elliptic Curve
	k, err = p521.Generate()
	if err != nil {
		panic(err)
	}

	printKey("P521", k)

	// Generate a nist ed25519 Edwards Curve
	k2, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	printKey("ed25519", k2)
}

func printKey(name string, k rome.PrivateKey) {
	// Format private key using PEM and ASN.1 DER bytes
	private, err := k.Private()
	if err != nil {
		panic(err)
	}

	public, err := k.Public().Key()
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s:\n Private:\n%s\n Public:\n%s\n",
		name, string(private), string(public))
}
