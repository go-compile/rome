package main

import (
	"fmt"

	"github.com/go-compile/rome/p256"
	"github.com/go-compile/rome/ssh"
)

func main() {
	// Generate a nist P256 Elliptic Curve
	k, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	sshPub, sshAuthorisedKey, err := ssh.ToMarshaledKey(k.Public())
	if err != nil {
		panic(err)
	}

	fmt.Printf("Authorised Key: %s", sshAuthorisedKey)
	fmt.Printf("Key Len: %X\n", len(sshPub))
}
