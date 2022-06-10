package brainpool

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/ebfe/brainpool"
	"github.com/go-compile/rome"
)

// GenerateP160r will create a new Brainpool P160r elliptic curve public/private key pair
func GenerateP160r() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P160r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}
