package p224

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/go-compile/rome"
)

// Generate will create a new nist-P224 elliptic curve public/private key pair
func Generate() (*rome.ECKey, error) {
	d, x, y, err := elliptic.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return nil, err
	}

	private := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(d),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P224(),
			X:     x,
			Y:     y,
		},
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(private), nil
}
