package rome_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/go-compile/rome"
)

// Generate will create a new nist-P521 elliptic curve public/private key pair
func generate() (*rome.ECKey, error) {
	d, x, y, err := elliptic.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}

	private := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(d),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     x,
			Y:     y,
		},
	}

	return rome.NewECCurve(private), nil
}
