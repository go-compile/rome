package p384

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/go-compile/rome"
)

// Generate will create a new nist-P256 elliptic curve public/private key pair
func Generate() (*rome.ECKey, error) {
	d, x, y, err := elliptic.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	private := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(d),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     x,
			Y:     y,
		},
	}

	return rome.NewECCurve(private), nil
}
