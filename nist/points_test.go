package nist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestParsePoints(t *testing.T) {
	key, err := generate()
	if err != nil {
		t.Fatal(err)
	}

	x, y := key.Public().Points()

	// compare pointers and make sure they don't match
	if &key.ecdsa.X == &x || &key.ecdsa.Y == &y {
		t.Fatal("curve points did not clone")
	}
}

// Generate will create a new nist-P521 elliptic curve public/private key pair
func generate() (*Key, error) {
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

	return NewCurve(private), nil
}
