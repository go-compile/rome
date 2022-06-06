package rome

import (
	"crypto/ecdsa"
	"crypto/rand"
)

// Sign will take a digest and use the private key to sign it
func (k *ECKey) Sign(digest []byte) ([]byte, error) {
	// using go's ECDSA tried and tested implementation for
	// security and performance
	return ecdsa.SignASN1(rand.Reader, k.ecdsa, digest)
}

// Verify will take a ASN.1 signature and return true if it's valid
func (k *ECPublicKey) Verify(digest []byte, signature []byte) (bool, error) {
	return ecdsa.VerifyASN1(k.ecdsa, digest, signature), nil
}
