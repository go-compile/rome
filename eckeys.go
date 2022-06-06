package rome

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

// ECKey is a Elliptic Curve
type ECKey struct {
	priv []byte

	ecdsa *ecdsa.PrivateKey
	pub   *ECPublicKey
}

// ECPublicKey holds the X and Y parameters for the key
type ECPublicKey struct {
	ecdsa *ecdsa.PublicKey
}

// NewECCurve takes a ECDSA key and converts it to a Rome private key
func NewECCurve(priv *ecdsa.PrivateKey) *ECKey {
	return &ECKey{priv: priv.D.Bytes(), ecdsa: priv, pub: &ECPublicKey{
		ecdsa: &priv.PublicKey,
	}}
}

// Public returns the public key interface
func (k *ECKey) Public() PublicKey {
	return k.pub
}

// Sign will take a digest and use the private key to sign it
func (k *ECKey) Sign(digest []byte) ([]byte, error) {
	// using go's ECDSA tried and tested implementation for
	// security and performance
	return ecdsa.SignASN1(rand.Reader, k.ecdsa, digest)
}

// Private will return the private key as PEM ASN.1 DER bytes
func (k *ECKey) Private() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// PrivateASN1 will return the private key as ASN.1 DER bytes
func (k *ECKey) PrivateASN1() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Key returns the public key in PEM ASN.1 DER format
func (k *ECPublicKey) Key() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// KeyASN1 returns the public key formatted in ASN.1
func (k *ECPublicKey) KeyASN1() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Points returns the Elliptic Curve coordinates
func (k *ECPublicKey) Points() (x *big.Int, y *big.Int) {
	// clone X & Y
	x = &*k.ecdsa.X
	y = &*k.ecdsa.Y

	return x, y
}

// Verify will take a ASN.1 signature and return true if it's valid
func (k *ECPublicKey) Verify(digest []byte, signature []byte) (bool, error) {
	return ecdsa.VerifyASN1(k.ecdsa, digest, signature), nil
}

// ParsePublic will read elliptic curve public key from PEM ASN.1 DER format
func ParsePublic(public []byte) (*ECPublicKey, error) {
	b, _ := pem.Decode(public)
	if b.Type != "EC PUBLIC KEY" {
		return nil, ErrWrongKey
	}

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsa, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrWrongKey
	}

	return &ECPublicKey{
		ecdsa: ecdsa,
	}, nil
}

// ParsePublicASN1 will read a elliptic curve public key from ASN.1 DER format
func ParsePublicASN1(der []byte) (*ECPublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	ecdsa, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrWrongKey
	}

	return &ECPublicKey{
		ecdsa: ecdsa,
	}, nil
}

// ParsePrivate will read a PEM ASN.1 DER encoded key
func ParsePrivate(private []byte) (*ECKey, error) {
	b, _ := pem.Decode(private)
	if b.Type != "EC PRIVATE KEY" {
		return nil, ErrWrongKey
	}

	priv, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return &ECKey{
		ecdsa: priv,
		pub: &ECPublicKey{
			ecdsa: &priv.PublicKey,
		},
		priv: priv.D.Bytes(),
	}, nil
}

// ParsePrivateASN1 will read a ASN.1 DER encoded key
func ParsePrivateASN1(private []byte) (*ECKey, error) {
	priv, err := x509.ParseECPrivateKey(private)
	if err != nil {
		return nil, err
	}

	return &ECKey{
		ecdsa: priv,
		pub: &ECPublicKey{
			ecdsa: &priv.PublicKey,
		},
		priv: priv.D.Bytes(),
	}, nil
}
