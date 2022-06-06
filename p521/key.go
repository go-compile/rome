package p521

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/go-compile/rome"
)

// Key is a nist-P521 Elliptic Curve
type Key struct {
	priv []byte

	ecdsa *ecdsa.PrivateKey

	Public *PublicKey
}

// PublicKey holds the X and Y parameters for the key
type PublicKey struct {
	ecdsa *ecdsa.PublicKey
}

// Generate will create a new nist-P521 elliptic curve public/private key pair
func Generate() (*Key, error) {
	priv, x, y, err := elliptic.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}

	pub := ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     x,
		Y:     y,
	}

	return &Key{priv: priv, ecdsa: &ecdsa.PrivateKey{
		D:         new(big.Int).SetBytes(priv),
		PublicKey: pub,
	},
		Public: &PublicKey{ecdsa: &pub},
	}, nil
}

// Sign will take a digest and use the private key to sign it
func (k *Key) Sign(digest []byte) ([]byte, error) {
	// using go's ECDSA tried and tested implementation for
	// security and performance
	return ecdsa.SignASN1(rand.Reader, k.ecdsa, digest)
}

// Private will return the private key as PEM ASN.1 DER bytes
func (k *Key) Private() ([]byte, error) {
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
func (k *Key) PrivateASN1() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Public returns the public key in PEM ASN.1 DER format
func (k *PublicKey) Public() ([]byte, error) {
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

// PublicASN1 returns the public key formatted in ASN.1
func (k *PublicKey) PublicASN1() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Points returns the Elliptic Curve coordinates
func (k *PublicKey) Points() (x *big.Int, y *big.Int) {
	// clone X & Y
	x = &*k.ecdsa.X
	y = &*k.ecdsa.Y

	return x, y
}

// Verify will take a ASN.1 signature and return true if it's valid
func (k *PublicKey) Verify(digest []byte, signature []byte) (bool, error) {
	return ecdsa.VerifyASN1(k.ecdsa, digest, signature), nil
}

// ParsePublic will read a nist-P521 public key from PEM ASN.1 DER format
func ParsePublic(public []byte) (*PublicKey, error) {
	b, _ := pem.Decode(public)
	if b.Type != "EC PUBLIC KEY" {
		return nil, rome.ErrWrongKey
	}

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsa, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	return &PublicKey{
		ecdsa: ecdsa,
	}, nil
}

// ParsePublicASN1 will read a nist-P521 public key from ASN.1 DER format
func ParsePublicASN1(der []byte) (*PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	ecdsa, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	return &PublicKey{
		ecdsa: ecdsa,
	}, nil
}

// ParsePrivate will read a PEM ASN.1 DER encoded P521 key
func ParsePrivate(private []byte) (*Key, error) {
	b, _ := pem.Decode(private)
	if b.Type != "EC PRIVATE KEY" {
		return nil, rome.ErrWrongKey
	}

	priv, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return &Key{
		ecdsa: priv,
		priv:  priv.D.Bytes(),
	}, nil
}
