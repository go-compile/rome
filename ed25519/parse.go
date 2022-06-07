package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-compile/rome"
)

// ParseEdPublic will read edward curve public key from PEM ASN.1 DER format
func ParseEdPublic(public []byte) (*EdPublicKey, error) {
	b, _ := pem.Decode(public)
	if b.Type != "ED PUBLIC KEY" {
		return nil, rome.ErrWrongKey
	}

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	key := EdPublicKey(p)
	return &key, nil
}

// ParseECPublicASN1 will read a edward curve public key from ASN.1 DER format
func ParseECPublicASN1(der []byte) (*EdPublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	key := EdPublicKey(p)
	return &key, nil
}

// ParseEdPrivate will read a PEM ASN.1 DER encoded key
func ParseEdPrivate(public, private []byte) (*EdKey, error) {
	b, _ := pem.Decode(private)
	if b.Type != "ED PRIVATE KEY" {
		return nil, rome.ErrWrongKey
	}

	priv, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	p, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	b, _ = pem.Decode(public)
	// TODO: check if block is nil and return invalid pem error
	if b.Type != "ED PUBLIC KEY" {
		return nil, rome.ErrWrongKey
	}

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	pk, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	return &EdKey{
		priv: p,
		pub:  pk,
	}, nil
}

// ParseEdPrivateASN1 will read a ASN.1 DER encoded key
func ParseEdPrivateASN1(public, private []byte) (*EdKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}

	p, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	pub, err := x509.ParsePKCS8PrivateKey(public)
	if err != nil {
		return nil, err
	}

	pk, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	return &EdKey{
		priv: p,
		pub:  pk,
	}, nil
}