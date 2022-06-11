package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/go-compile/rome"
)

// ParseEdPublic will read edward curve public key from PEM ASN.1 DER format
func ParseEdPublic(public []byte) (*EdPublicKey, error) {
	b, _ := pem.Decode(public)
	if b == nil {
		return nil, rome.ErrInvalidPem
	}

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

// ParseEdPublicASN1 will read a edward curve public key from ASN.1 DER format
func ParseEdPublicASN1(der []byte) (*EdPublicKey, error) {
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
func ParseEdPrivate(private []byte) (*EdKey, error) {
	b, _ := pem.Decode(private)
	if b == nil {
		return nil, rome.ErrInvalidPem
	}

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

	pub, ok := p.Public().([]byte)
	if !ok {
		return nil, errors.New("could not derive public key")
	}

	return &EdKey{
		priv: p,
		pub:  pub,
	}, nil
}

// ParseEdPrivateASN1 will read a ASN.1 DER encoded key
func ParseEdPrivateASN1(private []byte) (*EdKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}

	p, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	pub, ok := p.Public().([]byte)
	if !ok {
		return nil, errors.New("could not derive public key")
	}

	return &EdKey{
		priv: p,
		pub:  pub,
	}, nil
}
