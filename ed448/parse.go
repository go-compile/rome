package ed448

import (
	"encoding/pem"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/go-compile/rome"
	"github.com/go-compile/rome/derbytes"
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

	pub, err := derbytes.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	p, ok := pub.(ed448.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	key := EdPublicKey(p)
	return &key, nil
}

// ParseEdPublicASN1 will read a edward curve public key from ASN.1 DER format
func ParseEdPublicASN1(der []byte) (*EdPublicKey, error) {
	pub, err := derbytes.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	p, ok := pub.(ed448.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	key := EdPublicKey(p)
	return &key, nil
}

// ParseEdPrivate will read a PEM ASN.1 DER encoded key
func ParseEdPrivate(public, private []byte) (*EdKey, error) {
	b, _ := pem.Decode(private)
	if b == nil {
		return nil, rome.ErrInvalidPem
	}

	if b.Type != "ED PRIVATE KEY" {
		return nil, rome.ErrWrongKey
	}

	priv, err := derbytes.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	p, ok := priv.(ed448.PrivateKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	b, _ = pem.Decode(public)
	if b == nil {
		return nil, rome.ErrInvalidPem
	}

	if b.Type != "ED PUBLIC KEY" {
		return nil, rome.ErrWrongKey
	}

	pub, err := derbytes.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	pk, ok := pub.(ed448.PublicKey)
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
	priv, err := derbytes.ParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}

	p, ok := priv.(ed448.PrivateKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	pub, err := derbytes.ParsePKCS8PrivateKey(public)
	if err != nil {
		return nil, err
	}

	pk, ok := pub.(ed448.PublicKey)
	if !ok {
		return nil, rome.ErrWrongKey
	}

	return &EdKey{
		priv: p,
		pub:  pk,
	}, nil
}
