package parse

import (
	"crypto/ecdsa"
	stdEd25519 "crypto/ed25519"
	"encoding/pem"
	"strings"

	circlx448 "github.com/cloudflare/circl/sign/ed448"
	"github.com/go-compile/rome"
	"github.com/go-compile/rome/derbytes"
	"github.com/go-compile/rome/ed25519"
	"github.com/go-compile/rome/ed448"
)

// Public takes input as a PEM encoded ASN.1 DER bytes public key
func Public(pemPub []byte) (rome.PublicKey, error) {
	p, _ := pem.Decode(pemPub)
	if p == nil {
		return nil, rome.ErrInvalidPem
	}

	switch strings.ToUpper(p.Type) {
	case "EC PUBLIC KEY":
		return rome.ParseECPublicASN1(p.Bytes)
	case "ED PUBLIC KEY":
		pub, err := derbytes.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, err
		}

		switch x := pub.(type) {
		case circlx448.PublicKey:
			return ed448.PublicFrom(x), nil
		case stdEd25519.PublicKey:
			return ed25519.PublicFrom(x), nil
		}
	}

	return nil, rome.ErrWrongKey
}

// PublicASN1 takes input as a ASN.1 DER bytes public key
func PublicASN1(derBytes []byte) (rome.PublicKey, error) {
	pub, err := derbytes.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, err
	}

	switch x := pub.(type) {
	case circlx448.PublicKey:
		return ed448.PublicFrom(x), nil
	case stdEd25519.PublicKey:
		return ed25519.PublicFrom(x), nil
	case *ecdsa.PublicKey:
		return rome.ParseECPublicASN1(derBytes)
	}

	return nil, rome.ErrWrongKey
}
