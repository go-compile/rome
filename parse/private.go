package parse

import (
	stdEd25519 "crypto/ed25519"
	"encoding/pem"
	"strings"

	circlx448 "github.com/cloudflare/circl/sign/ed448"
	"github.com/go-compile/rome"
	"github.com/go-compile/rome/derbytes"
	"github.com/go-compile/rome/ed25519"
	"github.com/go-compile/rome/ed448"
)

// Private takes input as a PEM encoded ASN.1 DER bytes private key
func Private(pemPub []byte) (rome.PrivateKey, error) {

	p, _ := pem.Decode(pemPub)
	if p == nil {
		return nil, rome.ErrInvalidPem
	}

	switch strings.ToUpper(p.Type) {
	case "EC PRIVATE KEY":
		return rome.ParseECPrivateASN1(p.Bytes)
	case "ED PRIVATE KEY":
		priv, err := derbytes.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			return nil, err
		}

		switch x := priv.(type) {
		case circlx448.PrivateKey:
			return ed448.PrivateFrom(x), nil
		case stdEd25519.PrivateKey:
			return ed25519.PrivateFrom(x), nil
		}
	}

	return nil, rome.ErrWrongKey
}

// PrivateASN1 takes input as a ASN.1 DER bytes private key
func PrivateASN1(derBytes []byte) (rome.PrivateKey, error) {

	priv, err := derbytes.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		if err == derbytes.ErrUseECParseInstead {
			return rome.ParseECPrivateASN1(derBytes)
		}

		return nil, err
	}

	switch x := priv.(type) {
	case circlx448.PrivateKey:
		return ed448.PrivateFrom(x), nil
	case stdEd25519.PrivateKey:
		return ed25519.PrivateFrom(x), nil
	}

	return nil, rome.ErrWrongKey
}
