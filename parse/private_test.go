package parse_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome/brainpool"
	"github.com/go-compile/rome/ed25519"
	"github.com/go-compile/rome/ed448"
	"github.com/go-compile/rome/p521"
	"github.com/go-compile/rome/parse"
)

func TestPrivatePemParseP521(t *testing.T) {
	k, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.Private()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Private(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivatePemParseEd25519(t *testing.T) {
	k, err := ed25519.Generate()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.Private()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Private(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivatePemParseEd448(t *testing.T) {
	k, err := ed448.Generate()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.Private()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Private(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivatePemParseBrainpoolP256r1(t *testing.T) {
	k, err := brainpool.GenerateP256r1()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.Private()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Private(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivateASN1ParseP521(t *testing.T) {
	k, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.PrivateASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PrivateASN1(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivateASN1ParseEd25519(t *testing.T) {
	k, err := ed25519.Generate()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.PrivateASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PrivateASN1(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivateASN1ParseEd448(t *testing.T) {
	k, err := ed448.Generate()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.PrivateASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PrivateASN1(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPrivateASN1ParseBrainpoolP256r1(t *testing.T) {
	k, err := brainpool.GenerateP256r1()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := k.PrivateASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PrivateASN1(priv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Public().Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}
