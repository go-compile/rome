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

func TestPemParseP521(t *testing.T) {
	k, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Public(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseEd25519(t *testing.T) {
	k, err := ed25519.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Public(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseEd448(t *testing.T) {
	k, err := ed448.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Public(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseBrainpoolP256r1(t *testing.T) {
	k, err := brainpool.GenerateP256r1()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.Public(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseP521ASN1(t *testing.T) {
	k, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PublicASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseEd25519ASN1(t *testing.T) {
	k, err := ed25519.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PublicASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseEd448ASN1(t *testing.T) {
	k, err := ed448.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PublicASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}

func TestPemParseBrainpoolP256r1ASN1(t *testing.T) {
	k, err := brainpool.GenerateP256r1()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := k.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := parse.PublicASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk.Fingerprint(sha256.New()), k.Public().Fingerprint(sha256.New())) {
		t.Fatal("fingerprint does not match")
	}
}
