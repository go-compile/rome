package ed448_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome/ed448"
)

func TestParsePrivateKeyEd448(t *testing.T) {
	key, err := ed448.Generate()
	if err != nil {
		t.Fatal(err)
	}

	p, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := key.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := ed448.ParseEdPrivate(pubKey, p)
	if err != nil {
		t.Fatal(err)
	}

	k1, err := priv.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	k2, err := key.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k1, k2) {
		t.Fatal("keys do not match")
	}
}

func TestParsePubVerify(t *testing.T) {
	key, err := ed448.Generate()
	if err != nil {
		t.Fatal(err)
	}

	m := "This is a important message which must be authenticated."
	h := sha256.New()
	h.Write([]byte(m))
	digest := h.Sum(nil)

	sig, err := key.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	p, err := ed448.ParseEdPublic(pub)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := p.Verify(digest, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("signature was expected to be valid")
	}
}
