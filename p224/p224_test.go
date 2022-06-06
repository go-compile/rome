package p224_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome"

	"github.com/go-compile/rome/p224"
)

func TestParsePrivateKeyP224(t *testing.T) {
	key, err := p224.Generate()
	if err != nil {
		t.Fatal(err)
	}

	p, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := rome.ParsePrivate(p)
	if err != nil {
		t.Fatal(err)
	}

	x, y := priv.Public().Points()
	x1, y1 := key.Public().Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}

func TestParsePubVerify(t *testing.T) {
	key, err := p224.Generate()
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

	p, err := rome.ParsePublic(pub)
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
