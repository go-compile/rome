package p256_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome/nist"
	"github.com/go-compile/rome/p256"
)

func TestParsePrivateKeyP256(t *testing.T) {
	key, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	p, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := nist.ParsePrivate(p)
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
	key, err := p256.Generate()
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

	p, err := nist.ParsePublic(pub)
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
