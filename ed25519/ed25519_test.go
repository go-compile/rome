package ed25519_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/go-compile/rome/ed25519"
)

func TestParsePrivateKeyEd25519(t *testing.T) {
	key, err := ed25519.Generate()
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

	priv, err := ed25519.ParseEdPrivate(pubKey, p)
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
	key, err := ed25519.Generate()
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

	p, err := ed25519.ParseEdPublic(pub)
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

func TestKeySize(t *testing.T) {
	key, err := ed25519.Generate()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Private", len(key.PrivateRaw()))
	fmt.Println("Public", len(key.PublicRaw()))
	x, y := key.Public().Points()
	fmt.Println(len(x.Bytes()))
	fmt.Println(len(y.Bytes()))
}
