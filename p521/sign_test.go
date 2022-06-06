package p521_test

import (
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome/p521"
)

func TestSign(t *testing.T) {
	key, err := p521.Generate()
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

	valid, err := key.Public.Verify(digest, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("signature was expected to be valid")
	}
}

func TestSignFail(t *testing.T) {
	key, err := p521.Generate()
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

	// modify digest
	digest[5] = digest[5] + 1

	valid, err := key.Public.Verify(digest, sig)
	if err != nil {
		t.Fatal(err)
	}

	if valid {
		t.Fatal("signature was expected to be invalid")
	}
}
