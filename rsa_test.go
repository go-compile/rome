package rome_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-compile/rome"
)

func TestParsePrivateKeyRSA(t *testing.T) {
	key, err := rome.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}

	p, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := rome.ParseRSAPrivate(p)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(priv.PrivateRaw(), key.PrivateRaw()) || !bytes.Equal(priv.Public().Fingerprint(sha256.New()), key.Public().Fingerprint(sha256.New())) {
		t.Fatal("keys don't match")
	}
}
