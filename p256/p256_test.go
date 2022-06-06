package p256_test

import (
	"bytes"
	"testing"

	"github.com/go-compile/rome/nist"
	"github.com/go-compile/rome/p256"
)

func TestParsePrivateKeyP256(t *testing.T) {
	key, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := nist.ParsePrivate(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := priv.Public().Points()
	x1, y1 := key.Public().Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}
