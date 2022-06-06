package nist_test

import (
	"bytes"
	"testing"

	"github.com/go-compile/rome/nist"
)

func TestParsePublicKey(t *testing.T) {
	key, err := generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	pub1, err := nist.ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := pub1.Points()
	x1, y1 := key.Public().Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}

func TestParseASN1PublicKey(t *testing.T) {
	key, err := generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Public().KeyASN1()
	if err != nil {
		t.Fatal(err)
	}

	pub1, err := nist.ParsePublicASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := pub1.Points()
	x1, y1 := key.Public().Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}

func TestParsePrivateKey(t *testing.T) {
	key, err := generate()
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

func TestParseASN1PrivateKey(t *testing.T) {
	key, err := generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.PrivateASN1()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := nist.ParsePrivateASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := priv.Public().Points()
	x1, y1 := key.Public().Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}
