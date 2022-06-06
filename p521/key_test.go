package p521_test

import (
	"bytes"
	"testing"

	"github.com/go-compile/rome/p521"
)

func TestParsePublicKey(t *testing.T) {
	key, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Public.Public()
	if err != nil {
		t.Fatal(err)
	}

	pub1, err := p521.ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := pub1.Points()
	x1, y1 := key.Public.Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}

func TestParseASN1PublicKey(t *testing.T) {
	key, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Public.PublicASN1()
	if err != nil {
		t.Fatal(err)
	}

	pub1, err := p521.ParsePublicASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := pub1.Points()
	x1, y1 := key.Public.Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}

func TestParseASN1PrivateKey(t *testing.T) {
	key, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.PrivateASN1()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := p521.ParsePrivateASN1(pub)
	if err != nil {
		t.Fatal(err)
	}

	x, y := priv.Public.Points()
	x1, y1 := key.Public.Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}
