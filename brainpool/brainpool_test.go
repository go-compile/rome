package brainpool_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/go-compile/rome"

	"github.com/go-compile/rome/brainpool"
)

func TestP160r1(t *testing.T) {
	key, err := brainpool.GenerateP160r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP160t1(t *testing.T) {
	key, err := brainpool.GenerateP160t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP192r1(t *testing.T) {
	key, err := brainpool.GenerateP192r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP192t1(t *testing.T) {
	key, err := brainpool.GenerateP192t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP224r1(t *testing.T) {
	key, err := brainpool.GenerateP224r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP224t1(t *testing.T) {
	key, err := brainpool.GenerateP224t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP256r1(t *testing.T) {
	key, err := brainpool.GenerateP256r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP256t1(t *testing.T) {
	key, err := brainpool.GenerateP256t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP320r1(t *testing.T) {
	key, err := brainpool.GenerateP320r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP320t1(t *testing.T) {
	key, err := brainpool.GenerateP320t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP384r1(t *testing.T) {
	key, err := brainpool.GenerateP384r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP384t1(t *testing.T) {
	key, err := brainpool.GenerateP384t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP512r1(t *testing.T) {
	key, err := brainpool.GenerateP512r1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func TestP512t1(t *testing.T) {
	key, err := brainpool.GenerateP512t1()
	if err != nil {
		t.Fatal(err)
	}

	parsePrivateKey(t, key)
	parsePubVerify(t, key)
	ECIES(t, key)
}

func parsePrivateKey(t *testing.T, key rome.PrivateKey) {
	p, err := key.Private()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := rome.ParseECPrivate(p)
	if err != nil {
		t.Fatal(err)
	}

	x, y := priv.Public().Points()
	x1, y1 := key.Public().Points()

	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("points don't match")
	}
}

func parsePubVerify(t *testing.T, key rome.PrivateKey) {
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

	p, err := rome.ParseECPublic(pub)
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

func ECIES(t *testing.T, key rome.PrivateKey) {
	m := []byte("secret message.")

	ciphertext, err := key.Public().Encrypt(m, rome.CipherAES_GCM, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := key.Decrypt(ciphertext, rome.CipherAES_GCM, sha256.New())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(m, plaintext) {
		t.Fatal("plain text does not match")
	}
}

func ExampleGenerateP512t1() {
	key, err := brainpool.GenerateP512t1()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Curve: %s\n", key.Public().Name())
	// Output: Curve: P512t1
}

func ExampleGenerateP512r1() {
	key, err := brainpool.GenerateP512r1()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Curve: %s\n", key.Public().Name())
	// Output: Curve: P512r1
}

func ExampleGenerateP160r1() {
	key, err := brainpool.GenerateP160r1()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Curve: %s\n", key.Public().Name())
	// Output: Curve: P160r1
}

func ExampleGenerateP224r1() {
	key, err := brainpool.GenerateP224r1()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Curve: %s\n", key.Public().Name())
	// Output: Curve: P224r1
}

func ExampleGenerateP192r1() {
	key, err := brainpool.GenerateP192r1()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Curve: %s\n", key.Public().Name())
	// Output: Curve: P192r1
}
