package rome_test

import (
	"testing"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/ed25519"
)

func TestPadding(t *testing.T) {
	for i := 0; i <= 100; i++ {
		buf := make([]byte, i)
		if len(rome.Pad(buf, 100)) != 100 {
			t.Fatal("length of padded output not 100")
		}
	}
}

func TestKeyPaddingP521(t *testing.T) {
	for i := 1; i <= 500; i++ {
		k, err := generate()
		if err != nil {
			t.Fatal(err)
		}

		if len(k.PrivateRaw()) != k.Public().Size() {
			t.Fatal("private key returned in wrong size compared with curve's stated size")
		}
	}
}

func TestKeyPaddingEd25519(t *testing.T) {
	for i := 1; i <= 500; i++ {
		k, err := ed25519.Generate()
		if err != nil {
			t.Fatal(err)
		}

		if actual := len(k.PrivateRaw()); actual != k.Public().Size() {
			t.Fatalf("private key: %d, expected: %d", actual, k.Public().Size())
		}

		if actual := len(k.PublicRaw()); actual != k.Public().Size() {
			t.Fatalf("private key: %d, expected: %d", actual, k.Public().Size())
		}
	}
}
