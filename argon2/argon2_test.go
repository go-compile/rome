package argon2_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/go-compile/rome/argon2"
)

func TestArgon2ID(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	h := argon2.ID(salt)
	h.Write([]byte("12345"))
	h.Write([]byte("....."))

	result1 := h.Sum(nil)

	h2 := argon2.ID(salt)
	h2.Write([]byte("12345"))
	h2.Write([]byte("....."))

	if !bytes.Equal(result1, h2.Sum(nil)) {
		t.Fatal("hashes don't match")
	}
}

func ExampleArgon2ID() {
	// import "github.com/go-compile/rome/argon2"
	// import "crypto/rand"

	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	h := argon2.ID(salt)
	h.Write([]byte("12345"))
	h.Write([]byte("....."))

	digest := h.Sum(nil)
	fmt.Printf("%x\n", digest)
}
