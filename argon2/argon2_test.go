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

func ExampleID() {
	// import "github.com/go-compile/rome/argon2"

	salt := []byte("dangerous-example-salt")
	// Here is a real world example of what you should do instead

	// salt := make([]byte, 16)
	// _, err := rand.Read(salt)
	// if err != nil {
	// 	panic(err)
	// }

	h := argon2.ID(salt)
	h.Write([]byte("12345"))
	h.Write([]byte("....."))

	digest := h.Sum(nil)

	// if your salt isn't constant make sure to prepend it to the
	// digest
	fmt.Printf("%x\n", digest)
	// Output: 9e200b0b4a7eb363be8f314733da18b2e7d9afa552a30e1bf57869786faf4125
}

func ExampleNewID() {
	// import "github.com/go-compile/rome/argon2"

	salt := []byte("dangerous-example-salt")
	// Here is a real world example of what you should do instead

	// salt := make([]byte, 16)
	// _, err := rand.Read(salt)
	// if err != nil {
	// 	panic(err)
	// }

	// specify your own argon2id parameters
	h := argon2.NewID(salt, 1, 20, 1, 64)
	h.Write([]byte("12345"))
	h.Write([]byte("....."))

	digest := h.Sum(nil)

	// if your salt isn't constant make sure to prepend it to the
	// digest
	fmt.Printf("%x\n", digest)
	// Output: 13ecf23484ce58153dc0dbae3a0a1f034596abe353a60f68f9441f39952178adab4c85e14704edf73d4910b7027f7565210c28e00832293cea524fe66a5b9137
}
