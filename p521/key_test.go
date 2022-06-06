package p521_test

import (
	"fmt"
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

	fmt.Println(pub1)
}
