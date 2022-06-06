package rome_test

import (
	"fmt"
	"testing"

	"github.com/go-compile/rome/p521"
)

func TestECDSAP521(t *testing.T) {
	key, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := key.Public().Key()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s\n", string(pub))
}
