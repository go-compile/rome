package rome_test

import (
	"testing"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p521"
)

func TestECDSAP521(t *testing.T) {
	key, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var priv rome.PrivateKey
	priv = key

	_, err = priv.Public().Key()
	if err != nil {
		t.Fatal(err)
	}
}
