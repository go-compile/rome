package rome_test

import (
	"fmt"
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

	k, _ := priv.Public().Key()
	fmt.Println(string(k))

}
