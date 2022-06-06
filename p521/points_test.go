package p521

import (
	"testing"
)

func TestParsePoints(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	x, y := key.Public.Points()

	// compare pointers and make sure they don't match
	if &key.ecdsa.X == &x || &key.ecdsa.Y == &y {
		t.Fatal("curve points did not clone")
	}
}
