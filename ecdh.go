package rome

import (
	"hash"
)

// DH calculates a ECDH using your specified hash function for
// key generation
func (k *ECPublicKey) DH(hash hash.Hash, g PrivateKey) ([]byte, error) {

	// calculate shared secret
	x, y := k.ecdsa.ScalarMult(k.ecdsa.X, k.ecdsa.Y, g.PrivateRaw())

	// generate shared secret
	hash.Write(append(x.Bytes(), y.Bytes()...))
	secret := hash.Sum(nil)

	return secret, nil
}
