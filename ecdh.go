package rome

import (
	"crypto/sha256"
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
)

// DH calculates a ECDH using your specified hash function for
// key generation
func (k *ECPublicKey) DH(hash hash.Hash, g PrivateKey, options ...Option) ([]byte, error) {
	// calculate shared secret
	x, y := k.ecdsa.ScalarMult(k.ecdsa.X, k.ecdsa.Y, g.PrivateRaw())

	// generate shared secret
	for i := range options {
		switch o := options[i].(type) {
		case OptionHKDF:
			kdf := hkdf.New(sha256.New, append(x.Bytes(), y.Bytes()...), o.Salt, nil)

			secret := make([]byte, o.KeySize)
			if _, err := kdf.Read(secret); err != nil {
				return nil, err
			}

			return secret, nil
		default:
			fmt.Printf("%v", o)
		}
	}

	hash.Write(append(x.Bytes(), y.Bytes()...))
	secret := hash.Sum(nil)

	return secret, nil
}
