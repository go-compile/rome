package ed448

import (
	"crypto/rand"

	"github.com/cloudflare/circl/sign/ed448"
)

// Generate will create a new Ed25519 edward curve public/private key pair
func Generate() (*EdKey, error) {

	pub, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &EdKey{
		pub:  pub,
		priv: priv,
	}, nil
}
