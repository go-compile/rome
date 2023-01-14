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

// PublicFrom will take the public key bytes and return a EdPublic key
func PublicFrom(p []byte) *EdPublicKey {
	pub := EdPublicKey(p)
	return &pub
}

// PrivateFrom will take the private key bytes and return a EdKey
func PrivateFrom(p []byte) *EdKey {
	return &EdKey{priv: p, pub: ed448.PrivateKey(p).Public().(ed448.PublicKey)}
}
