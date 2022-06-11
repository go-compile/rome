package ed25519

import (
	"crypto/rand"

	"crypto/ed25519"
)

// Generate will create a new Ed25519 edward curve public/private key pair
func Generate() (*EdKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &EdKey{pub: pub, priv: priv}, nil
}

// PublicFrom will take the public key bytes and return a EdPublic key
func PublicFrom(p []byte) *EdPublicKey {
	pub := EdPublicKey(p)
	return &pub
}

// PrivateFrom will take the private key bytes and return a EdKey
func PrivateFrom(p []byte) *EdKey {
	return &EdKey{priv: p, pub: ed25519.PrivateKey(p).Public().([]byte)}
}
