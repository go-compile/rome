package rome

import (
	"errors"
	"hash"
	"math/big"
)

var (
	// ErrWrongKey is returned if the key is the wrong type
	ErrWrongKey = errors.New("wrong key type or curve")
	// ErrInvalidPem is returned when invalid PEM data is attempted to be decoded
	ErrInvalidPem = errors.New("invalid PEM data failed to parse")
)

// PrivateKey holds the D point for the curve and the public
// key.
type PrivateKey interface {
	// Sign returns a ASN.1 formatted signature
	Sign(digest []byte) ([]byte, error)
	// Public returns the public key interface
	Public() PublicKey

	// Private returns the private key as PEM ANS.1 DER bytes
	//
	// Example Output:
	//
	// 	-----BEGIN EC PUBLIC KEY-----
	// MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcnk2OsBaHEE1LW40x5ZyRubtyYN0
	// P0lfNYr/J621MzgmHFWUhPXiGiNi5OLsoWkXAWBqoM5JHPI4GJXzrjBjh2gAgve4
	// miuuyibmAF+KgXN8t24pm/Wo2owBTXjTPn2R4kPf8lvkeom3/uM8OQUxx3sn4Gld
	// wnDkkVtMdB42du+DMQw=
	//
	// -----END EC PUBLIC KEY-----
	Private() ([]byte, error)
	// Private returns the private key as ANS.1 DER bytes
	PrivateASN1() ([]byte, error)

	// PrivateRaw if a elliptic or edwards curve the returned bytes will
	// be the value D
	PrivateRaw() []byte

	// Decrypt will take a ECIES encrypted ciphertext and decrypt it using the
	// private key
	Decrypt(ciphertext []byte, cipher Cipher, hash hash.Hash) ([]byte, error)
}

// PublicKey is a Elliptic/Edward curve public key
type PublicKey interface {
	// Name returns the curve name
	Name() string
	// Size returns the key size in bytes
	Size() int
	// Verify will take a ASN.1 signature and return true if it's valid
	Verify(digest []byte, signature []byte) (bool, error)
	// Points returns the Elliptic/Edward Curve coordinates
	Points() (x *big.Int, y *big.Int)
	// Key returns the public key in PEM ASN.1 DER format
	Key() ([]byte, error)
	// KeyASN1 returns the public key formatted in ASN.1
	KeyASN1() ([]byte, error)
	// DH takes a hasher and the ephemeral private key
	DH(h hash.Hash, g PrivateKey) ([]byte, error)
	// Encrypt will uses ECIES to encrypt your message to the public key
	Encrypt(msg []byte, cipher Cipher, hash hash.Hash) ([]byte, error)

	// Fingerprint returns the hashed ASN.1 digest representing this
	// public key. This function will panic if it fails to encode the
	// public key.
	Fingerprint(hash.Hash) []byte
}
