package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"math/big"

	"github.com/go-compile/rome"
)

// EdKey is a Edwards Curve private key
type EdKey struct {
	pub, priv []byte
}

// EdPublicKey is a Edward Curve public key
type EdPublicKey []byte

// Public returns the public key interface
func (k *EdKey) Public() rome.PublicKey {
	x := EdPublicKey(k.pub)
	return &x
}

// PrivateRaw returns the private bytes D
func (k *EdKey) PrivateRaw() []byte {
	return rome.Pad(k.priv, k.Public().Size())
}

// PublicRaw returns the public key as bytes
func (k *EdKey) PublicRaw() []byte {
	x := make([]byte, len(k.pub))
	copy(x, k.pub)

	return rome.Pad(x, int(k.Public().Size()))
}

// Private will return the private key as PEM ASN.1 DER bytes
func (k *EdKey) Private() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(k.priv))
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "ED PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// PrivateASN1 will return the private key as ASN.1 DER bytes
func (k *EdKey) PrivateASN1() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(k.priv))
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Key returns the public key in PEM ASN.1 DER format
func (k *EdPublicKey) Key() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(*k))
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "ED PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// KeyASN1 returns the public key formatted in ASN.1
func (k *EdPublicKey) KeyASN1() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(*k))
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Size returns the size of the key in bytes
func (k *EdPublicKey) Size() int {
	return 64
}

// Bits returns the size of the key in bits
func (k *EdPublicKey) Bits() int {
	return 64 * 8
}

// Points are not implemented for Edward Curves.
// Usage will result in a panic.
func (k *EdPublicKey) Points() (x *big.Int, y *big.Int) {
	panic("Edward curves do not support this method")
}

// Sign will take a digest and use the private key to sign it
func (k *EdKey) Sign(digest []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, digest), nil
}

// Verify will take a ASN.1 signature and return true if it's valid
func (k *EdPublicKey) Verify(msg []byte, signature []byte) (bool, error) {
	return ed25519.Verify(ed25519.PublicKey(*k), msg, signature), nil
}

// DH is a placeholder function to satisfy rome's Key interface.
func (k *EdPublicKey) DH(h hash.Hash, g rome.PrivateKey, options ...rome.Option) ([]byte, error) {
	panic("Edward Curve does not support ECDH")
}

// Name returns the name of the Edward Curve
func (k *EdPublicKey) Name() string {
	return "ED25519"
}

// Encrypt is not supported on Edwards Curves
func (k *EdPublicKey) Encrypt(msg []byte, cipher rome.Cipher, hash hash.Hash, options ...rome.Option) ([]byte, error) {
	panic("ECIES is not supported on Edward Curves")
}

// Decrypt is not supported on Edwards Curves
func (k *EdKey) Decrypt(ciphertext []byte, cipher rome.Cipher, hash hash.Hash, options ...rome.Option) ([]byte, error) {
	panic("ECIES is not supported on Edward Curves")
}

// Fingerprint returns the hashed ASN.1 digest representing this
// public key. This function will panic if it fails to encode the
// public key.
func (k *EdPublicKey) Fingerprint(h hash.Hash) []byte {
	pub, err := k.KeyASN1()
	if err != nil {
		panic(err)
	}

	h.Write(pub)

	return h.Sum(nil)
}
