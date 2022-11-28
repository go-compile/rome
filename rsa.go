package rome

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"hash"
	"math/big"
	"strconv"

	"github.com/go-compile/rome/derbytes"
)

var (
	// ErrOptionsNotSupported is returned when options are used on a function which
	// does not support it.
	ErrOptionsNotSupported = errors.New("encryption options are not supported for this key")
)

// RSAKey is a RSA private key
type RSAKey struct {
	priv *rsa.PrivateKey
	pub  *RSAPublicKey
}

// RSAPublicKey is the pub key
type RSAPublicKey struct {
	k *rsa.PublicKey
}

// GenerateRSA will create a new RSA key pair
func GenerateRSA(bits int) (*RSAKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return NewRSAKey(k), nil
}

// NewRSAKey takes a ECDSA key and converts it to a Rome private key
func NewRSAKey(priv *rsa.PrivateKey) *RSAKey {
	return &RSAKey{priv: priv, pub: &RSAPublicKey{
		k: &priv.PublicKey,
	}}
}

// Public returns the public key interface
func (k *RSAKey) Public() PublicKey {
	return k.pub
}

// ECPublic returns the ECPublic interface instead of the unified rome
// interface. It is not recommended this function is used.
func (k *RSAKey) RSAPublic() *RSAPublicKey {
	return k.pub
}

// PrivateRaw is incompatible with RSA
func (k *RSAKey) PrivateRaw() []byte {
	return nil
}

// Name returns the name of the key
func (k *RSAPublicKey) Name() string {
	return "RSA-" + strconv.Itoa(k.k.Size())
}

// Size returns the key size in bytes
func (k *RSAPublicKey) Size() int {
	// TODO: RSA size function
	return 0
}

// Private will return the private key as PEM ASN.1 DER bytes
func (k *RSAKey) Private() ([]byte, error) {
	der := derbytes.MarshalPKCS1PrivateKey(k.priv)

	b := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// PrivateASN1 will return the private key as ASN.1 DER bytes
func (k *RSAKey) PrivateASN1() ([]byte, error) {
	der := derbytes.MarshalPKCS1PrivateKey(k.priv)
	return der, nil
}

// Key returns the public key in PEM ASN.1 DER format
func (k *RSAPublicKey) Key() ([]byte, error) {
	der, err := derbytes.MarshalPKIXPublicKey(k.k)
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// KeyASN1 returns the public key formatted in ASN.1
func (k *RSAPublicKey) KeyASN1() ([]byte, error) {
	der, err := derbytes.MarshalPKIXPublicKey(k.k)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Points returns the Elliptic Curve coordinates (incompatible)
func (k *RSAPublicKey) Points() (x *big.Int, y *big.Int) {
	return nil, nil
}

// ParseRSAPublic will read RSA public key from PEM ASN.1 DER format
func ParseRSAPublic(public []byte) (*RSAPublicKey, error) {
	b, _ := pem.Decode(public)
	if b == nil {
		return nil, ErrInvalidPem
	}

	if b.Type != "RSA PUBLIC KEY" {
		return nil, ErrWrongKey
	}

	pub, err := derbytes.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	rsa, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, ErrWrongKey
	}

	return &RSAPublicKey{
		k: rsa,
	}, nil
}

// ParseRSAPublicASN1 will read a RSA public key from ASN.1 DER format
func ParseRSAPublicASN1(der []byte) (*RSAPublicKey, error) {
	pub, err := derbytes.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	rsa, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, ErrWrongKey
	}

	return &RSAPublicKey{
		k: rsa,
	}, nil
}

// ParseRSAPrivate will read a PEM ASN.1 DER encoded key
func ParseRSAPrivate(private []byte) (*RSAKey, error) {
	b, _ := pem.Decode(private)
	if b == nil {
		return nil, ErrInvalidPem
	}

	if b.Type != "RSA PRIVATE KEY" {
		return nil, ErrWrongKey
	}

	priv, err := derbytes.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return &RSAKey{
		priv: priv,
		pub: &RSAPublicKey{
			k: &priv.PublicKey,
		},
	}, nil
}

// ParseRSAPrivateASN1 will read a ASN.1 DER encoded key
func ParseRSAPrivateASN1(private []byte) (*RSAKey, error) {
	priv, err := derbytes.ParsePKCS1PrivateKey(private)
	if err != nil {
		return nil, err
	}

	return &RSAKey{
		priv: priv,
		pub: &RSAPublicKey{
			k: &priv.PublicKey,
		},
	}, nil
}

// Fingerprint returns the hashed ASN.1 digest representing this
// public key. This function will panic if it fails to encode the
// public key.
func (k *RSAPublicKey) Fingerprint(h hash.Hash) []byte {
	pub, err := k.KeyASN1()
	if err != nil {
		panic(err)
	}

	h.Write(pub)

	return h.Sum(nil)
}

// ECDSAKey returns the key in ecdsa.PublicKey
func (k *RSAPublicKey) RSAKey() rsa.PublicKey {
	return *k.k
}

// Encrypt uses PKCS1v15 RSA. DO NOT PROVIDE A CIPHER, HASH OR OPTIONS
func (k *RSAPublicKey) Encrypt(m []byte, c Cipher, hash hash.Hash, options ...Option) ([]byte, error) {
	if options != nil {
		return nil, ErrOptionsNotSupported
	}

	if c != 0 || hash != nil {
		return nil, ErrOptionsNotSupported
	}

	return rsa.EncryptPKCS1v15(rand.Reader, k.k, m)
}

// Decrypt uses PKCS1v15 RSA. DO NOT PROVIDE A CIPHER, HASH OR OPTIONS
func (k *RSAKey) Decrypt(ciphertext []byte, c Cipher, hash hash.Hash, options ...Option) ([]byte, error) {
	if options != nil {
		return nil, ErrOptionsNotSupported
	}

	if c != 0 || hash != nil {
		return nil, ErrOptionsNotSupported
	}

	return rsa.DecryptPKCS1v15(rand.Reader, k.priv, ciphertext)
}

func (k *RSAPublicKey) DH(hash hash.Hash, g PrivateKey, options ...Option) ([]byte, error) {
	return nil, nil
}

// Sign will take a digest and use the private key to sign it
func (k *RSAKey) Sign(digest []byte) ([]byte, error) {
	return nil, nil
}

// Verify will take a ASN.1 signature and return true if it's valid
func (k *RSAPublicKey) Verify(digest []byte, signature []byte) (bool, error) {
	return false, nil
}
