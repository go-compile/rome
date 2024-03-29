package rome

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"
	"hash"
	"math"
	"math/big"

	"github.com/go-compile/rome/derbytes"
)

// ECKey is a Elliptic Curve
type ECKey struct {
	priv []byte

	ecdsa *ecdsa.PrivateKey
	pub   *ECPublicKey
}

// ECPublicKey holds the X and Y parameters for the key
type ECPublicKey struct {
	ecdsa *ecdsa.PublicKey
}

// NewECCurve takes a ECDSA key and converts it to a Rome private key
func NewECCurve(priv *ecdsa.PrivateKey) *ECKey {
	return &ECKey{priv: priv.D.Bytes(), ecdsa: priv, pub: &ECPublicKey{
		ecdsa: &priv.PublicKey,
	}}
}

// Public returns the public key interface
func (k *ECKey) Public() PublicKey {
	return k.pub
}

// ECPublic returns the ECPublic interface instead of the unified rome
// interface. It is not recommended this function is used.
func (k *ECKey) ECPublic() *ECPublicKey {
	return k.pub
}

// PrivateRaw returns the private key (D)
func (k *ECKey) PrivateRaw() []byte {
	return Pad(k.priv, k.pub.Size())
}

// Name returns the name of the curve
func (k *ECPublicKey) Name() string {
	return k.ecdsa.Params().Name
}

// Size returns the key size in bytes
func (k *ECPublicKey) Size() int {
	// convert bits to bytes and round up to full byte
	x := math.Round(float64(k.ecdsa.Curve.Params().BitSize / 8))
	// if even
	if int(x)%2 == 0 {
		return int(x)
	}

	// if odd
	return int(x) + 1
}

// Private will return the private key as PEM ASN.1 DER bytes
func (k *ECKey) Private() ([]byte, error) {
	der, err := derbytes.MarshalECPrivateKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// PrivateASN1 will return the private key as ASN.1 DER bytes
func (k *ECKey) PrivateASN1() ([]byte, error) {
	der, err := derbytes.MarshalECPrivateKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Key returns the public key in PEM ASN.1 DER format
func (k *ECPublicKey) Key() ([]byte, error) {
	der, err := derbytes.MarshalPKIXPublicKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(b), nil
}

// KeyASN1 returns the public key formatted in ASN.1
func (k *ECPublicKey) KeyASN1() ([]byte, error) {
	der, err := derbytes.MarshalPKIXPublicKey(k.ecdsa)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// Points returns the Elliptic Curve coordinates
func (k *ECPublicKey) Points() (x *big.Int, y *big.Int) {
	// clone X & Y
	x = &*k.ecdsa.X
	y = &*k.ecdsa.Y

	return x, y
}

// ParseECPublic will read elliptic curve public key from PEM ASN.1 DER format
func ParseECPublic(public []byte) (*ECPublicKey, error) {
	b, _ := pem.Decode(public)
	if b == nil {
		return nil, ErrInvalidPem
	}

	if b.Type != "EC PUBLIC KEY" {
		return nil, ErrWrongKey
	}

	pub, err := derbytes.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsa, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrWrongKey
	}

	return &ECPublicKey{
		ecdsa: ecdsa,
	}, nil
}

// ParseECPublicASN1 will read a elliptic curve public key from ASN.1 DER format
func ParseECPublicASN1(der []byte) (*ECPublicKey, error) {
	pub, err := derbytes.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	ecdsa, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrWrongKey
	}

	return &ECPublicKey{
		ecdsa: ecdsa,
	}, nil
}

// ParseECPrivate will read a PEM ASN.1 DER encoded key
func ParseECPrivate(private []byte) (*ECKey, error) {
	b, _ := pem.Decode(private)
	if b == nil {
		return nil, ErrInvalidPem
	}

	if b.Type != "EC PRIVATE KEY" {
		return nil, ErrWrongKey
	}

	priv, err := derbytes.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return &ECKey{
		ecdsa: priv,
		pub: &ECPublicKey{
			ecdsa: &priv.PublicKey,
		},
		priv: priv.D.Bytes(),
	}, nil
}

// ParseECPrivateASN1 will read a ASN.1 DER encoded key
func ParseECPrivateASN1(private []byte) (*ECKey, error) {
	priv, err := derbytes.ParseECPrivateKey(private)
	if err != nil {
		return nil, err
	}

	return &ECKey{
		ecdsa: priv,
		pub: &ECPublicKey{
			ecdsa: &priv.PublicKey,
		},
		priv: priv.D.Bytes(),
	}, nil
}

// Fingerprint returns the hashed ASN.1 digest representing this
// public key. This function will panic if it fails to encode the
// public key.
func (k *ECPublicKey) Fingerprint(h hash.Hash) []byte {
	pub, err := k.KeyASN1()
	if err != nil {
		panic(err)
	}

	h.Write(pub)

	return h.Sum(nil)
}

// ECDSAKey returns the key in ecdsa.PublicKey
func (k *ECPublicKey) ECDSAKey() elliptic.Curve {
	return k.ecdsa
}
