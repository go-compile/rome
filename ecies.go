package rome

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"hash"
)

// Cipher specifies what cipher to use in encryption
type Cipher uint8

const (
	// CipherAES_GCM is a AHEAD cipher and is recommended for most use cases
	CipherAES_GCM = iota
)

var (
	// ErrUnknownCipher is returned if the cipher provided is unsupported
	ErrUnknownCipher = errors.New("unknown cipher suite")
)

// Encrypt uses ECIES hybrid encryption
func (k *ECPublicKey) Encrypt(m []byte, c Cipher, hash hash.Hash) ([]byte, error) {

	// generate ephemeral key to perform ECDH
	// it is important this key is never used again
	k2, err := k.generateEphemeralKey()
	if err != nil {
		return nil, err
	}

	// perform ECDH with provided hash function and the new ephemeral key
	secret, err := k.DH(hash, k2)
	if err != nil {
		return nil, err
	}

	// format public key in ASN.1 DER bytes
	public, err := k2.Public().KeyASN1()
	if err != nil {
		return nil, err
	}

	// create new output buffer and write the ephemeral public key
	output := bytes.NewBuffer(public)

	// generate a nonce for added security
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	switch c {
	case CipherAES_GCM:
		b, err := aes.NewCipher(secret)
		if err != nil {
			return nil, err
		}

		cipher, err := cipher.NewGCMWithNonceSize(b, len(nonce))
		if err != nil {
			return nil, err
		}

		// prepend the nonce with the cipher text to the end
		// the nonce is a fixed length so we should be able to decode
		// it on the other end
		ciphertext := cipher.Seal(nil, nonce, m, nil)
		output.Write(append(nonce, ciphertext...))

		return output.Bytes(), nil
	default:
		return nil, ErrUnknownCipher
	}
}

// Decrypt uses ECIES hybrid encryption
func (k *ECKey) Decrypt(ciphertext []byte, c Cipher, hash hash.Hash) ([]byte, error) {

	// unmarshal ASN.1 der bytes to get length
	var pub pkixPublicKey
	rest, err := asn1.Unmarshal(ciphertext, &pub)
	if err != nil {
		return nil, err
	}

	// calculate and trim public key ASN.1 bytes
	public := ciphertext[:len(ciphertext)-len(rest)]
	// parse public key
	key, err := ParseECPublicASN1(public)
	if err != nil {
		return nil, err
	}

	// trim public key prefix
	ciphertext = ciphertext[len(public):]

	secret, err := key.DH(hash, k)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:16]
	ciphertext = ciphertext[16:]

	switch c {
	case CipherAES_GCM:
		b, err := aes.NewCipher(secret)
		if err != nil {
			return nil, err
		}

		cipher, err := cipher.NewGCMWithNonceSize(b, len(nonce))
		if err != nil {
			return nil, err
		}

		return cipher.Open(nil, nonce, ciphertext, nil)
	}

	return nil, ErrUnknownCipher
}

// generateEphemeralKey will generate a temporary key on the same curve
func (k *ECPublicKey) generateEphemeralKey() (*ECKey, error) {

	k2, err := ecdsa.GenerateKey(k.ecdsa.Curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECKey{
		priv:  k2.D.Bytes(),
		ecdsa: k2,
		pub: &ECPublicKey{
			ecdsa: &k2.PublicKey,
		},
	}, nil
}
