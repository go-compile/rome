package rome

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher specifies what cipher to use in encryption
type Cipher uint8

const (
	// CipherAES_GCM is a AHEAD cipher and is recommended for most use cases
	CipherAES_GCM = iota
	// CipherChacha20 is a UNAUTHENTICATED cipher and is only provided with the expectation
	// you will handle the data integrity by using a MAC. Or instead please use one of the
	// provided authenticated ChaCha ciphers below.
	CipherChacha20
	// CipherChacha20_SHA256 is a authenticated Encrypt-then-MAC (EtM) cipher using ChaCha20
	// the MAC is a SHA256 hmac with the secret being the encryption key
	CipherChacha20_SHA256
	// CipherChacha20_SHA512 is a authenticated Encrypt-then-MAC (EtM) cipher using ChaCha20
	// the MAC is a SHA512 hmac with the secret being the encryption key
	CipherChacha20_SHA512
	// ChaCha20Poly1305 is a authenticated cipher which takes a 256bit key
	ChaCha20Poly1305
)

var (
	// ErrUnknownCipher is returned if the cipher provided is unsupported
	ErrUnknownCipher = errors.New("unknown cipher suite")
	// ErrCipherTxtSmall is returned if the data is so small it must be invalid
	ErrCipherTxtSmall = errors.New("cipher text is too small")
	// ErrAuthFail is returned when the ciphertext mac fails
	ErrAuthFail = errors.New("message authentication failed")
)

// Encrypt uses ECIES hybrid encryption. Cipher is used to specify the encryption
// algorithm and hash is used to derive the key via the ECDH
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
	nonce := make([]byte, 12)
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
	case CipherChacha20:
		b, err := chacha20.NewUnauthenticatedCipher(secret, nonce)
		if err != nil {
			return nil, err
		}

		dst := make([]byte, len(m))
		b.XORKeyStream(dst, m)

		output.Write(append(nonce, dst...))
		return output.Bytes(), nil
	case CipherChacha20_SHA256:
		b, err := chacha20.NewUnauthenticatedCipher(secret, nonce)
		if err != nil {
			return nil, err
		}

		dst := make([]byte, len(m))
		b.XORKeyStream(dst, m)

		// calculate SHA256 HMAC to authenticate the cipher
		h := hmac.New(sha256.New, secret)
		h.Write(dst)

		output.Write(nonce)
		output.Write(h.Sum(nil))
		output.Write(dst)

		return output.Bytes(), nil
	case CipherChacha20_SHA512:
		b, err := chacha20.NewUnauthenticatedCipher(secret, nonce)
		if err != nil {
			return nil, err
		}

		dst := make([]byte, len(m))
		b.XORKeyStream(dst, m)

		// calculate SHA512 HMAC to authenticate the cipher
		h := hmac.New(sha512.New, secret)
		h.Write(dst)

		output.Write(nonce)
		output.Write(h.Sum(nil))
		output.Write(dst)

		return output.Bytes(), nil
	case ChaCha20Poly1305:
		b, err := chacha20poly1305.New(secret)
		if err != nil {
			return nil, err
		}

		ciphertext := b.Seal(nil, nonce, m, nil)

		output.Write(nonce)
		output.Write(ciphertext)

		return output.Bytes(), nil
	default:
		return nil, ErrUnknownCipher
	}
}

// Decrypt uses ECIES hybrid encryption. Cipher is used to specify the encryption
// algorithm and hash is used to derive the key via the ECDH
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

	// range check length
	if len(ciphertext) < 12 {
		return nil, ErrCipherTxtSmall
	}

	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

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
	case CipherChacha20:

		b, err := chacha20.NewUnauthenticatedCipher(secret, nonce)
		if err != nil {
			return nil, err
		}

		// decrypt by xoring the ciphertext back
		plaintext := make([]byte, len(ciphertext))
		b.XORKeyStream(plaintext, ciphertext)

		return plaintext, nil
	case CipherChacha20_SHA256:
		if len(ciphertext) < 32 {
			return nil, ErrCipherTxtSmall
		}

		mac := ciphertext[:32]
		ciphertext = ciphertext[32:]

		b, err := chacha20.NewUnauthenticatedCipher(secret, nonce)
		if err != nil {
			return nil, err
		}

		// decrypt by xoring the ciphertext back
		plaintext := make([]byte, len(ciphertext))
		b.XORKeyStream(plaintext, ciphertext)

		// calculate SHA256 HMAC to authenticate the cipher
		h := hmac.New(sha256.New, secret)
		h.Write(ciphertext)

		if !bytes.Equal(h.Sum(nil), mac) {
			return nil, ErrAuthFail
		}

		return plaintext, nil
	case CipherChacha20_SHA512:
		if len(ciphertext) < 64 {
			return nil, ErrCipherTxtSmall
		}

		mac := ciphertext[:64]
		ciphertext = ciphertext[64:]

		b, err := chacha20.NewUnauthenticatedCipher(secret, nonce)
		if err != nil {
			return nil, err
		}

		// decrypt by xoring the ciphertext back
		plaintext := make([]byte, len(ciphertext))
		b.XORKeyStream(plaintext, ciphertext)

		// calculate SHA512 HMAC to authenticate the cipher
		h := hmac.New(sha512.New, secret)
		h.Write(ciphertext)

		if !bytes.Equal(h.Sum(nil), mac) {
			return nil, ErrAuthFail
		}

		return plaintext, nil
	case ChaCha20Poly1305:
		b, err := chacha20poly1305.New(secret)
		if err != nil {
			return nil, err
		}

		return b.Open(nil, nonce, ciphertext, nil)
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

func encryptGCM(b cipher.Block, m, nonce []byte) ([]byte, error) {
	cipher, err := cipher.NewGCMWithNonceSize(b, len(nonce))
	if err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nil, nonce, m, nil)

	return ciphertext, nil
}
