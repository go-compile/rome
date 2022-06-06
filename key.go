package rome

import "errors"

var (
	// ErrWrongKey is returned if the key is the wrong type
	ErrWrongKey = errors.New("wrong key type or curve")
)

type PrivateKey interface {
	// Sign returns a ASN.1 formatted signature
	Sign(digest []byte) ([]byte, error)

	Public() PublicKey
}

type PublicKey interface {
	Verify(digest []byte, signature []byte) ([]byte, error)
}

type Encrypt interface {
	AES(m []byte, k []byte) ([]byte, error)
}
