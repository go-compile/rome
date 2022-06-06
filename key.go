package rome

import "errors"

var (
	// ErrWrongKey is returned if the key is the wrong type
	ErrWrongKey = errors.New("wrong key type or curve")
)

type PrivateKey interface {
	// Sign returns a ASN.1 formatted signature
	Sign(digest []byte) ([]byte, error)
}

type PublicKey interface {
}

type Encrypt interface {
	AES(m []byte, k []byte) ([]byte, error)
}
