package ssh

import (
	"errors"

	"github.com/go-compile/rome"
	"golang.org/x/crypto/ssh"
)

var (
	// ErrUnsupportedKey is returned when the provided key is incompatible with
	// for a SSH key
	ErrUnsupportedKey = errors.New("unsupported key")
)

// ToKey converts a rome public key to a SSH key.
// Only works with: P-256, P-384 or P-521
func ToKey(pub rome.PublicKey) (ssh.PublicKey, error) {

	switch k := pub.(type) {
	case *rome.ECPublicKey:
		return ssh.NewPublicKey(k.ECDSAKey())
	default:
		return nil, ErrUnsupportedKey
	}
}

// ToMarshaledKey converts a rome public key to a marshaled SSH key.
// Only works with: P-256, P-384 or P-521
func ToMarshaledKey(pub rome.PublicKey) (pubKey []byte, authorisedKey []byte, err error) {

	sshKey, err := ToKey(pub)
	if err != nil {
		return nil, nil, err
	}

	return sshKey.Marshal(), ssh.MarshalAuthorizedKey(sshKey), nil
}
