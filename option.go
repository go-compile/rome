package rome

import "hash"

// Option allows you to specify exactly what you want a function to use.
// Functions only use the options relevant to them.
type Option any

// OptionHKDF is used in a DH and will overwrite the shared secret options
type OptionHKDF struct {
	KeySize int
	Salt    []byte
	Hash    func() hash.Hash
}

// NewHKDF allows you to use HKDF in your ECDH.
// Salt can be nil and keysize usually should be 32 (256bit)
func NewHKDF(h func() hash.Hash, keysize int, salt []byte) Option {
	return OptionHKDF{
		KeySize: keysize,
		Salt:    salt,
		Hash:    h,
	}
}
