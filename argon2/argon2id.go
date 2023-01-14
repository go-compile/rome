package argon2

import (
	"bytes"
	"hash"

	"golang.org/x/crypto/argon2"
)

// Argon2id is a hash.Hash
type Argon2id struct {
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32

	buf *bytes.Buffer
}

// ID creates a new Argon2ID hash.Hash
//
// It uses Argon2's recommended defaults. if you want to use custom
// argon parameters use argon2.New()
func ID(salt []byte) hash.Hash {
	h := &Argon2id{
		buf:  bytes.NewBuffer(nil),
		salt: salt,

		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
	}

	return h
}

// NewID creates a hash.Hash for Argon2ID
func NewID(salt []byte, time uint32, memory uint32, threads uint8, keyLen uint32) hash.Hash {
	h := &Argon2id{
		salt:    salt,
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
		buf:     bytes.NewBuffer(nil),
	}

	return h
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (h *Argon2id) Write(buf []byte) (int, error) {
	return h.buf.Write(buf)
}

// Reset resets the Hash to its initial state.
func (h *Argon2id) Reset() {
	h.buf.Reset()
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (h *Argon2id) BlockSize() int {
	return 32
}

// Size returns the number of bytes Sum will return.
func (h *Argon2id) Size() int {
	return int(h.keyLen)
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *Argon2id) Sum(b []byte) []byte {
	return append(b, argon2.IDKey(h.buf.Bytes(), h.salt, h.time, h.memory, h.threads, h.keyLen)...)
}
