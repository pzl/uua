package mkpass

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Create a new password hash (+salt) for storage
func Create(pass []byte) (hash []byte, salt []byte, err error) {
	const SaltLength = 16
	salt = make([]byte, SaltLength)
	n, err := io.ReadFull(rand.Reader, salt)
	if n != SaltLength {
		return nil, nil, errors.New("salt underread")
	}
	if err != nil {
		return nil, nil, err
	}

	hash = argon2.IDKey(pass, salt, 1, 64*1024, 4, 32)

	return hash, salt, nil
}

// Create a new password hash with a known salt
func CreateWithSalt(pass []byte, salt []byte) ([]byte, error) {
	return argon2.IDKey(pass, salt, 1, 64*1024, 4, 32), nil
}

// Checks password+salt match the given hash
func Match(pass []byte, salt []byte, hash []byte) bool {
	h := argon2.IDKey(pass, salt, 1, 64*1024, 4, 32)
	if bytes.Equal(hash, h) {
		return true
	}
	return false
}
