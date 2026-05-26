// Package aes implements convenience helpers for AES block cipher modes.
package aes

import (
	stdaes "crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Mode identifies an AES mode of operation.
type Mode uint8

const (
	// ModeCBC selects cipher block chaining mode.
	ModeCBC Mode = iota + 1

	// ModeCFB selects cipher feedback mode.
	ModeCFB

	// ModeCTR selects counter mode.
	ModeCTR

	// ModeECB selects electronic codebook mode.
	ModeECB

	// ModeIGE selects infinite garble extension mode.
	ModeIGE

	// ModeOFB selects output feedback mode.
	ModeOFB
)

const (
	// IGEIVSize is the size, in bytes, of an IGE initialization vector.
	IGEIVSize = stdaes.BlockSize << 1

	blockMask = stdaes.BlockSize - 1

	// KeySize128 is the size, in bytes, of an AES-128 key.
	KeySize128 = 16

	// KeySize192 is the size, in bytes, of an AES-192 key.
	KeySize192 = 24

	// KeySize256 is the size, in bytes, of an AES-256 key.
	KeySize256 = 32
)

// ErrUnknownMode is returned when New is called with an unknown mode.
var ErrUnknownMode = errors.New("aes: unknown cipher mode")

// KeySizeError is returned when an AES key has the wrong length.
type KeySizeError int

func (e KeySizeError) Error() string {
	return fmt.Sprintf("aes: invalid key size %d: must be 16, 24, or 32 bytes", int(e))
}

// IvSizeError is returned when an initialization vector has the wrong length.
type IvSizeError int

func (e IvSizeError) Error() string {
	return fmt.Sprintf("aes: invalid IV size %d: must be %d bytes", int(e), stdaes.BlockSize)
}

// IgeIvSizeError is returned when an IGE initialization vector has the wrong length.
type IgeIvSizeError int

func (e IgeIvSizeError) Error() string {
	return fmt.Sprintf("aes: invalid IGE IV size %d: must be %d bytes", int(e), IGEIVSize)
}

// InvalidDataError is returned when plaintext is empty or not block aligned.
type InvalidDataError int

func (e InvalidDataError) Error() string {
	if e == 0 {
		return "aes: plaintext is empty"
	}
	return fmt.Sprintf("aes: plaintext length %d is not a multiple of the block size", int(e))
}

// InvalidCiphertextError is returned when ciphertext is empty or not block aligned.
type InvalidCiphertextError int

func (e InvalidCiphertextError) Error() string {
	if e == 0 {
		return "aes: ciphertext is empty"
	}
	return fmt.Sprintf("aes: ciphertext length %d is not a multiple of the block size", int(e))
}

// GenerateRandomBytes returns n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateIV returns a new random AES initialization vector.
func GenerateIV() ([]byte, error) {
	return GenerateRandomBytes(stdaes.BlockSize)
}

// GenerateKey returns a new random AES key of the given size.
//
// The size must be [KeySize128], [KeySize192], or [KeySize256].
func GenerateKey(size int) ([]byte, error) {
	switch size {
	case KeySize128, KeySize192, KeySize256:
	default:
		return nil, KeySizeError(size)
	}
	return GenerateRandomBytes(size)
}
