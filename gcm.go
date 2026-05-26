package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	gcmStdNonceSize = 12
	gcmMinTagSize   = 12
	gcmMaxTagSize   = stdaes.BlockSize
)

// GCMNonceSizeError is returned when an AES-GCM nonce has the wrong length.
type GCMNonceSizeError int

func (e GCMNonceSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid nonce size %d: nonce must be > 0 bytes", int(e))
}

// GCMTagSizeError is returned when an AES-GCM tag has the wrong length.
type GCMTagSizeError int

func (e GCMTagSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid tag size %d: must be between %d and %d bytes", int(e), gcmMinTagSize, gcmMaxTagSize)
}

// GCMDataSizeError is returned when AES-GCM plaintext is too large.
type GCMDataSizeError int

func (e GCMDataSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: plaintext too large (%d bytes)", int(e))
}

// gcmCipher is a reusable AES-GCM authenticated encryption cipher.
type gcmCipher struct {
	aead           cipher.AEAD
	nonce          []byte
	additionalData []byte
}

var _ AEADCipher = (*gcmCipher)(nil)

// NewGCM returns a new AES-GCM cipher with the standard 16-byte tag.
//
// The key must be 16, 24, or 32 bytes. The nonce must not be reused with the
// same key. A 12-byte nonce is recommended.
func NewGCM(key, nonce, additionalData []byte) (AEADCipher, error) {
	return newGCMCipher(key, nonce, additionalData, 0)
}

// NewGCMWithTagSize returns a new AES-GCM cipher with a custom tag size.
//
// The tagSize must be between 12 and 16 bytes. The nonce must be 12 bytes.
func NewGCMWithTagSize(key, nonce, additionalData []byte, tagSize int) (AEADCipher, error) {
	return newGCMCipher(key, nonce, additionalData, tagSize)
}

func newGCMCipher(key, nonce, additionalData []byte, tagSize int) (AEADCipher, error) {
	if len(nonce) == 0 {
		return nil, GCMNonceSizeError(0)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, KeySizeError(len(key))
	}

	var aead cipher.AEAD
	switch {
	case tagSize != 0:
		if tagSize < gcmMinTagSize || tagSize > gcmMaxTagSize {
			return nil, GCMTagSizeError(tagSize)
		}
		if len(nonce) != gcmStdNonceSize {
			return nil, GCMNonceSizeError(len(nonce))
		}
		aead, err = cipher.NewGCMWithTagSize(block, tagSize)
	case len(nonce) != gcmStdNonceSize:
		aead, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	default:
		aead, err = cipher.NewGCM(block)
	}
	if err != nil {
		return nil, err
	}

	nonceCopy := make([]byte, len(nonce))
	copy(nonceCopy, nonce)

	var aadCopy []byte
	if n := len(additionalData); n > 0 {
		aadCopy = make([]byte, n)
		copy(aadCopy, additionalData)
	}

	return &gcmCipher{aead: aead, nonce: nonceCopy, additionalData: aadCopy}, nil
}

// NonceSize returns the required nonce size.
func (c *gcmCipher) NonceSize() int {
	return c.aead.NonceSize()
}

// Overhead returns the number of bytes added by Seal.
func (c *gcmCipher) Overhead() int {
	return c.aead.Overhead()
}

// Seal encrypts and authenticates plaintext, appending the result to dst.
func (c *gcmCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return c.aead.Seal(dst, nonce, plaintext, additionalData)
}

// Open authenticates and decrypts ciphertext, appending the result to dst.
func (c *gcmCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return c.aead.Open(dst, nonce, ciphertext, additionalData)
}

// Encrypt encrypts plaintext and appends the authentication tag to the ciphertext.
func (c *gcmCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, InvalidDataError(0)
	}
	if uint64(len(plaintext)) > (1<<32-2)*uint64(stdaes.BlockSize) {
		return nil, GCMDataSizeError(len(plaintext))
	}
	return c.aead.Seal(nil, c.nonce, plaintext, c.additionalData), nil
}

// Decrypt authenticates and decrypts ciphertext.
func (c *gcmCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, InvalidCiphertextError(0)
	}
	return c.aead.Open(nil, c.nonce, ciphertext, c.additionalData)
}
