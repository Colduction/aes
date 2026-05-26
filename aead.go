package aes

import "crypto/cipher"

// AEADCipher is an authenticated encryption cipher.
//
// It includes the standard [cipher.AEAD] API and the package's Encrypt and
// Decrypt convenience methods.
type AEADCipher interface {
	cipher.AEAD
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}
