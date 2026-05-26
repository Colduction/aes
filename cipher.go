package aes

import (
	stdaes "crypto/aes"
	stdcipher "crypto/cipher"

	"github.com/colduction/aes-go/padding"
)

// Cipher is a reusable AES cipher with a fixed mode, key, IV, and padding mode.
type Cipher struct {
	block stdcipher.Block
	mode  Mode
	iv    []byte
	pad   padding.Padding
}

// New returns a new Cipher for the given mode.
//
// The key must be 16, 24, or 32 bytes. The IV must be 16 bytes for most modes,
// [IGEIVSize] bytes for [ModeIGE], and nil for [ModeECB]. The padding mode may
// be nil when the input is already block aligned.
func New(mode Mode, key, iv []byte, pad padding.Padding) (*Cipher, error) {
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, KeySizeError(len(key))
	}
	switch mode {
	case ModeECB:
	case ModeIGE:
		if len(iv) != IGEIVSize {
			return nil, IgeIvSizeError(len(iv))
		}
	default:
		if len(iv) != stdaes.BlockSize {
			return nil, IvSizeError(len(iv))
		}
	}
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	return &Cipher{block: block, mode: mode, iv: ivCopy, pad: pad}, nil
}

// Encrypt encrypts plaintext and returns the ciphertext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, InvalidDataError(0)
	}
	switch c.mode {
	case ModeCBC:
		return encryptCBC(c.block, plaintext, c.iv, c.pad)
	case ModeCFB:
		return encryptCFB(c.block, plaintext, c.iv, c.pad)
	case ModeCTR:
		return encryptCTR(c.block, plaintext, c.iv, c.pad)
	case ModeECB:
		return encryptECB(c.block, plaintext, c.pad)
	case ModeIGE:
		return encryptIGE(c.block, plaintext, c.iv, c.pad)
	case ModeOFB:
		return encryptOFB(c.block, plaintext, c.iv, c.pad)
	}
	return nil, ErrUnknownMode
}

// Decrypt decrypts ciphertext and returns the plaintext.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, InvalidCiphertextError(0)
	}
	switch c.mode {
	case ModeCBC:
		return decryptCBC(c.block, ciphertext, c.iv, c.pad)
	case ModeCFB:
		return decryptCFB(c.block, ciphertext, c.iv, c.pad)
	case ModeCTR:
		return decryptCTR(c.block, ciphertext, c.iv, c.pad)
	case ModeECB:
		return decryptECB(c.block, ciphertext, c.pad)
	case ModeIGE:
		return decryptIGE(c.block, ciphertext, c.iv, c.pad)
	case ModeOFB:
		return decryptOFB(c.block, ciphertext, c.iv, c.pad)
	}
	return nil, ErrUnknownMode
}
