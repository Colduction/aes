// Package aes provides internal AES cipher-mode primitives.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// ErrSIVOpen is returned when SIV decryption fails authentication.
var ErrSIVOpen = errors.New("siv: authentication failed")

const sivBlockSize = aes.BlockSize // 16 bytes

// zeroBlock is the all-zero 128-bit string used as S2V initial input.
var zeroBlock [sivBlockSize]byte

// sivPRF is the pluggable PRF/MAC interface driving the SIV construction.
type sivPRF interface {
	s2v(additionalData [][]byte, plaintext []byte, out *[sivBlockSize]byte)
}

// SIV implements AES-SIV authenticated encryption with a pluggable PRF.
// Use NewSIV for AES-CMAC-SIV (RFC 5297) or NewGHASHSIV for GHASH-SIV.
type SIV struct {
	prf sivPRF       // PRF/MAC algorithm (CMAC or GHASH)
	ctr cipher.Block // AES key schedule for CTR encryption
}

// dblBlock multiplies a 128-bit GF(2^128) element by x (left-shift by 1 bit)
// with reduction modulo x^128+x^7+x^2+x+1. Block is big-endian.
func dblBlock(b *[sivBlockSize]byte) {
	msb := b[0] >> 7
	for i := range sivBlockSize - 1 {
		b[i] = (b[i] << 1) | (b[i+1] >> 7)
	}
	b[sivBlockSize-1] = (b[sivBlockSize-1] << 1) ^ (msb * 0x87)
}

// sivCTRIV derives the AES-CTR initial counter block from the SIV tag.
// Per RFC 5297: Q = SIV bitand (1^64 || 0 || 1^31 || 0 || 1^31).
func sivCTRIV(siv *[sivBlockSize]byte, q *[sivBlockSize]byte) {
	copy(q[:], siv[:])
	q[8] &^= 0x80
	q[12] &^= 0x80
}

// Seal encrypts and authenticates plaintext with optional associated-data.
// Output layout: SIV (16 bytes) || AES-CTR(ciphertext).
func (s *SIV) Seal(additionalData [][]byte, plaintext []byte) []byte {
	out := make([]byte, sivBlockSize+len(plaintext))
	siv := (*[sivBlockSize]byte)(out[:sivBlockSize])
	s.prf.s2v(additionalData, plaintext, siv)
	var q [sivBlockSize]byte
	sivCTRIV(siv, &q)
	cipher.NewCTR(s.ctr, q[:]).XORKeyStream(out[sivBlockSize:], plaintext)
	return out
}

// Open authenticates and decrypts ciphertext (SIV || encrypted body).
// Returns the plaintext on success, or ErrSIVOpen on failure.
func (s *SIV) Open(additionalData [][]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < sivBlockSize {
		return nil, ErrSIVOpen
	}
	var siv [sivBlockSize]byte
	copy(siv[:], ciphertext[:sivBlockSize])
	var q [sivBlockSize]byte
	sivCTRIV(&siv, &q)
	body := ciphertext[sivBlockSize:]
	pt := make([]byte, len(body))
	cipher.NewCTR(s.ctr, q[:]).XORKeyStream(pt, body)
	var expected [sivBlockSize]byte
	s.prf.s2v(additionalData, pt, &expected)
	if subtle.ConstantTimeCompare(siv[:], expected[:]) != 1 {
		for i := range pt {
			pt[i] = 0
		}
		return nil, ErrSIVOpen
	}
	return pt, nil
}
