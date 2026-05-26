package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

const (
	// IVSize is the required IV length: two concatenated AES blocks.
	IVSize = aes.BlockSize << 1
	// blockMask is used for fast block-alignment checks without division.
	blockMask = aes.BlockSize - 1
)

// igeEncrypter holds the mutable IGE encryption state.
type igeEncrypter struct {
	b      cipher.Block
	prevCT [aes.BlockSize]byte
	prevPT [aes.BlockSize]byte
}

// igeDecrypter holds the mutable IGE decryption state.
type igeDecrypter struct {
	b      cipher.Block
	prevCT [aes.BlockSize]byte
	prevPT [aes.BlockSize]byte
}

// NewIGEEncrypter returns a [cipher.BlockMode] that encrypts data in IGE mode
// using the given block cipher and iv.
func NewIGEEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	var enc igeEncrypter
	enc.b = block
	copy(enc.prevCT[:], iv[:aes.BlockSize])
	copy(enc.prevPT[:], iv[aes.BlockSize:IVSize])
	return &enc
}

// NewIGEDecrypter returns a [cipher.BlockMode] that decrypts data in IGE mode
// using the given block cipher and iv. The iv layout is identical to [NewIGEEncrypter].
func NewIGEDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	var dec igeDecrypter
	dec.b = block
	copy(dec.prevCT[:], iv[:aes.BlockSize])
	copy(dec.prevPT[:], iv[aes.BlockSize:IVSize])
	return &dec
}

// BlockSize returns the cipher block size.
func (*igeEncrypter) BlockSize() int { return aes.BlockSize }

// CryptBlocks encrypts full blocks of src into dst using the IGE recurrence.
func (x *igeEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)&blockMask != 0 {
		panic("ige: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("ige: output smaller than input")
	}

	var saved [aes.BlockSize]byte
	for i := 0; i < len(src); i += aes.BlockSize {
		var (
			s = src[i : i+aes.BlockSize : i+aes.BlockSize]
			d = dst[i : i+aes.BlockSize : i+aes.BlockSize]
		)
		copy(saved[:], s)

		subtle.XORBytes(d, s, x.prevCT[:])
		x.b.Encrypt(d, d)
		subtle.XORBytes(d, d, x.prevPT[:])

		copy(x.prevCT[:], d)
		copy(x.prevPT[:], saved[:])
	}
}

// BlockSize returns the cipher block size.
func (*igeDecrypter) BlockSize() int { return aes.BlockSize }

// CryptBlocks decrypts full blocks of src into dst using the IGE recurrence.
func (x *igeDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)&blockMask != 0 {
		panic("ige: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("ige: output smaller than input")
	}

	var saved [aes.BlockSize]byte
	for i := 0; i < len(src); i += aes.BlockSize {
		var (
			s = src[i : i+aes.BlockSize : i+aes.BlockSize]
			d = dst[i : i+aes.BlockSize : i+aes.BlockSize]
		)
		copy(saved[:], s)

		subtle.XORBytes(d, s, x.prevPT[:])
		x.b.Decrypt(d, d)
		subtle.XORBytes(d, d, x.prevCT[:])

		copy(x.prevCT[:], saved[:])
		copy(x.prevPT[:], d)
	}
}
