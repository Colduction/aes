// Package aes provides internal AES cipher-mode primitives.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// cmacPRF implements RFC 5297 AES-CMAC-S2V as a sivPRF.
//
// It holds the MAC cipher block and the two precomputed CMAC subkeys
// K1 and K2 (derived once from AES(K1, 0^128) in NewSIV).
type cmacPRF struct {
	mac cipher.Block
	k1  [sivBlockSize]byte
	k2  [sivBlockSize]byte
}

// NewSIV creates an AES-CMAC-SIV cipher (RFC 5297) from a 32, 48, or 64-byte
// composite key. The key is split in half: key[:n/2] drives AES-CMAC (S2V),
// and key[n/2:] drives AES-CTR encryption.
func NewSIV(key []byte) (*SIV, error) {
	n := len(key)
	if n != 32 && n != 48 && n != 64 {
		return nil, errors.New("siv: CMAC key must be 32, 48, or 64 bytes")
	}
	half := n >> 1
	mac, err := aes.NewCipher(key[:half])
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, err
	}
	p := &cmacPRF{mac: mac}
	p.deriveSubkeys()
	return &SIV{prf: p, ctr: ctr}, nil
}

// deriveSubkeys precomputes CMAC subkeys K1 and K2 from the CMAC block cipher.
//
// L  = AES-K1(0^128)
// K1 = dbl(L)
// K2 = dbl(K1)
func (p *cmacPRF) deriveSubkeys() {
	p.mac.Encrypt(p.k1[:], zeroBlock[:])
	dblBlock(&p.k1)
	copy(p.k2[:], p.k1[:])
	dblBlock(&p.k2)
}

// cmac computes AES-CMAC(K1, msg) per RFC 4493 and stores the 16-byte tag in out.
// It reuses the precomputed subkeys p.k1 / p.k2 to avoid per-call key derivation.
func (p *cmacPRF) cmac(msg []byte, out *[sivBlockSize]byte) {
	var x [sivBlockSize]byte
	n := len(msg)

	if n == 0 {
		var last [sivBlockSize]byte
		last[0] = 0x80
		subtle.XORBytes(last[:], last[:], p.k2[:])
		p.mac.Encrypt(out[:], last[:])
		return
	}

	fullBlocks := (n - 1) / sivBlockSize
	for i := range fullBlocks {
		subtle.XORBytes(x[:], x[:], msg[i*sivBlockSize:(i+1)*sivBlockSize])
		p.mac.Encrypt(x[:], x[:])
	}

	last := msg[fullBlocks*sivBlockSize:]
	var lastBlock [sivBlockSize]byte
	if len(last) == sivBlockSize {
		copy(lastBlock[:], last)
		subtle.XORBytes(lastBlock[:], lastBlock[:], p.k1[:])
	} else {
		copy(lastBlock[:], last)
		lastBlock[len(last)] = 0x80
		subtle.XORBytes(lastBlock[:], lastBlock[:], p.k2[:])
	}
	subtle.XORBytes(x[:], x[:], lastBlock[:])
	p.mac.Encrypt(out[:], x[:])
}

// cmacBlock is a fast path for CMAC of a single complete 16-byte block.
//
// output = AES(K1, block XOR K1)
func (p *cmacPRF) cmacBlock(block *[sivBlockSize]byte, out *[sivBlockSize]byte) {
	var tmp [sivBlockSize]byte
	subtle.XORBytes(tmp[:], block[:], p.k1[:])
	p.mac.Encrypt(out[:], tmp[:])
}

// cmacWithTail computes AES-CMAC(prefix || tail) where tail is exactly 16 bytes.
//
// This avoids allocating a combined slice when S2V needs to XOR the last 16
// bytes of the plaintext with D before computing the final CMAC.
// The total message length is len(prefix)+16 bytes.
func (p *cmacPRF) cmacWithTail(prefix []byte, tail *[sivBlockSize]byte, out *[sivBlockSize]byte) {
	var x [sivBlockSize]byte
	n := len(prefix)

	fullBlocks := n / sivBlockSize
	for i := range fullBlocks {
		subtle.XORBytes(x[:], x[:], prefix[i*sivBlockSize:(i+1)*sivBlockSize])
		p.mac.Encrypt(x[:], x[:])
	}

	rem := n % sivBlockSize
	if rem == 0 {
		var last [sivBlockSize]byte
		copy(last[:], tail[:])
		subtle.XORBytes(last[:], last[:], p.k1[:])
		subtle.XORBytes(x[:], x[:], last[:])
		p.mac.Encrypt(out[:], x[:])
		return
	}

	var mid [sivBlockSize]byte
	copy(mid[:rem], prefix[fullBlocks*sivBlockSize:])
	copy(mid[rem:], tail[:sivBlockSize-rem])
	subtle.XORBytes(x[:], x[:], mid[:])
	p.mac.Encrypt(x[:], x[:])

	var last [sivBlockSize]byte
	copy(last[:], tail[sivBlockSize-rem:])
	last[rem] = 0x80
	subtle.XORBytes(last[:], last[:], p.k2[:])
	subtle.XORBytes(x[:], x[:], last[:])
	p.mac.Encrypt(out[:], x[:])
}

// s2v computes the Synthetic IV described in RFC 5297, section 2.4.
//
// S2V(K1, AD_1, ..., AD_m, plaintext) returns a 16-byte tag.
//
// The zero-copy path avoids materialising a modified plaintext copy when
// len(plaintext) is at least 16: only the last 16 bytes are XOR'd with D on the stack.
func (p *cmacPRF) s2v(additionalData [][]byte, plaintext []byte, out *[sivBlockSize]byte) {
	var d [sivBlockSize]byte
	p.cmac(zeroBlock[:], &d)

	for _, ad := range additionalData {
		var t [sivBlockSize]byte
		p.cmac(ad, &t)
		dblBlock(&d)
		subtle.XORBytes(d[:], d[:], t[:])
	}

	n := len(plaintext)
	if n >= sivBlockSize {
		var tail [sivBlockSize]byte
		copy(tail[:], plaintext[n-sivBlockSize:])
		subtle.XORBytes(tail[:], tail[:], d[:])
		p.cmacWithTail(plaintext[:n-sivBlockSize], &tail, out)
	} else {
		dblBlock(&d)
		var t [sivBlockSize]byte
		copy(t[:], plaintext)
		t[n] = 0x80
		subtle.XORBytes(t[:], t[:], d[:])
		p.cmacBlock(&t, out)
	}
}
