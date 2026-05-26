// Package aes provides internal AES cipher-mode primitives.
package aes

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// GCMSIV implements RFC 8452 AES-GCM-SIV authenticated encryption.
//
// AES-GCM-SIV uses POLYVAL (a variant of GHASH in the "reverse" field) as its
// authentication primitive and a key-derivation step to produce per-nonce
// authentication and encryption keys from a single master key.
//
// Key sizes: 16 bytes (AES-128-GCM-SIV) or 32 bytes (AES-256-GCM-SIV).
// Nonce size: 12 bytes (fixed by the RFC).
// Tag size: 16 bytes, appended at the end of the ciphertext.
type GCMSIV struct {
	keyLen    int
	masterKey [32]byte
	nonce     [12]byte
}

// NewGCMSIV creates an RFC 8452 AES-GCM-SIV AEAD from a 16 or 32-byte master
// key and a 12-byte nonce. The nonce must be unique per encryption operation.
func NewGCMSIV(masterKey, nonce []byte) (*GCMSIV, error) {
	switch len(masterKey) {
	case 16, 32:
	default:
		return nil, errors.New("siv: GCM-SIV master key must be 16 or 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, errors.New("siv: GCM-SIV nonce must be 12 bytes")
	}
	g := &GCMSIV{keyLen: len(masterKey)}
	copy(g.masterKey[:], masterKey)
	copy(g.nonce[:], nonce)
	return g, nil
}

// gcmsivDeriveKeys performs the RFC 8452 section 4 per-nonce key derivation.
//
// Counter blocks are LE32(i) || nonce (16 bytes). The master-key cipher
// encrypts each counter block and the first 8 bytes of each output are
// accumulated until we have 16 bytes for the authentication key and
// 16 or 32 bytes for the encryption key.
//
// Returns authKey (16 bytes) and encKey (16 or 32 bytes, len == g.keyLen).
func (g *GCMSIV) gcmsivDeriveKeys() (authKey [16]byte, encKey []byte) {
	block, err := aes.NewCipher(g.masterKey[:g.keyLen])
	if err != nil {
		panic("siv: gcmsivDeriveKeys: " + err.Error())
	}

	need := 16 + g.keyLen
	material := make([]byte, 0, 40)

	var ctr [sivBlockSize]byte
	copy(ctr[4:], g.nonce[:])

	for i := 0; len(material) < need; i++ {
		binary.LittleEndian.PutUint32(ctr[:4], uint32(i))
		var enc [sivBlockSize]byte
		block.Encrypt(enc[:], ctr[:])
		material = append(material, enc[:8]...)
	}

	copy(authKey[:], material[:16])
	encKey = make([]byte, g.keyLen)
	copy(encKey, material[16:16+g.keyLen])
	return
}

// gcmsivPolyval computes POLYVAL(H, aad, plaintext, lenBlock) per RFC 8452 section 4.
// It reuses our existing polyvalCompute helper from siv_ghash.go.
func gcmsivPolyval(authKey *[16]byte, aad, plaintext []byte) (result [sivBlockSize]byte) {
	var lenBlock [sivBlockSize]byte
	binary.LittleEndian.PutUint64(lenBlock[0:], uint64(len(aad))*8)
	binary.LittleEndian.PutUint64(lenBlock[8:], uint64(len(plaintext))*8)
	return polyvalCompute(authKey, aad, plaintext, lenBlock[:])
}

// gcmsivComputeTag computes the RFC 8452 authentication tag.
//
// S = POLYVAL(authKey, aad, plaintext) XOR nonce  (bytes 0..11)
// S[15] &= 0x7f  (clear bit 127)
// tag = AES_encKey(S)
func (g *GCMSIV) gcmsivComputeTag(encKey []byte, authKey *[16]byte, aad, plaintext []byte) (tag [sivBlockSize]byte) {
	S := gcmsivPolyval(authKey, aad, plaintext)

	for i := 0; i < 12; i++ {
		S[i] ^= g.nonce[i]
	}

	S[15] &= 0x7f

	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic("siv: gcmsivComputeTag: " + err.Error())
	}
	block.Encrypt(tag[:], S[:])
	return
}

// gcmsivCTREncrypt encrypts/decrypts using AES-CTR with the RFC 8452 counter
// mode: the initial counter is the tag with bit 127 set (tag[15] |= 0x80),
// and the counter increments as a 32-bit little-endian value in bytes 0..3
// (the remaining 12 bytes of the counter block are fixed).
//
// This is NOT the standard NIST CTR (which increments the last 4 bytes as
// big-endian). The 32-bit LE counter means this is limited to 2^32-1 blocks
// (~64 GiB) but the RFC imposes a 65535-block (1 MiB) per-call limit anyway.
func gcmsivCTREncrypt(encKey []byte, tag *[sivBlockSize]byte, dst, src []byte) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic("siv: gcmsivCTREncrypt: " + err.Error())
	}

	var ctr [sivBlockSize]byte
	copy(ctr[:], tag[:])
	ctr[15] |= 0x80

	var keyStream [sivBlockSize]byte
	ctrVal := binary.LittleEndian.Uint32(ctr[:4])

	for len(src) > 0 {
		binary.LittleEndian.PutUint32(ctr[:4], ctrVal)
		block.Encrypt(keyStream[:], ctr[:])
		ctrVal++

		n := len(src)
		if n > sivBlockSize {
			n = sivBlockSize
		}
		for i := range n {
			dst[i] = src[i] ^ keyStream[i]
		}
		src = src[n:]
		dst = dst[n:]
	}
}

// Seal encrypts and authenticates plaintext with associated data aad.
//
// Output layout: ciphertext || tag (16-byte authentication tag at the end).
// This follows the RFC 8452 convention (opposite to AES-CMAC-SIV which places
// the SIV at the front).
func (g *GCMSIV) Seal(aad, plaintext []byte) ([]byte, error) {
	authKey, encKey := g.gcmsivDeriveKeys()

	tag := g.gcmsivComputeTag(encKey, &authKey, aad, plaintext)

	out := make([]byte, len(plaintext)+sivBlockSize)
	gcmsivCTREncrypt(encKey, &tag, out[:len(plaintext)], plaintext)

	copy(out[len(plaintext):], tag[:])
	return out, nil
}

// Open authenticates and decrypts ciphertext (body || 16-byte tag).
//
// Returns the plaintext on success. On authentication failure it returns
// ErrSIVOpen and never exposes unauthenticated plaintext to the caller.
func (g *GCMSIV) Open(aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < sivBlockSize {
		return nil, ErrSIVOpen
	}

	body := ciphertext[:len(ciphertext)-sivBlockSize]
	var tag [sivBlockSize]byte
	copy(tag[:], ciphertext[len(ciphertext)-sivBlockSize:])

	authKey, encKey := g.gcmsivDeriveKeys()

	pt := make([]byte, len(body))
	gcmsivCTREncrypt(encKey, &tag, pt, body)

	expected := g.gcmsivComputeTag(encKey, &authKey, aad, pt)

	var mismatch uint8
	for i := range sivBlockSize {
		mismatch |= tag[i] ^ expected[i]
	}
	if mismatch != 0 {
		for i := range pt {
			pt[i] = 0
		}
		return nil, ErrSIVOpen
	}
	return pt, nil
}
