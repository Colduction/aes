package aes

import (
	"errors"
	"fmt"

	aesinternal "github.com/colduction/aes-go/internal/aes"
)

const (
	// SIVTagSize is the size, in bytes, of an AES-SIV authentication tag.
	SIVTagSize = 16

	// SIVKeySize128 is the size, in bytes, of an AES-128-SIV key.
	SIVKeySize128 = KeySize128 << 1

	// SIVKeySize192 is the size, in bytes, of an AES-192-SIV key.
	SIVKeySize192 = KeySize192 << 1

	// SIVKeySize256 is the size, in bytes, of an AES-256-SIV key.
	SIVKeySize256 = KeySize256 << 1
)

// SIVKeySizeError is returned when an AES-SIV key has the wrong length.
type SIVKeySizeError int

func (e SIVKeySizeError) Error() string {
	return fmt.Sprintf("aes-siv: invalid key size %d: must be %d, %d, or %d bytes", int(e), SIVKeySize128, SIVKeySize192, SIVKeySize256)
}

// ErrSIVAuthFailed is returned when SIV authentication fails.
var ErrSIVAuthFailed = aesinternal.ErrSIVOpen

// sivCipher is an AES-SIV authenticated encryption cipher.
//
// Its nonce size is zero because RFC 5297 AES-SIV is deterministic. The output
// is a 16-byte SIV tag followed by ciphertext.
type sivCipher struct {
	siv            *aesinternal.SIV
	additionalData [][]byte
}

var _ AEADCipher = (*sivCipher)(nil)

// GenerateSIVKey returns a new random AES-SIV key of the given size.
//
// The size must be [SIVKeySize128], [SIVKeySize192], or [SIVKeySize256].
func GenerateSIVKey(size int) ([]byte, error) {
	switch size {
	case SIVKeySize128, SIVKeySize192, SIVKeySize256:
	default:
		return nil, SIVKeySizeError(size)
	}
	return GenerateRandomBytes(size)
}

// NewSIV returns a new AES-SIV AEAD.
//
// The key must be [SIVKeySize128], [SIVKeySize192], or [SIVKeySize256] bytes
// long. Additional data should normally be supplied to Seal and Open. The
// optional additionalData values are kept for the legacy Encrypt and Decrypt
// helpers.
func NewSIV(key []byte, additionalData ...[]byte) (AEADCipher, error) {
	switch len(key) {
	case SIVKeySize128, SIVKeySize192, SIVKeySize256:
	default:
		return nil, SIVKeySizeError(len(key))
	}

	siv, err := aesinternal.NewSIV(key)
	if err != nil {
		return nil, err
	}
	return &sivCipher{siv: siv, additionalData: cloneAdditionalData(additionalData)}, nil
}

// NonceSize returns zero.
func (c *sivCipher) NonceSize() int { return 0 }

// Overhead returns the number of bytes added by Seal.
func (c *sivCipher) Overhead() int { return SIVTagSize }

// Seal encrypts and authenticates plaintext, appending the result to dst.
func (c *sivCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 0 {
		panic("aes-siv: incorrect nonce length given to Seal")
	}
	sealed := c.siv.Seal(c.sivAdditionalData(additionalData), plaintext)
	return append(dst, sealed...)
}

// Open authenticates and decrypts ciphertext, appending the result to dst.
func (c *sivCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 0 {
		panic("aes-siv: incorrect nonce length given to Open")
	}
	if len(ciphertext) < SIVTagSize {
		return nil, InvalidCiphertextError(len(ciphertext))
	}
	plaintext, err := c.siv.Open(c.sivAdditionalData(additionalData), ciphertext)
	if err != nil {
		return nil, ErrSIVAuthFailed
	}
	return append(dst, plaintext...), nil
}

// Encrypt encrypts plaintext using the additional data passed to NewSIV.
func (c *sivCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.Seal(nil, nil, plaintext, nil), nil
}

// Decrypt decrypts ciphertext using the additional data passed to NewSIV.
func (c *sivCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.Open(nil, nil, ciphertext, nil)
}

func (c *sivCipher) sivAdditionalData(additionalData []byte) [][]byte {
	if len(c.additionalData) == 0 {
		if len(additionalData) == 0 {
			return nil
		}
		return [][]byte{additionalData}
	}
	out := make([][]byte, 0, len(c.additionalData)+1)
	out = append(out, c.additionalData...)
	if len(additionalData) != 0 {
		out = append(out, additionalData)
	}
	return out
}

const (
	// GHASHSIVKeySize128 is the size, in bytes, of an AES-128-GHASH-SIV key.
	GHASHSIVKeySize128 = KeySize128

	// GHASHSIVKeySize192 is the size, in bytes, of an AES-192-GHASH-SIV key.
	GHASHSIVKeySize192 = KeySize192

	// GHASHSIVKeySize256 is the size, in bytes, of an AES-256-GHASH-SIV key.
	GHASHSIVKeySize256 = KeySize256
)

// GHASHSIVKeySizeError is returned when an AES-GHASH-SIV key has the wrong length.
type GHASHSIVKeySizeError int

func (e GHASHSIVKeySizeError) Error() string {
	return fmt.Sprintf("aes-ghash-siv: invalid key size %d: must be %d, %d, or %d bytes", int(e), GHASHSIVKeySize128, GHASHSIVKeySize192, GHASHSIVKeySize256)
}

// NewGHASHSIV returns a new AES-GHASH-SIV AEAD.
//
// AES-GHASH-SIV has the same public behavior as [NewSIV], but uses GHASH
// instead of CMAC for the synthetic IV calculation.
func NewGHASHSIV(key []byte, additionalData ...[]byte) (AEADCipher, error) {
	switch len(key) {
	case GHASHSIVKeySize128, GHASHSIVKeySize192, GHASHSIVKeySize256:
	default:
		return nil, GHASHSIVKeySizeError(len(key))
	}

	siv, err := aesinternal.NewGHASHSIV(key)
	if err != nil {
		return nil, err
	}
	return &sivCipher{siv: siv, additionalData: cloneAdditionalData(additionalData)}, nil
}

const (
	// AESGCMSIVKeySize128 is the size, in bytes, of an AES-128-GCM-SIV key.
	AESGCMSIVKeySize128 = KeySize128

	// AESGCMSIVKeySize256 is the size, in bytes, of an AES-256-GCM-SIV key.
	AESGCMSIVKeySize256 = KeySize256

	// AESGCMSIVNonceSize is the required AES-GCM-SIV nonce size, in bytes.
	AESGCMSIVNonceSize = 12

	// AESGCMSIVTagSize is the size, in bytes, of an AES-GCM-SIV tag.
	AESGCMSIVTagSize = 16
)

// AESGCMSIVKeySizeError is returned when an AES-GCM-SIV key has the wrong length.
type AESGCMSIVKeySizeError int

func (e AESGCMSIVKeySizeError) Error() string {
	return fmt.Sprintf("aes-gcm-siv: invalid key size %d: must be %d or %d bytes", int(e), AESGCMSIVKeySize128, AESGCMSIVKeySize256)
}

// AESGCMSIVNonceSizeError is returned when an AES-GCM-SIV nonce has the wrong length.
type AESGCMSIVNonceSizeError int

func (e AESGCMSIVNonceSizeError) Error() string {
	return fmt.Sprintf("aes-gcm-siv: invalid nonce size %d: must be %d bytes", int(e), AESGCMSIVNonceSize)
}

// aesGCMSIVCipher is an RFC 8452 AES-GCM-SIV authenticated encryption cipher.
//
// Its nonce size is 12 bytes, and Seal appends a 16-byte authentication tag
// after the ciphertext.
type aesGCMSIVCipher struct {
	masterKey      []byte
	nonce          []byte
	additionalData []byte
}

var _ AEADCipher = (*aesGCMSIVCipher)(nil)

var errTooManyAESGCMSIVOptions = errors.New("aes-gcm-siv: too many constructor arguments")

// NewAESGCMSIV returns a new RFC 8452 AES-GCM-SIV AEAD.
//
// The masterKey must be [AESGCMSIVKeySize128] or [AESGCMSIVKeySize256] bytes
// long. New code should pass the nonce and additional data to Seal and Open.
// Passing nonce and additionalData here is supported for the legacy Encrypt
// and Decrypt helpers.
func NewAESGCMSIV(masterKey []byte, nonceAndData ...[]byte) (AEADCipher, error) {
	switch len(masterKey) {
	case AESGCMSIVKeySize128, AESGCMSIVKeySize256:
	default:
		return nil, AESGCMSIVKeySizeError(len(masterKey))
	}
	if len(nonceAndData) > 2 {
		return nil, errTooManyAESGCMSIVOptions
	}

	keyCopy := make([]byte, len(masterKey))
	copy(keyCopy, masterKey)

	var nonceCopy []byte
	if len(nonceAndData) > 0 {
		nonce := nonceAndData[0]
		if len(nonce) != AESGCMSIVNonceSize {
			return nil, AESGCMSIVNonceSizeError(len(nonce))
		}
		nonceCopy = make([]byte, len(nonce))
		copy(nonceCopy, nonce)
	}

	var adCopy []byte
	if len(nonceAndData) > 1 && len(nonceAndData[1]) > 0 {
		adCopy = make([]byte, len(nonceAndData[1]))
		copy(adCopy, nonceAndData[1])
	}

	return &aesGCMSIVCipher{masterKey: keyCopy, nonce: nonceCopy, additionalData: adCopy}, nil
}

// NonceSize returns the required nonce size.
func (c *aesGCMSIVCipher) NonceSize() int { return AESGCMSIVNonceSize }

// Overhead returns the number of bytes added by Seal.
func (c *aesGCMSIVCipher) Overhead() int { return AESGCMSIVTagSize }

// Seal encrypts and authenticates plaintext, appending the result to dst.
func (c *aesGCMSIVCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != AESGCMSIVNonceSize {
		panic("aes-gcm-siv: incorrect nonce length given to Seal")
	}
	g, err := aesinternal.NewGCMSIV(c.masterKey, nonce)
	if err != nil {
		panic("aes-gcm-siv: " + err.Error())
	}
	sealed, err := g.Seal(additionalData, plaintext)
	if err != nil {
		panic("aes-gcm-siv: " + err.Error())
	}
	return append(dst, sealed...)
}

// Open authenticates and decrypts ciphertext, appending the result to dst.
func (c *aesGCMSIVCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != AESGCMSIVNonceSize {
		panic("aes-gcm-siv: incorrect nonce length given to Open")
	}
	if len(ciphertext) < AESGCMSIVTagSize {
		return nil, InvalidCiphertextError(len(ciphertext))
	}
	g, err := aesinternal.NewGCMSIV(c.masterKey, nonce)
	if err != nil {
		return nil, err
	}
	plaintext, err := g.Open(additionalData, ciphertext)
	if err != nil {
		return nil, ErrSIVAuthFailed
	}
	return append(dst, plaintext...), nil
}

// Encrypt encrypts plaintext using the nonce and additional data passed to NewAESGCMSIV.
func (c *aesGCMSIVCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(c.nonce) != AESGCMSIVNonceSize {
		return nil, AESGCMSIVNonceSizeError(len(c.nonce))
	}
	return c.Seal(nil, c.nonce, plaintext, c.additionalData), nil
}

// Decrypt decrypts ciphertext using the nonce and additional data passed to NewAESGCMSIV.
func (c *aesGCMSIVCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(c.nonce) != AESGCMSIVNonceSize {
		return nil, AESGCMSIVNonceSizeError(len(c.nonce))
	}
	return c.Open(nil, c.nonce, ciphertext, c.additionalData)
}

func cloneAdditionalData(additionalData [][]byte) [][]byte {
	if len(additionalData) == 0 {
		return nil
	}
	out := make([][]byte, len(additionalData))
	for i, data := range additionalData {
		if len(data) == 0 {
			continue
		}
		out[i] = make([]byte, len(data))
		copy(out[i], data)
	}
	return out
}
