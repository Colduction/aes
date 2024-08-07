package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"fmt"
	"strconv"

	"github.com/colduction/aes/padding"
)

const (
	gcmBlockSize    int = 16
	gcmMinTagSize   int = 12
	gcmStdNonceSize int = gcmMinTagSize
)

type (
	GCMBlockSizeError     int
	GCMDataSizeError      int
	GCMNonceZeroSizeError int
	GCMStdNonceSizeError  int
	GCMTagSizeError       int
)

func (i GCMBlockSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid block size %s, it must equal 16 bytes", strconv.FormatInt(int64(i), 10))
}

func (GCMNonceZeroSizeError) Error() string {
	return "aes-gcm: the nonce can't have zero length, or the security of the key will be immediately compromised"
}

func (i GCMStdNonceSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid nonce standard size %s, it must equal 12 bytes", strconv.FormatInt(int64(i), 10))
}

func (i GCMDataSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid data size %s", strconv.FormatInt(int64(i), 10))
}

func (i GCMTagSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: incorrect tag size %s, sizes betweeen 12 and 16 bytes are allowed", strconv.FormatInt(int64(i), 10))
}

func (gcm) ValidBlockSize(length int) error {
	if length != gcmBlockSize {
		return GCMBlockSizeError(length)
	}
	return nil
}

func (gcm) ValidNonceSize(length int) error {
	if length <= 0 {
		return GCMNonceZeroSizeError(length)
	}
	return nil
}

func (gcm) ValidStdNonceSize(length int) error {
	if length != gcmStdNonceSize {
		return GCMStdNonceSizeError(length)
	}
	return nil
}

func (gcm) ValidTagSize(length int) error {
	if length < gcmMinTagSize || length > gcmBlockSize {
		return GCMTagSizeError(length)
	}
	return nil
}

func (gcm) ValidDataSize(length, blocksize int) error {
	if uint64(length) > ((1<<32)-2)*uint64(blocksize) {
		return GCMDataSizeError(length)
	}
	return nil
}

// Encrypts input using AES in GCM mode
func (gcm) Encrypt(input, key, nonce, additionalData []byte, pad padding.Padding, dst ...byte) ([]byte, error) {
	var (
		lenInput int   = len(input)
		lenKey   int   = len(key)
		lenNonce int   = len(nonce)
		err      error = nil
	)
	if err = EmptyData(lenInput); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, KeySizeError(lenKey)
	}
	if err = GCM.ValidStdNonceSize(lenNonce); err != nil {
		return nil, err
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenInput, block.BlockSize()); err != nil {
		return nil, err
	}
	if pad != nil {
		if input, err = pad.Pad(input, block.BlockSize()); err != nil {
			return nil, err
		}
	}
	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aed.Seal(dst, nonce, input, additionalData), nil
}

// Encrypts input using AES in GCM mode with custom nonce size and default tag size (16)
func (gcm) EncryptWithNonceSize(input, key, nonce, additionalData []byte, pad padding.Padding, dst ...byte) ([]byte, error) {
	var (
		lenInput int   = len(input)
		lenKey   int   = len(key)
		lenNonce int   = len(nonce)
		err      error = nil
	)
	if err = EmptyData(lenInput); err != nil {
		return nil, err
	}
	if err := ValidKeySize(lenKey); err != nil {
		return nil, KeySizeError(lenKey)
	}
	if err = GCM.ValidNonceSize(lenNonce); err != nil {
		return nil, err
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenInput, block.BlockSize()); err != nil {
		return nil, err
	}
	if pad != nil {
		if input, err = pad.Pad(input, block.BlockSize()); err != nil {
			return nil, err
		}
	}
	aed, err := cipher.NewGCMWithNonceSize(block, lenNonce)
	if err != nil {
		return nil, err
	}
	return aed.Seal(dst, nonce, input, additionalData), nil
}

// Encrypts input using AES in GCM mode with custom tag size and default nonce size (12)
func (gcm) EncryptWithTagSize(input, key, nonce, additionalData []byte, tagSize int, pad padding.Padding, dst ...byte) ([]byte, error) {
	var (
		lenInput int   = len(input)
		lenKey   int   = len(key)
		lenNonce int   = len(nonce)
		err      error = nil
	)
	if err = EmptyData(lenInput); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, KeySizeError(lenKey)
	}
	if err = GCM.ValidStdNonceSize(lenNonce); err != nil {
		return nil, err
	}
	if err = GCM.ValidTagSize(tagSize); err != nil {
		return nil, err
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenInput, block.BlockSize()); err != nil {
		return nil, err
	}
	if pad != nil {
		if input, err = pad.Pad(input, block.BlockSize()); err != nil {
			return nil, err
		}
	}
	aed, err := cipher.NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, err
	}
	return aed.Seal(dst, nonce, input, additionalData), nil
}

// Decrypts ciphertext using AES in GCM mode
func (gcm) Decrypt(ciphertext, key, nonce, additionalData []byte, pad padding.Padding, dst ...byte) ([]byte, error) {
	var (
		lenCt    int   = len(ciphertext)
		lenKey   int   = len(key)
		lenNonce int   = len(nonce)
		err      error = nil
	)
	if err = EmptyData(lenCt); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, err
	}
	if err = GCM.ValidStdNonceSize(lenNonce); err != nil {
		return nil, err
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenCt, block.BlockSize()); err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := mode.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	if pad != nil {
		pt, err = pad.Unpad(pt, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return pt, nil
}

// Decrypts ciphertext using AES in GCM mode with custom nonce size and default tag size (16)
func (gcm) DecryptWithNonceSize(ciphertext, key, nonce, additionalData []byte, pad padding.Padding, dst ...byte) ([]byte, error) {
	var (
		lenCt    int   = len(ciphertext)
		lenKey   int   = len(key)
		lenNonce int   = len(nonce)
		err      error = nil
	)
	if err = EmptyData(lenCt); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, err
	}
	if err = GCM.ValidNonceSize(lenNonce); err != nil {
		return nil, err
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenCt, block.BlockSize()); err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCMWithNonceSize(block, lenNonce)
	if err != nil {
		return nil, err
	}
	pt, err := mode.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	if pad != nil {
		pt, err = pad.Unpad(pt, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return pt, nil
}

// Decrypts ciphertext using AES in GCM mode with custom tag size and default nonce size (12)
func (gcm) DecryptWithTagSize(ciphertext, key, nonce, additionalData []byte, tagSize int, pad padding.Padding, dst ...byte) ([]byte, error) {
	var (
		lenCt    int   = len(ciphertext)
		lenKey   int   = len(key)
		lenNonce int   = len(nonce)
		err      error = nil
	)
	if err = EmptyData(lenCt); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, err
	}
	if err = GCM.ValidStdNonceSize(lenNonce); err != nil {
		return nil, err
	}
	if err = GCM.ValidTagSize(tagSize); err != nil {
		return nil, err
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenCt, block.BlockSize()); err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCMWithTagSize(block, lenNonce)
	if err != nil {
		return nil, err
	}
	pt, err := mode.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	if pad != nil {
		pt, err = pad.Unpad(pt, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return pt, nil
}
