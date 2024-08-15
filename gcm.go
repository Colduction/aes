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
	GCMDataSizeError     int
	GCMStdNonceSizeError int
	GCMTagSizeError      int
)

func (i GCMStdNonceSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid nonce standard size %s, it must equal 12 bytes", strconv.FormatInt(int64(i), 10))
}

func (i GCMDataSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: invalid data size %s", strconv.FormatInt(int64(i), 10))
}

func (i GCMTagSizeError) Error() string {
	return fmt.Sprintf("aes-gcm: incorrect tag size %s, sizes betweeen 12 and 16 bytes are allowed", strconv.FormatInt(int64(i), 10))
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
	lenInput := len(input)
	if lenInput == 0 {
		return nil, InvalidDataError(lenInput)
	}
	err := GCM.ValidStdNonceSize(len(nonce))
	if err != nil {
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
	lenInput := len(input)
	if lenInput == 0 {
		return nil, InvalidDataError(lenInput)
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
	aed, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	return aed.Seal(dst, nonce, input, additionalData), nil
}

// Encrypts input using AES in GCM mode with custom tag size and default nonce size (12)
func (gcm) EncryptWithTagSize(input, key, nonce, additionalData []byte, tagSize int, pad padding.Padding, dst ...byte) ([]byte, error) {
	lenInput := len(input)
	if lenInput == 0 {
		return nil, InvalidDataError(lenInput)
	}
	err := GCM.ValidStdNonceSize(len(nonce))
	if err != nil {
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
	lenCt := len(ciphertext)
	if lenCt == 0 {
		return nil, InvalidCiphertextError(lenCt)
	}
	err := GCM.ValidStdNonceSize(len(nonce))
	if err != nil {
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
	lenCt := len(ciphertext)
	if lenCt == 0 {
		return nil, InvalidCiphertextError(lenCt)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = GCM.ValidDataSize(lenCt, block.BlockSize()); err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCMWithNonceSize(block, len(nonce))
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
	lenCt := len(ciphertext)
	if lenCt == 0 {
		return nil, InvalidCiphertextError(lenCt)
	}
	err := GCM.ValidStdNonceSize(len(nonce))
	if err != nil {
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
	mode, err := cipher.NewGCMWithTagSize(block, tagSize)
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
