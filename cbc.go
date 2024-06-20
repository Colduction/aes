package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"

	"github.com/colduction/aes/padding"
)

// Encrypts plaintext using AES in CBC mode
func (cbc) Encrypt(input, key, iv []byte, pad padding.Padding) ([]byte, error) {
	var (
		lenInput int = len(input)
		lenKey   int = len(key)
		lenIv    int = len(iv)
	)
	if lenInput == 0 {
		return nil, InvalidDataError(lenInput)
	}
	err := ValidKeySize(lenKey)
	if err != nil {
		return nil, KeySizeError(lenKey)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = IvSizeEquality(lenIv, block.BlockSize()); err != nil {
		return nil, err
	}
	if lenInput%block.BlockSize() != 0 {
		return nil, InvalidDataError(lenInput)
	}
	if pad != nil {
		if input, err = pad.Pad(input, block.BlockSize()); err != nil {
			return nil, err
		}
	}
	ct := make([]byte, lenInput)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, input)
	return ct, nil
}

// Decrypts ciphertext using AES in CBC mode
func (cbc) Decrypt(ciphertext, key, iv []byte, pad padding.Padding) ([]byte, error) {
	var (
		lenCt  int   = len(ciphertext)
		lenKey int   = len(key)
		lenIv  int   = len(iv)
		err    error = nil
	)
	if err = ValidKeySize(lenKey); err != nil {
		return nil, KeySizeError(lenKey)
	}
	if lenCt%lenKey != 0 {
		return nil, InvalidDataError(lenCt)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = IvSizeEquality(lenIv, block.BlockSize()); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintextBytes := make([]byte, lenCt)
	mode.CryptBlocks(plaintextBytes, ciphertext)
	if pad != nil {
		plaintextBytes, err = pad.Unpad(plaintextBytes, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return plaintextBytes, nil
}
