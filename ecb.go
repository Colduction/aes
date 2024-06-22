package aes

import (
	stdaes "crypto/aes"

	"github.com/colduction/aes/padding"
)

// Encrypts plaintext using AES in ECB mode
func (ecb) Encrypt(input, key []byte, pad padding.Padding) ([]byte, error) {
	var (
		lenInput int = len(input)
		lenKey   int = len(key)
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
	if pad != nil {
		if input, err = pad.Pad(input, block.BlockSize()); err != nil {
			return nil, err
		}
		lenInput = len(input)
	}
	if lenInput%block.BlockSize() != 0 {
		return nil, InvalidDataError(lenInput)
	}
	ct := make([]byte, lenInput)
	for bs, be := 0, block.BlockSize(); bs < len(input); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(ct[bs:be], input[bs:be])
	}
	return ct, nil
}

// Decrypts ciphertext using AES in ECB mode
func (ecb) Decrypt(ciphertext, key []byte, pad padding.Padding) ([]byte, error) {
	var (
		lenCt  int   = len(ciphertext)
		lenKey int   = len(key)
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
	pt := make([]byte, lenCt)
	for bs, be := 0, block.BlockSize(); bs < len(ciphertext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(pt[bs:be], ciphertext[bs:be])
	}
	if pad != nil {
		pt, err = pad.Unpad(pt, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return pt, nil
}
