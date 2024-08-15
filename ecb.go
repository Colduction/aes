package aes

import (
	stdaes "crypto/aes"

	"github.com/colduction/aes/padding"
)

// Encrypts input using AES in ECB mode
func (ecb) Encrypt(input, key []byte, pad padding.Padding) ([]byte, error) {
	lenInput := len(input)
	if lenInput == 0 {
		return nil, InvalidDataError(lenInput)
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
	for bs, be := 0, block.BlockSize(); bs < lenInput; bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(ct[bs:be], input[bs:be])
	}
	return ct, nil
}

// Decrypts ciphertext using AES in ECB mode
func (ecb) Decrypt(ciphertext, key []byte, pad padding.Padding) ([]byte, error) {
	lenCt := len(ciphertext)
	if lenCt == 0 {
		return nil, InvalidCiphertextError(lenCt)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = ValidCiphertext(lenCt, block.BlockSize()); err != nil {
		return nil, err
	}
	pt := make([]byte, lenCt)
	for bs, be := 0, block.BlockSize(); bs < lenCt; bs, be = bs+block.BlockSize(), be+block.BlockSize() {
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
