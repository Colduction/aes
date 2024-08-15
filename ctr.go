package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"

	"github.com/colduction/aes/padding"
)

// Encrypts input using AES in CTR mode
func (ctr) Encrypt(input, key, iv []byte, pad padding.Padding) ([]byte, error) {
	lenInput := len(input)
	if lenInput == 0 {
		return nil, InvalidDataError(lenInput)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	lenIv := len(iv)
	if err = IvSizeEquality(lenIv, block.BlockSize()); err != nil {
		return nil, err
	}
	if pad != nil {
		if input, err = pad.Pad(input, block.BlockSize()); err != nil {
			return nil, err
		}
		lenInput = len(input)
	}
	ct := make([]byte, lenInput)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ct, input)
	return ct, nil
}

// Decrypts ciphertext using AES in CTR mode
func (ctr) Decrypt(ciphertext, key, iv []byte, pad padding.Padding) ([]byte, error) {
	lenCt := len(ciphertext)
	if lenCt == 0 {
		return nil, InvalidCiphertextError(lenCt)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	lenIv := len(iv)
	if err = IvSizeEquality(lenIv, block.BlockSize()); err != nil {
		return nil, err
	}
	mode := cipher.NewCTR(block, iv)
	pt := make([]byte, lenCt)
	mode.XORKeyStream(pt, ciphertext)
	if pad != nil {
		pt, err = pad.Unpad(pt, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return pt, nil
}
