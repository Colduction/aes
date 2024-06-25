package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"

	"github.com/colduction/aes/padding"
)

// Encrypts input using AES in CFB mode
func (cfb) Encrypt(input, key, iv []byte, pad padding.Padding) ([]byte, error) {
	var (
		lenInput int   = len(input)
		lenKey   int   = len(key)
		lenIv    int   = len(iv)
		err      error = nil
	)
	if err = EmptyData(lenInput); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, KeySizeError(lenKey)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
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
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ct, input)
	return ct, nil
}

// Decrypts ciphertext using AES in CFB mode
func (cfb) Decrypt(ciphertext, key, iv []byte, pad padding.Padding) ([]byte, error) {
	var (
		lenCt  int   = len(ciphertext)
		lenKey int   = len(key)
		lenIv  int   = len(iv)
		err    error = nil
	)
	if err = EmptyData(lenCt); err != nil {
		return nil, err
	}
	if err = ValidKeySize(lenKey); err != nil {
		return nil, KeySizeError(lenKey)
	}
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err = IvSizeEquality(lenIv, block.BlockSize()); err != nil {
		return nil, err
	}
	mode := cipher.NewCFBDecrypter(block, iv)
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
