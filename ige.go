package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"

	aesinternal "github.com/colduction/aes-go/internal/aes"
	"github.com/colduction/aes-go/padding"
)

func encryptIGE(block cipher.Block, src, iv []byte, pad padding.Padding) ([]byte, error) {
	var err error
	if pad != nil {
		if src, err = pad.Pad(src, stdaes.BlockSize); err != nil {
			return nil, err
		}
	}
	n := len(src)
	if n&blockMask != 0 {
		return nil, InvalidDataError(n)
	}
	dst := make([]byte, n)
	aesinternal.NewIGEEncrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

func decryptIGE(block cipher.Block, src, iv []byte, pad padding.Padding) ([]byte, error) {
	n := len(src)
	if n&blockMask != 0 {
		return nil, InvalidCiphertextError(n)
	}
	dst := make([]byte, n)
	aesinternal.NewIGEDecrypter(block, iv).CryptBlocks(dst, src)
	if pad != nil {
		return pad.Unpad(dst, stdaes.BlockSize)
	}
	return dst, nil
}
