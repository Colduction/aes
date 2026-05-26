package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"

	"github.com/colduction/aes-go/padding"
)

func encryptECB(block cipher.Block, src []byte, pad padding.Padding) ([]byte, error) {
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
	for i := 0; i < n; i += stdaes.BlockSize {
		block.Encrypt(dst[i:i+stdaes.BlockSize], src[i:i+stdaes.BlockSize])
	}
	return dst, nil
}

func decryptECB(block cipher.Block, src []byte, pad padding.Padding) ([]byte, error) {
	n := len(src)
	if n&blockMask != 0 {
		return nil, InvalidCiphertextError(n)
	}
	dst := make([]byte, n)
	for i := 0; i < n; i += stdaes.BlockSize {
		block.Decrypt(dst[i:i+stdaes.BlockSize], src[i:i+stdaes.BlockSize])
	}
	if pad != nil {
		return pad.Unpad(dst, stdaes.BlockSize)
	}
	return dst, nil
}
