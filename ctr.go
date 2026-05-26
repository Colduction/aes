package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"

	"github.com/colduction/aes-go/padding"
)

func encryptCTR(block cipher.Block, src, iv []byte, pad padding.Padding) ([]byte, error) {
	var err error
	if pad != nil {
		if src, err = pad.Pad(src, stdaes.BlockSize); err != nil {
			return nil, err
		}
	}
	dst := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func decryptCTR(block cipher.Block, src, iv []byte, pad padding.Padding) ([]byte, error) {
	dst := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	if pad != nil {
		return pad.Unpad(dst, stdaes.BlockSize)
	}
	return dst, nil
}
