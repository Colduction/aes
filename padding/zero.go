package padding

import "bytes"

func (zero) Pad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	padding := blocksize - lenB%blocksize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(b, padtext...), nil
}

func (zero) Unpad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	if lenB%blocksize != 0 {
		return nil, InvalidDataError(lenB)
	}
	return bytes.TrimFunc(b, func(r rune) bool {
		return r == 0
	}), nil
}
