package padding

import "bytes"

// Pads b to be a multiple of the block size using PKCS5
func (pkcs5) Pad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	padding := blocksize - lenB%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(b, padtext...), nil
}

// Removes the PKCS5 padding from b
func (pkcs5) Unpad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if lenB%blocksize != 0 {
		return nil, InvalidDataError(lenB)
	}
	padding := int(b[lenB-1])
	if padding > blocksize || padding == 0 {
		return nil, InvalidDataError(lenB)
	}
	for i, bPad := 0, byte(padding); i < padding; i++ {
		if b[lenB-1-i] != bPad {
			return nil, InvalidDataError(lenB)
		}
	}
	return b[:lenB-padding], nil
}
