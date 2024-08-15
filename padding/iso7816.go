package padding

import "bytes"

func (iso7816) String() string {
	return "ISO7816Padding"
}

// Pad pads the b according to ISO/IEC 7816-4
func (iso7816) Pad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	overhead := OverheadSize(lenB, blocksize)
	padtext := bytes.Repeat([]byte{0x00}, overhead-1)
	return append(append(b, 0x80), padtext...), nil
}

// Unpad unpads the b according to ISO/IEC 7816-4
func (iso7816) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	padding := int(b[lenB-1])
	if padding > lenB || padding > blocksize {
		return nil, InvalidDataError(lenB)
	}
	paddingStart := bytes.LastIndexByte(b, 0x80)
	if paddingStart == -1 {
		return nil, InvalidDataError(lenB)
	}
	return b[:paddingStart], nil
}
