package padding

import "bytes"

func (bit) String() string {
	return "BitPadding"
}

// Pad pads the b with bit padding.
func (bit) Pad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	overhead := OverheadSize(lenB, blocksize)
	padtext := append(b, 0x80)
	overhead--
	if overhead > 0 {
		padtext = append(padtext, bytes.Repeat([]byte{0x00}, overhead)...)
	}
	return padtext, nil
}

// Unpad removes the bit padding from the b.
func (bit) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	for lenB > 0 && b[lenB-1] == 0x00 {
		lenB--
	}
	if lenB > 0 && b[lenB-1] == 0x80 {
		lenB--
	} else {
		return nil, InvalidDataError(lenB)
	}
	return b[:lenB], nil
}
