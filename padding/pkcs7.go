package padding

import "bytes"

func (pkcs7) String() string {
	return "PKCS7Padding"
}

// Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func (pkcs7) Pad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	overhead := OverheadSize(lenB, blocksize)
	padded := make([]byte, lenB+overhead)
	copy(padded, b)
	copy(padded[lenB:], bytes.Repeat([]byte{byte(overhead)}, overhead))
	return padded, nil
}

// Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func (pkcs7) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	c := b[lenB-1]
	n := int(c)
	if n == 0 || n > lenB {
		return nil, InvalidDataError(lenB)
	}
	for i := 0; i < n; i++ {
		if b[lenB-n+i] != c {
			return nil, InvalidDataError(lenB)
		}
	}
	return b[:lenB-n], nil
}
