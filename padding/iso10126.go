package padding

import "crypto/rand"

func (iso10126) String() string {
	return "ISO10126Padding"
}

// Pad right-pads b to a multiple of blocksize using ISO/IEC 10126:
// intermediate bytes are random, and the final byte records the pad count.
func (iso10126) Pad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	var (
		overhead = OverheadSize(lenB, blocksize)
		padded   = make([]byte, lenB+overhead)
	)
	copy(padded, b)
	if _, err := rand.Read(padded[lenB : lenB+overhead-1]); err != nil {
		return nil, err
	}
	padded[lenB+overhead-1] = byte(overhead)
	return padded, nil
}

// Unpad removes ISO/IEC 10126 padding.
func (iso10126) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	padding := int(b[lenB-1])
	if padding > lenB || padding > blocksize {
		return nil, InvalidDataError(lenB)
	}
	return b[:lenB-padding], nil
}
