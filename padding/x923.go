package padding

func (x923) String() string {
	return "X923Padding"
}

// Pad pads the b according to ANSI X9.23
func (x923) Pad(b []byte, blocksize int) ([]byte, error) {
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
	for i := lenB; i < lenB+overhead-1; i++ {
		padded[i] = 0
	}
	padded[lenB+overhead-1] = byte(overhead)
	return padded, nil
}

// Unpad unpads the b according to ANSI X9.23
func (x923) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	for i := lenB - padding; i < lenB-1; i++ {
		if b[i] != 0 {
			return nil, InvalidDataError(lenB)
		}
	}
	return b[:lenB-padding], nil
}
