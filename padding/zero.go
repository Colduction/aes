package padding

func (zero) String() string {
	return "ZeroPadding"
}

// Pad appends zero bytes until b is a multiple of blocksize.
func (zero) Pad(b []byte, blocksize int) ([]byte, error) {
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
	return padded, nil
}

// Unpad strips trailing zero bytes.
func (zero) Unpad(b []byte, blocksize int) ([]byte, error) {
	lenB := len(b)
	if lenB == 0 {
		return nil, InvalidDataError(lenB)
	}
	if blocksize <= 0 {
		return nil, BlockSizeError(blocksize)
	}
	if lenB&(blocksize-1) != 0 {
		return nil, InvalidDataError(lenB)
	}
	i := lenB
	for i > 0 && b[i-1] == 0x00 {
		i--
	}
	return b[:i], nil
}
