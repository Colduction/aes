package padding

func (bit) String() string {
	return "BitPadding"
}

// Pad appends 0x80 followed by zero bytes until b is a multiple of blocksize.
func (bit) Pad(b []byte, blocksize int) ([]byte, error) {
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
	padded[lenB] = 0x80
	return padded, nil
}

// Unpad removes bit padding: strip trailing 0x00 bytes, then the 0x80 marker.
func (bit) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	i := lenB - 1
	for i > 0 && b[i] == 0x00 {
		i--
	}
	if b[i] != 0x80 {
		return nil, InvalidDataError(lenB)
	}
	return b[:i], nil
}
