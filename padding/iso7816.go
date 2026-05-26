package padding

func (iso7816) String() string {
	return "ISO7816Padding"
}

// Pad appends 0x80 followed by zero bytes until b is a multiple of blocksize
// (ISO/IEC 7816-4 bit padding).
func (iso7816) Pad(b []byte, blocksize int) ([]byte, error) {
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

// Unpad removes ISO/IEC 7816-4 padding.
func (iso7816) Unpad(b []byte, blocksize int) ([]byte, error) {
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
