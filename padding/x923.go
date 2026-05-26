package padding

func (x923) String() string {
	return "X923Padding"
}

// Pad pads b according to ANSI X9.23:
// zero-fills up to the second-to-last byte, then writes the pad count.
func (x923) Pad(b []byte, blocksize int) ([]byte, error) {
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
	padded[lenB+overhead-1] = byte(overhead)
	return padded, nil
}

// Unpad removes ANSI X9.23 padding.
func (x923) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	padLen := int(b[lenB-1])
	if padLen == 0 || padLen > lenB || padLen > blocksize {
		return nil, InvalidDataError(lenB)
	}
	for i := lenB - padLen; i < lenB-1; i++ {
		if b[i] != 0 {
			return nil, InvalidDataError(lenB)
		}
	}
	return b[:lenB-padLen], nil
}
