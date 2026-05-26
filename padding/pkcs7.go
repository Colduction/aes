package padding

func (pkcs7) String() string {
	return "PKCS7Padding"
}

// Pad right-pads b with 1 to blocksize bytes so that the total length is a
// multiple of blocksize. The pad byte value equals the number of bytes added.
func (pkcs7) Pad(b []byte, blocksize int) ([]byte, error) {
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
	for i := lenB; i < len(padded); i++ {
		padded[i] = byte(overhead)
	}
	return padded, nil
}

// Unpad validates and removes PKCS #7 padding.
func (pkcs7) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	var (
		c = b[lenB-1]
		n = int(c)
	)
	if n == 0 || n > lenB {
		return nil, InvalidDataError(lenB)
	}
	for i := lenB - n; i < lenB; i++ {
		if b[i] != c {
			return nil, InvalidDataError(lenB)
		}
	}
	return b[:lenB-n], nil
}
