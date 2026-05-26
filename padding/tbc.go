package padding

func (tbc) String() string {
	return "TBCPadding"
}

// Pad pads b according to the Trailing Bit Complement (TBC) method
// (NIST SP 800-38A, padding method 3): if the last bit of the message is 0,
// each padding bit is 1 (0xFF bytes); if the last bit is 1, each padding bit
// is 0 (0x00 bytes). At least one byte is always appended.
func (tbc) Pad(b []byte, blocksize int) ([]byte, error) {
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
	var padByte byte
	if b[lenB-1]&1 == 0 {
		padByte = 0xFF
	}
	for i := lenB; i < len(padded); i++ {
		padded[i] = padByte
	}
	return padded, nil
}

// Unpad removes Trailing Bit Complement padding.
func (tbc) Unpad(b []byte, blocksize int) ([]byte, error) {
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
	lastByte := b[lenB-1]
	if lastByte != 0x00 && lastByte != 0xFF {
		return nil, InvalidDataError(lenB)
	}
	i := lenB - 1
	for i > 0 && b[i] == lastByte {
		i--
	}
	if b[i] == lastByte {
		return nil, InvalidDataError(lenB)
	}
	return b[:i+1], nil
}
