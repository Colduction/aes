package padding

func (pkcs5) String() string {
	return "PKCS5Padding"
}

// Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func (pkcs5) Pad(b []byte, blocksize int) ([]byte, error) {
	return PKCS7.Pad(b, blocksize)
}

// Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func (pkcs5) Unpad(b []byte, blocksize int) ([]byte, error) {
	return PKCS7.Unpad(b, blocksize)
}
