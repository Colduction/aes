package padding

func (pkcs5) String() string {
	return "PKCS5Padding"
}

// Pad applies PKCS#5 padding, which is identical to PKCS#7 padding.
func (pkcs5) Pad(b []byte, blocksize int) ([]byte, error) {
	return PKCS7.Pad(b, blocksize)
}

// Unpad removes PKCS#5 padding.
func (pkcs5) Unpad(b []byte, blocksize int) ([]byte, error) {
	return PKCS7.Unpad(b, blocksize)
}
