// Package padding implements common block cipher padding schemes.
package padding

import "fmt"

// Padding pads and unpads block cipher input.
type Padding interface {
	Pad(b []byte, blocksize int) ([]byte, error)
	String() string
	Unpad(b []byte, blocksize int) ([]byte, error)
}

type (
	// BlockSizeError is returned when a padding block size is invalid.
	BlockSizeError int

	// InvalidDataError is returned when padded data is malformed.
	InvalidDataError int

	bit      struct{}
	iso10126 struct{}
	iso7816  struct{}
	pkcs5    struct{}
	pkcs7    struct{}
	tbc      struct{}
	x923     struct{}
	zero     struct{}
)

var (
	// Bit is the bit padding scheme.
	Bit bit

	// ISO10126 is the ISO/IEC 10126 padding scheme.
	ISO10126 iso10126

	// ISO7816 is the ISO/IEC 7816-4 padding scheme.
	ISO7816 iso7816

	// PKCS5 is the PKCS #5 padding scheme.
	PKCS5 pkcs5

	// PKCS7 is the PKCS #7 padding scheme.
	PKCS7 pkcs7

	// TBC is the trailing bit complement padding scheme.
	TBC tbc

	// X923 is the ANSI X9.23 padding scheme.
	X923 x923

	// Zero is the zero padding scheme.
	Zero zero
)

func (i BlockSizeError) Error() string {
	return fmt.Sprintf("padding: invalid block size: %d", int(i))
}

func (i InvalidDataError) Error() string {
	if i == 0 {
		return "padding: empty data"
	}
	return fmt.Sprintf("padding: invalid data (not padded or not multiple of the block size) with size: %d", int(i))
}

// OverheadSize returns the padding length for length and blocksize.
func OverheadSize(length, blocksize int) int {
	return blocksize - (length & (blocksize - 1))
}
