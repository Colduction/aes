package padding

import "strconv"

type Padding interface {
	Pad(data []byte, blocksize int) ([]byte, error)
	Unpad(data []byte, blocksize int) ([]byte, error)
}

type (
	BlockSizeError   int
	InvalidDataError int

	pkcs5 struct{}
	pkcs7 struct{}
	zero  struct{}
)

var (
	PKCS5 pkcs5
	PKCS7 pkcs7
	Zero  zero
)

func (i BlockSizeError) Error() string {
	return "padding: invalid block size " + strconv.FormatInt(int64(i), 10)
}

func (i InvalidDataError) Error() string {
	return "padding: invalid data (empty, not padded or not multiple of the block size) with size " + strconv.FormatInt(int64(i), 10)
}

func (pkcs5) String() string {
	return "PKCS5Padding"
}

func (pkcs7) String() string {
	return "PKCS7Padding"
}

func (zero) String() string {
	return "ZeroPadding"
}
