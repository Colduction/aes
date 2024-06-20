package padding

import "strconv"

type Padding interface {
	Padding(data []byte, blockSize int) ([]byte, error)
	Unpadding(data []byte, blockSize int) ([]byte, error)
}

type (
	BlockSizeError   int
	InvalidDataError int

	pkcs5 struct{}
	pkcs7 struct{}
)

var (
	PKCS5 pkcs5
	PKCS7 pkcs7
)

func (i BlockSizeError) Error() string {
	return "padding: invalid block size " + strconv.FormatInt(int64(i), 10)
}

func (i InvalidDataError) Error() string {
	return "padding: invalid data (empty, not padded or not multiple of the block size) with size " + strconv.FormatInt(int64(i), 10)
}
