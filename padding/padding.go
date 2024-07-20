package padding

import "strconv"

type Padding interface {
	Pad(b []byte, blocksize int) ([]byte, error)
	String() string
	Unpad(b []byte, blocksize int) ([]byte, error)
}

type (
	BlockSizeError   int
	InvalidDataError int

	bit      struct{}
	iso10126 struct{}
	iso7816  struct{}
	pkcs5    struct{}
	pkcs7    struct{}
	x923     struct{}
	zero     struct{}
)

var (
	Bit      bit
	ISO10126 iso10126
	ISO7816  iso7816
	PKCS5    pkcs5
	PKCS7    pkcs7
	X923     x923
	Zero     zero
)

func (i BlockSizeError) Error() string {
	return "padding: invalid block size " + strconv.FormatInt(int64(i), 10)
}

func (i InvalidDataError) Error() string {
	return "padding: invalid data (empty, not padded or not multiple of the block size) with size " + strconv.FormatInt(int64(i), 10)
}

func OverheadSize(length, blocksize int) int { return blocksize - (length % blocksize) }
