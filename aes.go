package aes

import (
	"crypto/rand"
	"io"
	"strconv"
)

type (
	cbc struct{}
	ecb struct{}
)

var (
	CBC cbc
	ECB ecb
)

type (
	BlockSizeError      int
	InvalidDataError    int
	IvSizeEqualityError int
	IvSizeError         int
	KeySizeError        int
)

func (i BlockSizeError) Error() string {
	return "aes: invalid block size " + strconv.FormatInt(int64(i), 10)
}

func (i InvalidDataError) Error() string {
	return "aes: invalid data (empty or not multiple of the block size) with size " + strconv.FormatInt(int64(i), 10)
}

func (i IvSizeEqualityError) Error() string {
	return "aes: iv size (" + strconv.FormatInt(int64(i), 10) + ") is not equal to the block size"
}

func (i IvSizeError) Error() string {
	return "aes: invalid iv size " + strconv.FormatInt(int64(i), 10)
}

func (k KeySizeError) Error() string {
	return "aes: invalid key size " + strconv.FormatInt(int64(k), 10)
}

func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func ValidBlockSize(length int) error {
	switch length {
	case 16, 24, 32:
		return nil
	default:
		return BlockSizeError(length)
	}
}

func ValidKeySize(length int) error {
	switch length {
	case 16, 24, 32:
		return nil
	default:
		return KeySizeError(length)
	}
}

func ValidIvSize(length int) error {
	switch length {
	case 16, 24, 32:
		return nil
	default:
		return IvSizeError(length)
	}
}

func IvSizeEquality(length, blocksize int) (err error) {
	if err = ValidIvSize(length); err != nil {
		return err
	}
	if err = ValidBlockSize(blocksize); err != nil {
		return err
	}
	if length != blocksize {
		return IvSizeEqualityError(length)
	}
	return err
}
