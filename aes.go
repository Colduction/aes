package aes

import (
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
)

type (
	cbc struct{}
	cfb struct{}
	ctr struct{}
	ecb struct{}
	gcm struct{}
	ofb struct{}
)

var (
	CBC cbc // CBC (Cipher Block Chaining): Encrypts each block of plaintext with XOR chaining to the previous ciphertext block.
	CFB cfb // CFB (Cipher Feedback): Encrypts an IV and XORs it with plaintext segments, turning AES into a self-synchronizing stream cipher.
	CTR ctr // CTR (Counter): Encrypts a counter value and XORs it with plaintext, effectively turning AES into a stream cipher.
	ECB ecb // ECB (Electronic Codebook): Encrypts each block of plaintext independently.
	GCM gcm // GCM (Galois/Counter Mode): Combines CTR mode encryption with Galois mode for authentication, providing confidentiality and integrity.
	OFB ofb // OFB (Output Feedback): Encrypts an IV to create a keystream, XORed with plaintext to produce ciphertext, making AES a stream cipher.
)

type (
	BlockSizeError      int
	EmptyDataError      int
	InvalidDataError    int
	IvSizeEqualityError int
	IvSizeError         int
	KeySizeError        int
)

func (i BlockSizeError) Error() string {
	return fmt.Sprintf("aes: invalid block size %s", strconv.FormatInt(int64(i), 10))
}

func (EmptyDataError) Error() string {
	return "aes: data is empty"
}

func (i InvalidDataError) Error() string {
	return fmt.Sprintf("aes: invalid data (empty or not multiple of the block size) with size %s", strconv.FormatInt(int64(i), 10))
}

func (i IvSizeEqualityError) Error() string {
	return fmt.Sprintf("aes: iv size %s is not equal to the block size", strconv.FormatInt(int64(i), 10))
}

func (i IvSizeError) Error() string {
	return fmt.Sprintf("aes: invalid iv size %s", strconv.FormatInt(int64(i), 10))
}

func (k KeySizeError) Error() string {
	return fmt.Sprintf("aes: invalid key size %s", strconv.FormatInt(int64(k), 10))
}

func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func EmptyData(length int) error {
	if length <= 0 {
		return EmptyData(length)
	}
	return nil
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
