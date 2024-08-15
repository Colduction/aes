package aes

import (
	"crypto/rand"
	"fmt"
	"io"
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
	BlockSizeError         int
	EmptyDataError         int
	InvalidCiphertextError int
	InvalidDataError       int
	IvSizeEqualityError    int
	IvSizeError            int
	KeySizeError           int
)

func (i BlockSizeError) Error() string {
	return fmt.Sprintf("aes: invalid block size %d", int(i))
}

func (i InvalidCiphertextError) Error() string {
	if i == 0 {
		return "aes: empty ciphertext"
	}
	return fmt.Sprintf("aes: ciphertext size is not multiple of the block size: %d", int(i))
}

func (i InvalidDataError) Error() string {
	if i == 0 {
		return "aes: empty data"
	}
	return fmt.Sprintf("aes: data size is not multiple of the block size: %d", int(i))
}

func (i IvSizeEqualityError) Error() string {
	return fmt.Sprintf("aes: iv size is not equal to the block size: %d", int(i))
}

func (i IvSizeError) Error() string {
	return fmt.Sprintf("aes: invalid iv size: %d", int(i))
}

func (k KeySizeError) Error() string {
	return fmt.Sprintf("aes: invalid key size: %d", int(k))
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
	}
	return BlockSizeError(length)
}

func ValidKeySize(length int) error {
	switch length {
	case 16, 24, 32:
		return nil
	}
	return KeySizeError(length)
}

func ValidIvSize(length int) error {
	switch length {
	case 16, 24, 32:
		return nil
	}
	return IvSizeError(length)
}

func ValidCiphertext(length, blocksize int) error {
	if length%blocksize != 0 {
		return InvalidCiphertextError(length)
	}
	return nil
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
