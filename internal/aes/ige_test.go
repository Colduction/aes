package aes

import (
	"bytes"
	stdaes "crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"
)

func xorBuf(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func refEncrypt(block cipher.Block, iv, src []byte) []byte {
	bs := stdaes.BlockSize
	ct := make([]byte, len(src))
	prevCT := make([]byte, bs)
	prevPT := make([]byte, bs)
	copy(prevCT, iv[:bs])
	copy(prevPT, iv[bs:IVSize])
	tmp := make([]byte, bs)
	for i := 0; i < len(src); i += bs {
		xorBuf(tmp, src[i:i+bs], prevCT)
		block.Encrypt(tmp, tmp)
		xorBuf(ct[i:i+bs], tmp, prevPT)
		copy(prevCT, ct[i:i+bs])
		copy(prevPT, src[i:i+bs])
	}
	return ct
}

func refDecrypt(block cipher.Block, iv, src []byte) []byte {
	bs := stdaes.BlockSize
	pt := make([]byte, len(src))
	prevCT := make([]byte, bs)
	prevPT := make([]byte, bs)
	copy(prevCT, iv[:bs])
	copy(prevPT, iv[bs:IVSize])
	tmp := make([]byte, bs)
	for i := 0; i < len(src); i += bs {
		xorBuf(tmp, src[i:i+bs], prevPT)
		block.Decrypt(tmp, tmp)
		xorBuf(pt[i:i+bs], tmp, prevCT)
		copy(prevCT, src[i:i+bs])
		copy(prevPT, pt[i:i+bs])
	}
	return pt
}

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func fillBytes(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func newBlock(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	block, err := stdaes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher(%d-byte key): %v", len(key), err)
	}
	return block
}

var testKeySizes = []struct {
	label string
	size  int
}{
	{"AES-128", 16},
	{"AES-192", 24},
	{"AES-256", 32},
}

func TestBlockSize(t *testing.T) {
	block := newBlock(t, fillBytes(16, 0xaa))
	iv := fillBytes(IVSize, 0xbb)
	if got := NewIGEEncrypter(block, iv).BlockSize(); got != stdaes.BlockSize {
		t.Errorf("IGEEncrypter.BlockSize() = %d, want %d", got, stdaes.BlockSize)
	}
	if got := NewIGEDecrypter(block, iv).BlockSize(); got != stdaes.BlockSize {
		t.Errorf("IGEDecrypter.BlockSize() = %d, want %d", got, stdaes.BlockSize)
	}
}

func TestEncryptMatchesReference(t *testing.T) {
	sizes := []int{
		stdaes.BlockSize,
		stdaes.BlockSize * 2,
		stdaes.BlockSize * 8,
		stdaes.BlockSize * 64,
	}
	for _, ks := range testKeySizes {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%s/%dB", ks.label, sz), func(t *testing.T) {
				key := seqBytes(ks.size)
				iv := seqBytes(IVSize)
				pt := seqBytes(sz)

				block := newBlock(t, key)
				want := refEncrypt(block, iv, pt)

				dst := make([]byte, sz)
				NewIGEEncrypter(block, iv).CryptBlocks(dst, pt)

				if !bytes.Equal(dst, want) {
					t.Error("output does not match reference implementation")
				}
			})
		}
	}
}

func TestDecryptMatchesReference(t *testing.T) {
	sizes := []int{
		stdaes.BlockSize,
		stdaes.BlockSize * 2,
		stdaes.BlockSize * 8,
		stdaes.BlockSize * 64,
	}
	for _, ks := range testKeySizes {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%s/%dB", ks.label, sz), func(t *testing.T) {
				key := seqBytes(ks.size)
				iv := seqBytes(IVSize)
				ct := seqBytes(sz)

				block := newBlock(t, key)
				want := refDecrypt(block, iv, ct)

				dst := make([]byte, sz)
				NewIGEDecrypter(block, iv).CryptBlocks(dst, ct)

				if !bytes.Equal(dst, want) {
					t.Error("output does not match reference implementation")
				}
			})
		}
	}
}

func TestRoundTrip(t *testing.T) {
	sizes := []int{
		stdaes.BlockSize,
		stdaes.BlockSize * 3,
		stdaes.BlockSize * 63,
	}
	for _, ks := range testKeySizes {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%s/%dB", ks.label, sz), func(t *testing.T) {
				key := seqBytes(ks.size)
				iv := seqBytes(IVSize)
				pt := seqBytes(sz)

				block := newBlock(t, key)
				ct := make([]byte, sz)
				NewIGEEncrypter(block, iv).CryptBlocks(ct, pt)

				got := make([]byte, sz)
				NewIGEDecrypter(block, iv).CryptBlocks(got, ct)

				if !bytes.Equal(got, pt) {
					t.Error("round-trip: decrypt(encrypt(pt)) != pt")
				}
			})
		}
	}
}

func TestInPlaceEncrypt(t *testing.T) {
	key := seqBytes(16)
	iv := seqBytes(IVSize)
	original := seqBytes(stdaes.BlockSize * 4)
	block := newBlock(t, key)

	want := make([]byte, len(original))
	NewIGEEncrypter(block, iv).CryptBlocks(want, original)

	got := append([]byte(nil), original...)
	NewIGEEncrypter(block, iv).CryptBlocks(got, got)

	if !bytes.Equal(got, want) {
		t.Error("in-place encrypt differs from out-of-place encrypt")
	}
}

func TestInPlaceDecrypt(t *testing.T) {
	key := seqBytes(16)
	iv := seqBytes(IVSize)
	block := newBlock(t, key)

	pt := seqBytes(stdaes.BlockSize * 4)
	ct := make([]byte, len(pt))
	NewIGEEncrypter(block, iv).CryptBlocks(ct, pt)

	want := make([]byte, len(ct))
	NewIGEDecrypter(block, iv).CryptBlocks(want, ct)

	got := append([]byte(nil), ct...)
	NewIGEDecrypter(block, iv).CryptBlocks(got, got)

	if !bytes.Equal(got, want) {
		t.Error("in-place decrypt differs from out-of-place decrypt")
	}
}

func TestEmptyInput(t *testing.T) {
	block := newBlock(t, fillBytes(16, 0xaa))
	iv := fillBytes(IVSize, 0xbb)
	dst := make([]byte, 0)
	src := make([]byte, 0)
	NewIGEEncrypter(block, iv).CryptBlocks(dst, src)
	NewIGEDecrypter(block, iv).CryptBlocks(dst, src)
}

func TestDeterminism(t *testing.T) {
	key := seqBytes(16)
	iv := seqBytes(IVSize)
	pt := seqBytes(stdaes.BlockSize * 8)
	block := newBlock(t, key)

	ct1 := make([]byte, len(pt))
	ct2 := make([]byte, len(pt))
	NewIGEEncrypter(block, iv).CryptBlocks(ct1, pt)
	NewIGEEncrypter(block, iv).CryptBlocks(ct2, pt)

	if !bytes.Equal(ct1, ct2) {
		t.Error("non-deterministic: identical inputs produced different ciphertexts")
	}
}

func TestIVSensitivity(t *testing.T) {
	key := seqBytes(16)
	pt := seqBytes(stdaes.BlockSize * 4)
	block := newBlock(t, key)

	ct1 := make([]byte, len(pt))
	ct2 := make([]byte, len(pt))
	NewIGEEncrypter(block, fillBytes(IVSize, 0x00)).CryptBlocks(ct1, pt)
	NewIGEEncrypter(block, fillBytes(IVSize, 0x01)).CryptBlocks(ct2, pt)

	if bytes.Equal(ct1, ct2) {
		t.Error("different IVs produced the same ciphertext")
	}
}

func TestKeySensitivity(t *testing.T) {
	iv := seqBytes(IVSize)
	pt := seqBytes(stdaes.BlockSize * 4)

	ct1 := make([]byte, len(pt))
	ct2 := make([]byte, len(pt))
	NewIGEEncrypter(newBlock(t, fillBytes(16, 0x00)), iv).CryptBlocks(ct1, pt)
	NewIGEEncrypter(newBlock(t, fillBytes(16, 0x01)), iv).CryptBlocks(ct2, pt)

	if bytes.Equal(ct1, ct2) {
		t.Error("different keys produced the same ciphertext")
	}
}

func TestErrorPropagation(t *testing.T) {
	const totalBlocks = 6
	const corruptAt = 2

	key := seqBytes(16)
	iv := seqBytes(IVSize)
	pt := seqBytes(totalBlocks * stdaes.BlockSize)
	block := newBlock(t, key)

	ct := make([]byte, len(pt))
	NewIGEEncrypter(block, iv).CryptBlocks(ct, pt)

	corruptCT := append([]byte(nil), ct...)
	corruptCT[corruptAt*stdaes.BlockSize] ^= 0xff

	got := make([]byte, len(pt))
	NewIGEDecrypter(block, iv).CryptBlocks(got, corruptCT)

	bs := stdaes.BlockSize
	for i := range totalBlocks {
		start := i * bs
		end := start + bs
		if i < corruptAt {
			if !bytes.Equal(got[start:end], pt[start:end]) {
				t.Errorf("block %d: unexpected corruption; blocks before index %d must be unaffected", i, corruptAt)
			}
		} else {
			if bytes.Equal(got[start:end], pt[start:end]) {
				t.Errorf("block %d: not corrupted; IGE must propagate errors from block %d onward", i, corruptAt)
			}
		}
	}
}

func TestPanicNonAligned(t *testing.T) {
	block := newBlock(t, fillBytes(16, 1))
	iv := fillBytes(IVSize, 2)
	src := make([]byte, stdaes.BlockSize+1)
	dst := make([]byte, len(src))

	mustPanic := func(t *testing.T, label string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic on non-aligned input", label)
			}
		}()
		fn()
	}

	mustPanic(t, "encrypt", func() { NewIGEEncrypter(block, iv).CryptBlocks(dst, src) })
	mustPanic(t, "decrypt", func() { NewIGEDecrypter(block, iv).CryptBlocks(dst, src) })
}

func TestPanicDstTooSmall(t *testing.T) {
	block := newBlock(t, fillBytes(16, 1))
	iv := fillBytes(IVSize, 2)
	src := make([]byte, stdaes.BlockSize*2)
	dst := make([]byte, stdaes.BlockSize)

	mustPanic := func(t *testing.T, label string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic when len(dst) < len(src)", label)
			}
		}()
		fn()
	}

	mustPanic(t, "encrypt", func() { NewIGEEncrypter(block, iv).CryptBlocks(dst, src) })
	mustPanic(t, "decrypt", func() { NewIGEDecrypter(block, iv).CryptBlocks(dst, src) })
}
