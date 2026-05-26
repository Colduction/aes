package aes

import (
	stdaes "crypto/aes"
	"testing"
)

var benchSizes = []struct {
	name string
	n    int
}{
	{"1KB", 1 << 10},
	{"8KB", 1 << 13},
	{"64KB", 1 << 16},
	{"1MB", 1 << 20},
}

func BenchmarkIGEEncrypt(b *testing.B) {
	for _, ks := range testKeySizes {
		block, _ := stdaes.NewCipher(fillBytes(ks.size, 0xab))
		iv := fillBytes(IVSize, 0xcd)

		for _, sz := range benchSizes {
			src := fillBytes(sz.n, 0x42)
			dst := make([]byte, sz.n)

			b.Run(ks.label+"/"+sz.name, func(b *testing.B) {
				b.SetBytes(int64(sz.n))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					NewIGEEncrypter(block, iv).CryptBlocks(dst, src)
				}
			})
		}
	}
}

func BenchmarkIGEDecrypt(b *testing.B) {
	for _, ks := range testKeySizes {
		block, _ := stdaes.NewCipher(fillBytes(ks.size, 0xab))
		iv := fillBytes(IVSize, 0xcd)

		for _, sz := range benchSizes {
			pt := fillBytes(sz.n, 0x42)
			ct := make([]byte, sz.n)
			NewIGEEncrypter(block, iv).CryptBlocks(ct, pt)
			dst := make([]byte, sz.n)

			b.Run(ks.label+"/"+sz.name, func(b *testing.B) {
				b.SetBytes(int64(sz.n))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					NewIGEDecrypter(block, iv).CryptBlocks(dst, ct)
				}
			})
		}
	}
}

func BenchmarkIGEEncryptInPlace(b *testing.B) {
	block, _ := stdaes.NewCipher(fillBytes(16, 0xab))
	iv := fillBytes(IVSize, 0xcd)

	for _, sz := range benchSizes {
		buf := fillBytes(sz.n, 0x42)

		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				NewIGEEncrypter(block, iv).CryptBlocks(buf, buf)
			}
		})
	}
}

func BenchmarkIGEDecryptInPlace(b *testing.B) {
	block, _ := stdaes.NewCipher(fillBytes(16, 0xab))
	iv := fillBytes(IVSize, 0xcd)

	for _, sz := range benchSizes {
		buf := fillBytes(sz.n, 0x42)

		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				NewIGEDecrypter(block, iv).CryptBlocks(buf, buf)
			}
		})
	}
}

func BenchmarkIGENew(b *testing.B) {
	block, _ := stdaes.NewCipher(fillBytes(16, 0xab))
	iv := fillBytes(IVSize, 0xcd)

	b.Run("Encrypter", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = NewIGEEncrypter(block, iv)
		}
	})
	b.Run("Decrypter", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = NewIGEDecrypter(block, iv)
		}
	})
}
