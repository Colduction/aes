package aes

import (
	stdaes "crypto/aes"
	"testing"
)

// sivBenchSizes mirrors the IGE benchmark sizes so results are comparable.
var sivBenchSizes = []struct {
	name string
	n    int
}{
	{"1KB", 1 << 10},
	{"8KB", 1 << 13},
	{"64KB", 1 << 16},
	{"1MB", 1 << 20},
}

var sivBenchKeySizes = []struct {
	label string
	size  int
}{
	{"AES-128-SIV", 32},
	{"AES-192-SIV", 48},
	{"AES-256-SIV", 64},
}

// BenchmarkSIVSeal measures the Seal (encrypt + authenticate) path.
func BenchmarkSIVSeal(b *testing.B) {
	for _, ks := range sivBenchKeySizes {
		key := fillBytes(ks.size, 0xab)
		ad := fillBytes(16, 0xcd)

		s, err := NewSIV(key)
		if err != nil {
			b.Fatalf("NewSIV: %v", err)
		}

		for _, sz := range sivBenchSizes {
			pt := fillBytes(sz.n, 0x42)

			b.Run(ks.label+"/"+sz.name, func(b *testing.B) {
				b.SetBytes(int64(sz.n))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					_ = s.Seal([][]byte{ad}, pt)
				}
			})
		}
	}
}

// BenchmarkSIVOpen measures the Open (decrypt + verify) path.
func BenchmarkSIVOpen(b *testing.B) {
	for _, ks := range sivBenchKeySizes {
		key := fillBytes(ks.size, 0xab)
		ad := fillBytes(16, 0xcd)

		s, err := NewSIV(key)
		if err != nil {
			b.Fatalf("NewSIV: %v", err)
		}

		for _, sz := range sivBenchSizes {
			pt := fillBytes(sz.n, 0x42)
			ct := s.Seal([][]byte{ad}, pt)

			b.Run(ks.label+"/"+sz.name, func(b *testing.B) {
				b.SetBytes(int64(sz.n))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					_, _ = s.Open([][]byte{ad}, ct)
				}
			})
		}
	}
}

// BenchmarkSIVNew measures the cost of constructing a SIV cipher (key schedule
// + CMAC subkey derivation).
func BenchmarkSIVNew(b *testing.B) {
	for _, ks := range sivBenchKeySizes {
		key := fillBytes(ks.size, 0xab)

		b.Run(ks.label, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_, _ = NewSIV(key)
			}
		})
	}
}

// BenchmarkSIVSealNoAD measures Seal without any associated data.
func BenchmarkSIVSealNoAD(b *testing.B) {
	key := fillBytes(32, 0xab)

	s, err := NewSIV(key)
	if err != nil {
		b.Fatalf("NewSIV: %v", err)
	}

	for _, sz := range sivBenchSizes {
		pt := fillBytes(sz.n, 0x42)

		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = s.Seal(nil, pt)
			}
		})
	}
}

// BenchmarkCMAC measures the standalone CMAC primitive used inside S2V.
func BenchmarkCMAC(b *testing.B) {
	block, _ := stdaes.NewCipher(fillBytes(16, 0xab))
	p := &cmacPRF{mac: block}
	p.deriveSubkeys()

	for _, sz := range sivBenchSizes {
		msg := fillBytes(sz.n, 0x42)
		var out [sivBlockSize]byte

		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				p.cmac(msg, &out)
			}
		})
	}
}
