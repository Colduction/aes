package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// TestRFC5297_A1 verifies Appendix A.1: AES-128-SIV, one AD string,
// plaintext shorter than one block (14 bytes).
//
// Key (32 bytes):
//
//	fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
//	f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
//
// AD (24 bytes):
//
//	10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627
//
// Plaintext (14 bytes): 11223344 55667788 99aabbcc ddee
// Expected output (30 bytes):
//
//	85632d07 c6e8f37f 950acd32 0a2ecc93   SIV
//	40c02b96 90c4dc04 daef7f6a fe5c       ciphertext
func TestRFC5297_A1(t *testing.T) {
	key := mustDecodeHex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := mustDecodeHex(t, "101112131415161718191a1b1c1d1e1f2021222324252627")
	pt := mustDecodeHex(t, "112233445566778899aabbccddee")
	want := mustDecodeHex(t, "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	got := s.Seal([][]byte{ad}, pt)
	if !bytes.Equal(got, want) {
		t.Errorf("Seal mismatch\n got  %x\n want %x", got, want)
	}

	recovered, err := s.Open([][]byte{ad}, got)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(recovered, pt) {
		t.Errorf("Open mismatch\n got  %x\n want %x", recovered, pt)
	}
}

// TestRFC5297_A2 verifies Appendix A.2: AES-128-SIV, two AD strings,
// plaintext longer than one block (47 bytes).
//
// Key (32 bytes):
//
//	7f7e7d7c 7b7a7978 77767574 73727170
//	40414243 44454647 48494a4b 4c4d4e4f
func TestRFC5297_A2(t *testing.T) {

	key := mustDecodeHex(t, "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	ad1 := mustDecodeHex(t, "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100")
	ad2 := mustDecodeHex(t, "102030405060708090a0")
	nonce := mustDecodeHex(t, "09f911029d74e35bd84156c5635688c0")

	pt := mustDecodeHex(t, "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553")

	want := mustDecodeHex(t,
		"7bdb6e3b432667eb06f4d14bff2fbd0f"+
			"cb900f2fddbe404326601965c889bf17"+
			"dba77ceb094fa663b7a3f748ba8af829"+
			"ea64ad544a272e9c485b62a3fd5c0d")

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	got := s.Seal([][]byte{ad1, ad2, nonce}, pt)
	if !bytes.Equal(got, want) {
		t.Errorf("Seal mismatch\n got  %x\n want %x", got, want)
	}

	recovered, err := s.Open([][]byte{ad1, ad2, nonce}, got)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(recovered, pt) {
		t.Errorf("Open mismatch\n got  %x\n want %x", recovered, pt)
	}
}

// TestDblBlock tests the GF(2^128) doubling function against known values.
func TestDblBlock(t *testing.T) {
	tests := []struct {
		name     string
		in, want string
	}{

		{"zero",
			"00000000000000000000000000000000",
			"00000000000000000000000000000000"},

		{"one",
			"00000000000000000000000000000001",
			"00000000000000000000000000000002"},

		{"high-bit",
			"80000000000000000000000000000000",
			"00000000000000000000000000000087"},

		{"all-ones",
			"ffffffffffffffffffffffffffffffff",
			"ffffffffffffffffffffffffffffff79"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := mustDecodeHex(t, tc.in)
			want := mustDecodeHex(t, tc.want)
			var b [sivBlockSize]byte
			copy(b[:], in)
			dblBlock(&b)
			if !bytes.Equal(b[:], want) {
				t.Errorf("dblBlock(%x)\n got  %x\n want %x", in, b, want)
			}
		})
	}
}

// TestCMAC verifies AES-CMAC against RFC 4493 test vectors.
//
// Key (16 bytes): 2b7e151628aed2a6abf7158809cf4f3c
func TestCMAC(t *testing.T) {

	key := mustDecodeHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	block := newBlock(t, key)

	s := &cmacPRF{mac: block}
	s.deriveSubkeys()

	tests := []struct {
		name string
		msg  string
		want string
	}{

		{
			name: "empty",
			msg:  "",
			want: "bb1d6929e95937287fa37d129b756746",
		},

		{
			name: "16B",
			msg:  "6bc1bee22e409f96e93d7e117393172a",
			want: "070a16b46b4d4144f79bdd9dd04a287c",
		},

		{
			name: "40B",
			msg:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			want: "dfa66747de9ae63030ca32611497c827",
		},

		{
			name: "64B",
			msg:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			want: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := mustDecodeHex(t, tc.msg)
			want := mustDecodeHex(t, tc.want)
			var out [sivBlockSize]byte
			s.cmac(msg, &out)
			if !bytes.Equal(out[:], want) {
				t.Errorf("CMAC(%s)\n got  %x\n want %x", tc.name, out, want)
			}
		})
	}
}

var sivKeySizes = []struct {
	label string
	size  int
}{
	{"AES-128-SIV", 32},
	{"AES-192-SIV", 48},
	{"AES-256-SIV", 64},
}

var sivDataSizes = []int{
	1,
	sivBlockSize - 1,
	sivBlockSize,
	sivBlockSize + 1,
	sivBlockSize * 2,
	sivBlockSize * 8,
	sivBlockSize * 64,
}

func TestSIVRoundTrip(t *testing.T) {
	for _, ks := range sivKeySizes {
		t.Run(ks.label, func(t *testing.T) {
			key := fillBytes(ks.size, 0xab)
			ad1 := fillBytes(24, 0x11)
			ad2 := fillBytes(10, 0x22)
			ads := [][]byte{ad1, ad2}

			s, err := NewSIV(key)
			if err != nil {
				t.Fatalf("NewSIV: %v", err)
			}

			for _, sz := range sivDataSizes {
				t.Run(fmt.Sprintf("%dB", sz), func(t *testing.T) {
					pt := seqBytes(sz)
					ct := s.Seal(ads, pt)
					if len(ct) != sz+sivBlockSize {
						t.Fatalf("ciphertext length = %d, want %d", len(ct), sz+sivBlockSize)
					}
					got, err := s.Open(ads, ct)
					if err != nil {
						t.Fatalf("Open: %v", err)
					}
					if !bytes.Equal(got, pt) {
						t.Error("round-trip: Open(Seal(pt)) != pt")
					}
				})
			}
		})
	}
}

// TestSIVDeterministic verifies that encrypting the same input twice produces
// identical output (deterministic AEAD property).
func TestSIVDeterministic(t *testing.T) {
	key := fillBytes(32, 0x42)
	ad := fillBytes(16, 0xde)
	pt := seqBytes(64)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct1 := s.Seal([][]byte{ad}, pt)
	ct2 := s.Seal([][]byte{ad}, pt)
	if !bytes.Equal(ct1, ct2) {
		t.Error("SIV is not deterministic: two identical encryptions differ")
	}
}

// TestSIVAuthFail verifies that Open rejects a tampered SIV tag.
func TestSIVAuthFail_TamperedTag(t *testing.T) {
	key := fillBytes(32, 0x77)
	pt := seqBytes(32)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct := s.Seal(nil, pt)
	ct[0] ^= 0xff

	if _, err := s.Open(nil, ct); err == nil {
		t.Error("Open accepted tampered SIV tag; expected error")
	}
}

// TestSIVAuthFail_TamperedBody verifies that Open rejects a tampered ciphertext body.
func TestSIVAuthFail_TamperedBody(t *testing.T) {
	key := fillBytes(32, 0x77)
	pt := seqBytes(32)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct := s.Seal(nil, pt)
	ct[sivBlockSize] ^= 0x01

	if _, err := s.Open(nil, ct); err == nil {
		t.Error("Open accepted tampered ciphertext body; expected error")
	}
}

// TestSIVAuthFail_WrongAD verifies that Open rejects correct ciphertext
// when presented with different associated data.
func TestSIVAuthFail_WrongAD(t *testing.T) {
	key := fillBytes(32, 0x55)
	ad := fillBytes(16, 0xaa)
	pt := seqBytes(48)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct := s.Seal([][]byte{ad}, pt)
	wrongAD := fillBytes(16, 0xbb)
	if _, err := s.Open([][]byte{wrongAD}, ct); err == nil {
		t.Error("Open accepted mismatched AD; expected error")
	}
}

// TestSIVCiphertextTooShort verifies that Open rejects ciphertext shorter than
// sivBlockSize bytes.
func TestSIVCiphertextTooShort(t *testing.T) {
	key := fillBytes(32, 0x11)
	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	short := make([]byte, sivBlockSize-1)
	if _, err := s.Open(nil, short); err == nil {
		t.Error("Open accepted ciphertext shorter than block size; expected error")
	}
}

// TestSIVNoAD verifies round-trip when no associated data is provided.
func TestSIVNoAD(t *testing.T) {
	key := fillBytes(32, 0x33)
	pt := seqBytes(33)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct := s.Seal(nil, pt)
	got, err := s.Open(nil, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("round-trip without AD failed")
	}
}

// TestSIVMultipleAD verifies that multiple associated-data strings are all
// authenticated (changing any one causes verification failure).
func TestSIVMultipleAD(t *testing.T) {
	key := fillBytes(32, 0xcc)
	ads := [][]byte{
		fillBytes(8, 0x01),
		fillBytes(12, 0x02),
		fillBytes(20, 0x03),
	}
	pt := seqBytes(47)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct := s.Seal(ads, pt)

	if _, err := s.Open(ads, ct); err != nil {
		t.Fatalf("Open with correct AD: %v", err)
	}

	for i := range ads {
		tampered := make([][]byte, len(ads))
		copy(tampered, ads)
		bad := make([]byte, len(ads[i]))
		copy(bad, ads[i])
		bad[0] ^= 0xff
		tampered[i] = bad

		if _, err := s.Open(tampered, ct); err == nil {
			t.Errorf("Open with tampered AD[%d] succeeded; expected error", i)
		}
	}
}

// TestSIVKeyError verifies that NewSIV rejects invalid key sizes.
func TestSIVKeyError(t *testing.T) {
	for _, sz := range []int{0, 16, 24, 31, 33, 63, 65} {
		if _, err := NewSIV(make([]byte, sz)); err == nil {
			t.Errorf("NewSIV(%d-byte key) succeeded; expected error", sz)
		}
	}
}

// TestSIVExactBlockSize verifies that plaintext of exactly one block (16 bytes)
// is handled correctly by the xorend path in s2v.
func TestSIVExactBlockSize(t *testing.T) {
	key := fillBytes(32, 0xfe)
	pt := fillBytes(sivBlockSize, 0xba)
	ad := fillBytes(7, 0xcd)

	s, err := NewSIV(key)
	if err != nil {
		t.Fatalf("NewSIV: %v", err)
	}

	ct := s.Seal([][]byte{ad}, pt)
	got, err := s.Open([][]byte{ad}, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("round-trip at exact block size failed")
	}
}
