// Package aes provides internal AES cipher-mode primitives.
package aes

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
	"unsafe"
	_ "unsafe"
)

//go:linkname sivCPUX86 internal/cpu.X86
var sivCPUX86 struct {
	_ [64]byte

	HasAES              bool
	HasADX              bool
	HasAVX              bool
	HasAVXVNNI          bool
	HasAVX2             bool
	HasAVX512           bool
	HasAVX512F          bool
	HasAVX512CD         bool
	HasAVX512BW         bool
	HasAVX512DQ         bool
	HasAVX512VL         bool
	HasAVX512GFNI       bool
	HasAVX512VAES       bool
	HasAVX512VNNI       bool
	HasAVX512VBMI       bool
	HasAVX512VBMI2      bool
	HasAVX512BITALG     bool
	HasAVX512VPOPCNTDQ  bool
	HasAVX512VPCLMULQDQ bool
	HasBMI1             bool
	HasBMI2             bool
	HasERMS             bool
	HasFSRM             bool
	HasFMA              bool
	HasGFNI             bool
	HasOSXSAVE          bool
	HasPCLMULQDQ        bool
	HasPOPCNT           bool
	HasRDTSCP           bool
	HasSHA              bool
	HasSSE3             bool
	HasSSSE3            bool
	HasSSE41            bool
	HasSSE42            bool
	HasVAES             bool
}

// sivHasAESNI reports whether the CPU supports AES-NI and PCLMULQDQ instructions.
// PCLMULQDQ is used for hardware-accelerated carry-less multiplication (GHASH).
// This reads the internal/cpu.X86 feature flags via go:linkname.
func sivHasAESNI() bool {
	return sivCPUX86.HasAES && sivCPUX86.HasPCLMULQDQ
}

// GHASH field element, GF(2^128) with polynomial x^128+x^7+x^2+x+1.
//
// The bit layout follows NIST SP 800-38D and the Go standard library GHASH code:
//   - low.bit63  = coefficient of x^0
//   - low.bit0   = coefficient of x^63
//   - high.bit63 = coefficient of x^64
//   - high.bit0  = coefficient of x^127
type ghashFieldElem struct{ low, high uint64 }

// ghashReductionTable maps a 4-bit value to the corresponding GF(2^128)
// reduction constant, used during the windowed multiplication.
var ghashReductionTable = [16]uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// ghashReverseBits4 reverses the bit order of a 4-bit value.
// Used to account for the reversed bit-order in the product table.
func ghashReverseBits4(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// ghashFieldDouble returns the result of multiplying x by the generator element
// (i.e., "doubling" x in the GF field). Because of the reversed bit ordering,
// this maps to a right-shift with optional reduction via XOR.
func ghashFieldDouble(x *ghashFieldElem) (d ghashFieldElem) {
	msbSet := x.high&1 == 1
	d.high = x.high>>1 | x.low<<63
	d.low = x.low >> 1
	if msbSet {
		d.low ^= 0xe100000000000000
	}
	return
}

// ghashFieldAdd adds two GF(2^128) elements (XOR in characteristic-2 fields).
func ghashFieldAdd(x, y ghashFieldElem) ghashFieldElem {
	return ghashFieldElem{x.low ^ y.low, x.high ^ y.high}
}

// ghashInitTable initialises a 16-entry precomputed product table for key H.
// The table holds the first 16 powers of H, stored in reversed-bit order
// (the same convention as the Go standard library's ghash implementation).
func ghashInitTable(pt *[16]ghashFieldElem, H *[sivBlockSize]byte) {
	x := ghashFieldElem{
		loadBE64(H[0:]),
		loadBE64(H[8:]),
	}
	pt[ghashReverseBits4(1)] = x
	for i := 2; i < 16; i += 2 {
		pt[ghashReverseBits4(i)] = ghashFieldDouble(&pt[ghashReverseBits4(i/2)])
		pt[ghashReverseBits4(i+1)] = ghashFieldAdd(pt[ghashReverseBits4(i)], x)
	}
}

// ghashMul multiplies y (in place) by the key H represented in the product table.
// Uses a 4-bit sliding window to process 4 bits per iteration.
func ghashMul(pt *[16]ghashFieldElem, y *ghashFieldElem) {
	var z ghashFieldElem
	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(ghashReductionTable[msw]) << 48
			t := pt[word&0xf]
			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}
	*y = z
}

// ghashUpdateBlocks processes an already block-aligned slice into the GHASH state.
// len(blocks) must be a multiple of sivBlockSize (16 bytes).
func ghashUpdateBlocks(pt *[16]ghashFieldElem, y *ghashFieldElem, blocks []byte) {
	for len(blocks) >= sivBlockSize {
		y.low ^= loadBE64(blocks)
		y.high ^= loadBE64(blocks[8:])
		ghashMul(pt, y)
		blocks = blocks[sivBlockSize:]
	}
}

// ghashUpdate extends the GHASH state with data, zero-padding the final partial
// block if necessary.
func ghashUpdate(pt *[16]ghashFieldElem, y *ghashFieldElem, data []byte) {
	full := (len(data) >> 4) << 4
	ghashUpdateBlocks(pt, y, data[:full])
	if len(data) != full {
		var pad [sivBlockSize]byte
		copy(pad[:], data[full:])
		y.low ^= loadBE64(pad[0:])
		y.high ^= loadBE64(pad[8:])
		ghashMul(pt, y)
	}
}

// ghashComputeWithTail computes GHASH(H, prefix || tail) zero-copy.
//
// tail is exactly sivBlockSize bytes. When len(prefix) is not block-aligned,
// the partial-block boundary between prefix and tail is handled inline by
// constructing a combined "mid" block and a "last" block on the stack,
// avoiding any allocation for even multi-megabyte prefixes.
func ghashComputeWithTail(pt *[16]ghashFieldElem, prefix []byte, tail *[sivBlockSize]byte, out *[sivBlockSize]byte) {
	var y ghashFieldElem
	n := len(prefix)
	rem := n % sivBlockSize
	full := n - rem

	ghashUpdateBlocks(pt, &y, prefix[:full])

	if rem == 0 {

		y.low ^= loadBE64(tail[0:])
		y.high ^= loadBE64(tail[8:])
		ghashMul(pt, &y)
	} else {

		var mid [sivBlockSize]byte
		copy(mid[:rem], prefix[full:])
		copy(mid[rem:], tail[:sivBlockSize-rem])
		y.low ^= loadBE64(mid[0:])
		y.high ^= loadBE64(mid[8:])
		ghashMul(pt, &y)

		var last [sivBlockSize]byte
		copy(last[:], tail[sivBlockSize-rem:])
		y.low ^= loadBE64(last[0:])
		y.high ^= loadBE64(last[8:])
		ghashMul(pt, &y)
	}

	storeBE64(out[0:], y.low)
	storeBE64(out[8:], y.high)
}

// ghashComputeOne computes GHASH(H, data) writing the 16-byte result into out.
func ghashComputeOne(pt *[16]ghashFieldElem, data []byte, out *[sivBlockSize]byte) {
	var y ghashFieldElem
	ghashUpdate(pt, &y, data)
	storeBE64(out[0:], y.low)
	storeBE64(out[8:], y.high)
}

// loadBE64 reads 8 bytes from b[0:8] as a big-endian uint64.
// The bounds-check hint (b[7]) is elided by the compiler when the caller
// already guarantees b has at least 8 bytes (e.g. from a 16-byte array).
func loadBE64(b []byte) uint64 {
	_ = b[7]
	return bits.ReverseBytes64(*(*uint64)(unsafe.Pointer(&b[0])))
}

// storeBE64 writes v to b[0:8] in big-endian order.
func storeBE64(b []byte, v uint64) {
	_ = b[7]
	*(*uint64)(unsafe.Pointer(&b[0])) = bits.ReverseBytes64(v)
}

// ghashPRF implements GHASH-based S2V as a sivPRF.
//
// Key H = AES(K, 0^128) is used as both the GHASH hash key (H in GHASH(H,.))
// and the initial S2V accumulator D_0. Using H rather than GHASH(H,0^128) = 0
// ensures the initial state is non-zero even without any associated data.
type ghashPRF struct {
	productTable [16]ghashFieldElem
	H            [sivBlockSize]byte
}

// newGHASHPRF initialises a ghashPRF from a single AES key.
// H = AES(key, 0^128) is computed once; the product table is precomputed for H.
func newGHASHPRF(key []byte) (*ghashPRF, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	p := &ghashPRF{}
	block.Encrypt(p.H[:], zeroBlock[:])
	ghashInitTable(&p.productTable, &p.H)
	return p, nil
}

// NewGHASHSIV creates an AES-GHASH-SIV cipher from a single 16, 24, or 32-byte
// key. Unlike AES-CMAC-SIV, GHASH-SIV uses one key for both the GHASH MAC and
// the AES-CTR encryption (analogous to AES-GCM's single-key design).
//
// GHASH is computed using our own GF(2^128) implementation with unsafe
// 64-bit word loads (BSWAP-optimised on amd64). Hardware AES-NI is used
// automatically for AES-CTR via crypto/aes.
func NewGHASHSIV(key []byte) (*SIV, error) {
	n := len(key)
	if n != 16 && n != 24 && n != 32 {
		return nil, errors.New("siv: GHASH key must be 16, 24, or 32 bytes")
	}
	prf, err := newGHASHPRF(key)
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &SIV{prf: prf, ctr: ctr}, nil
}

// s2v computes the GHASH-based Synthetic IV for GHASH-SIV.
//
// Algorithm (analogous to RFC 5297 S2V but with GHASH replacing CMAC):
//
//  1. D = H (= AES(K,0^128), the GHASH key and non-zero initial accumulator)
//  2. For each AD_i: D = dbl(D) XOR GHASH(H, AD_i)
//  3. If len(PT) >= 16: SIV = GHASH(H, PT[:n-16] || (PT[n-16:] XOR D))
//     Else: SIV = GHASH(H, dbl(D) XOR pad(PT))
//
// The zero-copy ghashComputeWithTail function handles step 3 without allocating
// a modified copy of the plaintext, matching the efficiency of cmacWithTail.
func (p *ghashPRF) s2v(additionalData [][]byte, plaintext []byte, out *[sivBlockSize]byte) {
	var D [sivBlockSize]byte
	copy(D[:], p.H[:])

	for _, ad := range additionalData {
		var T [sivBlockSize]byte
		ghashComputeOne(&p.productTable, ad, &T)
		dblBlock(&D)
		subtle.XORBytes(D[:], D[:], T[:])
	}

	n := len(plaintext)
	if n >= sivBlockSize {
		var tail [sivBlockSize]byte
		copy(tail[:], plaintext[n-sivBlockSize:])
		subtle.XORBytes(tail[:], tail[:], D[:])
		ghashComputeWithTail(&p.productTable, plaintext[:n-sivBlockSize], &tail, out)
	} else {
		dblBlock(&D)
		var T [sivBlockSize]byte
		copy(T[:], plaintext)
		T[n] = 0x80
		subtle.XORBytes(T[:], T[:], D[:])
		ghashComputeOne(&p.productTable, T[:], out)
	}
}

// POLYVAL is GF(2^128) with polynomial x^128+x^127+x^126+x^121+1 (RFC 8452).
//
// POLYVAL and GHASH are related by a per-byte bit-reflection:
//
//	POLYVAL(H, X) = byteReflect(GHASH(byteReflect(H), byteReflect(X)))
//
// where byteReflect applies bits.Reverse8 to every byte of the 16-byte value.
//
// This lets us reuse our GHASH product table infrastructure; each input byte
// is reflected in-place (no allocation) before being absorbed into the GHASH
// accumulator. The GHASH output is byte-reflected to recover the POLYVAL result.
// polyvalCompute computes POLYVAL(H, inputs...) via byte-reflected GHASH.
// Each input is zero-padded to a 16-byte boundary by ghashUpdate.
// This function performs no heap allocations; all temporaries are on the stack.
func polyvalCompute(H *[sivBlockSize]byte, inputs ...[]byte) (out [sivBlockSize]byte) {
	var rH [sivBlockSize]byte
	for i, b := range H {
		rH[i] = bits.Reverse8(b)
	}

	var pt [16]ghashFieldElem
	ghashInitTable(&pt, &rH)

	var y ghashFieldElem
	for _, inp := range inputs {
		n := len(inp)
		for i := 0; i < n; i += sivBlockSize {
			var block [sivBlockSize]byte
			end := i + sivBlockSize
			if end > n {
				end = n
			}

			for j, b := range inp[i:end] {
				block[j] = bits.Reverse8(b)
			}

			y.low ^= binary.BigEndian.Uint64(block[0:8])
			y.high ^= binary.BigEndian.Uint64(block[8:16])
			ghashMul(&pt, &y)
		}
	}

	var tmp [sivBlockSize]byte
	binary.BigEndian.PutUint64(tmp[0:8], y.low)
	binary.BigEndian.PutUint64(tmp[8:16], y.high)
	for i, b := range tmp {
		out[i] = bits.Reverse8(b)
	}
	return
}
