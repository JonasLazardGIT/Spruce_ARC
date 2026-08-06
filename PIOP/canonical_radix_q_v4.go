package PIOP

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// CanonicalProofCodecProfileV5 identifies the retired fixed-authentication-
// padding grammar. It remains named for diagnostics and explicit legacy
// rejection only; strict target proofs are never emitted or accepted as v5.
const CanonicalProofCodecProfileV5 = "SPRUCE/canonical-proof-codec/v5;fq=radix-q-v1;group=1024;q=ker-sum-omega-constant-v1"

// CanonicalProofCodecProfileV6 is part of the Fiat--Shamir public statement.
// The Merkle frontier is the exact positional frontier derived from the
// Fiat--Shamir tail. No node count, positions, or zero padding are carried on
// the wire. Changing any item in this profile requires a new wire version.
const CanonicalProofCodecProfileV6 = "SPRUCE/canonical-proof-codec/v6;fq=radix-q-v1;group=1024;q=ker-sum-omega-constant-v1;merkle=exact-tail-frontier-unpadded-v1"

const (
	CanonicalProofCodecVersionV5        = 5
	CanonicalProofCodecVersionV6        = 6
	CanonicalProofFieldEncodingV5       = "radix-q-v1;group=1024"
	CanonicalProofQKernelEncodingV5     = "ker-sum-omega-constant-v1"
	CanonicalProofRadixQGroupElementsV5 = 1024
	CanonicalProofFieldEncodingV6       = CanonicalProofFieldEncodingV5
	CanonicalProofQKernelEncodingV6     = CanonicalProofQKernelEncodingV5
	CanonicalProofRadixQGroupElementsV6 = CanonicalProofRadixQGroupElementsV5
)

const canonicalProofCodecProfileV5 = CanonicalProofCodecProfileV5
const canonicalProofCodecProfileV6 = CanonicalProofCodecProfileV6

const (
	// Groups are deliberately bounded.  A group contains at most about 2.5 KiB
	// of field data for the maintained 20-bit modulus, keeping adversarial
	// decoder arithmetic and allocations independent of the proof dimensions.
	canonicalRadixQGroupElementsV5 = CanonicalProofRadixQGroupElementsV5
	canonicalQKernelDomainV6       = "SPRUCE/SmallWood/Q-ker-sum-omega-constant/v6"
)

func canonicalProofCodecProfileBytesV5() []byte {
	return []byte(canonicalProofCodecProfileV5)
}

func canonicalProofCodecProfileBytesV6() []byte {
	return []byte(canonicalProofCodecProfileV6)
}

// canonicalRadixQMatrixByteLenV5 returns the exact, dimension-derived length
// of a row-major radix-q matrix.  Each bounded group encodes
//
//	a_0 + a_1 q + ... + a_{r-1} q^{r-1} < q^r
//
// in a fixed-width, big-endian byte string.  No dimensions or group lengths
// are accepted from the wire.
func canonicalRadixQMatrixByteLenV5(rows, cols int, q uint64) (int, error) {
	count, err := checkedCanonicalElementCount(rows, cols)
	if err != nil {
		return 0, err
	}
	return canonicalRadixQElementsByteLenV5(count, q)
}

func canonicalRadixQElementsByteLenV5(count int, q uint64) (int, error) {
	if count <= 0 || count > canonicalProofMaxElements || q <= 1 {
		return 0, errors.New("PIOP: canonical radix-q: invalid element count or modulus")
	}
	total := 0
	for remaining := count; remaining > 0; {
		group := remaining
		if group > canonicalRadixQGroupElementsV5 {
			group = canonicalRadixQGroupElementsV5
		}
		width, _, err := canonicalRadixQGroupParamsV5(group, q)
		if err != nil {
			return 0, err
		}
		if width <= 0 || total > canonicalProofMaxBytes-width {
			return 0, errors.New("PIOP: canonical radix-q: encoded length overflow")
		}
		total += width
		remaining -= group
	}
	return total, nil
}

func canonicalRadixQGroupParamsV5(count int, q uint64) (width int, limit *big.Int, err error) {
	if count <= 0 || count > canonicalRadixQGroupElementsV5 || q <= 1 {
		return 0, nil, errors.New("PIOP: canonical radix-q: invalid group")
	}
	limit = new(big.Int).Exp(new(big.Int).SetUint64(q), big.NewInt(int64(count)), nil)
	max := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
	width = (max.BitLen() + 7) / 8
	if width <= 0 || width > canonicalProofMaxBytes {
		return 0, nil, errors.New("PIOP: canonical radix-q: invalid group width")
	}
	return width, limit, nil
}

func packCanonicalFqMatrixRadixQV5(matrix [][]uint64, q uint64) ([]byte, error) {
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, errors.New("PIOP: canonical radix-q: cannot pack empty field matrix")
	}
	rows, cols := len(matrix), len(matrix[0])
	count, err := checkedCanonicalElementCount(rows, cols)
	if err != nil {
		return nil, err
	}
	width, err := canonicalRadixQElementsByteLenV5(count, q)
	if err != nil {
		return nil, err
	}
	flat := make([]uint64, 0, count)
	for i, row := range matrix {
		if len(row) != cols {
			return nil, fmt.Errorf("PIOP: canonical radix-q: ragged field matrix row %d", i)
		}
		for j, value := range row {
			if value >= q {
				return nil, fmt.Errorf("PIOP: canonical radix-q: noncanonical field value at (%d,%d)", i, j)
			}
			flat = append(flat, value)
		}
	}
	out := make([]byte, 0, width)
	qBig := new(big.Int).SetUint64(q)
	for offset := 0; offset < len(flat); {
		group := len(flat) - offset
		if group > canonicalRadixQGroupElementsV5 {
			group = canonicalRadixQGroupElementsV5
		}
		groupWidth, _, err := canonicalRadixQGroupParamsV5(group, q)
		if err != nil {
			return nil, err
		}
		// Horner from the most-significant radix digit avoids constructing a
		// separate large power for every element.
		code := new(big.Int)
		var digit big.Int
		for i := offset + group - 1; i >= offset; i-- {
			code.Mul(code, qBig)
			digit.SetUint64(flat[i])
			code.Add(code, &digit)
		}
		start := len(out)
		out = append(out, make([]byte, groupWidth)...)
		code.FillBytes(out[start:])
		offset += group
	}
	if len(out) != width {
		return nil, errors.New("PIOP: canonical radix-q: internal encoded-length mismatch")
	}
	return out, nil
}

func unpackCanonicalFqMatrixRadixQV5(data []byte, rows, cols int, q uint64) ([][]uint64, error) {
	count, err := checkedCanonicalElementCount(rows, cols)
	if err != nil {
		return nil, err
	}
	want, err := canonicalRadixQElementsByteLenV5(count, q)
	if err != nil {
		return nil, err
	}
	if len(data) != want {
		return nil, fmt.Errorf("radix-q field payload bytes=%d want=%d", len(data), want)
	}
	flat := make([]uint64, count)
	qBig := new(big.Int).SetUint64(q)
	var quotient, remainder big.Int
	byteOffset := 0
	for elemOffset := 0; elemOffset < count; {
		group := count - elemOffset
		if group > canonicalRadixQGroupElementsV5 {
			group = canonicalRadixQGroupElementsV5
		}
		groupWidth, limit, err := canonicalRadixQGroupParamsV5(group, q)
		if err != nil {
			return nil, err
		}
		payload := data[byteOffset : byteOffset+groupWidth]
		maxBits := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1)).BitLen()
		spare := groupWidth*8 - maxBits
		if spare > 0 && payload[0]>>(8-spare) != 0 {
			return nil, errors.New("nonzero spare radix-q field bits")
		}
		code := new(big.Int).SetBytes(payload)
		if code.Cmp(limit) >= 0 {
			return nil, errors.New("radix-q field group is outside the canonical range")
		}
		for i := 0; i < group; i++ {
			quotient.QuoRem(code, qBig, &remainder)
			flat[elemOffset+i] = remainder.Uint64()
			code.Set(&quotient)
		}
		if code.Sign() != 0 {
			return nil, errors.New("radix-q field group has a nonzero quotient")
		}
		elemOffset += group
		byteOffset += groupWidth
	}
	if byteOffset != len(data) {
		return nil, errors.New("radix-q field payload has trailing bytes")
	}
	out := make([][]uint64, rows)
	for i := range out {
		out[i] = append([]uint64(nil), flat[i*cols:(i+1)*cols]...)
	}
	return out, nil
}

func takeCanonicalFqMatrixRadixQV5(reader *canonicalProofReader, rows, cols int, q uint64, name string) ([][]uint64, error) {
	if reader == nil {
		return nil, errors.New("PIOP: canonical radix-q: nil reader")
	}
	width, err := canonicalRadixQMatrixByteLenV5(rows, cols, q)
	if err != nil {
		return nil, err
	}
	payload, err := reader.take(width)
	if err != nil {
		return nil, err
	}
	matrix, err := unpackCanonicalFqMatrixRadixQV5(payload, rows, cols, q)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: %s: %w", name, err)
	}
	return matrix, nil
}

// canonicalQKernelTranscriptBytesV6 injectively frames the compact Q
// coordinates used by Fiat--Shamir round 3.  Geometry is included even though
// it is verifier-derived, making cross-profile reuse impossible.
func canonicalQKernelTranscriptBytesV6(compact [][]uint64, omega []uint64, q uint64) ([]byte, error) {
	if len(compact) == 0 || len(compact[0]) == 0 || len(omega) == 0 {
		return nil, errors.New("PIOP: canonical Q kernel: empty transcript input")
	}
	payload, err := packCanonicalFqMatrixRadixQV5(compact, q)
	if err != nil {
		return nil, err
	}
	out := appendLengthPrefixedV3(nil, []byte(canonicalQKernelDomainV6))
	out = appendLengthPrefixedV3(out, canonicalProofCodecProfileBytesV6())
	var geometry [32]byte
	binary.BigEndian.PutUint64(geometry[0:8], q)
	binary.BigEndian.PutUint64(geometry[8:16], uint64(len(compact)))
	binary.BigEndian.PutUint64(geometry[16:24], uint64(len(compact[0])))
	binary.BigEndian.PutUint64(geometry[24:32], uint64(len(omega)))
	out = appendLengthPrefixedV3(out, geometry[:])
	out = appendLengthPrefixedV3(out, payload)
	return out, nil
}
