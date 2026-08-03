package ntru

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// ErrEntropySource identifies failures while reading randomness for NTRU key
// generation or preimage sampling. Callers can use errors.Is to distinguish an
// entropy failure from a rejected key or signature candidate.
var ErrEntropySource = errors.New("ntru entropy source failure")

func defaultEntropyReader(r io.Reader) io.Reader {
	if r == nil {
		return crand.Reader
	}
	return r
}

func readEntropy(r io.Reader, dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	if _, err := io.ReadFull(defaultEntropyReader(r), dst); err != nil {
		return fmt.Errorf("%w: %w", ErrEntropySource, err)
	}
	return nil
}

func entropyUint64(r io.Reader) (uint64, error) {
	var buf [8]byte
	if err := readEntropy(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

func entropyByte(r io.Reader) (byte, error) {
	var buf [1]byte
	if err := readEntropy(r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// entropyFloat64 returns a uniform value in [0,1) with 53 random mantissa bits.
func entropyFloat64(r io.Reader) (float64, error) {
	u, err := entropyUint64(r)
	if err != nil {
		return 0, err
	}
	return math.Ldexp(float64(u>>11), -53), nil
}

func entropyFloat64s(r io.Reader, n int) ([]float64, error) {
	if n < 0 {
		return nil, fmt.Errorf("entropyFloat64s: negative count %d", n)
	}
	if n == 0 {
		return nil, nil
	}
	if n > int(^uint(0)>>1)/8 {
		return nil, fmt.Errorf("entropyFloat64s: count %d overflows byte length", n)
	}
	buf := make([]byte, 8*n)
	if err := readEntropy(r, buf); err != nil {
		return nil, err
	}
	out := make([]float64, n)
	for i := range out {
		u := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = math.Ldexp(float64(u>>11), -53)
	}
	return out, nil
}

// entropyFloat53 returns a uniform value in [0,1) with 53 random mantissa
// bits. This is used by the discrete-Gaussian rejection step.
func entropyFloat53(r io.Reader) (float64, error) {
	u, err := entropyUint64(r)
	if err != nil {
		return 0, err
	}
	return math.Ldexp(float64(u&0x1fffffffffffff), -53), nil
}

// entropyNormalPair draws two independent standard normal values with the
// Box-Muller transform. A zero first uniform is rejected, as log(0) is not
// defined; every retry remains checked and reader-local.
func entropyNormalPair(r io.Reader) (float64, float64, error) {
	var u1 float64
	for u1 == 0 {
		var err error
		u1, err = entropyFloat64(r)
		if err != nil {
			return 0, 0, err
		}
	}
	u2, err := entropyFloat64(r)
	if err != nil {
		return 0, 0, err
	}
	radius := math.Sqrt(-2 * math.Log(u1))
	theta := 2 * math.Pi * u2
	return radius * math.Cos(theta), radius * math.Sin(theta), nil
}
