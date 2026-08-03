package ntru

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"reflect"
	"testing"
)

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestKeygenRadialReaderInjectionIsDeterministic(t *testing.T) {
	par, err := NewParams(2, big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	}
	f1, g1, err := KeygenRadialFGOptsWithReader(par, 1.2, false, 0, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("first radial sample: %v", err)
	}
	f2, g2, err := KeygenRadialFGOptsWithReader(par, 1.2, false, 0, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("second radial sample: %v", err)
	}
	if !reflect.DeepEqual(f1.V, f2.V) || !reflect.DeepEqual(g1.V, g2.V) {
		t.Fatal("identical entropy streams produced different radial samples")
	}
}

func TestKeygenRadialEntropyFailureIsChecked(t *testing.T) {
	par, err := NewParams(2, big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}
	sourceErr := errors.New("rng offline")
	_, _, err = KeygenRadialFGOptsWithReader(par, 1.2, false, 0, errorReader{err: sourceErr})
	if !errors.Is(err, ErrEntropySource) || !errors.Is(err, sourceErr) {
		t.Fatalf("error=%v, want entropy and source errors", err)
	}
}

func TestDiscreteSamplerReaderInjectionAndFailure(t *testing.T) {
	// A zero stream selects z0=0 and accepts z=0 on the first CDT attempt.
	zeroes := make([]byte, 17)
	z1, err := sampleZ(0, 1, bytes.NewReader(zeroes))
	if err != nil {
		t.Fatalf("first sampleZ: %v", err)
	}
	z2, err := sampleZ(0, 1, bytes.NewReader(zeroes))
	if err != nil {
		t.Fatalf("second sampleZ: %v", err)
	}
	if z1 != 0 || z2 != z1 {
		t.Fatalf("deterministic sampleZ results=(%d,%d), want (0,0)", z1, z2)
	}

	sourceErr := io.ErrUnexpectedEOF
	_, err = sampleZ(0, 1, errorReader{err: sourceErr})
	if !errors.Is(err, ErrEntropySource) || !errors.Is(err, sourceErr) {
		t.Fatalf("error=%v, want entropy and source errors", err)
	}
}

func TestEvaluationGaussianUsesSamplerLocalReader(t *testing.T) {
	par, err := NewParams(2, big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x5a}, 32)
	s1 := &Sampler{Par: par, Prec: 128, entropy: bytes.NewReader(seed)}
	s2 := &Sampler{Par: par, Prec: 128, entropy: bytes.NewReader(seed)}
	y1, err := s1.sampleEvalGaussian([]float64{1, 2})
	if err != nil {
		t.Fatalf("first Gaussian sample: %v", err)
	}
	y2, err := s2.sampleEvalGaussian([]float64{1, 2})
	if err != nil {
		t.Fatalf("second Gaussian sample: %v", err)
	}
	for i := 0; i < par.N; i++ {
		r1, _ := y1.Coeffs[i].Real.Float64()
		r2, _ := y2.Coeffs[i].Real.Float64()
		i1, _ := y1.Coeffs[i].Imag.Float64()
		i2, _ := y2.Coeffs[i].Imag.Float64()
		if r1 != r2 || i1 != i2 {
			t.Fatalf("Gaussian coefficient %d differs: (%g,%g) vs (%g,%g)", i, r1, i1, r2, i2)
		}
	}

	sourceErr := errors.New("rng offline")
	s3 := &Sampler{Par: par, Prec: 128, entropy: errorReader{err: sourceErr}}
	if _, err := s3.sampleEvalGaussian([]float64{1, 2}); !errors.Is(err, ErrEntropySource) || !errors.Is(err, sourceErr) {
		t.Fatalf("error=%v, want entropy and source errors", err)
	}
}

func TestEntropyFloat64NeverRoundsToOne(t *testing.T) {
	allOnes := bytes.Repeat([]byte{0xff}, 8)
	v, err := entropyFloat64(bytes.NewReader(allOnes))
	if err != nil {
		t.Fatal(err)
	}
	if v < 0 || v >= 1 {
		t.Fatalf("uniform value %g outside [0,1)", v)
	}
}
