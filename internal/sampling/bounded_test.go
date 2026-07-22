package sampling

import (
	"bytes"
	"errors"
	"math"
	mathrand "math/rand"
	"testing"
)

func TestCenteredInt64StaysWithinBound(t *testing.T) {
	random := mathrand.New(mathrand.NewSource(7))
	for i := 0; i < 1000; i++ {
		value, err := CenteredInt64(random, 4)
		if err != nil {
			t.Fatal(err)
		}
		if value < -4 || value > 4 {
			t.Fatalf("sample=%d outside [-4,4]", value)
		}
	}
}

func TestBoundedSamplingRejectsInvalidInputs(t *testing.T) {
	if _, err := Int64n(nil, 2); err == nil {
		t.Fatal("expected nil-reader rejection")
	}
	if _, err := Int64n(bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected empty-range rejection")
	}
	if _, err := CenteredInt64(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("expected negative-bound rejection")
	}
	if _, err := CenteredInt64(bytes.NewReader(nil), math.MaxInt64); err == nil {
		t.Fatal("expected overflowing-bound rejection")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestInt64nPropagatesReaderFailure(t *testing.T) {
	if _, err := Int64n(failingReader{}, 9); err == nil {
		t.Fatal("expected reader failure")
	}
}
