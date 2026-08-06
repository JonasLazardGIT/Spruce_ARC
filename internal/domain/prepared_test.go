package domain

import (
	"encoding/binary"
	"reflect"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"
)

func legacySampleForTest(t *testing.T, binding Binding, prefix []uint64, seed []byte) []uint64 {
	t.Helper()
	xof := sha3.NewShake256()
	if prefix == nil {
		_, _ = xof.Write([]byte("SmallWood:E"))
	} else {
		_, _ = xof.Write([]byte("SmallWood:E:prefixed"))
	}
	writeSamplingParameters(xof, binding)
	seen := make(map[uint64]struct{}, binding.NLeaves)
	points := make([]uint64, 0, binding.NLeaves)
	var buf [8]byte
	for _, value := range prefix {
		value %= binding.Q
		if _, exists := seen[value]; exists {
			t.Fatalf("legacy test prefix duplicate %d", value)
		}
		seen[value] = struct{}{}
		points = append(points, value)
		binary.LittleEndian.PutUint64(buf[:], value)
		_, _ = xof.Write(buf[:])
	}
	if len(seed) > 0 {
		_, _ = xof.Write(seed)
	}
	for len(points) < binding.NLeaves {
		value, err := sampleUniformMod(xof, binding.Q)
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		points = append(points, value)
	}
	return points
}

func TestPreparedSamplingMatchesLegacyOrder(t *testing.T) {
	cases := []struct {
		binding Binding
		seed    []byte
	}{
		{Binding{Q: 257, NLeaves: 64, OmegaSize: 8, Ell: 3}, nil},
		{Binding{Q: 1038337, NLeaves: 1024, OmegaSize: 32, Ell: 13}, []byte("domain-vector-a")},
		{Binding{Q: 1017857, NLeaves: 4096, OmegaSize: 43, Ell: 18}, []byte("domain-vector-b")},
	}
	for _, testCase := range cases {
		prepared, err := SamplePrepared(testCase.binding, testCase.seed)
		if err != nil {
			t.Fatal(err)
		}
		want := legacySampleForTest(t, testCase.binding, nil, testCase.seed)
		if got := prepared.CopyPoints(); !reflect.DeepEqual(got, want) {
			t.Fatalf("sample order changed for %+v", testCase.binding)
		}
	}
}

func TestPreparedPrefixedSamplingMatchesLegacyOrder(t *testing.T) {
	binding := Binding{Q: 1038337, NLeaves: 512, OmegaSize: 8, Ell: 4}
	prefix := []uint64{1038338, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	seed := []byte("prefixed-domain-vector")
	prepared, err := SamplePreparedWithPrefix(binding, prefix, seed)
	if err != nil {
		t.Fatal(err)
	}
	want := legacySampleForTest(t, binding, prefix, seed)
	if got := prepared.CopyPoints(); !reflect.DeepEqual(got, want) {
		t.Fatal("prefixed sampling order changed")
	}
}

func TestPreparedOwnsAllExposedPointStorage(t *testing.T) {
	binding := Binding{Q: 257, NLeaves: 8, OmegaSize: 2, Ell: 1}
	input := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	prepared, err := NewPrepared(binding, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 99
	if prepared.At(0) != 1 {
		t.Fatal("prepared domain aliases constructor input")
	}
	copyPoints := prepared.CopyPoints()
	copyPoints[0] = 98
	legacy := prepared.Domain()
	legacy.E[0] = 97
	if prepared.At(0) != 1 {
		t.Fatal("prepared domain exposes mutable backing storage")
	}
	if err := prepared.ValidateBinding(binding); err != nil {
		t.Fatal(err)
	}
	wrong := binding
	wrong.Ell++
	if err := prepared.ValidateBinding(wrong); err == nil {
		t.Fatal("accepted mismatched binding")
	}
}

func TestDistinctSetSelectionAndDifferential(t *testing.T) {
	bitsetQ := uint64(maxDistinctBitsetBytes) * 8
	if _, ok := newDistinctSet(bitsetQ, 1).(bitDistinctSet); !ok {
		t.Fatal("8 MiB boundary did not select bitset")
	}
	if _, ok := newDistinctSet(bitsetQ+1, 1).(mapDistinctSet); !ok {
		t.Fatal("value above 8 MiB boundary did not select map")
	}
	bitset := newDistinctSet(257, 8)
	mapSet := mapDistinctSet{}
	sequence := []uint64{0, 1, 256, 1, 128, 0, 255}
	for _, value := range sequence {
		if got, want := bitset.add(value), mapSet.add(value); got != want {
			t.Fatalf("membership result differs for %d: bitset=%v map=%v", value, got, want)
		}
	}
}

func TestPreparedConcurrentReads(t *testing.T) {
	binding := Binding{Q: 1038337, NLeaves: 1024, OmegaSize: 32, Ell: 13}
	prepared, err := SamplePrepared(binding, []byte("race-vector"))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			for i := 0; i < prepared.Len(); i++ {
				_ = prepared.At((i + offset) % prepared.Len())
			}
			_ = prepared.CopyRange(0, binding.OmegaSize+binding.Ell)
		}(worker)
	}
	wait.Wait()
}
