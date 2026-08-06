package PIOP

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// fallbackShakeXOF intentionally implements only the public XOF interface. It
// exercises the compatibility path against which the SHAKE clone fast path is
// compared.
type fallbackShakeXOF struct {
	shake Shake256XOF
	calls int
	input [][]byte
}

// embeddedOverrideXOF guards against accidentally selecting the built-in
// SHAKE clone path through method promotion. Its Expand method is authoritative
// even though it embeds Shake256XOF.
type embeddedOverrideXOF struct {
	Shake256XOF
	calls int
}

func (x *embeddedOverrideXOF) Expand(label string, parts ...[]byte) []byte {
	x.calls++
	out := x.Shake256XOF.Expand("embedded-override:"+label, parts...)
	out[0] = 0
	return out
}

func (x *fallbackShakeXOF) Expand(label string, parts ...[]byte) []byte {
	x.calls++
	framed := append([]byte(label), flattenBytes(parts)...)
	x.input = append(x.input, append([]byte(nil), framed...))
	return x.shake.Expand(label, parts...)
}

func strictV3FSParams(kappa [4]int) FSParams {
	return FSParams{
		Lambda:             128,
		Kappa:              kappa,
		TranscriptVersion:  TranscriptVersionSmallWood2025V3,
		TranscriptProtocol: TranscriptProtocolSmallField2025V3,
	}
}

func TestFSV3ShakePrefixCloneSingleCounterMatchesReference(t *testing.T) {
	lengths := []int{0, 1, 127, 128, 135, 136, 137, 271, 272, 273}
	for _, length := range lengths {
		material := [][]byte{
			bytes.Repeat([]byte{byte(length)}, length),
			[]byte("second-material-item"),
		}
		for _, counter := range []uint64{0, 1, 255, 256, math.MaxUint64} {
			fs := NewFS(NewShake256XOF(fsDigestBytes), []byte("rate-boundary-salt"), strictV3FSParams([4]int{}))
			got := fs.expandRoundV3At(0, material, counter)
			want := NewShake256XOF(fsDigestBytes).Expand(fs.labels[0], fs.roundInputV3(0, material, counter))
			if !bytes.Equal(got, want) {
				t.Fatalf("material length=%d counter=%d digest mismatch", length, counter)
			}
		}
	}
}

func TestFSV3ShakePrefixCloneFourRoundGrindingMatchesFallback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kappa [4]int
	}{
		{name: "bq128", kappa: [4]int{5, 6, 12, 13}},
		{name: "wf128", kappa: [4]int{1, 0, 2, 13}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fast := NewFS(NewShake256XOF(fsDigestBytes), []byte("frozen-prefix-vector"), strictV3FSParams(tc.kappa))
			fallbackXOF := &fallbackShakeXOF{shake: NewShake256XOF(fsDigestBytes)}
			fallback := NewFS(fallbackXOF, []byte("frozen-prefix-vector"), strictV3FSParams(tc.kappa))
			for round := 0; round < 4; round++ {
				material := [][]byte{
					bytes.Repeat([]byte{byte(0x40 + round)}, 120+round*17),
					[]byte{0, byte(round), 0xff},
				}
				fastDigest, fastCounter, fastChallenge := fast.GrindAndDerive(round, material, func(h []byte) []byte {
					return append([]byte("challenge:"), h...)
				})
				fallbackDigest, fallbackCounter, fallbackChallenge := fallback.GrindAndDerive(round, material, func(h []byte) []byte {
					return append([]byte("challenge:"), h...)
				})
				if fastCounter != fallbackCounter || !bytes.Equal(fastDigest, fallbackDigest) || !bytes.Equal(fastChallenge, fallbackChallenge) {
					t.Fatalf("round %d differs: counters=%d/%d", round, fastCounter, fallbackCounter)
				}
			}
			if !reflect.DeepEqual(fast.ctr, fallback.ctr) || !reflect.DeepEqual(fast.h, fallback.h) {
				t.Fatal("final chained FS state differs")
			}
		})
	}
}

type counterScriptXOF struct {
	rejectUntil uint64
	counters    []uint64
}

func (x *counterScriptXOF) Expand(_ string, parts ...[]byte) []byte {
	input := flattenBytes(parts)
	counter := binary.BigEndian.Uint64(input[len(input)-8:])
	x.counters = append(x.counters, counter)
	out := make([]byte, fsDigestBytes)
	if counter < x.rejectUntil {
		out[0] = 0xff
	}
	return out
}

func TestFSV3CustomXOFFallbackRemainsSequential(t *testing.T) {
	xof := &counterScriptXOF{rejectUntil: 256}
	fs := NewFS(xof, []byte("salt"), strictV3FSParams([4]int{8}))
	digest, counter, _ := fs.GrindAndDerive(0, [][]byte{[]byte("payload")}, func(h []byte) []byte { return h })
	if counter != 256 || !hasZeroPrefix(digest, 8) {
		t.Fatalf("accepted counter=%d digest=%x", counter, digest[:1])
	}
	if len(xof.counters) != 257 {
		t.Fatalf("fallback calls=%d want 257", len(xof.counters))
	}
	for i, got := range xof.counters {
		if got != uint64(i) {
			t.Fatalf("fallback counter[%d]=%d", i, got)
		}
	}
}

func TestFSV3EmbeddedCustomXOFDoesNotInheritBuiltinFastPath(t *testing.T) {
	xof := &embeddedOverrideXOF{Shake256XOF: NewShake256XOF(fsDigestBytes)}
	fs := NewFS(xof, []byte("salt"), strictV3FSParams([4]int{}))
	material := [][]byte{[]byte("payload")}
	digest, counter, _ := fs.GrindAndDerive(0, material, func(h []byte) []byte { return h })
	if counter != 0 || xof.calls != 1 {
		t.Fatalf("grinding counter/calls=%d/%d want 0/1", counter, xof.calls)
	}
	want := NewShake256XOF(fsDigestBytes).Expand("embedded-override:"+fs.labels[0], fs.roundInputV3(0, material, 7))
	want[0] = 0
	got := fs.expandRoundV3At(0, material, 7)
	if xof.calls != 2 || !bytes.Equal(got, want) || !bytes.Equal(digest, func() []byte {
		reference := NewShake256XOF(fsDigestBytes).Expand("embedded-override:"+fs.labels[0], fs.roundInputV3(0, material, 0))
		reference[0] = 0
		return reference
	}()) {
		t.Fatalf("embedded custom XOF override was bypassed: calls=%d", xof.calls)
	}
}

type rejectAllXOF struct{}

func (rejectAllXOF) Expand(_ string, _ ...[]byte) []byte {
	return bytes.Repeat([]byte{0xff}, fsDigestBytes)
}

func TestFSV3CounterOverflowStillPanics(t *testing.T) {
	fs := NewFS(rejectAllXOF{}, []byte("salt"), strictV3FSParams([4]int{1}))
	fs.ctr[0] = math.MaxUint64
	defer func() {
		got := recover()
		if got == nil || !strings.Contains(fmt.Sprint(got), "counter wrapped") {
			t.Fatalf("panic=%v want counter wrapped", got)
		}
	}()
	fs.GrindAndDerive(0, nil, func(h []byte) []byte { return h })
}

func TestFSV3PhaseRecorderSplitsPrefixAndCounterLoop(t *testing.T) {
	recorder := NewPhaseRecorder()
	fs := NewFS(NewShake256XOF(fsDigestBytes), []byte("salt"), strictV3FSParams([4]int{}))
	fs.setPhaseRecorder(recorder, "issuance")
	fs.GrindAndDerive(0, [][]byte{[]byte("payload")}, func(h []byte) []byte { return h })
	timings := recorder.Snapshot()
	if len(timings) != 2 || timings[0].Label != "issuance.fs.round1.prefix" || timings[1].Label != "issuance.fs.round1.counter_loop" {
		t.Fatalf("phase timings=%+v", timings)
	}
}
