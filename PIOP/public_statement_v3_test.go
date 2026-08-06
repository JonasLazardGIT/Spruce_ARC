package PIOP

import (
	"bytes"
	"testing"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestCanonicalPublicInputsBytesV3BindsEveryScalarAndExtras(t *testing.T) {
	coeffs := make([]uint64, 1024)
	copy(coeffs, []uint64{1, 2, 3})
	poly := &ring.Poly{Coeffs: [][]uint64{coeffs}}
	base := PublicInputs{
		Com: []*ring.Poly{poly}, RI0: []*ring.Poly{poly}, RI1: []*ring.Poly{poly},
		Ac: [][]*ring.Poly{{poly}}, CM: [][]*ring.Poly{{poly}}, AS: [][]*ring.Poly{{poly}}, A: [][]*ring.Poly{{poly}}, B: []*ring.Poly{poly},
		T: []int64{1}, Tag: []int64{2}, Context: []int64{3}, ContextDigest: []byte{4},
		BoundB: 5, X0Len: 6, X0CoeffBound: 7, HashInputBound: 8, TargetDim: 9,
		TargetHidingLambda: 10, RingDegree: 1024, HashRelation: "relation", IntGenISIS: true,
		Extras: map[string]interface{}{"z": []byte("last"), "a": []byte("first")},
	}
	want, err := canonicalPublicInputsBytesV3(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*PublicInputs){
		func(p *PublicInputs) { p.BoundB++ },
		func(p *PublicInputs) { p.X0Len++ },
		func(p *PublicInputs) { p.X0CoeffBound++ },
		func(p *PublicInputs) { p.HashInputBound++ },
		func(p *PublicInputs) { p.TargetDim++ },
		func(p *PublicInputs) { p.TargetHidingLambda++ },
		func(p *PublicInputs) { p.RingDegree++ },
		func(p *PublicInputs) { p.HashRelation += "-changed" },
		func(p *PublicInputs) { p.IntGenISIS = false },
		func(p *PublicInputs) { p.Extras["a"] = []byte("changed") },
	}
	for i, mutate := range mutations {
		changed := base
		changed.Extras = map[string]interface{}{"z": []byte("last"), "a": []byte("first")}
		mutate(&changed)
		got, err := canonicalPublicInputsBytesV3(changed)
		if err != nil && i != 6 {
			t.Fatalf("mutation %d: %v", i, err)
		}
		if err == nil && bytes.Equal(got, want) {
			t.Fatalf("mutation %d did not change canonical public statement", i)
		}
	}
}

func TestCanonicalPublicInputsBytesV3RejectsUnframedExtraTypesAndNilPolys(t *testing.T) {
	if _, err := canonicalPublicInputsBytesV3(PublicInputs{RingDegree: 1024, Extras: map[string]interface{}{"x": int64(1)}}); err == nil {
		t.Fatal("strict v3 accepted a non-byte public extra")
	}
	if _, err := canonicalPublicInputsBytesV3(PublicInputs{RingDegree: 1024, Com: []*ring.Poly{nil}}); err == nil {
		t.Fatal("strict v3 accepted a nil public polynomial")
	}
	wide := &ring.Poly{Coeffs: [][]uint64{make([]uint64, 1024), make([]uint64, 1024)}}
	if _, err := canonicalPublicInputsBytesV3(PublicInputs{RingDegree: 1024, Com: []*ring.Poly{wide}}); err == nil {
		t.Fatal("strict v3 accepted a multi-limb public polynomial")
	}
	noncanonical := &ring.Poly{Coeffs: [][]uint64{make([]uint64, 1024)}}
	noncanonical.Coeffs[0][0] = credential.IntGenISISSharedModulusQ
	if _, err := canonicalPublicInputsBytesV3(PublicInputs{RingDegree: 1024, Com: []*ring.Poly{noncanonical}}); err == nil {
		t.Fatal("strict v3 accepted a public coefficient >=q")
	}
}

func TestCanonicalPublicInputsBytesV3SortsExtras(t *testing.T) {
	a := PublicInputs{RingDegree: 1024, Extras: map[string]interface{}{"a": []byte{1}, "b": []byte{2}}}
	b := PublicInputs{RingDegree: 1024, Extras: map[string]interface{}{"b": []byte{2}, "a": []byte{1}}}
	left, err := canonicalPublicInputsBytesV3(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := canonicalPublicInputsBytesV3(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("canonical v3 extras depend on map iteration order")
	}
}

func TestCanonicalPublicStatementWithLayoutBytesV3BindsCompleteReconstructedLayout(t *testing.T) {
	pub := PublicInputs{RingDegree: 1024}
	layout := RowLayout{
		RingDegree:         1024,
		SigCount:           423,
		HasExplicitBaseIdx: true,
		IntGenISISShowing: &IntGenISISShowingRowLayout{
			LayoutVersion:       intGenISISShowingLayoutVersionInputTraceCarrierV3,
			LinearHatSourceMode: intGenISISLinearHatSourceMuX0AggregateFused,
			MuSigHatStart:       -1,
			X0HatStart:          -1,
			X1HatStart:          385,
			X1HatCount:          32,
			ZHatStart:           417,
			ZHatCount:           32,
		},
	}
	want, err := canonicalPublicStatementWithLayoutBytesV3(pub, layout)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(want, canonicalProofCodecProfileBytesV6()) {
		t.Fatal("complete public statement does not bind canonical codec profile v6")
	}
	mutations := []func(*RowLayout){
		func(l *RowLayout) { l.SigCount++ },
		func(l *RowLayout) { l.IntGenISISShowing.LinearHatSourceMode = intGenISISLinearHatSourceMaterialized },
		func(l *RowLayout) { l.IntGenISISShowing.X1HatStart++ },
		func(l *RowLayout) { l.CarrierMuBlockRows = []int{} }, // nil and empty are distinct canonical states.
	}
	for i, mutate := range mutations {
		changed := layout
		showing := *layout.IntGenISISShowing
		changed.IntGenISISShowing = &showing
		mutate(&changed)
		got, err := canonicalPublicStatementWithLayoutBytesV3(pub, changed)
		if err != nil {
			t.Fatalf("mutation %d: %v", i, err)
		}
		if bytes.Equal(got, want) {
			t.Fatalf("layout mutation %d did not change the v3 public statement", i)
		}
	}
}
