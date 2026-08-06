package PIOP

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	"vSIS-Signature/credential"
)

func publicationV4FSParams(bits int, phase FSTranscriptPhase, relation string) FSParams {
	return FSParams{
		Lambda:             256,
		TranscriptVersion:  TranscriptVersionSmallWood2025V4,
		TranscriptProtocol: TranscriptProtocolSmallField2025V4,
		OutputBits:         bits,
		Phase:              phase,
		Relation:           relation,
	}
}

func TestPublicationV4FSExactWidthsAndFailClosedPolicy(t *testing.T) {
	for _, bits := range []int{168, 256, 264, 296, 392} {
		t.Run(fmt.Sprintf("bits_%d", bits), func(t *testing.T) {
			opts := SimOpts{
				TranscriptVersion: TranscriptVersionSmallWood2025V4,
				FSOutputBits:      bits,
				FSCollisionBits:   bits,
				DECSHashBits:      bits,
			}
			got, err := ResolveFSOutputBits(opts)
			if err != nil || got != bits {
				t.Fatalf("ResolveFSOutputBits()=(%d,%v), want (%d,nil)", got, err, bits)
			}
			fs, err := NewFSChecked(NewShake256XOF(bits/8), []byte("publication-v4-width"), publicationV4FSParams(bits, FSTranscriptPhaseIssuance, "relation/a"))
			if err != nil {
				t.Fatal(err)
			}
			digest, _, _ := fs.GrindAndDerive(0, [][]byte{[]byte("statement")}, func(v []byte) []byte { return v })
			if len(digest)*8 != bits {
				t.Fatalf("observed digest bits=%d want=%d", len(digest)*8, bits)
			}

			bad := opts
			bad.FSOutputBits -= 8
			if _, err := ResolveFSOutputBits(bad); err == nil {
				t.Fatal("one-byte-short FS width accepted against manifest collision/hash widths")
			}
		})
	}

	for _, params := range []FSParams{
		publicationV4FSParams(0, FSTranscriptPhaseIssuance, "relation/a"),
		publicationV4FSParams(167, FSTranscriptPhaseIssuance, "relation/a"),
		publicationV4FSParams(168, "", "relation/a"),
		publicationV4FSParams(168, FSTranscriptPhaseIssuance, ""),
	} {
		if _, err := NewFSChecked(NewShake256XOF(21), nil, params); err == nil {
			t.Fatalf("invalid v4 params accepted: %+v", params)
		}
	}
}

func TestPublicationV4ExactFiveWidthPoliciesRejectOneByteLess(t *testing.T) {
	for _, presetID := range credential.IntGenISISPublicationPresetNamesV4() {
		policy, ok := PublicationV4WidthPolicyForPreset(presetID)
		if !ok {
			t.Fatalf("missing manifest-derived width policy for %s", presetID)
		}
		opts := SimOpts{
			TranscriptVersion:          TranscriptVersionSmallWood2025V4,
			PresetID:                   presetID,
			FSOutputBits:               policy.FSOutputBits,
			FSCollisionBits:            policy.HashBits,
			DECSCollisionBits:          policy.HashBits,
			DECSHashBits:               policy.HashBits,
			DECSTapeBits:               policy.TapeBits,
			SaltBits:                   policy.SaltBits,
			AggregateROQueryCapLog2:    32,
			AggregateROQueryCapLog2Set: !policy.WorkFactor,
		}
		if err := ValidatePublicationV4Widths(opts); err != nil {
			t.Fatalf("%s exact width policy: %v", presetID, err)
		}
		short := opts
		short.FSOutputBits -= 8
		short.FSCollisionBits -= 8
		short.DECSCollisionBits -= 8
		short.DECSHashBits -= 8
		if err := ValidatePublicationV4Widths(short); err == nil {
			t.Fatalf("%s accepted one-byte-short hash/FS widths", presetID)
		}
	}
}

func TestPublicationV4FSBindsPhaseAndRelation(t *testing.T) {
	derive := func(params FSParams) []byte {
		fs, err := NewFSChecked(NewShake256XOF(params.OutputBits/8), []byte("same-salt"), params)
		if err != nil {
			t.Fatal(err)
		}
		digest, _, _ := fs.GrindAndDerive(0, [][]byte{[]byte("same-statement")}, func(v []byte) []byte { return v })
		return digest
	}
	issuance := derive(publicationV4FSParams(168, FSTranscriptPhaseIssuance, "intgenisis/presign/bb-tran"))
	showing := derive(publicationV4FSParams(168, FSTranscriptPhaseShowing, "intgenisis/showing/bb-tran"))
	otherRelation := derive(publicationV4FSParams(168, FSTranscriptPhaseIssuance, "intgenisis/presign/other"))
	if bytes.Equal(issuance, showing) || bytes.Equal(issuance, otherRelation) || bytes.Equal(showing, otherRelation) {
		t.Fatal("v4 Fiat-Shamir digest did not bind phase and relation identity")
	}
}

func TestPublicationV4RequiresTrustedPresetIdentityForSameThetaProfiles(t *testing.T) {
	missing := SimOpts{TranscriptVersion: TranscriptVersionSmallWood2025V4, Theta: 10}
	if _, err := targetPresetForPRFOptsV3(missing); err == nil || !strings.Contains(err.Error(), "trusted preset ID") {
		t.Fatalf("missing preset identity error=%v", err)
	}
	ids := []string{
		credential.IntGenISISPublicationPresetBQ96Q96V4,
		credential.IntGenISISPublicationPresetBQ128Q64V4,
	}
	for _, id := range ids {
		preset, err := targetPresetForPRFOptsV3(SimOpts{
			TranscriptVersion: TranscriptVersionSmallWood2025V4,
			Theta:             10,
			PresetID:          id,
		})
		if err != nil {
			t.Fatalf("resolve %s: %v", id, err)
		}
		if preset.CanonicalID != id {
			t.Fatalf("resolved ID=%q want=%q", preset.CanonicalID, id)
		}
	}
	pub := PublicInputs{Extras: map[string]interface{}{
		"IntGenISIS.preset_id": []byte(ids[1]),
	}}
	if _, err := optsWithTrustedPresetID(SimOpts{TranscriptVersion: TranscriptVersionSmallWood2025V4, PresetID: ids[0]}, pub); err == nil {
		t.Fatal("same-theta cross-preset identity mismatch accepted")
	}
}

func TestAggregateWholeGameSoundnessHasNoDomainOrPhaseDuplication(t *testing.T) {
	issuance := SoundnessBudget{
		CollisionSpaceBits:    264,
		AggregateQueryBudget:  true,
		AggregateQueryCapBits: 64,
		NativeAlgebraicTerms: [4]float64{
			math.Exp2(-200), math.Exp2(-210), math.Exp2(-220), math.Exp2(-230),
		},
	}
	showing := SoundnessBudget{
		CollisionSpaceBits:    264,
		AggregateQueryBudget:  true,
		AggregateQueryCapBits: 64,
		NativeAlgebraicTerms: [4]float64{
			math.Exp2(-192), math.Exp2(-205), math.Exp2(-215), math.Exp2(-225),
		},
	}
	got := ComposeFullGameSoundness(issuance, showing, 7, 11)
	wantCollision := math.Exp2(-136)
	wantAlgebraic := math.Exp2(-128)
	want := wantCollision + wantAlgebraic
	if got.AccountingMode != FullGameAccountingAggregateV4 {
		t.Fatalf("accounting mode=%q", got.AccountingMode)
	}
	if got.GlobalCollisionError != wantCollision || got.ShowingAlgebraicContribution != wantAlgebraic || got.IssuanceAlgebraicContribution != 0 {
		t.Fatalf("aggregate terms: %+v", got)
	}
	if got.GlobalCollisionFullGameError != want || got.ConservativeFullGameError != want {
		t.Fatalf("full-game error=%g conservative=%g want=%g", got.GlobalCollisionFullGameError, got.ConservativeFullGameError, want)
	}
	if got.GlobalCollisionBits != 136 || got.MaxNativeAlgebraicBits != 192 {
		t.Fatalf("collision/native bits=(%g,%g), want (136,192)", got.GlobalCollisionBits, got.MaxNativeAlgebraicBits)
	}
}

func TestPublicationV4DoesNotMaterializeFiveImplicitQueryBudgets(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		TranscriptVersion:          TranscriptVersionSmallWood2025V4,
		AggregateROQueryCapLog2:    64,
		AggregateROQueryCapLog2Set: true,
	})
	if opts.ROQueryCaps != [5]int{} || opts.ROQueryCapBits != [5]float64{} {
		t.Fatalf("publication-v4 materialized legacy per-domain caps: ints=%v bits=%v", opts.ROQueryCaps, opts.ROQueryCapBits)
	}
	legacy := opts
	legacy.ROQueryCapsSet = true
	legacy.ROQueryCaps = [5]int{1, 1, 1, 1, 1}
	if err := ValidateAggregateROQueryBudget(legacy); err == nil {
		t.Fatal("publication-v4 accepted explicit legacy per-domain query caps")
	}
}

func TestPublicationV4SoundnessReportsOnlyItsSelectedQueryPolicy(t *testing.T) {
	compute := func(opts SimOpts, collisionBits, tapeBits int) SoundnessBudget {
		opts.Theta = 10
		opts.Rho = 1
		opts.Ell = 2
		opts.EllPrime = 1
		opts.Eta = 2
		opts.Kappa = [4]int{128, 128, 128, 128}
		return computeSoundnessBudget(opts, 12289, math.Pow(12289, 10), collisionBits, collisionBits, tapeBits, 8, 16, 32, 2, 1, 2, 64, 128)
	}
	assertNoPhaseCaps := func(name string, budget SoundnessBudget) {
		t.Helper()
		if budget.QueryCaps != [5]int{} {
			t.Fatalf("%s integer query caps=%v", name, budget.QueryCaps)
		}
		for i, bits := range budget.QueryCapBits {
			if !math.IsInf(bits, -1) {
				t.Fatalf("%s query-cap bits[%d]=%g want -Inf", name, i, bits)
			}
		}
	}
	assertFullPhaseCaps := func(name string, full FullGameSoundnessReport) {
		t.Helper()
		if full.IssuanceQueryCaps != [5]int{} || full.ShowingQueryCaps != [5]int{} || full.GlobalQueryCaps != [5]int{} {
			t.Fatalf("%s full-game integer query caps are nonzero: %+v", name, full)
		}
		for _, phase := range [][5]float64{full.IssuanceQueryCapBits, full.ShowingQueryCapBits} {
			for i, bits := range phase {
				if !math.IsInf(bits, -1) {
					t.Fatalf("%s phase query-cap bits[%d]=%g want -Inf", name, i, bits)
				}
			}
		}
		for i, bits := range full.GlobalQueryCapBits {
			if !math.IsInf(bits, -1) {
				t.Fatalf("%s global query-cap bits[%d]=%g want -Inf", name, i, bits)
			}
		}
	}

	qBits := 32.0
	bq := compute(SimOpts{
		TranscriptVersion:          TranscriptVersionSmallWood2025V4,
		PresetID:                   credential.IntGenISISPublicationPresetBQ96Q32V4,
		AggregateROQueryCapLog2:    qBits,
		AggregateROQueryCapLog2Set: true,
	}, 168, 136)
	assertNoPhaseCaps("BQ96-32", bq)
	if !bq.AggregateQueryBudget || bq.AggregateQueryCapBits != qBits || bq.WorkFactorMode {
		t.Fatalf("BQ96-32 selected the wrong query policy: %+v", bq)
	}
	bqFull := ComposeFullGameSoundness(bq, bq, 1, 1)
	if bqFull.AggregateQueryCapLog2 != qBits {
		t.Fatalf("BQ96-32 aggregate query cap=%g want %g", bqFull.AggregateQueryCapLog2, qBits)
	}
	assertFullPhaseCaps("BQ96-32", bqFull)

	wf := compute(SimOpts{
		TranscriptVersion: TranscriptVersionSmallWood2025V4,
		PresetID:          credential.IntGenISISPublicationPresetWF128V4,
	}, 256, 136)
	assertNoPhaseCaps("WF128", wf)
	if wf.AggregateQueryBudget || !wf.WorkFactorMode {
		t.Fatalf("WF128 selected the wrong query policy: %+v", wf)
	}
	assertFullPhaseCaps("WF128", ComposeFullGameSoundness(wf, wf, 1, 1))
}

func TestWF128UsesNativeWorkFactorGateWithoutAggregateQ(t *testing.T) {
	opts := SimOpts{
		TranscriptVersion: TranscriptVersionSmallWood2025V4,
		PresetID:          credential.IntGenISISPublicationPresetWF128V4,
	}
	if err := ValidateAggregateROQueryBudget(opts); err != nil {
		t.Fatalf("WF128 without aggregate Q: %v", err)
	}
	opts.AggregateROQueryCapLog2Set = true
	opts.AggregateROQueryCapLog2 = 64
	if err := ValidateAggregateROQueryBudget(opts); err == nil {
		t.Fatal("WF128 accepted a bounded-query residual policy")
	}

	budget := SoundnessBudget{
		CollisionSpaceBits:   256,
		DECSTapeBits:         136,
		WorkFactorMode:       true,
		WorkFactorBits:       128,
		NativeAlgebraicBits:  [4]float64{128, 129, 130, 131},
		WorkFactorComponents: [6]float64{128, 128, 129, 130, 131, 136},
	}
	wfOpts := SimOpts{TranscriptVersion: TranscriptVersionSmallWood2025V4, PresetID: credential.IntGenISISPublicationPresetWF128V4}
	if err := validatePublicationV4SoundnessBudget(wfOpts, budget); err != nil {
		t.Fatal(err)
	}
	bad := budget
	bad.NativeAlgebraicBits[2] = 127.99
	if err := validatePublicationV4SoundnessBudget(wfOpts, bad); err == nil {
		t.Fatal("WF128 accepted a sub-128-bit native algebraic branch")
	}
	full := ComposeFullGameSoundness(budget, budget, 9, 13)
	if full.AccountingMode != FullGameAccountingWorkFactorV4 || full.WorkFactorBits != 128 || full.MaxNativeAlgebraicBits != 128 || full.MaxNativeAlgebraicError != math.Exp2(-128) {
		t.Fatalf("WF128 full-game report: %+v", full)
	}
}

func TestPublicationV4BQNativeBranchGate(t *testing.T) {
	policy, _ := PublicationV4WidthPolicyForPreset(credential.IntGenISISPublicationPresetBQ128Q64V4)
	opts := SimOpts{TranscriptVersion: TranscriptVersionSmallWood2025V4, PresetID: credential.IntGenISISPublicationPresetBQ128Q64V4}
	budget := SoundnessBudget{NativeAlgebraicBits: [4]float64{
		policy.NativeTargetBits,
		policy.NativeTargetBits + 1,
		policy.NativeTargetBits + 2,
		policy.NativeTargetBits + 3,
	}}
	if err := validatePublicationV4SoundnessBudget(opts, budget); err != nil {
		t.Fatal(err)
	}
	budget.NativeAlgebraicBits[0] = policy.NativeTargetBits - 0.000001
	if err := validatePublicationV4SoundnessBudget(opts, budget); err == nil {
		t.Fatal("BQ preset accepted a native algebraic branch below its exact gate")
	}
}
