package PIOP

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func signatureBoundsRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func signatureBoundsChdirRepoRoot(t *testing.T) {
	t.Helper()
	root := signatureBoundsRepoRoot(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir %s: %v", root, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

func TestIntGenISISUShortnessTopDigitCapForN512Beta(t *testing.T) {
	const q = uint64(1017857)
	spec, err := intGenISISUShortnessSpecForOpts(q, 6002, SimOpts{
		SigShortnessRadix: 7,
		SigShortnessL:     5,
	})
	if err != nil {
		t.Fatalf("shortness spec: %v", err)
	}
	if spec.MaxAbs != 6002 {
		t.Fatalf("maxAbs=%d want 6002", spec.MaxAbs)
	}
	if len(spec.DigitHi) != 5 || spec.DigitHi[4] != 2 || spec.DigitLo[4] != -2 {
		t.Fatalf("top digit range=%v/%v want cap 2", spec.DigitLo, spec.DigitHi)
	}
	if _, err := decomposeLinfDigitsSigned(6002, spec); err != nil {
		t.Fatalf("decompose 6002: %v", err)
	}
	if _, err := decomposeLinfDigitsSigned(-6002, spec); err != nil {
		t.Fatalf("decompose -6002: %v", err)
	}
	if _, err := decomposeLinfDigitsSigned(6003, spec); err == nil {
		t.Fatalf("decompose 6003 unexpectedly succeeded")
	}
}

func TestIntGenISISUShortnessDefaultCapacityWhenTopCapCannotFit(t *testing.T) {
	const q = uint64(1017857)
	spec, err := intGenISISUShortnessSpecForOpts(q, 6142, SimOpts{
		SigShortnessRadix: 7,
		SigShortnessL:     5,
	})
	if err != nil {
		t.Fatalf("shortness spec: %v", err)
	}
	if spec.MaxAbs != 8403 {
		t.Fatalf("maxAbs=%d want full R7/L5 capacity 8403", spec.MaxAbs)
	}
}

func TestSignatureShortnessProfileMetrics(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	beta, err := productionSignatureCoeffLinfBeta()
	if err != nil {
		t.Fatalf("load production beta: %v", err)
	}
	if beta == 0 {
		t.Fatalf("production beta is zero")
	}

	tests := []struct {
		name     string
		opts     SimOpts
		wantBase int
		wantL    int
		wantRows int
		wantDeg  int
		wantCaps []int
		wantErr  bool
	}{
		{
			name:     "production_r11_l4",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR11L4Production},
			wantBase: 11,
			wantL:    4,
			wantRows: 4,
			wantDeg:  11,
			wantCaps: nil,
		},
		{
			name:     "custom_balanced_r7_l5",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessRadix: 7, SigShortnessL: 5},
			wantBase: 7,
			wantL:    5,
			wantRows: 5,
			wantDeg:  7,
			wantCaps: nil,
		},
		{
			name:     "compact_r24_l3",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR24L3Compact},
			wantBase: 24,
			wantL:    3,
			wantRows: 3,
			wantDeg:  24,
			wantCaps: nil,
		},
		{
			name:     "compact_r111_l2",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR111L2Compact},
			wantBase: 111,
			wantL:    2,
			wantRows: 2,
			wantDeg:  111,
			wantCaps: nil,
		},
		{
			name:     "research_r12285_l1",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR12285L1Compact},
			wantBase: 12285,
			wantL:    1,
			wantRows: 1,
			wantDeg:  12285,
			wantCaps: nil,
		},
		{
			name:    "default_r12_l3_rejects_current_beta",
			opts:    SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR12L3Default},
			wantErr: true,
		},
		{
			name:    "legacy_r13_l3_rejects_current_beta",
			opts:    SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR13L3Legacy},
			wantErr: true,
		},
		{
			name:    "experimental_r7_l4_rejects_current_beta",
			opts:    SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR7L4LowRadix},
			wantErr: true,
		},
	}

	const ringQ = uint64(1054721)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, L, rowsPerSig, degree, err := ResolveSignatureShortnessMetricsForOpts(ringQ, tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected resolve shortness metrics to fail for beta=%d", beta)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve shortness metrics: %v", err)
			}
			if base != tc.wantBase || L != tc.wantL || rowsPerSig != tc.wantRows || degree != tc.wantDeg {
				t.Fatalf("metrics=(R=%d,L=%d,rows=%d,deg=%d) want (R=%d,L=%d,rows=%d,deg=%d)", base, L, rowsPerSig, degree, tc.wantBase, tc.wantL, tc.wantRows, tc.wantDeg)
			}
			gotBase, gotL, _, gotCaps, err := signatureBoundShapeForOpts(ringQ, tc.opts)
			if err != nil {
				t.Fatalf("resolve bound shape: %v", err)
			}
			if gotBase != tc.wantBase || gotL != tc.wantL {
				t.Fatalf("bound shape=(R=%d,L=%d) want (R=%d,L=%d)", gotBase, gotL, tc.wantBase, tc.wantL)
			}
			if len(gotCaps) != len(tc.wantCaps) {
				t.Fatalf("caps len=%d want %d", len(gotCaps), len(tc.wantCaps))
			}
			for i := range tc.wantCaps {
				if gotCaps[i] != tc.wantCaps[i] {
					t.Fatalf("caps[%d]=%d want %d", i, gotCaps[i], tc.wantCaps[i])
				}
			}
		})
	}
}

func TestSignatureShortnessProductionProfileRepresentability(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(1054721)
	spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR11L4Production,
	})
	if err != nil {
		t.Fatalf("resolve production shortness spec: %v", err)
	}
	beta, err := productionSignatureCoeffLinfBeta()
	if err != nil {
		t.Fatalf("load production beta: %v", err)
	}
	for v := -int64(beta); v <= int64(beta); v++ {
		digits, err := decomposeLinfDigitsSigned(v, spec)
		if err != nil {
			t.Fatalf("decompose %d: %v", v, err)
		}
		if got := recomposeLinfDigits(digits, spec); got != v {
			t.Fatalf("recompose %d => %d", v, got)
		}
	}
}

func TestSignatureShortnessCustomBalanced75Representability(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(1054721)
	spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   7,
		SigShortnessL:       5,
	})
	if err != nil {
		t.Fatalf("resolve custom shortness spec: %v", err)
	}
	beta, err := productionSignatureCoeffLinfBeta()
	if err != nil {
		t.Fatalf("load production beta: %v", err)
	}
	for v := -int64(beta); v <= int64(beta); v++ {
		digits, err := decomposeLinfDigitsSigned(v, spec)
		if err != nil {
			t.Fatalf("decompose %d: %v", v, err)
		}
		if got := recomposeLinfDigits(digits, spec); got != v {
			t.Fatalf("recompose %d => %d", v, got)
		}
	}
}

func TestSignatureShortnessNamedCompactProfilesRepresentability(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(1054721)
	beta, err := productionSignatureCoeffLinfBeta()
	if err != nil {
		t.Fatalf("load production beta: %v", err)
	}
	for _, profile := range []string{
		SigShortnessProfileR24L3Compact,
		SigShortnessProfileR111L2Compact,
		SigShortnessProfileR12285L1Compact,
	} {
		spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
			CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
			SigShortnessProfile: profile,
		})
		if err != nil {
			t.Fatalf("resolve %s shortness spec: %v", profile, err)
		}
		for v := -int64(beta); v <= int64(beta); v++ {
			digits, err := decomposeLinfDigitsSigned(v, spec)
			if err != nil {
				t.Fatalf("%s decompose %d: %v", profile, v, err)
			}
			if got := recomposeLinfDigits(digits, spec); got != v {
				t.Fatalf("%s recompose %d => %d", profile, v, got)
			}
		}
	}
}

func TestSignatureShortnessObsoleteProfilesRejectCurrentBeta(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(1054721)
	for _, profile := range []string{
		SigShortnessProfileR12L3Default,
		SigShortnessProfileR13L3Legacy,
		SigShortnessProfileR7L4LowRadix,
	} {
		if _, err := signatureChainSpecForOpts(ringQ, SimOpts{
			CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
			SigShortnessProfile: profile,
		}); err == nil {
			t.Fatalf("expected obsolete profile %q to reject current beta", profile)
		}
	}
}

func TestSignatureShortnessLegacyProfileRejectsRawOverrides(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(1054721)
	_, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR13L3Legacy,
		SigShortnessRadix:   12,
	})
	if err == nil {
		t.Fatalf("expected legacy shortness profile to reject raw overrides")
	}
}

func TestSignatureShortnessRawOverridesReportAsCustomBalanced(t *testing.T) {
	got := ResolveSignatureShortnessProfileLabelForOpts(SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR11L4Production,
		SigShortnessRadix:   7,
		SigShortnessL:       5,
	})
	if got != SigShortnessProfileCustomBalanced {
		t.Fatalf("reported profile=%q want %q", got, SigShortnessProfileCustomBalanced)
	}
}

func TestSignatureShortnessTemptingCappedShapeIsNotProductionDefault(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(1054721)
	beta, err := productionSignatureCoeffLinfBeta()
	if err != nil {
		t.Fatalf("load production beta: %v", err)
	}
	const cappedCapacity = uint64(5856)
	spec := NewSignedLinfChainSpecRadix(ringQ, 11, 4, 1, cappedCapacity, []int{4, 4, 4, 4})
	missing := 0
	for v := -int64(beta); v <= int64(beta); v++ {
		if _, err := decomposeLinfDigitsSigned(v, spec); err != nil {
			missing++
		}
	}
	if missing == 0 {
		t.Fatalf("expected capped R=11,L=4,[4,4,4,4] shape to miss some values in [-%d,%d]", beta, beta)
	}
	base, L, _, caps, err := signatureBoundShapeForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR11L4Production,
	})
	if err != nil {
		t.Fatalf("resolve production default shape: %v", err)
	}
	if base != 11 || L != 4 || len(caps) != 0 {
		t.Fatalf("production default unexpectedly resolved to capped shape: R=%d L=%d caps=%v", base, L, caps)
	}
}

func recomposeLinfDigits(digits []int64, spec LinfSpec) int64 {
	value := int64(0)
	weight := int64(1)
	R := int64(spec.R)
	for i := 0; i < len(digits); i++ {
		value += digits[i] * weight
		weight *= R
	}
	return value
}

func TestResolveShowingPresetLabelForOpts(t *testing.T) {
	cases := []struct {
		name string
		opts SimOpts
		want string
	}{
		{
			name: "explicit_inline_target_replay_compact",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				ShowingPreset:       ShowingPresetInlineTargetReplayCompact,
			},
			want: ShowingPresetInlineTargetReplayCompact,
		},
		{
			name: "raw_override_has_no_maintained_preset_label",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				SigShortnessRadix:   5,
				SigShortnessL:       5,
			},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveShowingPresetLabelForOpts(tc.opts); got != tc.want {
				t.Fatalf("showing preset=%q want %q", got, tc.want)
			}
		})
	}
}

func TestResolveSimOptsDefaultsInlineTargetReplayCompactPreset(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:          true,
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:       ShowingPresetInlineTargetReplayCompact,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetInlineTargetReplayCompact {
		t.Fatalf("showing preset=%q want %q", got, ShowingPresetInlineTargetReplayCompact)
	}
	if opts.SigShortnessProfile != SigShortnessProfileR11L4Production {
		t.Fatalf("sig shortness profile=%q want %q", opts.SigShortnessProfile, SigShortnessProfileR11L4Production)
	}
	if opts.LVCSNCols != 84 || opts.PostSignLVCSNCols != 84 || opts.PRFLVCSNCols != 84 {
		t.Fatalf("unexpected lvcs preset resolution: %+v", opts)
	}
	if opts.Theta != 3 || opts.Rho != 2 || opts.Ell != 16 || opts.EllPrime != 2 || opts.Eta != 41 {
		t.Fatalf("unexpected inline-target tuple: theta=%d rho=%d ell=%d ellPrime=%d eta=%d", opts.Theta, opts.Rho, opts.Ell, opts.EllPrime, opts.Eta)
	}
	if opts.NLeaves != 5760 || opts.PostSignNLeaves != 5760 || opts.PRFNLeaves != 5760 {
		t.Fatalf("unexpected inline-target nleaves: n=%d post=%d prf=%d", opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves)
	}
	if opts.Kappa != [4]int{10, 0, 0, 6} {
		t.Fatalf("unexpected kappa=%v want [10 0 0 6]", opts.Kappa)
	}
}
