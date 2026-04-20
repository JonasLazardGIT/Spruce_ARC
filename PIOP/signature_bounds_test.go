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
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR12285L1Research},
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
			opts:    SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR7L4Experimental},
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
			gotBase, gotL, gotCaps, err := ResolveSignatureBoundShapeForOpts(ringQ, tc.opts)
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
		SigShortnessProfileR12285L1Research,
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
		SigShortnessProfileR7L4Experimental,
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
	base, L, caps, err := ResolveSignatureBoundShapeForOpts(ringQ, SimOpts{
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

func TestResolveShowingPresetLabelForOpts(t *testing.T) {
	cases := []struct {
		name string
		opts SimOpts
		want string
	}{
		{
			name: "default_soundness_balanced",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
			},
			want: ShowingPresetSoundnessBalanced,
		},
		{
			name: "explicit_transcript_first",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				ShowingPreset:       ShowingPresetTranscriptFirst,
			},
			want: ShowingPresetTranscriptFirst,
		},
		{
			name: "explicit_compact_l2",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				ShowingPreset:       ShowingPresetCompactL2,
			},
			want: ShowingPresetCompactL2,
		},
		{
			name: "explicit_production_balance",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				ShowingPreset:       ShowingPresetProductionBalance,
			},
			want: ShowingPresetProductionBalance,
		},
		{
			name: "raw_override_is_custom",
			opts: SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				SigShortnessRadix:   5,
				SigShortnessL:       5,
			},
			want: ShowingPresetCustom,
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

func TestResolveSimOptsDefaultsSoundnessBalancedPreset(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:          true,
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetSoundnessBalanced {
		t.Fatalf("showing preset=%q want %q", got, ShowingPresetSoundnessBalanced)
	}
	if opts.SigShortnessProfile != SigShortnessProfileR11L4Production {
		t.Fatalf("sig shortness profile=%q want %q", opts.SigShortnessProfile, SigShortnessProfileR11L4Production)
	}
	if opts.LVCSNCols != 89 || opts.PostSignLVCSNCols != 89 || opts.PRFLVCSNCols != 89 {
		t.Fatalf("unexpected lvcs preset resolution: %+v", opts)
	}
	if opts.Theta != 3 || opts.Rho != 2 || opts.EllPrime != 2 || opts.Eta != 43 {
		t.Fatalf("unexpected soundness-balanced tuple: theta=%d rho=%d ellPrime=%d eta=%d", opts.Theta, opts.Rho, opts.EllPrime, opts.Eta)
	}
	if opts.NLeaves != 4096 || opts.PostSignNLeaves != 4096 || opts.PRFNLeaves != 4096 {
		t.Fatalf("unexpected nleaves resolution: n=%d post=%d prf=%d", opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves)
	}
	if opts.Kappa != [4]int{0, 0, 0, 5} {
		t.Fatalf("unexpected kappa=%v want [0 0 0 5]", opts.Kappa)
	}
}

func TestResolveSimOptsDefaultsCompactPresets(t *testing.T) {
	cases := []struct {
		name        string
		preset      string
		wantProfile string
		wantLVCS    int
		wantEta     int
	}{
		{
			name:        "compact_l3",
			preset:      ShowingPresetCompactL3,
			wantProfile: SigShortnessProfileR24L3Compact,
			wantLVCS:    68,
			wantEta:     36,
		},
		{
			name:        "compact_l2",
			preset:      ShowingPresetCompactL2,
			wantProfile: SigShortnessProfileR111L2Compact,
			wantLVCS:    70,
			wantEta:     36,
		},
		{
			name:        "compact_l1_research",
			preset:      ShowingPresetCompactL1Research,
			wantProfile: SigShortnessProfileR12285L1Research,
			wantLVCS:    32,
			wantEta:     26,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := ResolveSimOptsDefaults(SimOpts{
				Credential:          true,
				CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
				ShowingPreset:       tc.preset,
			})
			if got := ResolveShowingPresetLabelForOpts(opts); got != tc.preset {
				t.Fatalf("showing preset=%q want %q", got, tc.preset)
			}
			if opts.SigShortnessProfile != tc.wantProfile {
				t.Fatalf("sig shortness profile=%q want %q", opts.SigShortnessProfile, tc.wantProfile)
			}
			if opts.LVCSNCols != tc.wantLVCS || opts.PostSignLVCSNCols != tc.wantLVCS || opts.PRFLVCSNCols != tc.wantLVCS {
				t.Fatalf("unexpected lvcs preset resolution: %+v", opts)
			}
			wantEllPrime := 2
			wantKappa := [4]int{0, 0, 0, 5}
			if tc.preset == ShowingPresetCompactL1Research {
				wantEllPrime = 3
				wantKappa = [4]int{0, 11, 0, 11}
			}
			if opts.Theta != 3 || opts.Rho != 2 || opts.EllPrime != wantEllPrime || opts.Eta != tc.wantEta {
				t.Fatalf("unexpected compact tuple: theta=%d rho=%d ellPrime=%d eta=%d", opts.Theta, opts.Rho, opts.EllPrime, opts.Eta)
			}
			if opts.NLeaves != 4096 || opts.PostSignNLeaves != 4096 || opts.PRFNLeaves != 4096 {
				t.Fatalf("unexpected compact nleaves resolution: n=%d post=%d prf=%d", opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves)
			}
			if opts.Kappa != wantKappa {
				t.Fatalf("unexpected compact kappa=%v want %v", opts.Kappa, wantKappa)
			}
		})
	}
}
