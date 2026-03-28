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
	}{
		{
			name:     "default_r12_l3",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR12L3Default},
			wantBase: 12,
			wantL:    3,
			wantRows: 3,
			wantDeg:  12,
			wantCaps: nil,
		},
		{
			name:     "legacy_r13_l3",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR13L3Legacy},
			wantBase: 13,
			wantL:    3,
			wantRows: 3,
			wantDeg:  13,
			wantCaps: []int{6, 6, 4},
		},
		{
			name:     "experimental_r7_l4",
			opts:     SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: SigShortnessProfileR7L4Experimental},
			wantBase: 7,
			wantL:    4,
			wantRows: 4,
			wantDeg:  7,
			wantCaps: nil,
		},
	}

	const ringQ = uint64(12289)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, L, rowsPerSig, degree, err := ResolveSignatureShortnessMetricsForOpts(ringQ, tc.opts)
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

func TestSignatureShortnessDefaultProfileRepresentability(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(12289)
	spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR12L3Default,
	})
	if err != nil {
		t.Fatalf("resolve default shortness spec: %v", err)
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

func TestSignatureShortnessExperimentalProfileRepresentability(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(12289)
	spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR7L4Experimental,
	})
	if err != nil {
		t.Fatalf("resolve experimental shortness spec: %v", err)
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

func TestSignatureShortnessCustomBalanced55Representability(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(12289)
	spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   5,
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

func TestSignatureShortnessLegacyProfilePreserved(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(12289)
	spec, err := signatureChainSpecForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR13L3Legacy,
	})
	if err != nil {
		t.Fatalf("resolve legacy shortness spec: %v", err)
	}
	if spec.R != 13 || spec.L != 3 {
		t.Fatalf("legacy spec=(R=%d,L=%d) want (13,3)", spec.R, spec.L)
	}
	if spec.DigitLo[0] != -6 || spec.DigitHi[0] != 6 || spec.DigitLo[2] != -4 || spec.DigitHi[2] != 4 {
		t.Fatalf("unexpected legacy digit ranges: lo=%v hi=%v", spec.DigitLo, spec.DigitHi)
	}
}

func TestSignatureShortnessLegacyProfileRejectsRawOverrides(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(12289)
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
		SigShortnessProfile: SigShortnessProfileR12L3Default,
		SigShortnessRadix:   5,
		SigShortnessL:       5,
	})
	if got != SigShortnessProfileCustomBalanced {
		t.Fatalf("reported profile=%q want %q", got, SigShortnessProfileCustomBalanced)
	}
}

func TestSignatureShortnessTemptingCappedShapeIsNotProductionDefault(t *testing.T) {
	signatureBoundsChdirRepoRoot(t)
	const ringQ = uint64(12289)
	spec := NewSignedLinfChainSpecRadix(ringQ, 12, 3, 1, 745, []int{5, 5, 5})
	missing := 0
	for v := int64(-745); v <= 745; v++ {
		if _, err := decomposeLinfDigitsSigned(v, spec); err != nil {
			missing++
		}
	}
	if missing == 0 {
		t.Fatalf("expected capped R=12,L=3,[5,5,5] shape to miss some values in [-745,745]")
	}
	base, L, caps, err := ResolveSignatureBoundShapeForOpts(ringQ, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR12L3Default,
	})
	if err != nil {
		t.Fatalf("resolve production default shape: %v", err)
	}
	if base != 12 || L != 3 || len(caps) != 0 {
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
	if opts.SigShortnessProfile != SigShortnessProfileR7L4Experimental {
		t.Fatalf("sig shortness profile=%q want %q", opts.SigShortnessProfile, SigShortnessProfileR7L4Experimental)
	}
	if opts.LVCSNCols != 96 || opts.PostSignLVCSNCols != 96 || opts.PRFLVCSNCols != 96 {
		t.Fatalf("unexpected lvcs preset resolution: %+v", opts)
	}
	if opts.Theta != 5 || opts.Rho != 2 || opts.EllPrime != 2 || opts.Eta != 63 {
		t.Fatalf("unexpected soundness-balanced tuple: theta=%d rho=%d ellPrime=%d eta=%d", opts.Theta, opts.Rho, opts.EllPrime, opts.Eta)
	}
	if opts.NLeaves != 4096 || opts.PostSignNLeaves != 4096 || opts.PRFNLeaves != 4096 {
		t.Fatalf("unexpected nleaves resolution: n=%d post=%d prf=%d", opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves)
	}
	if opts.Kappa != [4]int{0, 0, 0, 5} {
		t.Fatalf("unexpected kappa=%v want [0 0 0 5]", opts.Kappa)
	}
}
