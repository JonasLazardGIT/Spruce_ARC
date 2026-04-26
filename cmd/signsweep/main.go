package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"sort"
	"strings"

	PIOP "vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/signverify"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type presignSubmission struct {
	T []int64 `json:"t"`
}

type config struct {
	Name string
	Opts ntru.SamplerOpts
}

type sampleStats struct {
	MaxAbs       int64
	MaxPositive  int64
	MaxNegative  int64
	ResidualLInf int64
	Trials       int
}

type summary struct {
	Name      string
	Values    []sampleStats
	Best      []sampleStats
	Failures  int
	Threshold map[int64]int
	BestThr   map[int64]int
}

func main() {
	samples := flag.Int("samples", 16, "deterministic target count")
	reps := flag.Int("reps", 4, "signatures per target/config")
	maxTrials := flag.Int("max-trials", 2048, "max trials inside one signer call")
	publicPath := flag.String("public-params", "Parameters/credential_public.json", "credential public params path for deterministic issuance targets")
	currentPath := flag.String("current", "credential/issuance/presign_submission.json", "current presign submission path")
	includeCurrent := flag.Bool("include-current", true, "include current credential target")
	only := flag.String("only", "", "comma-separated config names to run; empty runs all")
	flag.Parse()

	if *samples < 0 || *reps <= 0 {
		log.Fatalf("invalid samples=%d reps=%d", *samples, *reps)
	}
	public, err := credential.LoadPublicParams(*publicPath)
	if err != nil {
		log.Fatalf("load credential public params: %v", err)
	}
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		log.Fatalf("load ring: %v", err)
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:    true,
		ShowingPreset: PIOP.ShowingPresetInlineTargetReplayCompactResearch,
	})
	omega, err := PIOP.DeriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, public.HashRelation)
	if err != nil {
		log.Fatalf("derive omega: %v", err)
	}
	B, err := loadBAny(ringQ, public.BPath)
	if err != nil {
		log.Fatalf("load B: %v", err)
	}
	targets := make([][]int64, 0, *samples+1)
	targetLabels := make([]string, 0, *samples+1)
	if *includeCurrent {
		t, err := loadCurrentTarget(*currentPath)
		if err != nil {
			log.Fatalf("load current target: %v", err)
		}
		targets = append(targets, t)
		targetLabels = append(targetLabels, "current")
	}
	for i := 0; i < *samples; i++ {
		t, err := sampleCredentialTarget(ringQ, B, public, omega, i)
		if err != nil {
			log.Fatalf("target %d: %v", i, err)
		}
		targets = append(targets, t)
		targetLabels = append(targetLabels, fmt.Sprintf("det%03d", i))
	}
	configs := []config{
		{Name: "current_prec256_alpha1.25", Opts: ntru.SamplerOpts{Prec: 256, Alpha: 1.25, Slack: 1.042, ReduceIters: 64}},
		{Name: "prec512_alpha1.25", Opts: ntru.SamplerOpts{Prec: 512, Alpha: 1.25, Slack: 1.042, ReduceIters: 64}},
		{Name: "autotune_margin1.00", Opts: ntru.SamplerOpts{Prec: 512, AutoTuneAlpha: true, AutoTuneAlphaMargin: 1.00, Slack: 1.042, ReduceIters: 64}},
		{Name: "autotune_margin1.02", Opts: ntru.SamplerOpts{Prec: 512, AutoTuneAlpha: true, AutoTuneAlphaMargin: 1.02, Slack: 1.042, ReduceIters: 64}},
		{Name: "autotune_margin1.05", Opts: ntru.SamplerOpts{Prec: 512, AutoTuneAlpha: true, AutoTuneAlphaMargin: 1.05, Slack: 1.042, ReduceIters: 64}},
		{Name: "autotune_margin1.00_reduce128", Opts: ntru.SamplerOpts{Prec: 512, AutoTuneAlpha: true, AutoTuneAlphaMargin: 1.00, Slack: 1.042, ReduceIters: 128}},
	}
	configs = filterConfigs(configs, *only)
	thresholds := []int64{4444, 4630, 5070, 6142}

	fmt.Printf("sign-sweep: targets=%d deterministic=%d include_current=%v reps=%d max_trials=%d\n", len(targets), *samples, *includeCurrent, *reps, *maxTrials)
	fmt.Printf("sign-sweep: thresholds=%v\n", thresholds)
	for ci, cfg := range configs {
		sum := summary{Name: cfg.Name, Threshold: map[int64]int{}, BestThr: map[int64]int{}}
		fmt.Printf("config[%d]=%s\n", ci, cfg.Name)
		for ti, target := range targets {
			var best sampleStats
			for r := 0; r < *reps; r++ {
				mrand.Seed(int64(0x715eed00) + int64(ci)*1_000_000 + int64(ti)*1_000 + int64(r))
				sig, err := signverify.SignTarget(target, *maxTrials, cfg.Opts)
				if err != nil {
					sum.Failures++
					fmt.Printf("  fail target=%s rep=%d err=%v\n", targetLabels[ti], r, err)
					continue
				}
				st := statsForSignature(sig.Signature.S1, sig.Signature.S2)
				st.ResidualLInf = sig.Signature.Norm.ResidualLinf
				st.Trials = sig.Signature.TrialsUsed
				sum.Values = append(sum.Values, st)
				if best.MaxAbs == 0 || st.MaxAbs < best.MaxAbs {
					best = st
				}
				for _, th := range thresholds {
					if st.MaxAbs <= th {
						sum.Threshold[th]++
					}
				}
			}
			if best.MaxAbs > 0 {
				sum.Best = append(sum.Best, best)
				for _, th := range thresholds {
					if best.MaxAbs <= th {
						sum.BestThr[th]++
					}
				}
			}
		}
		printSummary(sum, thresholds)
	}
}

func filterConfigs(configs []config, only string) []config {
	if only == "" {
		return configs
	}
	want := map[string]bool{}
	for _, name := range strings.Split(only, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			want[name] = true
		}
	}
	out := configs[:0]
	for _, cfg := range configs {
		if want[cfg.Name] {
			out = append(out, cfg)
		}
	}
	if len(out) == 0 {
		log.Fatalf("no configs matched -only=%q", only)
	}
	return out
}

func loadCurrentTarget(path string) ([]int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sub presignSubmission
	if err := json.Unmarshal(raw, &sub); err != nil {
		return nil, err
	}
	if len(sub.T) == 0 {
		return nil, fmt.Errorf("missing t in %s", path)
	}
	return sub.T, nil
}

func loadBAny(ringQ *ring.Ring, path string) ([]*ring.Poly, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload struct {
		B [][]uint64 `json:"B"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if len(payload.B) == 0 {
		return nil, fmt.Errorf("missing B rows")
	}
	out := make([]*ring.Poly, len(payload.B))
	for i, coeffs := range payload.B {
		if len(coeffs) != ringQ.N {
			return nil, fmt.Errorf("B[%d] length=%d want %d", i, len(coeffs), ringQ.N)
		}
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], coeffs)
		ringQ.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

func sampleCredentialTarget(ringQ *ring.Ring, B []*ring.Poly, public credential.PublicParams, omega []uint64, idx int) ([]int64, error) {
	rng := mrand.New(mrand.NewSource(int64(0x51a70000) + int64(idx)))
	mu := sampleCoeffPoly(ringQ, []int64{-1, 0, 1}, rng)
	r0Alphabet := make([]int64, 0, 2*public.X0CoeffBound+1)
	for v := -public.X0CoeffBound; v <= public.X0CoeffBound; v++ {
		r0Alphabet = append(r0Alphabet, v)
	}
	r0 := make([]*ring.Poly, public.X0Len)
	for i := range r0 {
		r0[i] = sampleCoeffHead(ringQ, r0Alphabet, omega, rng)
	}
	r1 := sampleCoeffHead(ringQ, []int64{-1, 0, 1}, omega, rng)
	_, t, err := credential.ComputeTargetVectorFromMu(ringQ, B, mu, r0, r1)
	return t, err
}

func sampleCoeffPoly(ringQ *ring.Ring, alphabet []int64, rng *mrand.Rand) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N; i++ {
		v := alphabet[rng.Intn(len(alphabet))]
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func sampleCoeffHead(ringQ *ring.Ring, alphabet []int64, omega []uint64, rng *mrand.Rand) *ring.Poly {
	q := int64(ringQ.Modulus[0])
	head := make([]uint64, len(omega))
	for i := range head {
		v := alphabet[rng.Intn(len(alphabet))]
		if v < 0 {
			v += q
		}
		head[i] = uint64(v)
	}
	p := ringQ.NewPoly()
	copy(p.Coeffs[0], PIOP.Interpolate(omega, head, ringQ.Modulus[0]))
	return p
}

func statsForSignature(s1, s2 []int64) sampleStats {
	var out sampleStats
	for _, row := range [][]int64{s1, s2} {
		for _, v := range row {
			if v > out.MaxPositive {
				out.MaxPositive = v
			}
			if v < out.MaxNegative {
				out.MaxNegative = v
			}
			a := v
			if a < 0 {
				a = -a
			}
			if a > out.MaxAbs {
				out.MaxAbs = a
			}
		}
	}
	return out
}

func printSummary(sum summary, thresholds []int64) {
	printSet := func(label string, vals []sampleStats, thr map[int64]int) {
		if len(vals) == 0 {
			fmt.Printf("  %s: no successes\n", label)
			return
		}
		maxAbs := make([]int64, len(vals))
		trials := make([]int, len(vals))
		posMax := int64(0)
		negMin := int64(0)
		for i, st := range vals {
			maxAbs[i] = st.MaxAbs
			trials[i] = st.Trials
			if st.MaxPositive > posMax {
				posMax = st.MaxPositive
			}
			if st.MaxNegative < negMin {
				negMin = st.MaxNegative
			}
		}
		sort.Slice(maxAbs, func(i, j int) bool { return maxAbs[i] < maxAbs[j] })
		sort.Ints(trials)
		fmt.Printf("  %s: n=%d min=%d p50=%d p90=%d p95=%d max=%d pos_max=%d neg_min=%d trials_p50=%d trials_max=%d\n",
			label,
			len(vals),
			maxAbs[0],
			quantile(maxAbs, 0.50),
			quantile(maxAbs, 0.90),
			quantile(maxAbs, 0.95),
			maxAbs[len(maxAbs)-1],
			posMax,
			negMin,
			trials[len(trials)/2],
			trials[len(trials)-1],
		)
		for _, th := range thresholds {
			fmt.Printf("    <=%d: %d/%d (%.1f%%)\n", th, thr[th], len(vals), 100*float64(thr[th])/float64(len(vals)))
		}
	}
	printSet("all", sum.Values, sum.Threshold)
	printSet("best_per_target", sum.Best, sum.BestThr)
	if sum.Failures > 0 {
		fmt.Printf("  failures=%d\n", sum.Failures)
	}
}

func quantile(vals []int64, q float64) int64 {
	if len(vals) == 0 {
		return 0
	}
	idx := int(mathRound(q * float64(len(vals)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx]
}

func mathRound(x float64) int64 {
	if x < 0 {
		return int64(x - 0.5)
	}
	return int64(x + 0.5)
}
