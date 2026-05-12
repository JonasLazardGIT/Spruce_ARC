package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

const (
	fixtureVersion       = "q12289-n512-signature-fixture-v1"
	deterministicSeedTag = "spruce-q12289-n512-fixture-v1"
	productionProofLInf  = int64(6142)
)

type config struct {
	out                 string
	force               bool
	samples             int
	n                   int
	q                   uint64
	paramsBeta          uint64
	keygenAlpha         float64
	keygenPrec          uint
	keygenMaxTrials     int
	keygenAttempts      int
	samplerAlpha        float64
	slack               float64
	signPrec            uint
	maxTrials           int
	targetRetries       int
	reduceIters         int
	auxCoeffBound       int64
	auxRatPolys         int
	auxOpeningPolys     int
	sisRingPolys        int
	skipEstimator       bool
	sageBin             string
	estimatorPath       string
	autoTuneSignerAlpha bool
	autoTuneAlphaMargin float64
}

type fixtureReport struct {
	Version     string              `json:"version"`
	GeneratedAt string              `json:"generated_at"`
	Paths       map[string]string   `json:"paths"`
	Parameters  parametersReport    `json:"parameters"`
	Sampler     samplerReport       `json:"sampler"`
	Auxiliary   auxiliaryReport     `json:"auxiliary_bounds"`
	Batch       batchReport         `json:"batch"`
	Bounds      boundsReport        `json:"bounds"`
	Cases       []securityCase      `json:"security_cases"`
	Estimator   estimatorRunSummary `json:"estimator"`
	Notes       []string            `json:"notes"`
}

type parametersReport struct {
	N                  int     `json:"N"`
	Q                  uint64  `json:"q"`
	QHalfEstimatorCut  float64 `json:"q_half_estimator_cut"`
	ParamsBeta         uint64  `json:"params_beta_placeholder"`
	SISN               int     `json:"sis_n"`
	SISM               int     `json:"sis_m"`
	SISRingPolys       int     `json:"sis_ring_polys"`
	ProductionProofInf int64   `json:"production_proof_linf"`
}

type samplerReport struct {
	KeygenAlpha            float64 `json:"keygen_alpha"`
	KeygenPrec             uint    `json:"keygen_prec"`
	KeygenMaxTrials        int     `json:"keygen_max_trials"`
	SamplerAlpha           float64 `json:"sampler_alpha"`
	AutoTuneSignerAlpha    bool    `json:"auto_tune_signer_alpha"`
	AutoTuneAlphaMargin    float64 `json:"auto_tune_alpha_margin"`
	Slack                  float64 `json:"slack"`
	RSmoothing             float64 `json:"r_smoothing"`
	RSquare                float64 `json:"r_square"`
	SignPrec               uint    `json:"sign_prec"`
	ReduceIters            int     `json:"reduce_iters"`
	MaxTrials              int     `json:"max_trials"`
	RawPerCoefficientScale float64 `json:"raw_per_coefficient_scale"`
	RawSignatureL2Bound    float64 `json:"raw_signature_l2_bound"`
}

type auxiliaryReport struct {
	CoefficientBound int64   `json:"coefficient_bound"`
	RatPolys         int     `json:"rat_polys"`
	OpeningPolys     int     `json:"opening_polys"`
	BetaRat          float64 `json:"beta_rat"`
	Gamma            float64 `json:"gamma"`
	ExtraL2Squared   float64 `json:"extra_l2_squared"`
}

type batchReport struct {
	Samples                  int            `json:"samples"`
	BatchMaxLInf             int64          `json:"batch_max_linf"`
	BatchMaxIndex            int            `json:"batch_max_index"`
	BatchMaxS1LInf           int64          `json:"batch_max_s1_linf"`
	BatchMaxS1Index          int            `json:"batch_max_s1_index"`
	BatchMaxS2LInf           int64          `json:"batch_max_s2_linf"`
	BatchMaxS2Index          int            `json:"batch_max_s2_index"`
	BatchMaxL2               float64        `json:"batch_max_l2"`
	BatchMaxL2Squared        float64        `json:"batch_max_l2_squared"`
	BatchMaxL2Index          int            `json:"batch_max_l2_index"`
	AllNormPassed            bool           `json:"all_norm_passed"`
	AllVerified              bool           `json:"all_verified"`
	WorstSignatureL2         float64        `json:"worst_signature_l2"`
	WorstSignatureL2Squared  float64        `json:"worst_signature_l2_squared"`
	WorstSignatureTrialsUsed int            `json:"worst_signature_trials_used"`
	Stats                    batchStats     `json:"stats"`
	PerSample                []sampleReport `json:"per_sample"`
}

type batchStats struct {
	S1LInf          statSummary            `json:"s1_linf"`
	S2LInf          statSummary            `json:"s2_linf"`
	CombinedLInf    statSummary            `json:"combined_linf"`
	S1L2            statSummary            `json:"s1_l2"`
	S2L2            statSummary            `json:"s2_l2"`
	TotalL2         statSummary            `json:"total_l2"`
	TrialsUsed      statSummary            `json:"trials_used"`
	TargetRetries   statSummary            `json:"target_retries"`
	S1CoordinateAbs coordinateDistribution `json:"s1_coordinate_abs"`
	S2CoordinateAbs coordinateDistribution `json:"s2_coordinate_abs"`
}

type statSummary struct {
	Min    float64 `json:"min"`
	Mean   float64 `json:"mean"`
	RMS    float64 `json:"rms"`
	StdDev float64 `json:"stddev"`
	P50    float64 `json:"p50"`
	P75    float64 `json:"p75"`
	P90    float64 `json:"p90"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
	P999   float64 `json:"p999"`
	Max    float64 `json:"max"`
}

type coordinateDistribution struct {
	Count             int               `json:"count"`
	Abs               statSummary       `json:"abs"`
	TailProbabilities []tailProbability `json:"tail_probabilities"`
	Histogram         []histogramBucket `json:"histogram"`
}

type tailProbability struct {
	GreaterThan int64   `json:"greater_than"`
	Count       int     `json:"count"`
	Probability float64 `json:"probability"`
}

type histogramBucket struct {
	Label       string  `json:"label"`
	Low         int64   `json:"low"`
	High        int64   `json:"high"`
	Count       int     `json:"count"`
	Probability float64 `json:"probability"`
}

type sampleReport struct {
	Index          int     `json:"index"`
	MSeed          string  `json:"mseed"`
	X0Seed         string  `json:"x0seed"`
	X1Seed         string  `json:"x1seed"`
	TargetRetries  int     `json:"target_retries"`
	S1LInf         int64   `json:"s1_linf"`
	S2LInf         int64   `json:"s2_linf"`
	LInf           int64   `json:"linf"`
	S1L2           float64 `json:"s1_l2"`
	S2L2           float64 `json:"s2_l2"`
	S1L2Squared    float64 `json:"s1_l2_squared"`
	S2L2Squared    float64 `json:"s2_l2_squared"`
	S1L2Share      float64 `json:"s1_l2_share"`
	S2L2Share      float64 `json:"s2_l2_share"`
	L2             float64 `json:"l2"`
	L2Squared      float64 `json:"l2_squared"`
	StoredL2Square float64 `json:"stored_l2_squared"`
	ResidualLInf   int64   `json:"residual_linf"`
	NormPassed     bool    `json:"norm_passed"`
	Verified       bool    `json:"verified"`
	VerifyError    string  `json:"verify_error,omitempty"`
	TrialsUsed     int     `json:"trials_used"`
	Rejected       bool    `json:"rejected"`
}

type boundsReport struct {
	RawRegimenLInfCeiling         int64    `json:"raw_regimen_linf_ceiling"`
	NontrivialSISLInfCeiling      int64    `json:"nontrivial_sis_linf_ceiling"`
	RecommendedPureLInfCeiling    int64    `json:"recommended_pure_linf_ceiling"`
	ObservedWithinRecommendedLInf bool     `json:"observed_within_recommended_linf"`
	Explanation                   []string `json:"explanation"`
}

type securityCase struct {
	Name                 string          `json:"name"`
	Kind                 string          `json:"kind"`
	LInf                 *int64          `json:"linf,omitempty"`
	BetaSigL2            float64         `json:"beta_sig_l2"`
	BetaAugL2            float64         `json:"beta_aug_l2"`
	BetaAugL2Squared     float64         `json:"beta_aug_l2_squared"`
	BetaAugLessThanQHalf bool            `json:"beta_aug_less_than_q_half"`
	EstimatorReason      string          `json:"estimator_reason,omitempty"`
	Estimator            *estimateResult `json:"estimator,omitempty"`
}

type estimateMetric struct {
	OK      bool     `json:"ok"`
	Log2ROP *float64 `json:"log2_rop,omitempty"`
	Log2Red *float64 `json:"log2_red,omitempty"`
	BKZBeta *float64 `json:"bkz_beta,omitempty"`
	Tag     string   `json:"tag,omitempty"`
	Error   string   `json:"error,omitempty"`
	Stdout  string   `json:"stdout,omitempty"`
}

type estimateResult struct {
	Available          bool           `json:"available"`
	Status             string         `json:"status"`
	MATZOV             estimateMetric `json:"matzov"`
	ADPS16             estimateMetric `json:"adps16"`
	CoreSVPQuantumBits *float64       `json:"core_svp_quantum_bits,omitempty"`
	Error              string         `json:"error,omitempty"`
}

type estimatorRunSummary struct {
	Requested     bool   `json:"requested"`
	Available     bool   `json:"available"`
	SageBin       string `json:"sage_bin,omitempty"`
	EstimatorPath string `json:"estimator_path,omitempty"`
	InputPath     string `json:"input_path,omitempty"`
	ScriptPath    string `json:"script_path,omitempty"`
	OutputPath    string `json:"output_path,omitempty"`
	Stdout        string `json:"stdout,omitempty"`
	Error         string `json:"error,omitempty"`
}

type estimatorInputCase struct {
	Name      string  `json:"name"`
	SISN      int     `json:"sis_n"`
	SISM      int     `json:"sis_m"`
	Q         uint64  `json:"q"`
	BetaAugL2 float64 `json:"beta_aug_l2"`
}

func main() {
	cfg := parseConfig()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "q12289-signature-fixture: %v\n", err)
		os.Exit(1)
	}
}

func parseConfig() config {
	var cfg config
	flag.StringVar(&cfg.out, "out", filepath.Join("artifacts", "q12289_n512_signature_fixture"), "output fixture directory")
	flag.BoolVar(&cfg.force, "force", false, "allow overwriting known files in an existing output directory")
	flag.IntVar(&cfg.samples, "samples", 256, "number of deterministic targets to sign")
	flag.IntVar(&cfg.n, "N", 512, "ring degree")
	flag.Uint64Var(&cfg.q, "q", 12289, "modulus")
	flag.Uint64Var(&cfg.paramsBeta, "params-beta", uint64(productionProofLInf), "beta placeholder written to Parameters.json")
	flag.Float64Var(&cfg.keygenAlpha, "keygen-alpha", 1.20, "annulus key generation alpha")
	flag.UintVar(&cfg.keygenPrec, "keygen-prec", 512, "annulus key generation precision")
	flag.IntVar(&cfg.keygenMaxTrials, "keygen-max-trials", 10000, "annulus key generation max trials")
	flag.IntVar(&cfg.keygenAttempts, "keygen-attempts", 4, "number of key generation retries")
	flag.Float64Var(&cfg.samplerAlpha, "sampler-alpha", 1.25, "signing norm alpha")
	flag.BoolVar(&cfg.autoTuneSignerAlpha, "auto-tune-signer-alpha", false, "derive signer alpha from the generated trapdoor before signing")
	flag.Float64Var(&cfg.autoTuneAlphaMargin, "auto-tune-alpha-margin", 1.00, "margin used when signer alpha autotuning is enabled")
	flag.Float64Var(&cfg.slack, "slack", 1.042, "C-style signing norm slack")
	flag.UintVar(&cfg.signPrec, "sign-prec", 512, "signing precision")
	flag.IntVar(&cfg.maxTrials, "max-trials", 2048, "max sampler trials per target")
	flag.IntVar(&cfg.targetRetries, "target-retries", 64, "deterministic seed retries per target when the hash target is inadmissible")
	flag.IntVar(&cfg.reduceIters, "reduce-iters", 64, "Babai reduction iterations")
	flag.Int64Var(&cfg.auxCoeffBound, "aux-bound", 8, "coefficient bound for auxiliary Ajtai/message/rational parts")
	flag.IntVar(&cfg.auxRatPolys, "aux-rat-polys", 4, "number of bounded ring polynomials in beta_rat")
	flag.IntVar(&cfg.auxOpeningPolys, "aux-opening-polys", 4, "number of bounded ring polynomials in gamma")
	flag.IntVar(&cfg.sisRingPolys, "sis-ring-polys", 3, "SIS input ring-polynomial count used by estimator, so m = N * sis-ring-polys")
	flag.BoolVar(&cfg.skipEstimator, "skip-estimator", false, "skip Sage/lattice-estimator execution")
	flag.StringVar(&cfg.sageBin, "sage-bin", "sage", "Sage executable")
	flag.StringVar(&cfg.estimatorPath, "estimator-path", "lattice-estimator-main", "path to malb/lattice-estimator checkout")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := prepareOutputDir(cfg.out, cfg.force); err != nil {
		return err
	}

	paramsPath := filepath.Join(cfg.out, "Parameters.json")
	bPath := filepath.Join(cfg.out, "Bmatrix.json")
	publicPath := filepath.Join(cfg.out, "public_key.json")
	privatePath := filepath.Join(cfg.out, "private_key.json")
	worstSignaturePath := filepath.Join(cfg.out, "worst_signature.json")
	reportJSONPath := filepath.Join(cfg.out, "report.json")
	reportMarkdownPath := filepath.Join(cfg.out, "report.md")

	sys := ntrurio.SystemParams{N: cfg.n, Q: cfg.q, Beta: cfg.paramsBeta}
	if err := ntrurio.SaveParams(paramsPath, sys); err != nil {
		return fmt.Errorf("write params: %w", err)
	}
	if err := regenerateBMatrix(sys, bPath); err != nil {
		return fmt.Errorf("write B matrix: %w", err)
	}

	qInt := new(big.Int).SetUint64(cfg.q)
	par, err := ntru.NewParams(cfg.n, qInt)
	if err != nil {
		return fmt.Errorf("construct ntru params: %w", err)
	}
	if err := generateFixtureKeypair(par, cfg, publicPath, privatePath); err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	r := ntru.CReferenceSmoothing()
	opts := ntru.SamplerOpts{
		Prec:                cfg.signPrec,
		Alpha:               cfg.samplerAlpha,
		RSquare:             r * r,
		Slack:               cfg.slack,
		ReduceIters:         cfg.reduceIters,
		UseCNormalDist:      true,
		UseExactResidual:    true,
		BoundShape:          "cstyle",
		AutoTuneAlpha:       cfg.autoTuneSignerAlpha,
		AutoTuneAlphaMargin: cfg.autoTuneAlphaMargin,
	}
	paths := signverify.SignPaths{
		ParamsPath:    paramsPath,
		BFile:         bPath,
		PublicKeyPath: publicPath,
		PrivatePath:   privatePath,
	}
	normOpts, err := effectiveSamplerOpts(paths, par, opts)
	if err != nil {
		return fmt.Errorf("configure sampler opts: %w", err)
	}

	aux := computeAuxiliary(cfg.n, cfg.auxCoeffBound, cfg.auxRatPolys, cfg.auxOpeningPolys)
	effectiveR := math.Sqrt(normOpts.RSquare)
	rawPerCoeff := normOpts.Slack * effectiveR * normOpts.Alpha * math.Sqrt(float64(cfg.q))
	rawSignatureL2 := rawPerCoeff * math.Sqrt(float64(2*cfg.n))
	qHalf := float64(cfg.q-1) / 2.0
	rawLInfCeiling := int64(math.Floor(rawPerCoeff))
	nontrivialCeiling := linfCeilingForAugmentedLimit(qHalf, aux.ExtraL2Squared, cfg.n)
	recommendedCeiling := minInt64(rawLInfCeiling, nontrivialCeiling)

	batch, worstSig, err := signBatch(sys, paths, par, normOpts, cfg, paramsPath, bPath)
	if err != nil {
		return err
	}
	if err := keys.SaveSignatureFile(worstSignaturePath, worstSig); err != nil {
		return fmt.Errorf("write worst signature: %w", err)
	}

	cases := buildSecurityCases(cfg, aux, qHalf, rawSignatureL2, rawLInfCeiling, nontrivialCeiling, batch)
	estimatorSummary := runEstimator(cfg, cases)

	for i := range cases {
		if cases[i].Estimator != nil && cases[i].Estimator.ADPS16.BKZBeta != nil {
			qBits := 0.259 * *cases[i].Estimator.ADPS16.BKZBeta
			cases[i].Estimator.CoreSVPQuantumBits = &qBits
		}
	}

	report := fixtureReport{
		Version:     fixtureVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Paths: map[string]string{
			"params":          paramsPath,
			"b_matrix":        bPath,
			"public_key":      publicPath,
			"private_key":     privatePath,
			"worst_signature": worstSignaturePath,
			"report_json":     reportJSONPath,
			"report_md":       reportMarkdownPath,
		},
		Parameters: parametersReport{
			N:                  cfg.n,
			Q:                  cfg.q,
			QHalfEstimatorCut:  qHalf,
			ParamsBeta:         cfg.paramsBeta,
			SISN:               cfg.n,
			SISM:               cfg.n * cfg.sisRingPolys,
			SISRingPolys:       cfg.sisRingPolys,
			ProductionProofInf: productionProofLInf,
		},
		Sampler: samplerReport{
			KeygenAlpha:            cfg.keygenAlpha,
			KeygenPrec:             cfg.keygenPrec,
			KeygenMaxTrials:        cfg.keygenMaxTrials,
			SamplerAlpha:           normOpts.Alpha,
			AutoTuneSignerAlpha:    cfg.autoTuneSignerAlpha,
			AutoTuneAlphaMargin:    cfg.autoTuneAlphaMargin,
			Slack:                  normOpts.Slack,
			RSmoothing:             effectiveR,
			RSquare:                normOpts.RSquare,
			SignPrec:               cfg.signPrec,
			ReduceIters:            cfg.reduceIters,
			MaxTrials:              cfg.maxTrials,
			RawPerCoefficientScale: rawPerCoeff,
			RawSignatureL2Bound:    rawSignatureL2,
		},
		Auxiliary: aux,
		Batch:     batch,
		Bounds: boundsReport{
			RawRegimenLInfCeiling:         rawLInfCeiling,
			NontrivialSISLInfCeiling:      nontrivialCeiling,
			RecommendedPureLInfCeiling:    recommendedCeiling,
			ObservedWithinRecommendedLInf: batch.BatchMaxLInf <= recommendedCeiling,
			Explanation: []string{
				"raw_regimen_linf_ceiling is floor(slack * R * alpha * sqrt(q)); it is the strongest pure coefficient bound that implies the current raw C-style l2 signature norm.",
				"nontrivial_sis_linf_ceiling is the largest integer B_inf for which sqrt((B_inf*sqrt(2N))^2 + beta_rat^2 + gamma^2) is still below (q-1)/2.",
				"recommended_pure_linf_ceiling is the minimum of those two ceilings.",
			},
		},
		Cases:     cases,
		Estimator: estimatorSummary,
		Notes: []string{
			"The measured NIZK predicate is max_i max(|s1_i|, |s2_i|). This command does not construct a full NIZK transcript.",
			"Estimator cases use SIS n=N and m=N*sis_ring_polys. The default sis_ring_polys=3 matches the prior N=512 q=12289 augmented l2 worksheet values.",
			"If beta_aug_l2 is not below (q-1)/2, the malb lattice-estimator marks the SIS instance as trivially easy and no meaningful nontrivial SIS bit estimate is reported.",
		},
	}

	if err := writeJSON(reportJSONPath, report); err != nil {
		return fmt.Errorf("write report json: %w", err)
	}
	if err := os.WriteFile(reportMarkdownPath, []byte(renderMarkdown(report)), 0o644); err != nil {
		return fmt.Errorf("write report markdown: %w", err)
	}

	fmt.Printf("fixture written to %s\n", cfg.out)
	fmt.Printf("batch max l_inf=%d, recommended pure l_inf ceiling=%d\n", batch.BatchMaxLInf, recommendedCeiling)
	fmt.Printf("report: %s\n", reportMarkdownPath)
	return nil
}

func validateConfig(cfg config) error {
	if cfg.out == "" {
		return errors.New("empty --out")
	}
	if cfg.samples <= 0 {
		return fmt.Errorf("--samples must be positive, got %d", cfg.samples)
	}
	if cfg.n <= 0 {
		return fmt.Errorf("--N must be positive, got %d", cfg.n)
	}
	if cfg.q <= 2 {
		return fmt.Errorf("--q must be > 2, got %d", cfg.q)
	}
	if cfg.keygenAlpha <= 0 || cfg.samplerAlpha <= 0 || cfg.slack <= 0 {
		return errors.New("alpha and slack must be positive")
	}
	if cfg.keygenMaxTrials <= 0 || cfg.maxTrials <= 0 || cfg.keygenAttempts <= 0 || cfg.targetRetries <= 0 {
		return errors.New("trial counts and keygen attempts must be positive")
	}
	if cfg.auxCoeffBound < 0 || cfg.auxRatPolys < 0 || cfg.auxOpeningPolys < 0 {
		return errors.New("auxiliary bounds and polynomial counts must be non-negative")
	}
	if cfg.sisRingPolys <= 0 {
		return fmt.Errorf("--sis-ring-polys must be positive, got %d", cfg.sisRingPolys)
	}
	if cfg.autoTuneSignerAlpha && cfg.autoTuneAlphaMargin <= 0 {
		return errors.New("--auto-tune-alpha-margin must be positive")
	}
	return nil
}

func prepareOutputDir(out string, force bool) error {
	if st, err := os.Stat(out); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("output path exists and is not a directory: %s", out)
		}
		entries, err := os.ReadDir(out)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		if !force {
			return fmt.Errorf("output directory already exists: %s (pass --force to overwrite known fixture files)", out)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(out, 0o755)
}

func regenerateBMatrix(pp ntrurio.SystemParams, path string) error {
	ringQ, err := ring.NewRing(pp.N, []uint64{pp.Q})
	if err != nil {
		return err
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		return err
	}
	B, err := vsishash.GenerateB(ringQ, prng)
	if err != nil {
		return err
	}
	coeffs := make([][]uint64, len(B))
	for i := range B {
		coeffs[i] = append([]uint64(nil), B[i].Coeffs[0]...)
	}
	return ntrurio.SaveBMatrixCoeffs(path, coeffs)
}

func generateFixtureKeypair(par ntru.Params, cfg config, publicPath, privatePath string) error {
	kg := ntru.KeygenOpts{
		Prec:      cfg.keygenPrec,
		MaxTrials: cfg.keygenMaxTrials,
		Alpha:     cfg.keygenAlpha,
	}
	var lastErr error
	for attempt := 1; attempt <= cfg.keygenAttempts; attempt++ {
		_, _, err := signverify.GenerateKeypairAnnulusToFiles(par, kg, publicPath, privatePath)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

func effectiveSamplerOpts(paths signverify.SignPaths, par ntru.Params, opts ntru.SamplerOpts) (ntru.SamplerOpts, error) {
	opts.UseCNormalDist = true
	opts.UseExactResidual = true
	opts.BoundShape = "cstyle"
	if !opts.AutoTuneAlpha {
		opts.ApplyDefaults(par)
		return opts, nil
	}
	privatePath := paths.PrivatePath
	if privatePath == "" {
		privatePath = filepath.Join("ntru_keys", "private.json")
	}
	sk, err := keys.LoadPrivateFile(privatePath)
	if err != nil {
		return opts, err
	}
	prec := opts.Prec
	if prec == 0 {
		prec = 512
	}
	sampler, err := ntru.NewSampler(sk.Fsmall, sk.Gsmall, sk.F, sk.G, par, prec)
	if err != nil {
		return opts, err
	}
	alpha, err := sampler.RecommendedAlpha(opts.AutoTuneAlphaMargin)
	if err != nil {
		return opts, err
	}
	if alpha > 0 {
		opts.Alpha = alpha
	}
	opts.AutoTuneAlpha = false
	opts.ApplyDefaults(par)
	return opts, nil
}

func signBatch(sys ntrurio.SystemParams, paths signverify.SignPaths, par ntru.Params, opts ntru.SamplerOpts, cfg config, paramsPath, bPath string) (batchReport, *keys.Signature, error) {
	batch := batchReport{
		Samples:         cfg.samples,
		BatchMaxIndex:   -1,
		BatchMaxS1Index: -1,
		BatchMaxS2Index: -1,
		BatchMaxL2Index: -1,
		AllNormPassed:   true,
		AllVerified:     true,
		PerSample:       make([]sampleReport, 0, cfg.samples),
	}
	var worstSig *keys.Signature
	s1CoordinateAbs := make([]int64, 0, cfg.samples*cfg.n)
	s2CoordinateAbs := make([]int64, 0, cfg.samples*cfg.n)
	for i := 0; i < cfg.samples; i++ {
		tCoeffs, mSeed, x0Seed, x1Seed, targetRetries, err := deterministicTarget(&sys, bPath, i, cfg.targetRetries)
		if err != nil {
			return batch, nil, fmt.Errorf("target %d: %w", i, err)
		}
		mrand.Seed(int64(0x5a5a0000) + int64(i))
		sig, err := signverify.SignTargetNoPersistWithPaths(tCoeffs, cfg.maxTrials, opts, paths)
		if err != nil {
			return batch, nil, fmt.Errorf("sign target %d: %w", i, err)
		}
		sig.Hash.BFile = bPath
		sig.Hash.HashRelation = ""
		sig.Hash.MSeed = keys.EncodeSeed(mSeed)
		sig.Hash.X0Seed = keys.EncodeSeed(x0Seed)
		sig.Hash.X1Seed = keys.EncodeSeed(x1Seed)

		verifyErr := signverify.VerifyWithParamsPath(sig, paramsPath)
		s1LInf := maxAbs(sig.Signature.S1)
		s2LInf := maxAbs(sig.Signature.S2)
		appendAbsCoordinates(&s1CoordinateAbs, sig.Signature.S1)
		appendAbsCoordinates(&s2CoordinateAbs, sig.Signature.S2)
		lInf := maxInt64(s1LInf, s2LInf)
		s1L2Sq := coeffNormSquared(sig.Signature.S1)
		s2L2Sq := coeffNormSquared(sig.Signature.S2)
		l2Sq := ntru.CoefficientNormSquared(sig.Signature.S1, sig.Signature.S2, par, opts)
		s1Share := 0.0
		s2Share := 0.0
		if l2Sq > 0 {
			s1Share = s1L2Sq / l2Sq
			s2Share = s2L2Sq / l2Sq
		}
		sample := sampleReport{
			Index:          i,
			MSeed:          keys.EncodeSeed(mSeed),
			X0Seed:         keys.EncodeSeed(x0Seed),
			X1Seed:         keys.EncodeSeed(x1Seed),
			TargetRetries:  targetRetries,
			S1LInf:         s1LInf,
			S2LInf:         s2LInf,
			LInf:           lInf,
			S1L2:           math.Sqrt(s1L2Sq),
			S2L2:           math.Sqrt(s2L2Sq),
			S1L2Squared:    s1L2Sq,
			S2L2Squared:    s2L2Sq,
			S1L2Share:      s1Share,
			S2L2Share:      s2Share,
			L2:             math.Sqrt(l2Sq),
			L2Squared:      l2Sq,
			StoredL2Square: sig.Signature.Norm.L2Est,
			ResidualLInf:   sig.Signature.Norm.ResidualLinf,
			NormPassed:     sig.Signature.Norm.Passed,
			Verified:       verifyErr == nil,
			TrialsUsed:     sig.Signature.TrialsUsed,
			Rejected:       sig.Signature.Rejected,
		}
		if verifyErr != nil {
			sample.VerifyError = verifyErr.Error()
			batch.AllVerified = false
		}
		if !sample.NormPassed {
			batch.AllNormPassed = false
		}
		batch.PerSample = append(batch.PerSample, sample)
		if s1LInf > batch.BatchMaxS1LInf || batch.BatchMaxS1Index < 0 {
			batch.BatchMaxS1LInf = s1LInf
			batch.BatchMaxS1Index = i
		}
		if s2LInf > batch.BatchMaxS2LInf || batch.BatchMaxS2Index < 0 {
			batch.BatchMaxS2LInf = s2LInf
			batch.BatchMaxS2Index = i
		}
		if sample.L2 > batch.BatchMaxL2 || batch.BatchMaxL2Index < 0 {
			batch.BatchMaxL2 = sample.L2
			batch.BatchMaxL2Squared = sample.L2Squared
			batch.BatchMaxL2Index = i
		}
		if lInf > batch.BatchMaxLInf || worstSig == nil {
			batch.BatchMaxLInf = lInf
			batch.BatchMaxIndex = i
			batch.WorstSignatureL2 = sample.L2
			batch.WorstSignatureL2Squared = sample.L2Squared
			batch.WorstSignatureTrialsUsed = sample.TrialsUsed
			worstSig = sig
		}
	}
	if worstSig == nil {
		return batch, nil, errors.New("no signatures generated")
	}
	batch.Stats = summarizeBatch(batch.PerSample, s1CoordinateAbs, s2CoordinateAbs)
	return batch, worstSig, nil
}

func deterministicTarget(sys *ntrurio.SystemParams, bPath string, idx, maxRetries int) (tCoeffs []int64, mSeed, x0Seed, x1Seed []byte, retries int, err error) {
	if maxRetries <= 0 {
		maxRetries = 1
	}
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		mSeed = deterministicSeed("m", idx, attempt)
		x0Seed = deterministicSeed("x0", idx, attempt)
		x1Seed = deterministicSeed("x1", idx, attempt)
		tCoeffs, err = ntru.ComputeTargetFromSeeds(sys, bPath, "", mSeed, x0Seed, x1Seed)
		if err == nil {
			return tCoeffs, mSeed, x0Seed, x1Seed, attempt, nil
		}
		lastErr = err
	}
	return nil, nil, nil, nil, maxRetries, fmt.Errorf("no admissible target after %d deterministic seed attempts: %w", maxRetries, lastErr)
}

func deterministicSeed(prefix string, idx, attempt int) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d", deterministicSeedTag, prefix, idx, attempt)))
	return sum[:]
}

func computeAuxiliary(n int, coeffBound int64, ratPolys, openingPolys int) auxiliaryReport {
	b := float64(coeffBound)
	betaRat := b * math.Sqrt(float64(n*ratPolys))
	gamma := b * math.Sqrt(float64(n*openingPolys))
	return auxiliaryReport{
		CoefficientBound: coeffBound,
		RatPolys:         ratPolys,
		OpeningPolys:     openingPolys,
		BetaRat:          betaRat,
		Gamma:            gamma,
		ExtraL2Squared:   betaRat*betaRat + gamma*gamma,
	}
}

func buildSecurityCases(cfg config, aux auxiliaryReport, qHalf, rawSignatureL2 float64, rawLInfCeiling, nontrivialCeiling int64, batch batchReport) []securityCase {
	cases := []securityCase{
		newLInfCase("observed_batch_max_linf", "linf_implied_l2", batch.BatchMaxLInf, cfg.n, aux.ExtraL2Squared, qHalf),
		newLInfCase("worst_saved_signature_linf", "linf_implied_l2", batch.BatchMaxLInf, cfg.n, aux.ExtraL2Squared, qHalf),
		newLInfCase("current_production_proof_linf_6142", "linf_implied_l2", productionProofLInf, cfg.n, aux.ExtraL2Squared, qHalf),
		newLInfCase("raw_regimen_linf_ceiling", "linf_implied_l2", rawLInfCeiling, cfg.n, aux.ExtraL2Squared, qHalf),
		newLInfCase("largest_nontrivial_qhalf_linf_ceiling", "linf_implied_l2", nontrivialCeiling, cfg.n, aux.ExtraL2Squared, qHalf),
		newL2Case("raw_cstyle_l2_direct", "direct_l2", rawSignatureL2, aux.ExtraL2Squared, qHalf),
		newL2Case("worst_saved_signature_actual_l2", "direct_l2", batch.WorstSignatureL2, aux.ExtraL2Squared, qHalf),
		newL2Case("batch_max_actual_l2", "direct_l2", batch.BatchMaxL2, aux.ExtraL2Squared, qHalf),
	}
	for i := range cases {
		if cases[i].BetaAugLessThanQHalf {
			continue
		}
		cases[i].EstimatorReason = "beta_aug_l2 is not below (q-1)/2, so the SIS instance is trivial for the estimator"
		cases[i].Estimator = &estimateResult{
			Available: false,
			Status:    "not_run_invalid_bound",
			Error:     cases[i].EstimatorReason,
		}
	}
	return cases
}

func newLInfCase(name, kind string, linf int64, n int, extraSq, qHalf float64) securityCase {
	betaSig := float64(linf) * math.Sqrt(float64(2*n))
	l := linf
	return securityCase{
		Name:                 name,
		Kind:                 kind,
		LInf:                 &l,
		BetaSigL2:            betaSig,
		BetaAugL2:            math.Sqrt(betaSig*betaSig + extraSq),
		BetaAugL2Squared:     betaSig*betaSig + extraSq,
		BetaAugLessThanQHalf: math.Sqrt(betaSig*betaSig+extraSq) < qHalf,
	}
}

func newL2Case(name, kind string, betaSig, extraSq, qHalf float64) securityCase {
	betaAugSq := betaSig*betaSig + extraSq
	return securityCase{
		Name:                 name,
		Kind:                 kind,
		BetaSigL2:            betaSig,
		BetaAugL2:            math.Sqrt(betaAugSq),
		BetaAugL2Squared:     betaAugSq,
		BetaAugLessThanQHalf: math.Sqrt(betaAugSq) < qHalf,
	}
}

func linfCeilingForAugmentedLimit(limit, extraSq float64, n int) int64 {
	rem := limit*limit - extraSq
	if rem <= 0 {
		return -1
	}
	linf := int64(math.Floor(math.Sqrt(rem) / math.Sqrt(float64(2*n))))
	for linf >= 0 {
		betaSig := float64(linf) * math.Sqrt(float64(2*n))
		if math.Sqrt(betaSig*betaSig+extraSq) < limit {
			return linf
		}
		linf--
	}
	return -1
}

func runEstimator(cfg config, cases []securityCase) estimatorRunSummary {
	summary := estimatorRunSummary{
		Requested: !cfg.skipEstimator,
		SageBin:   cfg.sageBin,
	}
	if cfg.skipEstimator {
		markEstimatorUnavailable(cases, "skipped", "estimator execution skipped by --skip-estimator")
		summary.Error = "skipped by --skip-estimator"
		return summary
	}
	sagePath, err := exec.LookPath(cfg.sageBin)
	if err != nil {
		markEstimatorUnavailable(cases, "unavailable", fmt.Sprintf("sage executable not found: %v", err))
		summary.Error = err.Error()
		return summary
	}
	estimatorPath, err := absolutePath(cfg.estimatorPath)
	if err != nil {
		markEstimatorUnavailable(cases, "unavailable", err.Error())
		summary.Error = err.Error()
		return summary
	}
	if st, err := os.Stat(estimatorPath); err != nil || !st.IsDir() {
		msg := fmt.Sprintf("estimator path is not a directory: %s", estimatorPath)
		markEstimatorUnavailable(cases, "unavailable", msg)
		summary.Error = msg
		return summary
	}

	inputCases := make([]estimatorInputCase, 0, len(cases))
	for _, c := range cases {
		if !c.BetaAugLessThanQHalf {
			continue
		}
		inputCases = append(inputCases, estimatorInputCase{
			Name:      c.Name,
			SISN:      cfg.n,
			SISM:      cfg.n * cfg.sisRingPolys,
			Q:         cfg.q,
			BetaAugL2: c.BetaAugL2,
		})
	}
	if len(inputCases) == 0 {
		markEstimatorUnavailable(cases, "not_run", "no valid nontrivial SIS cases")
		summary.Error = "no valid nontrivial SIS cases"
		return summary
	}

	inputPath := filepath.Join(cfg.out, "estimator_cases.json")
	scriptPath := filepath.Join(cfg.out, "estimator_runner.sage")
	outputPath := filepath.Join(cfg.out, "estimator_results.json")
	if err := writeJSON(inputPath, inputCases); err != nil {
		markEstimatorUnavailable(cases, "error", err.Error())
		summary.Error = err.Error()
		return summary
	}
	if err := os.WriteFile(scriptPath, []byte(estimatorRunnerSage), 0o644); err != nil {
		markEstimatorUnavailable(cases, "error", err.Error())
		summary.Error = err.Error()
		return summary
	}

	cmd := exec.Command(sagePath, scriptPath, estimatorPath, inputPath, outputPath)
	var stream bytes.Buffer
	cmd.Stdout = &stream
	cmd.Stderr = &stream
	err = cmd.Run()
	summary.Available = err == nil
	summary.SageBin = sagePath
	summary.EstimatorPath = estimatorPath
	summary.InputPath = inputPath
	summary.ScriptPath = scriptPath
	summary.OutputPath = outputPath
	summary.Stdout = stream.String()
	if err != nil {
		msg := fmt.Sprintf("estimator failed: %v", err)
		markEstimatorUnavailable(cases, "error", msg)
		summary.Error = msg
		return summary
	}

	var results map[string]estimateResult
	if err := readJSON(outputPath, &results); err != nil {
		msg := fmt.Sprintf("read estimator results: %v", err)
		markEstimatorUnavailable(cases, "error", msg)
		summary.Error = msg
		return summary
	}
	summary.Available = true
	for i := range cases {
		if !cases[i].BetaAugLessThanQHalf {
			continue
		}
		res, ok := results[cases[i].Name]
		if !ok {
			cases[i].Estimator = &estimateResult{Available: false, Status: "missing", Error: "case missing from estimator output"}
			continue
		}
		cases[i].Estimator = &res
	}
	return summary
}

func markEstimatorUnavailable(cases []securityCase, status, msg string) {
	for i := range cases {
		if cases[i].Estimator != nil {
			continue
		}
		cases[i].Estimator = &estimateResult{Available: false, Status: status, Error: msg}
	}
}

func absolutePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, path), nil
}

func writeJSON(path string, value any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func readJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, value)
}

func maxAbs(xs []int64) int64 {
	var m int64
	for _, v := range xs {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	return m
}

func coeffNormSquared(xs []int64) float64 {
	var sum float64
	for _, v := range xs {
		fv := float64(v)
		sum += fv * fv
	}
	return sum
}

func appendAbsCoordinates(dst *[]int64, xs []int64) {
	for _, v := range xs {
		if v < 0 {
			v = -v
		}
		*dst = append(*dst, v)
	}
}

func summarizeBatch(samples []sampleReport, s1CoordinateAbs, s2CoordinateAbs []int64) batchStats {
	s1Inf := make([]float64, 0, len(samples))
	s2Inf := make([]float64, 0, len(samples))
	combinedInf := make([]float64, 0, len(samples))
	s1L2 := make([]float64, 0, len(samples))
	s2L2 := make([]float64, 0, len(samples))
	totalL2 := make([]float64, 0, len(samples))
	trials := make([]float64, 0, len(samples))
	targetRetries := make([]float64, 0, len(samples))
	for _, s := range samples {
		s1Inf = append(s1Inf, float64(s.S1LInf))
		s2Inf = append(s2Inf, float64(s.S2LInf))
		combinedInf = append(combinedInf, float64(s.LInf))
		s1L2 = append(s1L2, s.S1L2)
		s2L2 = append(s2L2, s.S2L2)
		totalL2 = append(totalL2, s.L2)
		trials = append(trials, float64(s.TrialsUsed))
		targetRetries = append(targetRetries, float64(s.TargetRetries))
	}
	return batchStats{
		S1LInf:          summarizeFloat64(s1Inf),
		S2LInf:          summarizeFloat64(s2Inf),
		CombinedLInf:    summarizeFloat64(combinedInf),
		S1L2:            summarizeFloat64(s1L2),
		S2L2:            summarizeFloat64(s2L2),
		TotalL2:         summarizeFloat64(totalL2),
		TrialsUsed:      summarizeFloat64(trials),
		TargetRetries:   summarizeFloat64(targetRetries),
		S1CoordinateAbs: summarizeCoordinateDistribution(s1CoordinateAbs),
		S2CoordinateAbs: summarizeCoordinateDistribution(s2CoordinateAbs),
	}
}

func summarizeFloat64(values []float64) statSummary {
	if len(values) == 0 {
		return statSummary{}
	}
	xs := append([]float64(nil), values...)
	sort.Float64s(xs)
	var sum float64
	var sumSq float64
	for _, v := range xs {
		sum += v
		sumSq += v * v
	}
	mean := sum / float64(len(xs))
	rms := math.Sqrt(sumSq / float64(len(xs)))
	variance := sumSq/float64(len(xs)) - mean*mean
	if variance < 0 && variance > -1e-9 {
		variance = 0
	}
	return statSummary{
		Min:    xs[0],
		Mean:   mean,
		RMS:    rms,
		StdDev: math.Sqrt(math.Max(0, variance)),
		P50:    percentileSorted(xs, 0.50),
		P75:    percentileSorted(xs, 0.75),
		P90:    percentileSorted(xs, 0.90),
		P95:    percentileSorted(xs, 0.95),
		P99:    percentileSorted(xs, 0.99),
		P999:   percentileSorted(xs, 0.999),
		Max:    xs[len(xs)-1],
	}
}

func summarizeCoordinateDistribution(absValues []int64) coordinateDistribution {
	values := make([]float64, 0, len(absValues))
	for _, v := range absValues {
		values = append(values, float64(v))
	}
	return coordinateDistribution{
		Count:             len(absValues),
		Abs:               summarizeFloat64(values),
		TailProbabilities: coordinateTailProbabilities(absValues),
		Histogram:         coordinateHistogram(absValues),
	}
}

func coordinateTailProbabilities(absValues []int64) []tailProbability {
	thresholds := []int64{64, 96, 128, 160, 190, 256, 320, 384, 448, 512, 576, 640, 704, 768}
	out := make([]tailProbability, 0, len(thresholds))
	for _, threshold := range thresholds {
		var count int
		for _, v := range absValues {
			if v > threshold {
				count++
			}
		}
		out = append(out, tailProbability{
			GreaterThan: threshold,
			Count:       count,
			Probability: probability(count, len(absValues)),
		})
	}
	return out
}

func coordinateHistogram(absValues []int64) []histogramBucket {
	const openEndedBucketHigh int64 = 1 << 62
	bounds := []struct {
		low  int64
		high int64
	}{
		{0, 31},
		{32, 63},
		{64, 95},
		{96, 127},
		{128, 159},
		{160, 190},
		{191, 255},
		{256, 319},
		{320, 383},
		{384, 447},
		{448, 511},
		{512, 575},
		{576, 639},
		{640, 703},
		{704, 767},
		{768, openEndedBucketHigh},
	}
	out := make([]histogramBucket, 0, len(bounds))
	for _, bound := range bounds {
		var count int
		for _, v := range absValues {
			if v >= bound.low && v <= bound.high {
				count++
			}
		}
		label := fmt.Sprintf("%d-%d", bound.low, bound.high)
		high := bound.high
		if bound.high == openEndedBucketHigh {
			label = fmt.Sprintf(">=%d", bound.low)
			high = -1
		}
		out = append(out, histogramBucket{
			Label:       label,
			Low:         bound.low,
			High:        high,
			Count:       count,
			Probability: probability(count, len(absValues)),
		})
	}
	return out
}

func probability(count, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(count) / float64(total)
}

func percentileSorted(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	if len(xs) == 1 {
		return xs[0]
	}
	if p <= 0 {
		return xs[0]
	}
	if p >= 1 {
		return xs[len(xs)-1]
	}
	pos := p * float64(len(xs)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return xs[lo]
	}
	frac := pos - float64(lo)
	return xs[lo]*(1-frac) + xs[hi]*frac
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func renderMarkdown(report fixtureReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# q=%d, N=%d Signature Fixture\n\n", report.Parameters.Q, report.Parameters.N)
	fmt.Fprintf(&b, "Generated at `%s`.\n\n", report.GeneratedAt)
	fmt.Fprintf(&b, "## What This Measures\n\n")
	fmt.Fprintf(&b, "The measured proof-side predicate is the coefficient bound `max_i max(|s1_i|, |s2_i|)`. This is the value currently represented by the signed-radix NIZK witness bound. It is not a full NIZK transcript.\n\n")
	fmt.Fprintf(&b, "The raw verifier norm is the C-style coefficient-domain `l2` check over `(s1, s2)`. A pure `l_inf` proof only implies that norm if `B_inf * sqrt(2N)` is no larger than the raw `l2` signature budget.\n\n")

	fmt.Fprintf(&b, "## Parameters\n\n")
	fmt.Fprintf(&b, "| field | value |\n|---|---:|\n")
	fmt.Fprintf(&b, "| N | %d |\n", report.Parameters.N)
	fmt.Fprintf(&b, "| q | %d |\n", report.Parameters.Q)
	fmt.Fprintf(&b, "| SIS n | %d |\n", report.Parameters.SISN)
	fmt.Fprintf(&b, "| SIS m | %d |\n", report.Parameters.SISM)
	fmt.Fprintf(&b, "| q-half estimator cut `(q-1)/2` | %.6f |\n", report.Parameters.QHalfEstimatorCut)
	fmt.Fprintf(&b, "| keygen alpha | %.6f |\n", report.Sampler.KeygenAlpha)
	fmt.Fprintf(&b, "| sampler alpha | %.6f |\n", report.Sampler.SamplerAlpha)
	fmt.Fprintf(&b, "| slack | %.6f |\n", report.Sampler.Slack)
	fmt.Fprintf(&b, "| R smoothing | %.6f |\n", report.Sampler.RSmoothing)
	fmt.Fprintf(&b, "| raw per-coefficient scale | %.6f |\n", report.Sampler.RawPerCoefficientScale)
	fmt.Fprintf(&b, "| raw signature l2 bound | %.6f |\n\n", report.Sampler.RawSignatureL2Bound)

	fmt.Fprintf(&b, "## Batch Result\n\n")
	fmt.Fprintf(&b, "| field | value |\n|---|---:|\n")
	fmt.Fprintf(&b, "| samples | %d |\n", report.Batch.Samples)
	fmt.Fprintf(&b, "| batch max l_inf | %d |\n", report.Batch.BatchMaxLInf)
	fmt.Fprintf(&b, "| batch max index | %d |\n", report.Batch.BatchMaxIndex)
	fmt.Fprintf(&b, "| max s1 l_inf | %d |\n", report.Batch.BatchMaxS1LInf)
	fmt.Fprintf(&b, "| max s1 index | %d |\n", report.Batch.BatchMaxS1Index)
	fmt.Fprintf(&b, "| max s2 l_inf | %d |\n", report.Batch.BatchMaxS2LInf)
	fmt.Fprintf(&b, "| max s2 index | %d |\n", report.Batch.BatchMaxS2Index)
	fmt.Fprintf(&b, "| max actual l2 | %.6f |\n", report.Batch.BatchMaxL2)
	fmt.Fprintf(&b, "| max actual l2 index | %d |\n", report.Batch.BatchMaxL2Index)
	fmt.Fprintf(&b, "| worst signature actual l2 | %.6f |\n", report.Batch.WorstSignatureL2)
	fmt.Fprintf(&b, "| all raw norm checks passed | %t |\n", report.Batch.AllNormPassed)
	fmt.Fprintf(&b, "| all public verifications passed | %t |\n\n", report.Batch.AllVerified)

	fmt.Fprintf(&b, "### Component Statistics\n\n")
	fmt.Fprintf(&b, "| metric | min | mean | rms | stddev | p50 | p75 | p90 | p95 | p99 | p99.9 | max |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	writeStatsRow(&b, "s1 l_inf", report.Batch.Stats.S1LInf)
	writeStatsRow(&b, "s2 l_inf", report.Batch.Stats.S2LInf)
	writeStatsRow(&b, "combined l_inf", report.Batch.Stats.CombinedLInf)
	writeStatsRow(&b, "s1 l2", report.Batch.Stats.S1L2)
	writeStatsRow(&b, "s2 l2", report.Batch.Stats.S2L2)
	writeStatsRow(&b, "total l2", report.Batch.Stats.TotalL2)
	writeStatsRow(&b, "trials used", report.Batch.Stats.TrialsUsed)
	writeStatsRow(&b, "target retries", report.Batch.Stats.TargetRetries)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "### Coordinate Absolute-Value Distribution\n\n")
	fmt.Fprintf(&b, "This section aggregates all `|s1_i|` and `|s2_i|` coordinates over the whole batch, so each side has `samples * N` observations.\n\n")
	fmt.Fprintf(&b, "| vector | count | min | mean | rms | stddev | p50 | p75 | p90 | p95 | p99 | p99.9 | max |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	writeCoordinateSummaryRow(&b, "s1 abs coordinate", report.Batch.Stats.S1CoordinateAbs)
	writeCoordinateSummaryRow(&b, "s2 abs coordinate", report.Batch.Stats.S2CoordinateAbs)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "#### Coordinate Tail Probabilities\n\n")
	fmt.Fprintf(&b, "| bound B | s1 count `|x| > B` | s1 probability | s2 count `|x| > B` | s2 probability |\n")
	fmt.Fprintf(&b, "|---:|---:|---:|---:|---:|\n")
	writeTailRows(&b, report.Batch.Stats.S1CoordinateAbs, report.Batch.Stats.S2CoordinateAbs)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "#### Coordinate Histogram\n\n")
	fmt.Fprintf(&b, "| `|x|` bucket | s1 count | s1 probability | s2 count | s2 probability |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---:|\n")
	writeHistogramRows(&b, report.Batch.Stats.S1CoordinateAbs, report.Batch.Stats.S2CoordinateAbs)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Enforceable Pure l_inf\n\n")
	fmt.Fprintf(&b, "| bound | value |\n|---|---:|\n")
	fmt.Fprintf(&b, "| raw-regimen l_inf ceiling | %d |\n", report.Bounds.RawRegimenLInfCeiling)
	fmt.Fprintf(&b, "| nontrivial SIS l_inf ceiling | %d |\n", report.Bounds.NontrivialSISLInfCeiling)
	fmt.Fprintf(&b, "| recommended pure l_inf ceiling | %d |\n", report.Bounds.RecommendedPureLInfCeiling)
	fmt.Fprintf(&b, "| observed max fits recommended ceiling | %t |\n\n", report.Bounds.ObservedWithinRecommendedLInf)

	fmt.Fprintf(&b, "Interpretation: if the observed batch maximum is above the recommended ceiling, then the current coefficient-only proof bound cannot truthfully imply the raw `l2` SIS model at `q=%d`. In that case the useful options are an actual `l2` norm proof, a smaller sampler output, or a different modulus/norm regimen.\n\n", report.Parameters.Q)

	fmt.Fprintf(&b, "## Security Cases\n\n")
	fmt.Fprintf(&b, "| case | l_inf | beta_sig_l2 | beta_aug_l2 | < q/2 | MATZOV bits | ADPS16 classical bits | CoreSVP quantum bits |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|:---:|---:|---:|---:|\n")
	for _, c := range report.Cases {
		linf := ""
		if c.LInf != nil {
			linf = fmt.Sprintf("%d", *c.LInf)
		}
		matzov := metricBits(c.Estimator, "matzov")
		adps := metricBits(c.Estimator, "adps16")
		quantum := ""
		if c.Estimator != nil && c.Estimator.CoreSVPQuantumBits != nil {
			quantum = fmt.Sprintf("%.3f", *c.Estimator.CoreSVPQuantumBits)
		}
		fmt.Fprintf(&b, "| %s | %s | %.3f | %.3f | %t | %s | %s | %s |\n", c.Name, linf, c.BetaSigL2, c.BetaAugL2, c.BetaAugLessThanQHalf, matzov, adps, quantum)
	}
	fmt.Fprintf(&b, "\n")

	if report.Estimator.Error != "" {
		fmt.Fprintf(&b, "Estimator note: `%s`.\n\n", report.Estimator.Error)
	}
	fmt.Fprintf(&b, "## Artifact Paths\n\n")
	for key, path := range report.Paths {
		fmt.Fprintf(&b, "- `%s`: `%s`\n", key, path)
	}
	return b.String()
}

func metricBits(est *estimateResult, which string) string {
	if est == nil {
		return ""
	}
	var metric estimateMetric
	switch which {
	case "matzov":
		metric = est.MATZOV
	case "adps16":
		metric = est.ADPS16
	default:
		return ""
	}
	if metric.Log2ROP == nil {
		return ""
	}
	return fmt.Sprintf("%.3f", *metric.Log2ROP)
}

func writeStatsRow(b *strings.Builder, name string, s statSummary) {
	fmt.Fprintf(b, "| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |\n",
		name, s.Min, s.Mean, s.RMS, s.StdDev, s.P50, s.P75, s.P90, s.P95, s.P99, s.P999, s.Max)
}

func writeCoordinateSummaryRow(b *strings.Builder, name string, d coordinateDistribution) {
	s := d.Abs
	fmt.Fprintf(b, "| %s | %d | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |\n",
		name, d.Count, s.Min, s.Mean, s.RMS, s.StdDev, s.P50, s.P75, s.P90, s.P95, s.P99, s.P999, s.Max)
}

func writeTailRows(b *strings.Builder, s1, s2 coordinateDistribution) {
	n := len(s1.TailProbabilities)
	if len(s2.TailProbabilities) < n {
		n = len(s2.TailProbabilities)
	}
	for i := 0; i < n; i++ {
		a := s1.TailProbabilities[i]
		c := s2.TailProbabilities[i]
		fmt.Fprintf(b, "| %d | %d | %.6f | %d | %.6f |\n",
			a.GreaterThan, a.Count, a.Probability, c.Count, c.Probability)
	}
}

func writeHistogramRows(b *strings.Builder, s1, s2 coordinateDistribution) {
	n := len(s1.Histogram)
	if len(s2.Histogram) < n {
		n = len(s2.Histogram)
	}
	for i := 0; i < n; i++ {
		a := s1.Histogram[i]
		c := s2.Histogram[i]
		fmt.Fprintf(b, "| %s | %d | %.6f | %d | %.6f |\n",
			a.Label, a.Count, a.Probability, c.Count, c.Probability)
	}
}

const estimatorRunnerSage = `
import contextlib
import io
import json
import math
import os
import sys

estimator_path, input_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]
if estimator_path not in sys.path:
    sys.path.insert(0, estimator_path)

from estimator import SIS
from estimator.reduction import RC
from sage.all import log

def finite_float(value):
    try:
        out = float(value)
    except Exception:
        return None
    if math.isfinite(out):
        return out
    return None

def log2_value(value):
    try:
        out = float(log(value, 2))
    except Exception:
        return None
    if math.isfinite(out):
        return out
    return None

def estimate_one(case, model):
    stream = io.StringIO()
    try:
        params = SIS.Parameters(
            n=int(case["sis_n"]),
            m=int(case["sis_m"]),
            q=int(case["q"]),
            length_bound=float(case["beta_aug_l2"]),
            norm=2,
            tag=str(case["name"]),
        )
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            raw = SIS.estimate(params, red_cost_model=model, quiet=True)
        lattice = raw.get("lattice")
        if lattice is None:
            return {"ok": False, "error": "missing lattice result", "stdout": stream.getvalue()}
        return {
            "ok": True,
            "log2_rop": log2_value(lattice.get("rop")),
            "log2_red": log2_value(lattice.get("red")),
            "bkz_beta": finite_float(lattice.get("beta")),
            "tag": str(lattice.get("tag", "")),
            "stdout": stream.getvalue(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "stdout": stream.getvalue()}

with open(input_path, "r") as fh:
    cases = json.load(fh)

results = {}
for case in cases:
    matzov = estimate_one(case, RC.MATZOV)
    adps16 = estimate_one(case, RC.ADPS16)
    status = "ok" if matzov.get("ok") and adps16.get("ok") else "partial_or_error"
    results[case["name"]] = {
        "available": status == "ok",
        "status": status,
        "matzov": matzov,
        "adps16": adps16,
    }

with open(output_path, "w") as fh:
    json.dump(results, fh, indent=2, sort_keys=True)
    fh.write("\n")
`
