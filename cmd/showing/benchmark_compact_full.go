package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	benchmarkCompactFullVersion               = 1
	compactFullBenchmarkBaselineTranscriptB   = 96529
	compactFullBenchmarkSoundnessFloorBits    = 118.0
	compactFullBenchmarkControlBalancedFull   = "soundness_balanced_full"
	compactFullBenchmarkControlCompactReduced = "compact_l1_research_reduced"
)

type benchmarkCompactFullPaperBuckets struct {
	TotalBytes        int `json:"total_bytes"`
	QBytes            int `json:"q_bytes"`
	PdecsBytes        int `json:"pdecs_bytes"`
	RBytes            int `json:"r_bytes"`
	SigShortnessBytes int `json:"sig_shortness_bytes"`
	AuthBytes         int `json:"auth_bytes"`
	VTargetsBytes     int `json:"vtargets_bytes"`
	BarSetsBytes      int `json:"barsets_bytes"`
}

type benchmarkCompactFullFocus struct {
	DQ                int `json:"dq"`
	LVCSNCols         int `json:"lvcs_ncols"`
	NLeaves           int `json:"nleaves"`
	PCols             int `json:"pcols"`
	RowOpeningEntries int `json:"row_opening_entries"`
	ReplayBlocks      int `json:"replay_blocks"`
	WitnessRows       int `json:"witness_rows"`
}

type benchmarkCompactFullRunReport struct {
	Run              int                              `json:"run"`
	Kind             string                           `json:"kind"`
	ID               string                           `json:"id"`
	CandidateID      string                           `json:"candidate_id,omitempty"`
	BasePreset       string                           `json:"base_preset"`
	ReplayMode       string                           `json:"replay_mode"`
	ShortnessMode    string                           `json:"shortness_mode"`
	ShortnessProfile string                           `json:"shortness_profile"`
	TranscriptBytes  int                              `json:"transcript_bytes"`
	ProofBytes       int                              `json:"proof_bytes"`
	PaperBuckets     benchmarkCompactFullPaperBuckets `json:"paper_buckets"`
	Focus            benchmarkCompactFullFocus        `json:"focus"`
	ProveMS          float64                          `json:"prove_ms"`
	VerifyMS         float64                          `json:"verify_ms"`
	TheoremTotalBits float64                          `json:"theorem_total_bits"`
}

type benchmarkCompactFullEntry struct {
	Kind             string                           `json:"kind"`
	ID               string                           `json:"id"`
	CandidateID      string                           `json:"candidate_id,omitempty"`
	BasePreset       string                           `json:"base_preset"`
	ReplayMode       string                           `json:"replay_mode"`
	ShortnessMode    string                           `json:"shortness_mode"`
	ShortnessProfile string                           `json:"shortness_profile"`
	TranscriptBytes  int                              `json:"transcript_bytes"`
	ProofBytes       int                              `json:"proof_bytes"`
	PaperBuckets     benchmarkCompactFullPaperBuckets `json:"paper_buckets"`
	Focus            benchmarkCompactFullFocus        `json:"focus"`
	AvgProveMS       float64                          `json:"avg_prove_ms"`
	AvgVerifyMS      float64                          `json:"avg_verify_ms"`
	TheoremTotalBits float64                          `json:"theorem_total_bits"`
	RunReports       []benchmarkCompactFullRunReport  `json:"run_reports"`
}

type benchmarkCompactFullWinner struct {
	CandidateID      string                           `json:"candidate_id"`
	TranscriptBytes  int                              `json:"transcript_bytes"`
	ProofBytes       int                              `json:"proof_bytes"`
	PaperBuckets     benchmarkCompactFullPaperBuckets `json:"paper_buckets"`
	Focus            benchmarkCompactFullFocus        `json:"focus"`
	AvgProveMS       float64                          `json:"avg_prove_ms"`
	TheoremTotalBits float64                          `json:"theorem_total_bits"`
}

type benchmarkCompactFullReport struct {
	Version                 int                         `json:"version"`
	GeneratedAt             string                      `json:"generated_at"`
	BaselineTranscriptBytes int                         `json:"baseline_transcript_bytes"`
	Entries                 []benchmarkCompactFullEntry `json:"entries"`
	Winner                  *benchmarkCompactFullWinner `json:"winner,omitempty"`
}

type compactFullBenchmarkConfig struct {
	Kind        string
	ID          string
	CandidateID string
	BasePreset  string
	ReplayMode  PIOP.ShowingReplayMode
}

type compactFullBenchmarkContext struct {
	ringQ        *ring.Ring
	state        credential.State
	publicParams credential.PublicParams
	prfParams    *prf.Params
	B            []*ring.Poly
	wit          PIOP.WitnessInputs
	A            [][]*ring.Poly
}

func loadShowingBenchmarkContextFromStatePath(statePath string) (*compactFullBenchmarkContext, error) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		return nil, fmt.Errorf("load ring: %w", err)
	}
	state, err := credential.LoadState(statePath)
	if err != nil {
		return nil, fmt.Errorf("load credential state: %w", err)
	}
	publicParams, err := loadCredentialPublicParamsFromState(state)
	if err != nil {
		return nil, fmt.Errorf("load credential public params: %w", err)
	}
	params, err := loadPRFParamsFromState(state)
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}
	B, err := loadBForShowing(ringQ, state, publicParams)
	if err != nil {
		return nil, fmt.Errorf("load B: %w", err)
	}
	wit, err := buildWitnessFromState(ringQ, state, B)
	if err != nil {
		return nil, fmt.Errorf("build witness: %w", err)
	}
	A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
	if err != nil {
		return nil, fmt.Errorf("build A: %w", err)
	}
	return &compactFullBenchmarkContext{
		ringQ:        ringQ,
		state:        state,
		publicParams: publicParams,
		prfParams:    params,
		B:            B,
		wit:          wit,
		A:            A,
	}, nil
}

func benchmarkCompactFullPaperBucketsFromReport(rep PIOP.ProofReport) benchmarkCompactFullPaperBuckets {
	return benchmarkCompactFullPaperBuckets{
		TotalBytes:        rep.PaperTranscript.OptimizedBytes,
		QBytes:            rep.PaperTranscript.Q.OptimizedBytes,
		PdecsBytes:        rep.PaperTranscript.Pdecs.OptimizedBytes,
		RBytes:            rep.PaperTranscript.R.OptimizedBytes,
		SigShortnessBytes: rep.PaperTranscript.SigShortness.OptimizedBytes,
		AuthBytes:         rep.PaperTranscript.Auth.OptimizedBytes,
		VTargetsBytes:     rep.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:      rep.PaperTranscript.BarSets.OptimizedBytes,
	}
}

func benchmarkCompactFullFocusFromReport(rep PIOP.ProofReport) benchmarkCompactFullFocus {
	return benchmarkCompactFullFocus{
		DQ:                rep.DQ,
		LVCSNCols:         rep.TranscriptFocus.LVCSNCols,
		NLeaves:           rep.TranscriptFocus.NLeaves,
		PCols:             rep.TranscriptFocus.PCols,
		RowOpeningEntries: rep.TranscriptFocus.RowOpeningEntries,
		ReplayBlocks:      rep.TranscriptFocus.ReplayBlocks,
		WitnessRows:       rep.TranscriptFocus.WitnessRows,
	}
}

func runBenchmarkCompactFull(args []string) error {
	fs := flag.NewFlagSet("benchmark-compact-full", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	candidates := fs.String("candidates", strings.Join(PIOP.CompactFullCandidateIDs(), ","), "comma-separated internal compact-full candidate ids")
	controls := fs.String("controls", compactFullBenchmarkControlBalancedFull+","+compactFullBenchmarkControlCompactReduced, "comma-separated benchmark control ids")
	runs := fs.Int("runs", 1, "number of benchmark runs per entry")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return benchmarkCompactFull(*candidates, *controls, *runs, *jsonOut)
}

func benchmarkCompactFull(candidatesCSV, controlsCSV string, runs int, jsonOut string) error {
	if runs <= 0 {
		return fmt.Errorf("runs must be > 0")
	}
	configs, err := parseCompactFullBenchmarkConfigs(candidatesCSV, controlsCSV)
	if err != nil {
		return err
	}
	ctx, err := loadCompactFullBenchmarkContext()
	if err != nil {
		return err
	}
	report := benchmarkCompactFullReport{
		Version:     benchmarkCompactFullVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, cfg := range configs {
		entry, err := runCompactFullBenchmarkEntry(ctx, cfg, runs)
		if err != nil {
			return err
		}
		report.Entries = append(report.Entries, entry)
		log.Printf("[showing-cli] benchmark-compact-full kind=%s id=%s preset=%s replay=%s shortness=%s profile=%s transcript=%d proof=%d soundness=%.2f prove=%s verify=%s",
			entry.Kind,
			entry.ID,
			entry.BasePreset,
			entry.ReplayMode,
			entry.ShortnessMode,
			entry.ShortnessProfile,
			entry.TranscriptBytes,
			entry.ProofBytes,
			entry.TheoremTotalBits,
			msString(entry.AvgProveMS),
			msString(entry.AvgVerifyMS),
		)
	}
	report.BaselineTranscriptBytes = compactFullCurrentBaselineTranscript(report.Entries)
	report.Winner = selectCompactFullBenchmarkWinner(report.Entries, report.BaselineTranscriptBytes)
	if report.Winner != nil {
		log.Printf("[showing-cli] benchmark-compact-full winner=%s transcript=%d proof=%d soundness=%.2f prove=%s",
			report.Winner.CandidateID,
			report.Winner.TranscriptBytes,
			report.Winner.ProofBytes,
			report.Winner.TheoremTotalBits,
			msString(report.Winner.AvgProveMS),
		)
	} else {
		log.Printf("[showing-cli] benchmark-compact-full no promotable winner (baseline=%d bytes)", report.BaselineTranscriptBytes)
	}
	if jsonOut != "" {
		if err := writeShowingJSONFile(jsonOut, report, 0o644); err != nil {
			return fmt.Errorf("write benchmark json: %w", err)
		}
		log.Printf("[showing-cli] benchmark-compact-full wrote %s", jsonOut)
	}
	return nil
}

func parseCompactFullBenchmarkConfigs(candidatesCSV, controlsCSV string) ([]compactFullBenchmarkConfig, error) {
	configs := make([]compactFullBenchmarkConfig, 0)
	for _, id := range parseCSV(candidatesCSV) {
		if !containsString(PIOP.CompactFullCandidateIDs(), id) {
			return nil, fmt.Errorf("unknown compact-full candidate %q", id)
		}
		configs = append(configs, compactFullBenchmarkConfig{
			Kind:        "candidate",
			ID:          id,
			CandidateID: id,
			BasePreset:  PIOP.ShowingPresetCompactL1Research,
			ReplayMode:  PIOP.ShowingReplayModeFull,
		})
	}
	for _, id := range parseCSV(controlsCSV) {
		switch id {
		case compactFullBenchmarkControlBalancedFull:
			configs = append(configs, compactFullBenchmarkConfig{
				Kind:       "control",
				ID:         id,
				BasePreset: PIOP.ShowingPresetSoundnessBalanced,
				ReplayMode: PIOP.ShowingReplayModeFull,
			})
		case compactFullBenchmarkControlCompactReduced:
			configs = append(configs, compactFullBenchmarkConfig{
				Kind:       "control",
				ID:         id,
				BasePreset: PIOP.ShowingPresetCompactL1Research,
				ReplayMode: PIOP.ShowingReplayModeReduced,
			})
		case "":
			continue
		default:
			return nil, fmt.Errorf("unknown compact-full control %q", id)
		}
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("no compact-full benchmark entries requested")
	}
	return configs, nil
}

func loadCompactFullBenchmarkContext() (*compactFullBenchmarkContext, error) {
	return loadShowingBenchmarkContextFromStatePath(filepath.Join("credential", "keys", "credential_state.json"))
}

func runCompactFullBenchmarkEntry(ctx *compactFullBenchmarkContext, cfg compactFullBenchmarkConfig, runs int) (benchmarkCompactFullEntry, error) {
	entry := benchmarkCompactFullEntry{
		Kind:        cfg.Kind,
		ID:          cfg.ID,
		CandidateID: cfg.CandidateID,
		BasePreset:  cfg.BasePreset,
		ReplayMode:  string(cfg.ReplayMode),
		RunReports:  make([]benchmarkCompactFullRunReport, 0, runs),
	}
	var (
		sumTranscript int
		sumProof      int
		sumProveMS    float64
		sumVerifyMS   float64
		sumBuckets    benchmarkCompactFullPaperBuckets
	)
	for run := 1; run <= runs; run++ {
		runReport, err := executeCompactFullBenchmarkRun(ctx, cfg, run)
		if err != nil {
			return benchmarkCompactFullEntry{}, fmt.Errorf("%s run %d: %w", cfg.ID, run, err)
		}
		entry.RunReports = append(entry.RunReports, runReport)
		sumTranscript += runReport.TranscriptBytes
		sumProof += runReport.ProofBytes
		sumProveMS += runReport.ProveMS
		sumVerifyMS += runReport.VerifyMS
		sumBuckets.TotalBytes += runReport.PaperBuckets.TotalBytes
		sumBuckets.QBytes += runReport.PaperBuckets.QBytes
		sumBuckets.PdecsBytes += runReport.PaperBuckets.PdecsBytes
		sumBuckets.RBytes += runReport.PaperBuckets.RBytes
		sumBuckets.SigShortnessBytes += runReport.PaperBuckets.SigShortnessBytes
		sumBuckets.AuthBytes += runReport.PaperBuckets.AuthBytes
		sumBuckets.VTargetsBytes += runReport.PaperBuckets.VTargetsBytes
		sumBuckets.BarSetsBytes += runReport.PaperBuckets.BarSetsBytes
	}
	denom := float64(len(entry.RunReports))
	entry.TranscriptBytes = int(math.Round(float64(sumTranscript) / denom))
	entry.ProofBytes = int(math.Round(float64(sumProof) / denom))
	entry.AvgProveMS = sumProveMS / denom
	entry.AvgVerifyMS = sumVerifyMS / denom
	entry.PaperBuckets = benchmarkCompactFullPaperBuckets{
		TotalBytes:        int(math.Round(float64(sumBuckets.TotalBytes) / denom)),
		QBytes:            int(math.Round(float64(sumBuckets.QBytes) / denom)),
		PdecsBytes:        int(math.Round(float64(sumBuckets.PdecsBytes) / denom)),
		RBytes:            int(math.Round(float64(sumBuckets.RBytes) / denom)),
		SigShortnessBytes: int(math.Round(float64(sumBuckets.SigShortnessBytes) / denom)),
		AuthBytes:         int(math.Round(float64(sumBuckets.AuthBytes) / denom)),
		VTargetsBytes:     int(math.Round(float64(sumBuckets.VTargetsBytes) / denom)),
		BarSetsBytes:      int(math.Round(float64(sumBuckets.BarSetsBytes) / denom)),
	}
	if len(entry.RunReports) > 0 {
		last := entry.RunReports[len(entry.RunReports)-1]
		entry.ShortnessMode = last.ShortnessMode
		entry.ShortnessProfile = last.ShortnessProfile
		entry.Focus = last.Focus
		entry.TheoremTotalBits = last.TheoremTotalBits
	}
	return entry, nil
}

func executeCompactFullBenchmarkRun(ctx *compactFullBenchmarkContext, cfg compactFullBenchmarkConfig, run int) (benchmarkCompactFullRunReport, error) {
	opts := compactFullBenchmarkOptsForConfig(cfg)
	omega, err := deriveOmegaForOpts(ctx.ringQ, opts, ctx.publicParams.HashRelation)
	if err != nil {
		return benchmarkCompactFullRunReport{}, fmt.Errorf("derive omega: %w", err)
	}
	nonce, noncePublic := sampleNonce(ctx.prfParams.LenNonce, len(omega), ctx.ringQ.Modulus[0])
	key, err := prfKeyFromWitnessOnOmega(ctx.ringQ, ctx.wit, omega, ctx.prfParams.LenKey)
	if err != nil {
		return benchmarkCompactFullRunReport{}, fmt.Errorf("prf key: %w", err)
	}
	tag, err := prf.Tag(key, nonce, ctx.prfParams)
	if err != nil {
		return benchmarkCompactFullRunReport{}, fmt.Errorf("prf tag: %w", err)
	}
	pub := PIOP.PublicInputs{
		A:                  ctx.A,
		B:                  ctx.B,
		Tag:                lanesFromElems(tag, len(omega)),
		Nonce:              noncePublic,
		BoundB:             ctx.publicParams.BoundB,
		X0Len:              ctx.publicParams.X0Len,
		X0CoeffBound:       ctx.publicParams.X0CoeffBound,
		TargetDim:          ctx.publicParams.TargetDim,
		TargetHidingLambda: ctx.publicParams.TargetHidingLambda,
		HashRelation:       ctx.publicParams.HashRelation,
	}
	proveStart := time.Now()
	proof, err := PIOP.BuildShowingCombined(pub, ctx.wit, opts)
	if err != nil {
		return benchmarkCompactFullRunReport{}, fmt.Errorf("build showing: %w", err)
	}
	proveDur := time.Since(proveStart)
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	verifyStart := time.Now()
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	verifyDur := time.Since(verifyStart)
	if err != nil || !ok {
		return benchmarkCompactFullRunReport{}, fmt.Errorf("verify showing failed: ok=%v err=%v", ok, err)
	}
	rep, err := PIOP.BuildProofReport(proof, opts, ctx.ringQ)
	if err != nil {
		return benchmarkCompactFullRunReport{}, fmt.Errorf("build proof report: %w", err)
	}
	if cfg.Kind == "candidate" {
		if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV7 {
			return benchmarkCompactFullRunReport{}, fmt.Errorf("candidate %s fell off V7: shortness_mode=%s", cfg.CandidateID, rep.TranscriptFocus.ShortnessMode)
		}
		if rep.TranscriptFocus.CompactFullCandidate != cfg.CandidateID {
			return benchmarkCompactFullRunReport{}, fmt.Errorf("candidate %s reported compact_full_candidate=%q", cfg.CandidateID, rep.TranscriptFocus.CompactFullCandidate)
		}
		if rep.Soundness.TotalBits < compactFullBenchmarkSoundnessFloorBits {
			return benchmarkCompactFullRunReport{}, fmt.Errorf("candidate %s theorem total bits=%.2f below floor %.2f", cfg.CandidateID, rep.Soundness.TotalBits, compactFullBenchmarkSoundnessFloorBits)
		}
	}
	return benchmarkCompactFullRunReport{
		Run:              run,
		Kind:             cfg.Kind,
		ID:               cfg.ID,
		CandidateID:      cfg.CandidateID,
		BasePreset:       rep.TranscriptFocus.ShowingPreset,
		ReplayMode:       rep.TranscriptFocus.ReplayMode,
		ShortnessMode:    rep.TranscriptFocus.ShortnessMode,
		ShortnessProfile: rep.TranscriptFocus.SigShortnessProfile,
		TranscriptBytes:  rep.PaperTranscript.OptimizedBytes,
		ProofBytes:       rep.ProofBytes,
		PaperBuckets:     benchmarkCompactFullPaperBucketsFromReport(rep),
		Focus:            benchmarkCompactFullFocusFromReport(rep),
		ProveMS:          float64(proveDur.Microseconds()) / 1000.0,
		VerifyMS:         float64(verifyDur.Microseconds()) / 1000.0,
		TheoremTotalBits: rep.Soundness.TotalBits,
	}, nil
}

func compactFullBenchmarkOptsForConfig(cfg compactFullBenchmarkConfig) PIOP.SimOpts {
	opts := PIOP.SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		Theta:                3,
		Rho:                  2,
		DomainMode:           PIOP.DomainModeExplicit,
		NLeaves:              4096,
		Kappa:                [4]int{0, 0, 0, 0},
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        cfg.BasePreset,
		ShowingReplayMode:    cfg.ReplayMode,
		CompactFullCandidate: cfg.CandidateID,
		PRFCompanionMode:     PIOP.PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	}
	return PIOP.ResolveSimOptsDefaults(opts)
}

func compactFullCurrentBaselineTranscript(entries []benchmarkCompactFullEntry) int {
	for _, entry := range entries {
		if entry.Kind == "candidate" && entry.CandidateID == PIOP.CompactFullCandidateCurrent {
			return entry.TranscriptBytes
		}
	}
	return compactFullBenchmarkBaselineTranscriptB
}

func selectCompactFullBenchmarkWinner(entries []benchmarkCompactFullEntry, baseline int) *benchmarkCompactFullWinner {
	var best *benchmarkCompactFullEntry
	for i := range entries {
		entry := &entries[i]
		if entry.Kind != "candidate" {
			continue
		}
		if entry.ShortnessMode != PIOP.SigShortnessModeHiddenV7 {
			continue
		}
		if entry.TheoremTotalBits < compactFullBenchmarkSoundnessFloorBits {
			continue
		}
		if entry.TranscriptBytes >= baseline {
			continue
		}
		if best == nil || compactFullBenchmarkEntryLess(entry, best) {
			best = entry
		}
	}
	if best == nil {
		return nil
	}
	return &benchmarkCompactFullWinner{
		CandidateID:      best.CandidateID,
		TranscriptBytes:  best.TranscriptBytes,
		ProofBytes:       best.ProofBytes,
		PaperBuckets:     best.PaperBuckets,
		Focus:            best.Focus,
		AvgProveMS:       best.AvgProveMS,
		TheoremTotalBits: best.TheoremTotalBits,
	}
}

func compactFullBenchmarkEntryLess(a, b *benchmarkCompactFullEntry) bool {
	if a.TranscriptBytes != b.TranscriptBytes {
		return a.TranscriptBytes < b.TranscriptBytes
	}
	aMain := a.PaperBuckets.PdecsBytes + a.PaperBuckets.VTargetsBytes + a.PaperBuckets.BarSetsBytes + a.PaperBuckets.QBytes
	bMain := b.PaperBuckets.PdecsBytes + b.PaperBuckets.VTargetsBytes + b.PaperBuckets.BarSetsBytes + b.PaperBuckets.QBytes
	if aMain != bMain {
		return aMain < bMain
	}
	if a.ProofBytes != b.ProofBytes {
		return a.ProofBytes < b.ProofBytes
	}
	return a.AvgProveMS < b.AvgProveMS
}

func parseCSV(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func writeShowingJSONFile(path string, value interface{}, perm os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), perm)
}

func msString(ms float64) string {
	return time.Duration(ms * float64(time.Millisecond)).String()
}
