package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/prf"
)

const (
	benchmarkTranscriptSweepVersion     = 3
	transcriptSweepTheoremFloorBits     = 100.0
	transcriptSweepTrackReduced         = "reduced"
	transcriptSweepTrackFullV6          = "full_v6"
	transcriptSweepTrackX0Controls      = "x0_controls"
	transcriptSweepTrackPRFReduced      = "prf_controls_reduced"
	transcriptSweepTrackPRFFull96       = "prf_controls_full96"
	transcriptSweepKindCandidate        = "candidate"
	transcriptSweepKindControl          = "control"
	transcriptSweepKindX0Control        = "x0_control"
	transcriptSweepBaselineReducedID    = "a1_w84_n4096_e40_ep2_sig_r11_l4_production_th3_r2_k0-0-0-5"
	transcriptSweepBaselineFullID       = "b2_w96_n4096_e43_ep2_sig_r24_l3_compact_th3_r2_k0-0-0-5"
	transcriptSweepBaselineFull96ID     = "full96_current_control"
	transcriptSweepBaselineFullAggR0ID  = "full96_aggregate_r0_control"
	transcriptSweepFullAggR0W64ID       = "full64_e34_aggregate_r0_control"
	transcriptSweepFullAggR0W76ID       = "full76_e38_aggregate_r0_control"
	transcriptSweepFullAggR0V11R24ID    = "full76_e38_aggregate_v11_direct_target_r24_control"
	transcriptSweepBaselinePRFReducedID = "prf_reduced_output_audit_g2_s8"
	transcriptSweepBaselinePRFFull96ID  = "prf_full96_output_audit_g2_s8"
)

type transcriptSweepPaperBuckets struct {
	QBytes            int `json:"q_bytes"`
	PdecsBytes        int `json:"pdecs_bytes"`
	RBytes            int `json:"r_bytes"`
	SigShortnessBytes int `json:"sig_shortness_bytes"`
	AuthBytes         int `json:"auth_bytes"`
	VTargetsBytes     int `json:"vtargets_bytes"`
	BarSetsBytes      int `json:"barsets_bytes"`
}

type transcriptSweepSigShortness struct {
	OpeningBytes     int `json:"opening_bytes"`
	HiddenProofBytes int `json:"hidden_proof_bytes"`
	BindingBytes     int `json:"binding_bytes"`
	SupportSlotCount int `json:"support_slot_count"`
	OpenedBlockCount int `json:"opened_block_count"`
}

type transcriptSweepGeometry struct {
	DQ                        int `json:"dq"`
	LVCSNCols                 int `json:"lvcs_ncols"`
	NLeaves                   int `json:"nleaves"`
	PCols                     int `json:"pcols"`
	RowOpeningEntries         int `json:"row_opening_entries"`
	ReplayBlocks              int `json:"replay_blocks"`
	WitnessRows               int `json:"witness_rows"`
	MainLVCSNCols             int `json:"main_lvcs_ncols"`
	MainNLeaves               int `json:"main_nleaves"`
	PRFLVCSNCols              int `json:"prf_lvcs_ncols"`
	PRFNLeaves                int `json:"prf_nleaves"`
	HiddenShortnessLVCSNCols  int `json:"hidden_shortness_lvcs_ncols"`
	HiddenShortnessNLeaves    int `json:"hidden_shortness_nleaves"`
	CarrierSelectedRows       int `json:"carrier_selected_rows"`
	PRFCompanionSelectedRows  int `json:"prf_companion_selected_rows"`
	SourceProductSelectedRows int `json:"source_product_selected_rows"`
	ReplayMHatSigmaRows       int `json:"replay_mhat_sigma_rows"`
	ReplayRHat0Rows           int `json:"replay_rhat0_rows"`
	ReplayR0B2HatRows         int `json:"replay_r0_b2_hat_rows"`
	ReplayTargetMR0HatRows    int `json:"replay_target_mr0_hat_rows"`
	ReplayRHat1Rows           int `json:"replay_rhat1_rows"`
	ReplayZHatRows            int `json:"replay_zhat_rows"`
	ReplayTHatRows            int `json:"replay_that_rows"`
	V11PackedGroupSize        int `json:"v11_packed_group_size"`
	V11PackedBlockWidth       int `json:"v11_packed_block_width"`
	V11EffectiveSigBlocks     int `json:"v11_effective_sig_blocks"`
	V11ShortnessRows          int `json:"v11_shortness_rows"`
	MaskRows                  int `json:"mask_rows"`
}

type transcriptSweepSoundness struct {
	Eq8TotalBits  float64 `json:"eq8_total_bits"`
	Thm9TotalBits float64 `json:"thm9_total_bits"`
	Eps1Bits      float64 `json:"eps1_bits"`
	Eps2Bits      float64 `json:"eps2_bits"`
	Eps3Bits      float64 `json:"eps3_bits"`
	Eps4Bits      float64 `json:"eps4_bits"`
}

type transcriptSweepRunReport struct {
	Run                  int                         `json:"run"`
	Track                string                      `json:"track"`
	Kind                 string                      `json:"kind"`
	CandidateID          string                      `json:"candidate_id"`
	BasePreset           string                      `json:"base_preset"`
	ReplayMode           string                      `json:"replay_mode"`
	ShortnessMode        string                      `json:"shortness_mode"`
	ShortnessProfile     string                      `json:"shortness_profile"`
	PRFMode              string                      `json:"prf_mode"`
	PRFCheckpointSamples int                         `json:"prf_checkpoint_samples"`
	PRFGroupRounds       int                         `json:"prf_group_rounds"`
	AggregateR0Replay    bool                        `json:"aggregate_r0_replay"`
	X0Profile            string                      `json:"x0_profile"`
	Verified             bool                        `json:"verified"`
	RejectReason         string                      `json:"reject_reason,omitempty"`
	PaperTranscriptBytes int                         `json:"paper_transcript_bytes"`
	ProofBytes           int                         `json:"proof_bytes"`
	PaperBuckets         transcriptSweepPaperBuckets `json:"paper_buckets"`
	SigShortness         transcriptSweepSigShortness `json:"sig_shortness"`
	Geometry             transcriptSweepGeometry     `json:"geometry"`
	Soundness            transcriptSweepSoundness    `json:"soundness"`
	ProveMS              float64                     `json:"prove_ms"`
	VerifyMS             float64                     `json:"verify_ms"`
}

type transcriptSweepEntry struct {
	Track                string                      `json:"track"`
	Kind                 string                      `json:"kind"`
	CandidateID          string                      `json:"candidate_id"`
	BasePreset           string                      `json:"base_preset"`
	ReplayMode           string                      `json:"replay_mode"`
	ShortnessMode        string                      `json:"shortness_mode"`
	ShortnessProfile     string                      `json:"shortness_profile"`
	PRFMode              string                      `json:"prf_mode"`
	PRFCheckpointSamples int                         `json:"prf_checkpoint_samples"`
	PRFGroupRounds       int                         `json:"prf_group_rounds"`
	AggregateR0Replay    bool                        `json:"aggregate_r0_replay"`
	X0Profile            string                      `json:"x0_profile"`
	Verified             bool                        `json:"verified"`
	RejectReason         string                      `json:"reject_reason,omitempty"`
	PaperTranscriptBytes int                         `json:"paper_transcript_bytes"`
	ProofBytes           int                         `json:"proof_bytes"`
	PaperBuckets         transcriptSweepPaperBuckets `json:"paper_buckets"`
	SigShortness         transcriptSweepSigShortness `json:"sig_shortness"`
	Geometry             transcriptSweepGeometry     `json:"geometry"`
	Soundness            transcriptSweepSoundness    `json:"soundness"`
	AvgProveMS           float64                     `json:"avg_prove_ms"`
	AvgVerifyMS          float64                     `json:"avg_verify_ms"`
	Promotable           bool                        `json:"promotable"`
	RunReports           []transcriptSweepRunReport  `json:"run_reports,omitempty"`
}

type transcriptSweepTrackSummary struct {
	Track                 string `json:"track"`
	BaselineCandidateID   string `json:"baseline_candidate_id,omitempty"`
	BaselineTranscriptB   int    `json:"baseline_transcript_bytes,omitempty"`
	EligibleCount         int    `json:"eligible_count"`
	RejectedCount         int    `json:"rejected_count"`
	WinnerCandidateID     string `json:"winner_candidate_id,omitempty"`
	WinnerTranscriptBytes int    `json:"winner_transcript_bytes,omitempty"`
	Promote               bool   `json:"promote"`
}

type transcriptSweepReport struct {
	Version        int                           `json:"version"`
	GeneratedAt    string                        `json:"generated_at"`
	Tracks         []string                      `json:"tracks"`
	Entries        []transcriptSweepEntry        `json:"entries"`
	TrackSummaries []transcriptSweepTrackSummary `json:"track_summaries"`
}

type transcriptSweepCandidateConfig struct {
	Track                string
	Kind                 string
	ID                   string
	BasePreset           string
	ReplayMode           PIOP.ShowingReplayMode
	SigShortnessProfile  string
	LVCSNCols            int
	NLeaves              int
	Eta                  int
	EllPrime             int
	Theta                int
	Rho                  int
	Kappa                [4]int
	CompactFullCandidate string
	BenchmarkCandidate   string
	PRFMode              PIOP.PRFCompanionMode
	PRFSamples           int
	PRFGroupRounds       int
	AggregateR0Replay    bool
	X0Profile            string
	Promotable           bool
}

type transcriptSweepContext struct {
	canonical *compactFullBenchmarkContext
	x0Cache   map[string]*compactFullBenchmarkContext
	cleanups  []func()
}

func runBenchmarkTranscriptSweep(args []string) error {
	fs := flag.NewFlagSet("benchmark-transcript-sweep", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tracksCSV := fs.String("tracks", strings.Join([]string{
		transcriptSweepTrackReduced,
		transcriptSweepTrackFullV6,
		transcriptSweepTrackX0Controls,
		transcriptSweepTrackPRFReduced,
		transcriptSweepTrackPRFFull96,
	}, ","), "comma-separated sweep tracks (reduced, full_v6, x0_controls, prf_controls_reduced, prf_controls_full96)")
	runs := fs.Int("runs", 1, "number of benchmark runs per entry")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	controlsOnly := fs.Bool("controls-only", false, "only run the fixed control rows for the requested tracks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return benchmarkTranscriptSweep(*tracksCSV, *runs, *jsonOut, *controlsOnly)
}

func benchmarkTranscriptSweep(tracksCSV string, runs int, jsonOut string, controlsOnly bool) error {
	if runs <= 0 {
		return fmt.Errorf("runs must be > 0")
	}
	tracks, err := parseTranscriptSweepTracks(tracksCSV)
	if err != nil {
		return err
	}
	ctx, err := loadTranscriptSweepContext()
	if err != nil {
		return err
	}
	defer ctx.Close()

	report := transcriptSweepReport{
		Version:     benchmarkTranscriptSweepVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tracks:      append([]string(nil), tracks...),
	}
	for _, track := range tracks {
		var (
			entries  []transcriptSweepEntry
			summary  transcriptSweepTrackSummary
			trackErr error
		)
		switch track {
		case transcriptSweepTrackReduced:
			entries, summary, trackErr = runReducedTranscriptSweepTrack(ctx, runs, controlsOnly)
		case transcriptSweepTrackFullV6:
			entries, summary, trackErr = runFullV6TranscriptSweepTrack(ctx, runs, controlsOnly)
		case transcriptSweepTrackX0Controls:
			entries, summary, trackErr = runX0ControlsTranscriptSweepTrack(ctx, runs)
		case transcriptSweepTrackPRFReduced:
			entries, summary, trackErr = runPRFControlsReducedTranscriptSweepTrack(ctx, runs)
		case transcriptSweepTrackPRFFull96:
			entries, summary, trackErr = runPRFControlsFull96TranscriptSweepTrack(ctx, runs)
		default:
			trackErr = fmt.Errorf("unsupported transcript sweep track %q", track)
		}
		if trackErr != nil {
			return trackErr
		}
		report.Entries = append(report.Entries, entries...)
		report.TrackSummaries = append(report.TrackSummaries, summary)
		log.Printf("[showing-cli] benchmark-transcript-sweep track=%s entries=%d eligible=%d rejected=%d winner=%s transcript=%d promote=%v",
			summary.Track,
			len(entries),
			summary.EligibleCount,
			summary.RejectedCount,
			summary.WinnerCandidateID,
			summary.WinnerTranscriptBytes,
			summary.Promote,
		)
	}
	if jsonOut != "" {
		if err := writeShowingJSONFile(jsonOut, report, 0o644); err != nil {
			return fmt.Errorf("write transcript sweep json: %w", err)
		}
		log.Printf("[showing-cli] benchmark-transcript-sweep wrote %s", jsonOut)
	}
	return nil
}

func parseTranscriptSweepTracks(csv string) ([]string, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, fmt.Errorf("no transcript sweep tracks requested")
	}
	out := make([]string, 0)
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch part {
		case transcriptSweepTrackReduced, transcriptSweepTrackFullV6, transcriptSweepTrackX0Controls, transcriptSweepTrackPRFReduced, transcriptSweepTrackPRFFull96:
			out = append(out, part)
		default:
			return nil, fmt.Errorf("unknown transcript sweep track %q", part)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no transcript sweep tracks requested")
	}
	return out, nil
}

func loadTranscriptSweepContext() (*transcriptSweepContext, error) {
	canonical, err := loadCompactFullBenchmarkContext()
	if err != nil {
		return nil, err
	}
	return &transcriptSweepContext{
		canonical: canonical,
		x0Cache:   make(map[string]*compactFullBenchmarkContext),
	}, nil
}

func (ctx *transcriptSweepContext) Close() {
	for _, cleanup := range ctx.cleanups {
		cleanup()
	}
}

func (ctx *transcriptSweepContext) benchmarkContextForX0Profile(profile string) (*compactFullBenchmarkContext, error) {
	switch strings.TrimSpace(profile) {
	case "", "lhl_default":
		return ctx.canonical, nil
	}
	if cached, ok := ctx.x0Cache[profile]; ok {
		return cached, nil
	}
	loaded, cleanup, err := buildIssuedShowingBenchmarkContextForX0Profile(profile)
	if err != nil {
		return nil, err
	}
	ctx.x0Cache[profile] = loaded
	ctx.cleanups = append(ctx.cleanups, cleanup)
	return loaded, nil
}

func buildIssuedShowingBenchmarkContextForX0Profile(profile string) (*compactFullBenchmarkContext, func(), error) {
	tmpDir, err := os.MkdirTemp("", "spruce-transcript-sweep-x0-*")
	if err != nil {
		return nil, nil, fmt.Errorf("mktemp: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	publicPath := filepath.Join(tmpDir, "credential_public.json")
	artifactDir := filepath.Join(tmpDir, "artifacts")
	statePath := filepath.Join(tmpDir, "credential_state.json")
	signaturePath := filepath.Join(tmpDir, "signature.json")
	if err := runLocalGoCommand(
		"run", "./cmd/issuance",
		"setup-demo-public",
		"-out", publicPath,
		"-force",
		"-x0-profile", profile,
	); err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := runLocalGoCommand(
		"run", "./cmd/issuance",
		"demo-local",
		"-public-params", publicPath,
		"-artifact-dir", artifactDir,
		"-state-out", statePath,
		"-signature-out", signaturePath,
		"-seed", "51",
	); err != nil {
		cleanup()
		return nil, nil, err
	}
	loaded, err := loadShowingBenchmarkContextFromStatePath(statePath)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return loaded, cleanup, nil
}

func runLocalGoCommand(args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Dir = "."
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("go %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}

func transcriptSweepBucketsFromReport(rep PIOP.ProofReport) transcriptSweepPaperBuckets {
	return transcriptSweepPaperBuckets{
		QBytes:            rep.PaperTranscript.Q.OptimizedBytes,
		PdecsBytes:        rep.PaperTranscript.Pdecs.OptimizedBytes,
		RBytes:            rep.PaperTranscript.R.OptimizedBytes,
		SigShortnessBytes: rep.PaperTranscript.SigShortness.OptimizedBytes,
		AuthBytes:         rep.PaperTranscript.Auth.OptimizedBytes,
		VTargetsBytes:     rep.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:      rep.PaperTranscript.BarSets.OptimizedBytes,
	}
}

func transcriptSweepSigShortnessFromReport(rep PIOP.ProofReport) transcriptSweepSigShortness {
	return transcriptSweepSigShortness{
		OpeningBytes:     rep.SigShortness.OpeningBytes,
		HiddenProofBytes: rep.SigShortness.HiddenProofBytes,
		BindingBytes:     rep.SigShortness.BindingBytes,
		SupportSlotCount: rep.SigShortness.SupportSlotCount,
		OpenedBlockCount: rep.SigShortness.OpenedBlockCount,
	}
}

func transcriptSweepGeometryFromReport(rep PIOP.ProofReport) transcriptSweepGeometry {
	return transcriptSweepGeometry{
		DQ:                        rep.DQ,
		LVCSNCols:                 rep.TranscriptFocus.LVCSNCols,
		NLeaves:                   rep.TranscriptFocus.NLeaves,
		PCols:                     rep.TranscriptFocus.PCols,
		RowOpeningEntries:         rep.TranscriptFocus.RowOpeningEntries,
		ReplayBlocks:              rep.TranscriptFocus.ReplayBlocks,
		WitnessRows:               rep.TranscriptFocus.WitnessRows,
		MainLVCSNCols:             rep.TranscriptFocus.MainLVCSNCols,
		MainNLeaves:               rep.TranscriptFocus.MainNLeaves,
		PRFLVCSNCols:              rep.TranscriptFocus.PRFLVCSNCols,
		PRFNLeaves:                rep.TranscriptFocus.PRFNLeaves,
		HiddenShortnessLVCSNCols:  rep.TranscriptFocus.HiddenShortnessLVCSNCols,
		HiddenShortnessNLeaves:    rep.TranscriptFocus.HiddenShortnessNLeaves,
		CarrierSelectedRows:       rep.TranscriptFocus.CarrierSelectedRows,
		PRFCompanionSelectedRows:  rep.TranscriptFocus.PRFCompanionSelectedRows,
		SourceProductSelectedRows: rep.TranscriptFocus.SourceProductSelectedRows,
		ReplayMHatSigmaRows:       rep.TranscriptFocus.ReplayMHatSigmaRows,
		ReplayRHat0Rows:           rep.TranscriptFocus.ReplayRHat0Rows,
		ReplayR0B2HatRows:         rep.TranscriptFocus.ReplayR0B2HatRows,
		ReplayTargetMR0HatRows:    rep.TranscriptFocus.ReplayTargetMR0HatRows,
		ReplayRHat1Rows:           rep.TranscriptFocus.ReplayRHat1Rows,
		ReplayZHatRows:            rep.TranscriptFocus.ReplayZHatRows,
		ReplayTHatRows:            rep.TranscriptFocus.ReplayTHatRows,
		V11PackedGroupSize:        rep.TranscriptFocus.V11PackedSigChainGroupSize,
		V11PackedBlockWidth:       rep.TranscriptFocus.V11PackedSigBlockWidth,
		V11EffectiveSigBlocks:     rep.TranscriptFocus.V11EffectiveSigBlocks,
		V11ShortnessRows:          rep.TranscriptFocus.V11ShortnessRows,
		MaskRows:                  rep.TranscriptFocus.MaskRows,
	}
}

func transcriptSweepSoundnessFromReport(rep PIOP.ProofReport) transcriptSweepSoundness {
	return transcriptSweepSoundness{
		Eq8TotalBits:  rep.Soundness.Eq8TotalBits,
		Thm9TotalBits: rep.Soundness.TotalBits,
		Eps1Bits:      rep.Soundness.Bits[0],
		Eps2Bits:      rep.Soundness.Bits[1],
		Eps3Bits:      rep.Soundness.Bits[2],
		Eps4Bits:      rep.Soundness.Bits[3],
	}
}

func buildTranscriptSweepOpts(cfg transcriptSweepCandidateConfig) PIOP.SimOpts {
	groupRounds := cfg.PRFGroupRounds
	if groupRounds <= 0 {
		groupRounds = 2
	}
	opts := PIOP.SimOpts{
		Credential:              true,
		NCols:                   16,
		Ell:                     18,
		Theta:                   cfg.Theta,
		Rho:                     cfg.Rho,
		EllPrime:                cfg.EllPrime,
		Eta:                     cfg.Eta,
		DomainMode:              PIOP.DomainModeExplicit,
		NLeaves:                 cfg.NLeaves,
		Kappa:                   cfg.Kappa,
		PRFGroupRounds:          groupRounds,
		CoeffPacking:            true,
		CoeffNativeSigModel:     PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:           cfg.BasePreset,
		ShowingReplayMode:       cfg.ReplayMode,
		CompactFullCandidate:    cfg.CompactFullCandidate,
		BenchmarkSweepCandidate: cfg.BenchmarkCandidate,
		SigShortnessProfile:     cfg.SigShortnessProfile,
		LVCSNCols:               cfg.LVCSNCols,
		PostSignLVCSNCols:       cfg.LVCSNCols,
		PRFLVCSNCols:            cfg.LVCSNCols,
		PostSignNLeaves:         cfg.NLeaves,
		PRFNLeaves:              cfg.NLeaves,
		PRFCompanionMode:        cfg.PRFMode,
		PRFCheckpointSamples:    cfg.PRFSamples,
		AggregateR0Replay:       cfg.AggregateR0Replay,
	}
	return PIOP.ResolveSimOptsDefaults(opts)
}

func executeTranscriptSweepRun(ctx *compactFullBenchmarkContext, cfg transcriptSweepCandidateConfig, run int) transcriptSweepRunReport {
	opts := buildTranscriptSweepOpts(cfg)
	out := transcriptSweepRunReport{
		Run:                  run,
		Track:                cfg.Track,
		Kind:                 cfg.Kind,
		CandidateID:          cfg.ID,
		BasePreset:           cfg.BasePreset,
		ReplayMode:           string(cfg.ReplayMode),
		PRFMode:              string(cfg.PRFMode),
		PRFCheckpointSamples: cfg.PRFSamples,
		PRFGroupRounds:       opts.PRFGroupRounds,
		AggregateR0Replay:    cfg.AggregateR0Replay,
		X0Profile:            cfg.X0Profile,
	}
	omega, err := deriveOmegaForOpts(ctx.ringQ, opts, ctx.publicParams.HashRelation)
	if err != nil {
		out.RejectReason = fmt.Sprintf("derive omega: %v", err)
		return out
	}
	nonce, noncePublic := sampleNonce(ctx.prfParams.LenNonce, len(omega), ctx.ringQ.Modulus[0])
	key, err := prfKeyFromWitnessOnOmega(ctx.ringQ, ctx.wit, omega, ctx.prfParams.LenKey)
	if err != nil {
		out.RejectReason = fmt.Sprintf("prf key: %v", err)
		return out
	}
	tag, err := prf.Tag(key, nonce, ctx.prfParams)
	if err != nil {
		out.RejectReason = fmt.Sprintf("prf tag: %v", err)
		return out
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
	proof, buildErr := PIOP.BuildShowingCombined(pub, ctx.wit, opts)
	proveDur := time.Since(proveStart)
	out.ProveMS = float64(proveDur.Microseconds()) / 1000.0
	if buildErr != nil {
		out.RejectReason = fmt.Sprintf("build showing: %v", buildErr)
		return out
	}
	rep, repErr := PIOP.BuildProofReport(proof, opts, ctx.ringQ)
	if repErr == nil {
		out.BasePreset = rep.TranscriptFocus.ShowingPreset
		out.ReplayMode = rep.TranscriptFocus.ReplayMode
		out.ShortnessMode = rep.TranscriptFocus.ShortnessMode
		out.ShortnessProfile = rep.TranscriptFocus.SigShortnessProfile
		out.PRFMode = rep.TranscriptFocus.PRFMode
		out.PRFCheckpointSamples = rep.TranscriptFocus.PRFAuditSamples
		out.PRFGroupRounds = opts.PRFGroupRounds
		out.PaperTranscriptBytes = rep.PaperTranscript.OptimizedBytes
		out.ProofBytes = rep.ProofBytes
		out.PaperBuckets = transcriptSweepBucketsFromReport(rep)
		out.SigShortness = transcriptSweepSigShortnessFromReport(rep)
		out.Geometry = transcriptSweepGeometryFromReport(rep)
		out.Soundness = transcriptSweepSoundnessFromReport(rep)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	verifyStart := time.Now()
	ok, verifyErr := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	verifyDur := time.Since(verifyStart)
	out.VerifyMS = float64(verifyDur.Microseconds()) / 1000.0
	out.Verified = verifyErr == nil && ok
	if repErr != nil && out.RejectReason == "" {
		out.RejectReason = fmt.Sprintf("build proof report: %v", repErr)
	}
	if verifyErr != nil && out.RejectReason == "" {
		out.RejectReason = fmt.Sprintf("verify showing: %v", verifyErr)
	}
	if verifyErr == nil && !ok && out.RejectReason == "" {
		out.RejectReason = "verify showing returned ok=false"
	}
	if out.RejectReason == "" && cfg.Promotable && out.Soundness.Thm9TotalBits < transcriptSweepTheoremFloorBits {
		out.RejectReason = fmt.Sprintf("theorem total bits %.2f below floor %.2f", out.Soundness.Thm9TotalBits, transcriptSweepTheoremFloorBits)
	}
	return out
}

func aggregateTranscriptSweepEntry(cfg transcriptSweepCandidateConfig, runs []transcriptSweepRunReport) transcriptSweepEntry {
	entry := transcriptSweepEntry{
		Track:                cfg.Track,
		Kind:                 cfg.Kind,
		CandidateID:          cfg.ID,
		BasePreset:           cfg.BasePreset,
		ReplayMode:           string(cfg.ReplayMode),
		PRFMode:              string(cfg.PRFMode),
		PRFCheckpointSamples: cfg.PRFSamples,
		PRFGroupRounds:       cfg.PRFGroupRounds,
		AggregateR0Replay:    cfg.AggregateR0Replay,
		X0Profile:            cfg.X0Profile,
		Promotable:           cfg.Promotable,
		RunReports:           append([]transcriptSweepRunReport(nil), runs...),
		Verified:             true,
	}
	if len(runs) == 0 {
		entry.Verified = false
		entry.RejectReason = "no benchmark runs"
		return entry
	}
	var (
		sumTranscript int
		sumProof      int
		sumProveMS    float64
		sumVerifyMS   float64
	)
	for _, run := range runs {
		if !run.Verified {
			entry.Verified = false
			if entry.RejectReason == "" {
				entry.RejectReason = run.RejectReason
			}
		}
		sumTranscript += run.PaperTranscriptBytes
		sumProof += run.ProofBytes
		sumProveMS += run.ProveMS
		sumVerifyMS += run.VerifyMS
	}
	denom := float64(len(runs))
	entry.PaperTranscriptBytes = int(math.Round(float64(sumTranscript) / denom))
	entry.ProofBytes = int(math.Round(float64(sumProof) / denom))
	entry.AvgProveMS = sumProveMS / denom
	entry.AvgVerifyMS = sumVerifyMS / denom
	last := runs[len(runs)-1]
	entry.BasePreset = last.BasePreset
	entry.ReplayMode = last.ReplayMode
	entry.ShortnessMode = last.ShortnessMode
	entry.ShortnessProfile = last.ShortnessProfile
	entry.PRFMode = last.PRFMode
	entry.PRFCheckpointSamples = last.PRFCheckpointSamples
	entry.PRFGroupRounds = last.PRFGroupRounds
	entry.AggregateR0Replay = last.AggregateR0Replay
	entry.X0Profile = last.X0Profile
	entry.PaperBuckets = last.PaperBuckets
	entry.SigShortness = last.SigShortness
	entry.Geometry = last.Geometry
	entry.Soundness = last.Soundness
	if !entry.Verified && entry.RejectReason == "" {
		entry.RejectReason = "candidate rejected"
	}
	return entry
}

func transcriptSweepEntryLess(a, b transcriptSweepEntry) bool {
	if a.PaperTranscriptBytes != b.PaperTranscriptBytes {
		return a.PaperTranscriptBytes < b.PaperTranscriptBytes
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

func runTranscriptSweepConfigs(ctx *transcriptSweepContext, configs []transcriptSweepCandidateConfig, runs int) ([]transcriptSweepEntry, map[string]transcriptSweepEntry, error) {
	entries := make([]transcriptSweepEntry, 0, len(configs))
	index := make(map[string]transcriptSweepEntry, len(configs))
	for _, cfg := range configs {
		benchCtx, err := ctx.benchmarkContextForX0Profile(cfg.X0Profile)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", cfg.ID, err)
		}
		runReports := make([]transcriptSweepRunReport, 0, runs)
		for run := 1; run <= runs; run++ {
			runReports = append(runReports, executeTranscriptSweepRun(benchCtx, cfg, run))
		}
		entry := aggregateTranscriptSweepEntry(cfg, runReports)
		entries = append(entries, entry)
		index[cfg.ID] = entry
		log.Printf("[showing-cli] benchmark-transcript-sweep track=%s kind=%s id=%s preset=%s replay=%s shortness=%s profile=%s aggregate_r0=%v x0=%s verified=%v transcript=%d proof=%d theorem=%.2f prove=%s verify=%s reject=%s",
			entry.Track,
			entry.Kind,
			entry.CandidateID,
			entry.BasePreset,
			entry.ReplayMode,
			entry.ShortnessMode,
			entry.ShortnessProfile,
			entry.AggregateR0Replay,
			entry.X0Profile,
			entry.Verified,
			entry.PaperTranscriptBytes,
			entry.ProofBytes,
			entry.Soundness.Thm9TotalBits,
			msString(entry.AvgProveMS),
			msString(entry.AvgVerifyMS),
			entry.RejectReason,
		)
	}
	return entries, index, nil
}

func eligibleTranscriptSweepEntry(entry transcriptSweepEntry, requireV7 bool) bool {
	_ = requireV7
	if !entry.Promotable || !entry.Verified {
		return false
	}
	if entry.Soundness.Thm9TotalBits < transcriptSweepTheoremFloorBits {
		return false
	}
	return true
}

func verifiedTranscriptSweepEntry(entry transcriptSweepEntry, requireV7 bool) bool {
	_ = requireV7
	if !entry.Verified {
		return false
	}
	return true
}

func topTranscriptSweepConfigs(configs []transcriptSweepCandidateConfig, entryByID map[string]transcriptSweepEntry, topN int, requireFloor bool, requireV7 bool) []transcriptSweepCandidateConfig {
	type ranked struct {
		cfg   transcriptSweepCandidateConfig
		entry transcriptSweepEntry
	}
	rankedEntries := make([]ranked, 0, len(configs))
	for _, cfg := range configs {
		entry, ok := entryByID[cfg.ID]
		if !ok {
			continue
		}
		if !verifiedTranscriptSweepEntry(entry, requireV7) {
			continue
		}
		if requireFloor && entry.Soundness.Thm9TotalBits < transcriptSweepTheoremFloorBits {
			continue
		}
		rankedEntries = append(rankedEntries, ranked{cfg: cfg, entry: entry})
	}
	sort.Slice(rankedEntries, func(i, j int) bool {
		return transcriptSweepEntryLess(rankedEntries[i].entry, rankedEntries[j].entry)
	})
	if topN > 0 && len(rankedEntries) > topN {
		rankedEntries = rankedEntries[:topN]
	}
	out := make([]transcriptSweepCandidateConfig, len(rankedEntries))
	for i := range rankedEntries {
		out[i] = rankedEntries[i].cfg
	}
	return out
}

func baselineTranscriptSweepEntry(entries []transcriptSweepEntry, baselineID string) (transcriptSweepEntry, bool) {
	for _, entry := range entries {
		if entry.CandidateID == baselineID {
			return entry, true
		}
	}
	return transcriptSweepEntry{}, false
}

func summarizeTranscriptSweepTrack(track string, entries []transcriptSweepEntry, baselineID string, requireV7 bool) transcriptSweepTrackSummary {
	summary := transcriptSweepTrackSummary{
		Track:               track,
		BaselineCandidateID: baselineID,
	}
	for _, entry := range entries {
		if entry.RejectReason != "" {
			summary.RejectedCount++
		}
		if eligibleTranscriptSweepEntry(entry, requireV7) {
			summary.EligibleCount++
			if summary.WinnerCandidateID == "" || transcriptSweepEntryLess(entry, baselineTranscriptSweepWinner(entries, summary.WinnerCandidateID)) {
				summary.WinnerCandidateID = entry.CandidateID
				summary.WinnerTranscriptBytes = entry.PaperTranscriptBytes
			}
		}
	}
	if baseline, ok := baselineTranscriptSweepEntry(entries, baselineID); ok {
		summary.BaselineTranscriptB = baseline.PaperTranscriptBytes
	}
	if summary.WinnerCandidateID != "" && summary.BaselineTranscriptB > 0 && summary.WinnerCandidateID != baselineID && summary.WinnerTranscriptBytes < summary.BaselineTranscriptB {
		summary.Promote = true
	}
	return summary
}

func baselineTranscriptSweepWinner(entries []transcriptSweepEntry, id string) transcriptSweepEntry {
	for _, entry := range entries {
		if entry.CandidateID == id {
			return entry
		}
	}
	return transcriptSweepEntry{}
}

func makeSweepCandidateID(prefix string, lvcsNCols, nLeaves, eta, ellPrime int, sigShortnessProfile string, theta, rho int, kappa [4]int) string {
	id := fmt.Sprintf("%s_w%d_n%d_e%d_ep%d_sig_%s", prefix, lvcsNCols, nLeaves, eta, ellPrime, PIOP.ResolveSignatureShortnessProfileLabelForOpts(PIOP.SimOpts{SigShortnessProfile: sigShortnessProfile}))
	if theta > 0 || rho > 0 || kappa != [4]int{} {
		id += fmt.Sprintf("_th%d_r%d_k%d-%d-%d-%d", theta, rho, kappa[0], kappa[1], kappa[2], kappa[3])
	}
	return id
}

func generateReducedWaveA1Configs() []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, lvcs := range []int{84, 89, 96, 104} {
		for _, nLeaves := range []int{2048, 4096, 8192} {
			for _, eta := range []int{40, 43, 46} {
				cfg := transcriptSweepCandidateConfig{
					Track:               transcriptSweepTrackReduced,
					Kind:                transcriptSweepKindCandidate,
					ID:                  makeSweepCandidateID("a1", lvcs, nLeaves, eta, 2, PIOP.SigShortnessProfileR11L4Production, 3, 2, [4]int{0, 0, 0, 5}),
					BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
					ReplayMode:          PIOP.ShowingReplayModeReduced,
					SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
					LVCSNCols:           lvcs,
					NLeaves:             nLeaves,
					Eta:                 eta,
					EllPrime:            2,
					Theta:               3,
					Rho:                 2,
					Kappa:               [4]int{0, 0, 0, 5},
					BenchmarkCandidate:  makeSweepCandidateID("a1", lvcs, nLeaves, eta, 2, PIOP.SigShortnessProfileR11L4Production, 3, 2, [4]int{0, 0, 0, 5}),
					PRFMode:             PIOP.PRFCompanionModeOutputAudit,
					PRFSamples:          8,
					X0Profile:           "lhl_default",
					Promotable:          true,
				}
				out = append(out, cfg)
			}
		}
	}
	return out
}

func expandReducedWaveA2Configs(base []transcriptSweepCandidateConfig) []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, cfg := range base {
		for _, ellPrime := range []int{1, 2, 3} {
			for _, profile := range []string{PIOP.SigShortnessProfileR11L4Production, PIOP.SigShortnessProfileR24L3Compact, PIOP.SigShortnessProfileR111L2Compact} {
				next := cfg
				next.ID = makeSweepCandidateID("a2", cfg.LVCSNCols, cfg.NLeaves, cfg.Eta, ellPrime, profile, cfg.Theta, cfg.Rho, cfg.Kappa)
				next.BenchmarkCandidate = next.ID
				next.SigShortnessProfile = profile
				next.EllPrime = ellPrime
				out = append(out, next)
			}
		}
	}
	return dedupeTranscriptSweepConfigs(out)
}

func expandReducedWaveA3Configs(base []transcriptSweepCandidateConfig) []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, cfg := range base {
		for _, theta := range []int{2, 3, 4} {
			for _, rho := range []int{1, 2, 3} {
				for _, kappa := range [][4]int{{0, 0, 0, 5}, {0, 0, 0, 6}, {0, 0, 1, 5}} {
					next := cfg
					next.ID = makeSweepCandidateID("a3", cfg.LVCSNCols, cfg.NLeaves, cfg.Eta, cfg.EllPrime, cfg.SigShortnessProfile, theta, rho, kappa)
					next.BenchmarkCandidate = next.ID
					next.Theta = theta
					next.Rho = rho
					next.Kappa = kappa
					out = append(out, next)
				}
			}
		}
	}
	return dedupeTranscriptSweepConfigs(out)
}

func generateFullV6WaveB1Configs() []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, lvcs := range []int{89, 96, 104} {
		for _, nLeaves := range []int{2048, 4096, 8192} {
			for _, eta := range []int{40, 43, 46} {
				id := makeSweepCandidateID("b1", lvcs, nLeaves, eta, 2, PIOP.SigShortnessProfileR11L4Production, 3, 2, [4]int{0, 0, 0, 5})
				out = append(out, transcriptSweepCandidateConfig{
					Track:               transcriptSweepTrackFullV6,
					Kind:                transcriptSweepKindCandidate,
					ID:                  id,
					BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
					ReplayMode:          PIOP.ShowingReplayModeFull,
					SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
					LVCSNCols:           lvcs,
					NLeaves:             nLeaves,
					Eta:                 eta,
					EllPrime:            2,
					Theta:               3,
					Rho:                 2,
					Kappa:               [4]int{0, 0, 0, 5},
					BenchmarkCandidate:  id,
					PRFMode:             PIOP.PRFCompanionModeOutputAudit,
					PRFSamples:          8,
					X0Profile:           "lhl_default",
					Promotable:          true,
				})
			}
		}
	}
	return out
}

func expandFullV6WaveB2Configs(base []transcriptSweepCandidateConfig) []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, cfg := range base {
		for _, ellPrime := range []int{1, 2, 3} {
			for _, profile := range []string{PIOP.SigShortnessProfileR11L4Production, PIOP.SigShortnessProfileR24L3Compact, PIOP.SigShortnessProfileR111L2Compact} {
				next := cfg
				next.ID = makeSweepCandidateID("b2", cfg.LVCSNCols, cfg.NLeaves, cfg.Eta, ellPrime, profile, cfg.Theta, cfg.Rho, cfg.Kappa)
				next.BenchmarkCandidate = next.ID
				next.EllPrime = ellPrime
				next.SigShortnessProfile = profile
				out = append(out, next)
			}
		}
	}
	return dedupeTranscriptSweepConfigs(out)
}

func expandFullV6WaveB3Configs(base []transcriptSweepCandidateConfig) []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, cfg := range base {
		for _, theta := range []int{2, 3, 4} {
			for _, rho := range []int{1, 2, 3} {
				for _, kappa := range [][4]int{{0, 0, 0, 5}, {0, 0, 0, 6}, {0, 0, 1, 5}} {
					next := cfg
					next.ID = makeSweepCandidateID("b3", cfg.LVCSNCols, cfg.NLeaves, cfg.Eta, cfg.EllPrime, cfg.SigShortnessProfile, theta, rho, kappa)
					next.BenchmarkCandidate = next.ID
					next.Theta = theta
					next.Rho = rho
					next.Kappa = kappa
					out = append(out, next)
				}
			}
		}
	}
	return dedupeTranscriptSweepConfigs(out)
}

func generateFullV6AggregateWaveB4Configs() []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, lvcs := range []int{60, 64, 68, 72, 76, 80, 84, 88, 96} {
		for eta := 32; eta <= 42; eta++ {
			for _, kappa := range [][4]int{{0, 0, 0, 5}, {1, 0, 0, 5}, {2, 0, 0, 5}} {
				id := makeSweepCandidateID("b4agg", lvcs, 4096, eta, 2, PIOP.SigShortnessProfileR24L3Compact, 3, 2, kappa)
				out = append(out, transcriptSweepCandidateConfig{
					Track:               transcriptSweepTrackFullV6,
					Kind:                transcriptSweepKindCandidate,
					ID:                  id,
					BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
					ReplayMode:          PIOP.ShowingReplayModeFull,
					SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
					LVCSNCols:           lvcs,
					NLeaves:             4096,
					Eta:                 eta,
					EllPrime:            2,
					Theta:               3,
					Rho:                 2,
					Kappa:               kappa,
					BenchmarkCandidate:  id,
					PRFMode:             PIOP.PRFCompanionModeOutputAudit,
					PRFSamples:          8,
					AggregateR0Replay:   true,
					X0Profile:           "lhl_default",
					Promotable:          true,
				})
			}
		}
	}
	return dedupeTranscriptSweepConfigs(out)
}

func generateFullV11RetuneConfigs() []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, lvcs := range []int{56, 60, 64, 68, 72, 76, 80} {
		for eta := 32; eta <= 40; eta++ {
			for _, ellPrime := range []int{2, 3} {
				for _, kappa := range [][4]int{{1, 0, 0, 5}, {2, 0, 0, 5}} {
					id := makeSweepCandidateID("v11retune", lvcs, 4096, eta, ellPrime, PIOP.SigShortnessProfileR24L3Compact, 3, 2, kappa)
					out = append(out, transcriptSweepCandidateConfig{
						Track:               transcriptSweepTrackFullV6,
						Kind:                transcriptSweepKindCandidate,
						ID:                  id,
						BasePreset:          PIOP.ShowingPresetAggregateV11DirectTargetResearch,
						ReplayMode:          PIOP.ShowingReplayModeFull,
						SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
						LVCSNCols:           lvcs,
						NLeaves:             4096,
						Eta:                 eta,
						EllPrime:            ellPrime,
						Theta:               3,
						Rho:                 2,
						Kappa:               kappa,
						BenchmarkCandidate:  id,
						PRFMode:             PIOP.PRFCompanionModeOutputAudit,
						PRFSamples:          8,
						AggregateR0Replay:   true,
						X0Profile:           "lhl_default",
						Promotable:          true,
					})
				}
			}
		}
	}
	return dedupeTranscriptSweepConfigs(out)
}

func dedupeTranscriptSweepConfigs(configs []transcriptSweepCandidateConfig) []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0, len(configs))
	seen := make(map[string]struct{}, len(configs))
	for _, cfg := range configs {
		if _, ok := seen[cfg.ID]; ok {
			continue
		}
		seen[cfg.ID] = struct{}{}
		out = append(out, cfg)
	}
	return out
}

func runReducedTranscriptSweepTrack(ctx *transcriptSweepContext, runs int, controlsOnly bool) ([]transcriptSweepEntry, transcriptSweepTrackSummary, error) {
	controlConfigs := []transcriptSweepCandidateConfig{
		{
			Track:               transcriptSweepTrackReduced,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepBaselineReducedID,
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeReduced,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
			LVCSNCols:           84,
			NLeaves:             4096,
			Eta:                 40,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackReduced,
			Kind:                transcriptSweepKindControl,
			ID:                  "reduced_direct_auth_control",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeReduced,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
			LVCSNCols:           84,
			NLeaves:             4096,
			Eta:                 40,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			PRFMode:             PIOP.PRFCompanionModeDirectAuth,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackReduced,
			Kind:                transcriptSweepKindControl,
			ID:                  "reduced_aux_instance_control",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeReduced,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
			LVCSNCols:           84,
			NLeaves:             4096,
			Eta:                 40,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			PRFMode:             PIOP.PRFCompanionModeAuxInstance,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
		},
	}
	allEntries := make([]transcriptSweepEntry, 0)
	if !controlsOnly {
		a1 := generateReducedWaveA1Configs()
		a1Entries, a1Map, err := runTranscriptSweepConfigs(ctx, a1, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, a1Entries...)
		a2 := expandReducedWaveA2Configs(topTranscriptSweepConfigs(a1, a1Map, 8, false, false))
		a2Entries, a2Map, err := runTranscriptSweepConfigs(ctx, a2, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, a2Entries...)
		a3 := expandReducedWaveA3Configs(topTranscriptSweepConfigs(a2, a2Map, 4, false, false))
		a3Entries, _, err := runTranscriptSweepConfigs(ctx, a3, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, a3Entries...)
	}
	if !controlsOnly {
		controlConfigs = controlConfigs[1:]
	}
	controlEntries, _, err := runTranscriptSweepConfigs(ctx, controlConfigs, runs)
	if err != nil {
		return nil, transcriptSweepTrackSummary{}, err
	}
	allEntries = append(allEntries, controlEntries...)
	summary := summarizeTranscriptSweepTrack(transcriptSweepTrackReduced, allEntries, transcriptSweepBaselineReducedID, false)
	return allEntries, summary, nil
}

func runFullV6TranscriptSweepTrack(ctx *transcriptSweepContext, runs int, controlsOnly bool) ([]transcriptSweepEntry, transcriptSweepTrackSummary, error) {
	allEntries := make([]transcriptSweepEntry, 0)
	controlConfigs := []transcriptSweepCandidateConfig{
		{
			Track:               transcriptSweepTrackFullV6,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepBaselineFullID,
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           96,
			NLeaves:             4096,
			Eta:                 43,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  transcriptSweepBaselineFullID,
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackFullV6,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepBaselineFull96ID,
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           96,
			NLeaves:             4096,
			Eta:                 43,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  transcriptSweepBaselineFull96ID,
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackFullV6,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepBaselineFullAggR0ID,
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           96,
			NLeaves:             4096,
			Eta:                 43,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  transcriptSweepBaselineFullAggR0ID,
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			AggregateR0Replay:   true,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackFullV6,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepFullAggR0W64ID,
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           64,
			NLeaves:             4096,
			Eta:                 34,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{1, 0, 0, 5},
			BenchmarkCandidate:  transcriptSweepFullAggR0W64ID,
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			AggregateR0Replay:   true,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackFullV6,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepFullAggR0W76ID,
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           76,
			NLeaves:             4096,
			Eta:                 38,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{2, 0, 0, 5},
			BenchmarkCandidate:  transcriptSweepFullAggR0W76ID,
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			AggregateR0Replay:   true,
			X0Profile:           "lhl_default",
		},
		{
			Track:               transcriptSweepTrackFullV6,
			Kind:                transcriptSweepKindControl,
			ID:                  transcriptSweepFullAggR0V11R24ID,
			BasePreset:          PIOP.ShowingPresetAggregateV11DirectTargetResearch,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           76,
			NLeaves:             4096,
			Eta:                 38,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{2, 0, 0, 5},
			BenchmarkCandidate:  transcriptSweepFullAggR0V11R24ID,
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			AggregateR0Replay:   true,
			X0Profile:           "lhl_default",
		},
	}
	if !controlsOnly {
		b1 := generateFullV6WaveB1Configs()
		b1Entries, b1Map, err := runTranscriptSweepConfigs(ctx, b1, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, b1Entries...)
		b2 := expandFullV6WaveB2Configs(topTranscriptSweepConfigs(b1, b1Map, 6, false, false))
		b2Entries, b2Map, err := runTranscriptSweepConfigs(ctx, b2, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, b2Entries...)
		b3 := expandFullV6WaveB3Configs(topTranscriptSweepConfigs(b2, b2Map, 3, false, false))
		b3Entries, _, err := runTranscriptSweepConfigs(ctx, b3, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, b3Entries...)
		b4 := generateFullV6AggregateWaveB4Configs()
		b4Entries, _, err := runTranscriptSweepConfigs(ctx, b4, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, b4Entries...)
		v11Retune := generateFullV11RetuneConfigs()
		v11Entries, _, err := runTranscriptSweepConfigs(ctx, v11Retune, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, v11Entries...)
	}
	if controlsOnly {
		controlEntries, _, err := runTranscriptSweepConfigs(ctx, controlConfigs, runs)
		if err != nil {
			return nil, transcriptSweepTrackSummary{}, err
		}
		allEntries = append(allEntries, controlEntries...)
	}
	summary := summarizeTranscriptSweepTrack(transcriptSweepTrackFullV6, allEntries, transcriptSweepBaselineFullID, false)
	return allEntries, summary, nil
}

func runX0ControlsTranscriptSweepTrack(ctx *transcriptSweepContext, runs int) ([]transcriptSweepEntry, transcriptSweepTrackSummary, error) {
	configs := []transcriptSweepCandidateConfig{
		{
			Track:               transcriptSweepTrackX0Controls,
			Kind:                transcriptSweepKindX0Control,
			ID:                  "x0_legacy_scalar_reduced",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeReduced,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
			LVCSNCols:           84,
			NLeaves:             4096,
			Eta:                 40,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  "x0_legacy_scalar_reduced",
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "legacy_scalar",
			Promotable:          false,
		},
		{
			Track:               transcriptSweepTrackX0Controls,
			Kind:                transcriptSweepKindX0Control,
			ID:                  "x0_lhl_default_reduced",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeReduced,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
			LVCSNCols:           84,
			NLeaves:             4096,
			Eta:                 40,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  "x0_lhl_default_reduced",
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
			Promotable:          true,
		},
		{
			Track:               transcriptSweepTrackX0Controls,
			Kind:                transcriptSweepKindX0Control,
			ID:                  "x0_lhl_alt_reduced",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeReduced,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
			LVCSNCols:           84,
			NLeaves:             4096,
			Eta:                 40,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  "x0_lhl_alt_reduced",
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_alt",
			Promotable:          true,
		},
		{
			Track:               transcriptSweepTrackX0Controls,
			Kind:                transcriptSweepKindX0Control,
			ID:                  "x0_legacy_scalar_full96",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           96,
			NLeaves:             4096,
			Eta:                 43,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  "x0_legacy_scalar_full96",
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "legacy_scalar",
			Promotable:          false,
		},
		{
			Track:               transcriptSweepTrackX0Controls,
			Kind:                transcriptSweepKindX0Control,
			ID:                  "x0_lhl_default_full96",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           96,
			NLeaves:             4096,
			Eta:                 43,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  "x0_lhl_default_full96",
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_default",
			Promotable:          true,
		},
		{
			Track:               transcriptSweepTrackX0Controls,
			Kind:                transcriptSweepKindX0Control,
			ID:                  "x0_lhl_alt_full96",
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          PIOP.ShowingReplayModeFull,
			SigShortnessProfile: PIOP.SigShortnessProfileR24L3Compact,
			LVCSNCols:           96,
			NLeaves:             4096,
			Eta:                 43,
			EllPrime:            2,
			Theta:               3,
			Rho:                 2,
			Kappa:               [4]int{0, 0, 0, 5},
			BenchmarkCandidate:  "x0_lhl_alt_full96",
			PRFMode:             PIOP.PRFCompanionModeOutputAudit,
			PRFSamples:          8,
			X0Profile:           "lhl_alt",
			Promotable:          true,
		},
	}
	entries, _, err := runTranscriptSweepConfigs(ctx, configs, runs)
	if err != nil {
		return nil, transcriptSweepTrackSummary{}, err
	}
	summary := summarizeTranscriptSweepTrack(transcriptSweepTrackX0Controls, entries, "x0_lhl_default_full96", false)
	summary.Promote = false
	return entries, summary, nil
}

func makePRFControlSweepID(prefix string, mode PIOP.PRFCompanionMode, groupRounds, samples int) string {
	if mode == PIOP.PRFCompanionModeAuxInstance {
		return fmt.Sprintf("%s_%s_g%d", prefix, mode, groupRounds)
	}
	return fmt.Sprintf("%s_%s_g%d_s%d", prefix, mode, groupRounds, samples)
}

func generatePRFControlConfigs(track, idPrefix string, replayMode PIOP.ShowingReplayMode, lvcs, nLeaves, eta, ellPrime, theta, rho int, kappa [4]int, sigShortnessProfile string) []transcriptSweepCandidateConfig {
	out := make([]transcriptSweepCandidateConfig, 0)
	for _, groupRounds := range []int{2} {
		for _, samples := range []int{4, 8, 12} {
			for _, mode := range []PIOP.PRFCompanionMode{
				PIOP.PRFCompanionModeOutputAudit,
				PIOP.PRFCompanionModeDirectAuth,
			} {
				out = append(out, transcriptSweepCandidateConfig{
					Track:               track,
					Kind:                transcriptSweepKindControl,
					ID:                  makePRFControlSweepID(idPrefix, mode, groupRounds, samples),
					BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
					ReplayMode:          replayMode,
					SigShortnessProfile: sigShortnessProfile,
					LVCSNCols:           lvcs,
					NLeaves:             nLeaves,
					Eta:                 eta,
					EllPrime:            ellPrime,
					Theta:               theta,
					Rho:                 rho,
					Kappa:               kappa,
					PRFMode:             mode,
					PRFSamples:          samples,
					PRFGroupRounds:      groupRounds,
					X0Profile:           "lhl_default",
					Promotable:          true,
				})
			}
		}
		out = append(out, transcriptSweepCandidateConfig{
			Track:               track,
			Kind:                transcriptSweepKindControl,
			ID:                  makePRFControlSweepID(idPrefix, PIOP.PRFCompanionModeAuxInstance, groupRounds, 8),
			BasePreset:          PIOP.ShowingPresetSoundnessBalanced,
			ReplayMode:          replayMode,
			SigShortnessProfile: sigShortnessProfile,
			LVCSNCols:           lvcs,
			NLeaves:             nLeaves,
			Eta:                 eta,
			EllPrime:            ellPrime,
			Theta:               theta,
			Rho:                 rho,
			Kappa:               kappa,
			PRFMode:             PIOP.PRFCompanionModeAuxInstance,
			PRFSamples:          8,
			PRFGroupRounds:      groupRounds,
			X0Profile:           "lhl_default",
			Promotable:          true,
		})
	}
	return out
}

func runPRFControlsReducedTranscriptSweepTrack(ctx *transcriptSweepContext, runs int) ([]transcriptSweepEntry, transcriptSweepTrackSummary, error) {
	configs := generatePRFControlConfigs(
		transcriptSweepTrackPRFReduced,
		"prf_reduced",
		PIOP.ShowingReplayModeReduced,
		84, 4096, 40, 2, 3, 2,
		[4]int{0, 0, 0, 5},
		PIOP.SigShortnessProfileR11L4Production,
	)
	entries, _, err := runTranscriptSweepConfigs(ctx, configs, runs)
	if err != nil {
		return nil, transcriptSweepTrackSummary{}, err
	}
	summary := summarizeTranscriptSweepTrack(transcriptSweepTrackPRFReduced, entries, transcriptSweepBaselinePRFReducedID, false)
	summary.Promote = false
	return entries, summary, nil
}

func runPRFControlsFull96TranscriptSweepTrack(ctx *transcriptSweepContext, runs int) ([]transcriptSweepEntry, transcriptSweepTrackSummary, error) {
	configs := generatePRFControlConfigs(
		transcriptSweepTrackPRFFull96,
		"prf_full96",
		PIOP.ShowingReplayModeFull,
		96, 4096, 43, 2, 3, 2,
		[4]int{0, 0, 0, 5},
		PIOP.SigShortnessProfileR24L3Compact,
	)
	entries, _, err := runTranscriptSweepConfigs(ctx, configs, runs)
	if err != nil {
		return nil, transcriptSweepTrackSummary{}, err
	}
	summary := summarizeTranscriptSweepTrack(transcriptSweepTrackPRFFull96, entries, transcriptSweepBaselinePRFFull96ID, false)
	summary.Promote = false
	return entries, summary, nil
}
