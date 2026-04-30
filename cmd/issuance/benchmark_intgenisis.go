package main

import (
	"fmt"
	"log"
	"math/rand"
	"path/filepath"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const benchmarkIntGenISISVersion = 2

type benchmarkIntGenISISProfile struct {
	Label     string                      `json:"label"`
	Profile   string                      `json:"profile"`
	Inventory PIOP.IntGenISISRowInventory `json:"inventory"`
	Metrics   benchmarkIntGenISISMetrics  `json:"metrics"`
}

type benchmarkIntGenISISMetrics struct {
	ProofSizeBytes                int        `json:"proof_size_bytes"`
	PaperTranscriptBytes          int        `json:"paper_transcript_bytes"`
	PaperTranscriptKB             float64    `json:"paper_transcript_kb"`
	QBytes                        int        `json:"q_bytes"`
	RBytes                        int        `json:"r_bytes"`
	PdecsBytes                    int        `json:"pdecs_bytes"`
	AuthBytes                     int        `json:"auth_bytes"`
	SigShortnessBytes             int        `json:"sig_shortness_bytes"`
	VTargetsBytes                 int        `json:"vtargets_bytes"`
	BarSetsBytes                  int        `json:"barsets_bytes"`
	ProvingMS                     float64    `json:"proving_ms"`
	VerificationMS                float64    `json:"verification_ms"`
	TotalRows                     int        `json:"total_rows"`
	PRFRows                       int        `json:"prf_rows"`
	CoefficientViewRows           int        `json:"coefficient_view_rows"`
	UCoefficientViewRows          int        `json:"u_coefficient_view_rows,omitempty"`
	SemanticViewRows              int        `json:"semantic_view_rows,omitempty"`
	CommitmentViewRows            int        `json:"commitment_view_rows,omitempty"`
	YCoefficientViewRows          int        `json:"y_coefficient_view_rows,omitempty"`
	IssuerViewRows                int        `json:"issuer_view_rows,omitempty"`
	BoundRows                     int        `json:"bound_rows"`
	ShortnessRows                 int        `json:"shortness_rows"`
	ShortnessConstraints          int        `json:"shortness_constraints,omitempty"`
	HatRows                       int        `json:"hat_rows"`
	YHatRows                      int        `json:"y_hat_rows,omitempty"`
	SourceBridgeConstraints       int        `json:"source_bridge_constraints"`
	UBridgeConstraints            int        `json:"u_bridge_constraints,omitempty"`
	CommitmentBridgeConstraints   int        `json:"commitment_bridge_constraints,omitempty"`
	YLinearConstraints            int        `json:"y_linear_constraints,omitempty"`
	ProjectedSignatureConstraints int        `json:"projected_signature_constraints,omitempty"`
	ReplayProjection              string     `json:"replay_projection,omitempty"`
	IssuerBridgeConstraints       int        `json:"issuer_bridge_constraints,omitempty"`
	PRFKeyBridgeConstraints       int        `json:"prf_key_bridge_constraints,omitempty"`
	FparIntConstraints            int        `json:"fpar_int_constraints,omitempty"`
	RangeConstraints              int        `json:"range_constraints,omitempty"`
	ParallelDegree                int        `json:"parallel_degree"`
	AggregatedDegree              int        `json:"aggregated_degree"`
	ParallelAlgDegree             int        `json:"parallel_alg_degree,omitempty"`
	AggregatedAlgDegree           int        `json:"aggregated_alg_degree,omitempty"`
	PaperConservativeDQ           int        `json:"paper_conservative_dq,omitempty"`
	MaskDegreeBound               int        `json:"mask_degree_bound,omitempty"`
	DominantDegreeSource          string     `json:"dominant_degree_source,omitempty"`
	TernaryRows                   int        `json:"ternary_rows,omitempty"`
	CompressedRows                int        `json:"compressed_rows"`
	MSECompressionLevel           int        `json:"mse_compression_level,omitempty"`
	MSECompressionPackWidth       int        `json:"mse_compression_pack_width,omitempty"`
	MSECompressionDegree          int        `json:"mse_compression_degree,omitempty"`
	RoundBits                     [4]float64 `json:"round_bits"`
	RawRoundBits                  [4]float64 `json:"raw_round_bits"`
	TheoremBits                   [4]float64 `json:"theorem_bits"`
	TheoremTotalBits              float64    `json:"theorem_total_bits"`
	CollisionBits                 float64    `json:"collision_bits"`
	Clamped                       [4]bool    `json:"clamped"`
	SoundnessEq8Bits              float64    `json:"soundness_eq8_bits"`
	DQ                            int        `json:"dq"`
	DDECS                         int        `json:"ddecs"`
	WitnessSupportCols            int        `json:"witness_support_cols"`
	CommittedCols                 int        `json:"committed_cols"`
	ProofReportBuckets            int        `json:"proof_report_buckets"`
	Theta                         int        `json:"theta"`
	Rho                           int        `json:"rho"`
	EllPrime                      int        `json:"ell_prime"`
	SmallFieldReplayRows          int        `json:"smallfield_replay_rows,omitempty"`
	MaskRows                      int        `json:"mask_rows,omitempty"`
	QSplitRows                    int        `json:"q_split_rows,omitempty"`
	QLimbRows                     int        `json:"q_limb_rows,omitempty"`
	MeasurementStatus             string     `json:"measurement_status"`
}

type benchmarkIntGenISISReport struct {
	Version   int                          `json:"version"`
	Generated string                       `json:"generated_at"`
	Profiles  []benchmarkIntGenISISProfile `json:"profiles"`
	Notes     []string                     `json:"notes"`
}

type benchmarkIntGenISISMeasuredProfile struct {
	PreSign benchmarkIntGenISISMetrics
	Showing benchmarkIntGenISISMetrics
}

func benchmarkIntGenISIS(profilesCSV string, packingFactor int, jsonOut string) error {
	if packingFactor <= 0 {
		return fmt.Errorf("invalid s-sw=%d", packingFactor)
	}
	parts := strings.Split(profilesCSV, ",")
	report := benchmarkIntGenISISReport{
		Version:   benchmarkIntGenISISVersion,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Notes: []string{
			"benchmark-intgenisis is a row-inventory command; profile-B proof_size_bytes/proving_ms/verification_ms come from the historical in-process proof smoke",
			"use benchmark-intgenisis-e2e -preset n256-sw96 or n256-sw128 for live profile-A issuance/showing measurements",
		},
	}
	var measuredB *benchmarkIntGenISISMeasuredProfile
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		inv, err := PIOP.BuildIntGenISISRowInventory(name, packingFactor)
		if err != nil {
			return err
		}
		presignMetrics := intGenISISInventoryMetrics(inv, "presign")
		showingMetrics := intGenISISInventoryMetrics(inv, "showing")
		if inv.Profile == credential.ProfileIntGenISISB {
			if measuredB == nil {
				measured, merr := measureIntGenISISProfileBProofs(packingFactor)
				if merr != nil {
					return fmt.Errorf("measure profile-B IntGenISIS proofs: %w", merr)
				}
				measuredB = &measured
			}
			presignMetrics = measuredB.PreSign
			showingMetrics = measuredB.Showing
		}
		report.Profiles = append(report.Profiles,
			benchmarkIntGenISISProfile{Label: "intgenisis_mlwe_presign", Profile: inv.Profile, Inventory: inv, Metrics: presignMetrics},
			benchmarkIntGenISISProfile{Label: "intgenisis_mlwe_showing", Profile: inv.Profile, Inventory: inv, Metrics: showingMetrics},
		)
		log.Printf("[issuance-cli] intgenisis profile=%s presign_rows=%d showing_non_prf_rows=%d ring_polys=%d/%d",
			inv.Profile, inv.PreSignRows, inv.ShowingNonPRFRows, inv.PreSignRingPolys, inv.ShowingRingPolys)
	}
	if len(report.Profiles) == 0 {
		return fmt.Errorf("no IntGenISIS profiles requested")
	}
	if jsonOut != "" {
		if err := writeJSONFile(jsonOut, report, 0o644); err != nil {
			return fmt.Errorf("write benchmark json: %w", err)
		}
		log.Printf("[issuance-cli] benchmark-intgenisis wrote %s", jsonOut)
	}
	return nil
}

func intGenISISInventoryMetrics(inv PIOP.IntGenISISRowInventory, kind string) benchmarkIntGenISISMetrics {
	rowsPerPoly := inv.RowsPerRingPoly
	switch kind {
	case "presign":
		core := inv.PreSignRows
		boundRows := inv.PreSignRingPolys * rowsPerPoly
		return benchmarkIntGenISISMetrics{
			TotalRows:            core + boundRows,
			BoundRows:            boundRows,
			TernaryRows:          boundRows,
			ParallelDegree:       3,
			AggregatedDegree:     1,
			ParallelAlgDegree:    3,
			AggregatedAlgDegree:  1,
			DominantDegreeSource: "ternary",
			ProofReportBuckets:   2,
			MeasurementStatus:    "inventory_plus_relation_buckets",
		}
	case "showing":
		boundPolys := 0
		uPolys := 0
		hatPolys := 0
		coeffPolys := 0
		yPolys := 1
		semanticPolys := 0
		commitmentPolys := 0
		bridgedHatPolys := 0
		for _, part := range inv.ShowingComponents {
			switch part.Name {
			case "u":
				uPolys += part.PolyRows
				hatPolys += part.PolyRows
				coeffPolys += part.PolyRows
				bridgedHatPolys += part.PolyRows
			case "M", "s", "e":
				coeffPolys += part.PolyRows
				boundPolys += part.PolyRows
				if part.Name == "M" || part.Name == "s" || part.Name == "e" {
					if part.Name == "M" {
						semanticPolys += part.PolyRows
					} else {
						commitmentPolys += part.PolyRows
					}
				}
			case "mu_sig", "x0", "x1", "Z":
				hatPolys += part.PolyRows
				// Issuer-side mu_sig/x0/x1/Z are direct hat rows in the live showing surface.
			case "m", "k":
				// Default no-disclosure showing derives message/key semantics from M.
			}
		}
		coeffPolys += yPolys
		hatPolys += yPolys
		bridgedHatPolys += yPolys
		coeffViewRows := coeffPolys * rowsPerPoly
		shortnessRows := uPolys * rowsPerPoly * 4
		boundRows := boundPolys * rowsPerPoly
		hatRows := hatPolys * rowsPerPoly
		return benchmarkIntGenISISMetrics{
			TotalRows:                   coeffViewRows + shortnessRows + hatRows,
			CoefficientViewRows:         coeffViewRows,
			UCoefficientViewRows:        uPolys * rowsPerPoly,
			SemanticViewRows:            semanticPolys * rowsPerPoly,
			CommitmentViewRows:          commitmentPolys * rowsPerPoly,
			YCoefficientViewRows:        yPolys * rowsPerPoly,
			IssuerViewRows:              0,
			BoundRows:                   boundRows,
			TernaryRows:                 boundRows,
			ShortnessRows:               shortnessRows,
			ShortnessConstraints:        uPolys * rowsPerPoly * 5,
			HatRows:                     hatRows,
			YHatRows:                    yPolys * rowsPerPoly,
			SourceBridgeConstraints:     (bridgedHatPolys + yPolys) * rowsPerPoly * inv.PackingFactor,
			UBridgeConstraints:          uPolys * rowsPerPoly * inv.PackingFactor,
			CommitmentBridgeConstraints: yPolys * rowsPerPoly * inv.PackingFactor,
			YLinearConstraints:          yPolys * rowsPerPoly * inv.PackingFactor,
			IssuerBridgeConstraints:     0,
			FparIntConstraints:          2 * rowsPerPoly,
			RangeConstraints:            boundRows,
			ParallelDegree:              11,
			AggregatedDegree:            2,
			ParallelAlgDegree:           11,
			AggregatedAlgDegree:         2,
			DominantDegreeSource:        "shortness",
			ProofReportBuckets:          3,
			MeasurementStatus:           "inventory_plus_relation_buckets",
		}
	default:
		return benchmarkIntGenISISMetrics{MeasurementStatus: "unknown"}
	}
}

func measureIntGenISISProfileBProofs(packingFactor int) (benchmarkIntGenISISMeasuredProfile, error) {
	profile := credential.PrimaryIntGenISISProfile()
	if profile.Name != credential.ProfileIntGenISISB {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("primary IntGenISIS profile=%q want %q", profile.Name, credential.ProfileIntGenISISB)
	}
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("load ring: %w", err)
	}
	prfParams, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("load prf params: %w", err)
	}
	ncols := packingFactor
	if ncols <= 0 {
		ncols = 16
	}
	lvcsNCols := 2 * ncols
	if lvcsNCols < ncols {
		lvcsNCols = ncols
	}
	optsPre := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential: true,
		RingDegree: profile.N,
		NCols:      ncols,
		LVCSNCols:  lvcsNCols,
		Ell:        4,
		EllPrime:   4,
		Eta:        8,
		Rho:        1,
		Theta:      1,
		DomainMode: PIOP.DomainModeExplicit,
		NLeaves:    4096,
	})
	optsShow := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:        true,
		CoeffPacking:      true,
		RingDegree:        profile.N,
		NCols:             ncols,
		LVCSNCols:         lvcsNCols,
		PostSignLVCSNCols: lvcsNCols,
		PRFLVCSNCols:      lvcsNCols,
		Ell:               4,
		EllPrime:          4,
		Eta:               8,
		Rho:               1,
		Theta:             1,
		DomainMode:        PIOP.DomainModeExplicit,
		NLeaves:           4096,
		PRFGroupRounds:    2,
		PRFCompanionMode:  PIOP.PRFCompanionModeOutputAudit,
	})

	cmCoeff, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.EllM)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("C_M: %w", err)
	}
	asCoeff, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.KS)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("A_s: %w", err)
	}
	cm, err := commitment.MatrixFromCoeff(ringQ, cmCoeff)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("lift C_M: %w", err)
	}
	as, err := commitment.MatrixFromCoeff(ringQ, asCoeff)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("lift A_s: %w", err)
	}
	layout, err := credential.DefaultSemanticMessageLayout(profile, prfParams.LenKey)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("semantic layout: %w", err)
	}
	keySigned := make([]int64, prfParams.LenKey)
	for i := range keySigned {
		keySigned[i] = int64((i % 3) - 1)
	}
	attrs := credential.ZeroSemanticAttributes(layout)
	for i, slot := range layout.Attribute {
		attrs[slot.Poly][slot.Coeff] = int64((i % 3) - 1)
	}
	msg, err := credential.EncodeSemanticMessage(layout, attrs, keySigned)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("semantic message: %w", err)
	}
	M := intGenISISBenchmarkPolysFromRows(ringQ, msg.M)
	MAttr := intGenISISBenchmarkPolysFromRows(ringQ, msg.MAttr)
	K := intGenISISBenchmarkPolysFromRows(ringQ, msg.K)
	targetParams := commitment.TargetParams{
		RingQ: ringQ,
		CM:    cm,
		AS:    as,
		EllM:  profile.EllM,
		KS:    profile.KS,
		NC:    profile.NC,
		Bound: profile.B,
	}
	s, e, err := commitment.SampleTernaryCommitmentRandomness(targetParams, rand.New(rand.NewSource(71317)))
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("sample opening: %w", err)
	}
	c, err := commitment.CommitMessage(targetParams, M, s, e)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("commit: %w", err)
	}
	pubPre := PIOP.PublicInputs{
		Com:          c,
		CM:           cm,
		AS:           as,
		BoundB:       profile.B,
		X0Len:        profile.EllX0,
		RingDegree:   profile.N,
		HashRelation: credential.HashRelationBBTran,
		IntGenISIS:   true,
		Extras:       map[string]interface{}{"IntGenISIS.signature_bound_value": int64(6142)},
	}
	preStart := time.Now()
	preProof, err := PIOP.BuildIntGenISISPreSign(ringQ, pubPre, PIOP.WitnessInputs{M: M, MAttr: MAttr, K: K, S: s, E: e}, optsPre)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("build pre-sign proof: %w", err)
	}
	preProveDur := time.Since(preStart)
	preVerifyStart := time.Now()
	ok, err := PIOP.VerifyIntGenISISPreSign(pubPre, preProof, optsPre)
	preVerifyDur := time.Since(preVerifyStart)
	if err != nil || !ok {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("verify pre-sign proof: ok=%v err=%w", ok, err)
	}
	preReport, err := PIOP.BuildProofReport(preProof, optsPre, ringQ)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("pre-sign proof report: %w", err)
	}

	showPub, showWit, err := intGenISISBenchmarkShowingFixture(ringQ, profile, prfParams, msg, M, MAttr, K, optsShow)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, err
	}
	showStart := time.Now()
	showProof, err := PIOP.BuildIntGenISISShowingCombined(showPub, showWit, optsShow)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("build showing proof: %w", err)
	}
	showProveDur := time.Since(showStart)
	showVerifyStart := time.Now()
	ok, err = PIOP.VerifyIntGenISISShowing(showPub, showProof, optsShow)
	showVerifyDur := time.Since(showVerifyStart)
	if err != nil || !ok {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("verify showing proof: ok=%v err=%w", ok, err)
	}
	showReport, err := PIOP.BuildProofReport(showProof, optsShow, ringQ)
	if err != nil {
		return benchmarkIntGenISISMeasuredProfile{}, fmt.Errorf("showing proof report: %w", err)
	}
	return benchmarkIntGenISISMeasuredProfile{
		PreSign: intGenISISMetricsFromProof(preProof, preReport, pubPre, optsPre, preProveDur, preVerifyDur, "profile_b_live_presign"),
		Showing: intGenISISMetricsFromProof(showProof, showReport, showPub, optsShow, showProveDur, showVerifyDur, "profile_b_live_showing"),
	}, nil
}

func intGenISISBenchmarkShowingFixture(ringQ *ring.Ring, profile credential.IntGenISISProfile, prfParams *prf.Params, msg credential.SemanticMessage, MRows, MAttrRows, KRows []*ring.Poly, opts PIOP.SimOpts) (PIOP.PublicInputs, PIOP.WitnessInputs, error) {
	if len(MRows) == 0 || len(MAttrRows) == 0 || len(KRows) == 0 {
		return PIOP.PublicInputs{}, PIOP.WitnessInputs{}, fmt.Errorf("missing semantic witness rows")
	}
	layout, err := credential.DefaultSemanticMessageLayout(profile, prfParams.LenKey)
	if err != nil {
		return PIOP.PublicInputs{}, PIOP.WitnessInputs{}, fmt.Errorf("semantic layout: %w", err)
	}
	keySigned, err := credential.PRFKeyFromSemanticMessage(layout, msg.M)
	if err != nil {
		return PIOP.PublicInputs{}, PIOP.WitnessInputs{}, fmt.Errorf("semantic key: %w", err)
	}
	key := make([]prf.Elem, len(keySigned))
	for i, v := range keySigned {
		key[i] = intGenISISBenchmarkElemFromSigned(v, ringQ.Modulus[0])
	}
	nonce, noncePublic := intGenISISBenchmarkNonce(prfParams.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, prfParams)
	if err != nil {
		return PIOP.PublicInputs{}, PIOP.WitnessInputs{}, fmt.Errorf("tag: %w", err)
	}
	zero := ringQ.NewPoly()
	one := intGenISISBenchmarkCoeffConst(ringQ, 1)
	MNTT := ringQ.NewPoly()
	ring.Copy(MRows[0], MNTT)
	ringQ.NTT(MNTT, MNTT)
	oneNTT := ringQ.NewPoly()
	ring.Copy(one, oneNTT)
	ringQ.NTT(oneNTT, oneNTT)
	u0NTT := ringQ.NewPoly()
	for i := 0; i < ringQ.N; i++ {
		u0NTT.Coeffs[0][i] = (MNTT.Coeffs[0][i] + oneNTT.Coeffs[0][i]) % ringQ.Modulus[0]
	}
	u0 := ringQ.NewPoly()
	ringQ.InvNTT(u0NTT, u0)
	wit := PIOP.WitnessInputs{CoeffNativeShowing: &PIOP.CoeffNativeShowingWitness{
		Sig:         []*ring.Poly{u0, zero.CopyNew()},
		M:           MRows[0],
		MAttr:       MAttrRows[0],
		K:           KRows[0],
		S:           []*ring.Poly{zero.CopyNew(), zero.CopyNew()},
		E:           []*ring.Poly{zero.CopyNew()},
		MuSig:       []*ring.Poly{zero.CopyNew()},
		X0:          []*ring.Poly{zero.CopyNew(), zero.CopyNew()},
		X1:          zero.CopyNew(),
		Z:           one,
		PackedNCols: opts.NCols,
	}}
	pub := PIOP.PublicInputs{
		A: [][]*ring.Poly{{
			intGenISISBenchmarkPublicConstNTT(ringQ, 1),
			intGenISISBenchmarkPublicConstNTT(ringQ, 0),
		}},
		B: []*ring.Poly{
			intGenISISBenchmarkPublicConstNTT(ringQ, 0),
			intGenISISBenchmarkPublicConstNTT(ringQ, 0),
			intGenISISBenchmarkPublicConstNTT(ringQ, 0),
			intGenISISBenchmarkPublicConstNTT(ringQ, 0),
			intGenISISBenchmarkPublicConstNTT(ringQ, 1),
		},
		CM:           [][]*ring.Poly{{intGenISISBenchmarkPublicConstNTT(ringQ, 1)}},
		AS:           [][]*ring.Poly{{intGenISISBenchmarkPublicConstNTT(ringQ, 0), intGenISISBenchmarkPublicConstNTT(ringQ, 0)}},
		Tag:          intGenISISBenchmarkLanesFromElems(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       profile.B,
		X0Len:        profile.EllX0,
		RingDegree:   profile.N,
		HashRelation: credential.HashRelationBBTran,
		IntGenISIS:   true,
	}
	return pub, wit, nil
}

func intGenISISMetricsFromProof(proof *PIOP.Proof, report PIOP.ProofReport, pub PIOP.PublicInputs, opts PIOP.SimOpts, proveDur, verifyDur time.Duration, status string) benchmarkIntGenISISMetrics {
	metrics := benchmarkIntGenISISMetrics{
		ProofSizeBytes:       report.ProofBytes,
		PaperTranscriptBytes: report.PaperTranscript.OptimizedBytes,
		PaperTranscriptKB:    float64(report.PaperTranscript.OptimizedBytes) / 1024.0,
		QBytes:               report.PaperTranscript.Q.OptimizedBytes,
		RBytes:               report.PaperTranscript.R.OptimizedBytes,
		PdecsBytes:           report.PaperTranscript.Pdecs.OptimizedBytes,
		AuthBytes:            report.PaperTranscript.Auth.OptimizedBytes,
		SigShortnessBytes:    report.PaperTranscript.SigShortness.OptimizedBytes,
		VTargetsBytes:        report.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:         report.PaperTranscript.BarSets.OptimizedBytes,
		ProvingMS:            float64(proveDur.Microseconds()) / 1000.0,
		VerificationMS:       float64(verifyDur.Microseconds()) / 1000.0,
		TotalRows:            proof.RowLayout.SigCount,
		ParallelDegree:       proof.QDegreeBound,
		AggregatedDegree:     proof.QDegreeBound,
		RoundBits:            report.Soundness.Bits,
		RawRoundBits:         report.Soundness.RawBits,
		TheoremBits:          report.Soundness.TheoremBits,
		TheoremTotalBits:     report.Soundness.TotalBits,
		CollisionBits:        report.Soundness.CollisionBits,
		Clamped:              report.Soundness.Clamped,
		SoundnessEq8Bits:     report.Soundness.Eq8TotalBits,
		DQ:                   report.DQ,
		DDECS:                report.Soundness.DDECS,
		WitnessSupportCols:   report.Soundness.WitnessSupportCols,
		CommittedCols:        report.Soundness.CommittedCols,
		ProofReportBuckets:   intGenISISProofSizeBucketCount(proof),
		MeasurementStatus:    status,
	}
	metrics.Theta = proof.Theta
	if metrics.Theta <= 0 {
		metrics.Theta = 1
	}
	if proof.Theta > 1 {
		metrics.Rho = len(proof.GammaPrimeK)
		metrics.EllPrime = len(proof.KPoint)
		metrics.SmallFieldReplayRows = proof.PCSGeometry.ReplayWitnessRows
		metrics.MaskRows = proof.PCSGeometry.MaskRows
		metrics.QLimbRows = proof.Theta
	} else {
		metrics.Rho = len(proof.GammaPrime)
		metrics.EllPrime = len(proof.EvalPoints)
	}
	if metrics.Rho <= 0 && proof.QOpening != nil {
		metrics.Rho = proof.QOpening.R
		if proof.Theta > 1 && proof.Theta > 0 {
			metrics.Rho = proof.QOpening.R / proof.Theta
		}
	}
	if proof.QOpening != nil {
		metrics.QSplitRows = proof.QOpening.R
	}
	if proof.RowLayout.IntGenISISPreSign != nil {
		l := proof.RowLayout.IntGenISISPreSign
		metrics.BoundRows = l.BoundViewCount
		metrics.TernaryRows = l.BoundViewCount
		metrics.ParallelAlgDegree = 3
		metrics.AggregatedAlgDegree = 1
		metrics.DominantDegreeSource = "ternary"
		metrics.ParallelDegree = metrics.ParallelAlgDegree
		metrics.AggregatedDegree = metrics.AggregatedAlgDegree
	}
	if proof.RowLayout.IntGenISISShowing != nil {
		l := proof.RowLayout.IntGenISISShowing
		countViews := func(start, components int) int {
			if start < 0 || components <= 0 || l.ViewRowsPerPoly <= 0 {
				return 0
			}
			return components * l.ViewRowsPerPoly
		}
		metrics.UCoefficientViewRows = countViews(l.UViewStart, l.UCount)
		metrics.SemanticViewRows = countViews(l.MViewStart, l.MCount) + countViews(l.MAttrViewStart, l.MAttrCount) + countViews(l.KViewStart, l.KCount)
		metrics.CommitmentViewRows = countViews(l.SViewStart, l.SCount) + countViews(l.EViewStart, l.ECount)
		metrics.YCoefficientViewRows = l.YViewCount
		metrics.IssuerViewRows = countViews(l.MuSigViewStart, l.MuSigCount) + countViews(l.X0ViewStart, l.X0Count) + countViews(l.X1ViewStart, l.X1Count) + countViews(l.ZViewStart, l.ZCount)
		metrics.CoefficientViewRows = metrics.UCoefficientViewRows + metrics.SemanticViewRows + metrics.CommitmentViewRows + metrics.YCoefficientViewRows + metrics.IssuerViewRows
		metrics.BoundRows = l.BoundViewCount
		metrics.TernaryRows = l.BoundViewCount
		metrics.CompressedRows = l.MSECarrierCount
		metrics.MSECompressionLevel = l.MSECompressionLevel
		metrics.MSECompressionPackWidth = l.MSECompressionPackWidth
		metrics.MSECompressionDegree = l.MSECompressionDecodeDegree
		metrics.RangeConstraints = l.BoundViewCount
		metrics.ShortnessRows = l.UShortnessGroupCount * l.UShortnessRowsPerGroup
		metrics.ShortnessConstraints = l.UShortnessSourceViewRows * (1 + l.UShortnessRowsPerGroup)
		metrics.YHatRows = l.YHatCount
		metrics.HatRows = l.UHatCount + l.MHatCount + l.SHatCount + l.EHatCount + l.YHatCount + l.MuSigHatCount + l.X0HatCount + l.X1HatCount + l.ZHatCount
		metrics.ReplayProjection = l.ReplayProjection
		if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_y_hat_v1" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUYHatV1
		} else if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_y_hat_y_view_v2" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2
		}
		if l.ViewRowsPerPoly > 0 {
			ncols := proof.RowLayout.RingDegree / l.ViewRowsPerPoly
			bridgeRows := func(viewStart, hatCount int) int {
				if viewStart < 0 || hatCount <= 0 {
					return 0
				}
				return hatCount * ncols
			}
			metrics.UBridgeConstraints = bridgeRows(l.UViewStart, l.UHatCount)
			metrics.CommitmentBridgeConstraints = bridgeRows(l.YViewStart, l.YHatCount)
			metrics.YLinearConstraints = l.YViewCount * ncols
			metrics.IssuerBridgeConstraints = bridgeRows(l.MuSigViewStart, l.MuSigHatCount) + bridgeRows(l.X0ViewStart, l.X0HatCount) + bridgeRows(l.X1ViewStart, l.X1HatCount) + bridgeRows(l.ZViewStart, l.ZHatCount)
			if metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 {
				metrics.ProjectedSignatureConstraints = l.ViewRowsPerPoly * ncols
			}
			metrics.SourceBridgeConstraints = metrics.UBridgeConstraints + metrics.CommitmentBridgeConstraints + metrics.YLinearConstraints + metrics.ProjectedSignatureConstraints + metrics.IssuerBridgeConstraints
		}
		semanticConstraints := 0
		if l.MViewStart >= 0 && l.MAttrViewStart >= 0 && l.KViewStart >= 0 {
			semanticConstraints = l.ViewRowsPerPoly
		}
		if metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 {
			metrics.FparIntConstraints = l.ViewRowsPerPoly + semanticConstraints
		} else {
			metrics.FparIntConstraints = 2*l.ViewRowsPerPoly + semanticConstraints
		}
	}
	if proof.RowLayout.IntGenISISPreSign != nil || proof.RowLayout.IntGenISISShowing != nil {
		if meta, err := PIOP.IntGenISISDegreeMetadataForProof(proof, pub, opts); err == nil {
			metrics.ParallelAlgDegree = meta.ParallelAlgDegree
			metrics.AggregatedAlgDegree = meta.AggregatedAlgDegree
			metrics.DominantDegreeSource = meta.DominantDegreeSource
			metrics.ParallelDegree = meta.ParallelAlgDegree
			metrics.AggregatedDegree = meta.AggregatedAlgDegree
			metrics.MSECompressionLevel = meta.CompressionLevel
			metrics.MSECompressionPackWidth = meta.CompressionPackWidth
			metrics.MSECompressionDegree = meta.CompressionDegree
		}
		metrics.MaskDegreeBound = proof.MaskDegreeBound
		metrics.PaperConservativeDQ = proof.QDegreeBound
	}
	if proof.PRFCompanion != nil && proof.PRFCompanion.Layout != nil {
		metrics.PRFRows = proof.PRFCompanion.Layout.PackedRows
		metrics.PRFKeyBridgeConstraints = proof.PRFCompanion.Layout.KeyCount
	}
	if metrics.ProofReportBuckets == 0 {
		metrics.ProofReportBuckets = report.TranscriptFocus.RowOpeningEntries
	}
	return metrics
}

func intGenISISProofSizeBucketCount(proof *PIOP.Proof) int {
	size := PIOP.MeasureProofSize(proof)
	count := 0
	for _, v := range size.Parts {
		if v > 0 {
			count++
		}
	}
	return count
}

func intGenISISBenchmarkPolysFromRows(ringQ *ring.Ring, rows [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	q := int64(ringQ.Modulus[0])
	for i := range rows {
		out[i] = ringQ.NewPoly()
		for j, v := range rows[i] {
			if j >= int(ringQ.N) {
				break
			}
			v %= q
			if v < 0 {
				v += q
			}
			out[i].Coeffs[0][j] = uint64(v)
		}
	}
	return out
}

func intGenISISBenchmarkElemFromSigned(v int64, q uint64) prf.Elem {
	mod := v % int64(q)
	if mod < 0 {
		mod += int64(q)
	}
	return prf.Elem(uint64(mod))
}

func intGenISISBenchmarkNonce(lenNonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lenNonce)
	public := make([][]int64, lenNonce)
	for i := 0; i < lenNonce; i++ {
		v := uint64(i+1) % q
		nonce[i] = prf.Elem(v)
		public[i] = intGenISISBenchmarkConstLane(ncols, int64(v))
	}
	return nonce, public
}

func intGenISISBenchmarkConstLane(ncols int, v int64) []int64 {
	out := make([]int64, ncols)
	for i := range out {
		out[i] = v
	}
	return out
}

func intGenISISBenchmarkLanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = intGenISISBenchmarkConstLane(ncols, int64(v))
	}
	return out
}

func intGenISISBenchmarkCoeffConst(ringQ *ring.Ring, v uint64) *ring.Poly {
	p := ringQ.NewPoly()
	p.Coeffs[0][0] = v % ringQ.Modulus[0]
	return p
}

func intGenISISBenchmarkPublicConstNTT(ringQ *ring.Ring, v uint64) *ring.Poly {
	p := intGenISISBenchmarkCoeffConst(ringQ, v)
	ringQ.NTT(p, p)
	return p
}
