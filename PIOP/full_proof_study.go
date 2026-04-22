package PIOP

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Internal study support for the shipped theorem-clean full baseline. This
// file drives the retained feasibility map and is not part of protocol
// execution.
type FullProofStudyLeverStatus string

const (
	FullProofStudyLeverAlreadyDerivedNow               FullProofStudyLeverStatus = "already_derived_now"
	FullProofStudyLeverDoableWithCurrentOpenings       FullProofStudyLeverStatus = "doable_with_current_openings"
	FullProofStudyLeverNeedsSameRootSubsetBridge       FullProofStudyLeverStatus = "needs_same_root_subset_bridge"
	FullProofStudyLeverNeedsSeparateOracleOrMasterRoot FullProofStudyLeverStatus = "needs_separate_oracle_or_master_root"
	FullProofStudyLeverChangesStatement                FullProofStudyLeverStatus = "changes_statement"
	FullProofStudyLeverNotWorthAfterMeasurement        FullProofStudyLeverStatus = "not_worth_it_after_measurement"
)

type FullProofStudyReport struct {
	BaselineSnapshot      FullProofStudyBaselineSnapshot       `json:"baseline_snapshot"`
	WitnessFamilies       []FullProofStudyWitnessFamily        `json:"witness_families"`
	HiddenShortness       FullProofStudyHiddenShortness        `json:"hidden_shortness"`
	ConstraintFamilies    []FullProofStudyConstraintFamily     `json:"constraint_families"`
	AuthenticatedSurfaces []FullProofStudyAuthenticatedSurface `json:"authenticated_surfaces"`
	LeverMatrix           []FullProofStudyLever                `json:"lever_matrix"`
	Recommendations       FullProofStudyRecommendations        `json:"recommendations"`
}

type FullProofStudyBaselineSnapshot struct {
	StatementClass            string  `json:"statement_class"`
	ReplayMode                string  `json:"replay_mode"`
	PRFMode                   string  `json:"prf_mode"`
	OptimizedBytes            int     `json:"optimized_bytes"`
	SigShortnessBytes         int     `json:"sig_shortness_bytes"`
	PdecsBytes                int     `json:"pdecs_bytes"`
	VTargetsBytes             int     `json:"vtargets_bytes"`
	BarSetsBytes              int     `json:"barsets_bytes"`
	QBytes                    int     `json:"q_bytes"`
	SoundnessBits             float64 `json:"soundness_bits"`
	ReplayBlocks              int     `json:"replay_blocks"`
	WitnessRows               int     `json:"witness_rows"`
	SelectorSelectedRows      int     `json:"selector_selected_rows"`
	SelectorWitnessRows       int     `json:"selector_witness_rows"`
	SelectorActiveBlocks      int     `json:"selector_active_blocks"`
	SigShortnessSupportSlots  int     `json:"sig_shortness_support_slots"`
	SigShortnessOpenedBlocks  int     `json:"sig_shortness_opened_blocks"`
	SigShortnessOpeningBytes  int     `json:"sig_shortness_opening_bytes"`
	HiddenShortnessProofBytes int     `json:"hidden_shortness_proof_bytes"`
	MainLVCSNCols             int     `json:"main_lvcs_ncols"`
	MainNLeaves               int     `json:"main_nleaves"`
	PRFLVCSNCols              int     `json:"prf_lvcs_ncols"`
	PRFNLeaves                int     `json:"prf_nleaves"`
	HiddenShortnessLVCSNCols  int     `json:"hidden_shortness_lvcs_ncols"`
	HiddenShortnessNLeaves    int     `json:"hidden_shortness_nleaves"`
}

type FullProofStudyWitnessFamily struct {
	Name               string   `json:"name"`
	Domain             string   `json:"domain"`
	LogicalRows        []int    `json:"logical_rows"`
	CommittedRows      []int    `json:"committed_rows"`
	PhysicalBlocks     []int    `json:"physical_blocks"`
	LogicalRowCount    int      `json:"logical_row_count"`
	CommittedRowCount  int      `json:"committed_row_count"`
	PhysicalBlockCount int      `json:"physical_block_count"`
	SelectedRows       []int    `json:"selected_rows"`
	SelectedRowCount   int      `json:"selected_row_count"`
	SelectedInReplay   bool     `json:"selected_in_replay"`
	AuthenticatedBy    []string `json:"authenticated_by"`
	Notes              string   `json:"notes"`
}

type FullProofStudyConstraintFamily struct {
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	SourceBuilder           string   `json:"source_builder"`
	Layer                   string   `json:"layer"`
	ConsumedWitnessFamilies []string `json:"consumed_witness_families"`
	ConsumedPublicData      []string `json:"consumed_public_data"`
	AuthenticatedBy         []string `json:"authenticated_by"`
	Notes                   string   `json:"notes"`
}

type FullProofStudyAuthenticatedSurface struct {
	Name                    string   `json:"name"`
	Kind                    string   `json:"kind"`
	Active                  bool     `json:"active"`
	ControlOnly             bool     `json:"control_only"`
	Bytes                   int      `json:"bytes"`
	BoundWitnessFamilies    []string `json:"bound_witness_families"`
	BoundConstraintFamilies []string `json:"bound_constraint_families"`
	Notes                   string   `json:"notes"`
}

type FullProofStudyHiddenShortness struct {
	Enabled               bool                          `json:"enabled"`
	OuterSupportSlotCount int                           `json:"outer_support_slot_count"`
	WitnessNCols          int                           `json:"witness_ncols"`
	LVCSNCols             int                           `json:"lvcs_ncols"`
	NLeaves               int                           `json:"nleaves"`
	HiddenProofBytes      int                           `json:"hidden_proof_bytes"`
	OpeningBytes          int                           `json:"opening_bytes"`
	BindingBytes          int                           `json:"binding_bytes"`
	PublicTHatRows        []int                         `json:"public_t_hat_rows"`
	WitnessFamilies       []FullProofStudyWitnessFamily `json:"witness_families"`
	FparFamilyCount       int                           `json:"fpar_family_count"`
	FaggFamilyCount       int                           `json:"fagg_family_count"`
	QBytes                int                           `json:"q_bytes"`
	PdecsBytes            int                           `json:"pdecs_bytes"`
	VTargetsBytes         int                           `json:"vtargets_bytes"`
	BarSetsBytes          int                           `json:"barsets_bytes"`
	BindingSummary        string                        `json:"binding_summary"`
}

type FullProofStudyLever struct {
	Name                  string                    `json:"name"`
	Status                FullProofStudyLeverStatus `json:"status"`
	WitnessFamilies       []string                  `json:"witness_families"`
	ConstraintFamilies    []string                  `json:"constraint_families"`
	AuthenticatedSurfaces []string                  `json:"authenticated_surfaces"`
	FeasibilityRank       int                       `json:"feasibility_rank"`
	ExpectedByteLeverage  string                    `json:"expected_byte_leverage"`
	RecommendationRank    int                       `json:"recommendation_rank"`
	Rationale             string                    `json:"rationale"`
}

type FullProofStudyRecommendations struct {
	NextBaselineDoable       string   `json:"next_baseline_doable"`
	NextBridgeRequired       string   `json:"next_bridge_required"`
	NextArchitectureRequired string   `json:"next_architecture_required"`
	Ordered                  []string `json:"ordered"`
}

const (
	fullStudyDomainMain            = "main_full_proof"
	fullStudyDomainHiddenShortness = "hidden_sig_shortness"
)

const (
	fullStudySurfaceMainPCSRowOpening        = "main_pcs_row_opening"
	fullStudySurfaceQOpening                 = "q_opening"
	fullStudySurfaceMainRoot                 = "main_root"
	fullStudySurfaceSourceProductBridge      = "source_product_same_root_bridge"
	fullStudySurfaceSigShortnessSubset       = "sig_shortness_t_hat_subset_opening"
	fullStudySurfaceSigShortnessHiddenRoot   = "sig_shortness_hidden_root"
	fullStudySurfaceSigShortnessHiddenDigest = "sig_shortness_hidden_public_digest"
	fullStudySurfacePRFScalarPayload         = "prf_companion_scalar_payload"
	fullStudySurfacePRFAuxSameRootBridge     = "prf_aux_same_root_bridge"
)

const (
	fullStudyWitnessCarrierM          = "carrier_m"
	fullStudyWitnessCarrierCtr        = "carrier_ctr"
	fullStudyWitnessTSource           = "t_source"
	fullStudyWitnessMHatSigma         = "mhat_sigma"
	fullStudyWitnessRHat0             = "rhat0"
	fullStudyWitnessRHat1             = "rhat1"
	fullStudyWitnessMSigmaR1Source    = "msigmar1_source"
	fullStudyWitnessR0R1Source        = "r0r1_source"
	fullStudyWitnessMSigmaR1Hat       = "msigmar1_hat"
	fullStudyWitnessR0R1Hat           = "r0r1_hat"
	fullStudyWitnessTHat              = "t_hat"
	fullStudyWitnessPRFKey            = "prf_key"
	fullStudyWitnessPRFCheckpoint     = "prf_checkpoint"
	fullStudyWitnessPRFFinalTag       = "prf_final_tag"
	fullStudyWitnessPRFHelper         = "prf_helper"
	fullStudyWitnessOuterSigShortness = "outer_sig_shortness_support"
	fullStudyWitnessHiddenLinfDigits  = "hidden_linf_digit_rows"
)

const (
	fullStudyConstraintTransformHashResidual = "transform_hash_residual_all_blocks"
	fullStudyConstraintCarrierDecode         = "carrier_decode_and_membership"
	fullStudyConstraintNonSignBridge         = "non_sign_source_to_hat_bridge"
	fullStudyConstraintSourceProductResidual = "bb_tran_source_product_source_residual"
	fullStudyConstraintSourceProductBridge   = "bb_tran_source_product_source_to_hat_bridge"
	fullStudyConstraintPRFQBridge            = "prf_companion_q_bridge"
	fullStudyConstraintPRFScalarOpenings     = "prf_companion_scalar_openings"
	fullStudyConstraintOuterShortness        = "sig_shortness_outer_subset_opening"
	fullStudyConstraintHiddenTHatBridge      = "sig_shortness_hidden_t_hat_bridge"
	fullStudyConstraintHiddenLinf            = "sig_shortness_hidden_linf"
)

const (
	fullStudyLeverTSource                    = "t_source_derivation"
	fullStudyLeverHiddenShortnessGeometry    = "hidden_sig_shortness_geometry_tuning"
	fullStudyLeverHiddenShortnessOuterBridge = "hidden_sig_shortness_outer_t_hat_opening"
	fullStudyLeverSourceProduct              = "source_product_extraction"
	fullStudyLeverPRFSameRootAux             = "prf_same_root_aux_instance"
	fullStudyLeverPRFMasterRoot              = "prf_packed_rows_master_root_bridge"
	fullStudyLeverCarrier                    = "carrier_row_extraction"
)

// BuildFullProofStudyReport builds the current-state study for the live
// theorem-clean full baseline. It is intended for internal planning and
// transcript-reduction analysis, not for protocol execution.
func BuildFullProofStudyReport(proof *Proof, pub PublicInputs, opts SimOpts, ringQ *ring.Ring) (FullProofStudyReport, error) {
	if proof == nil {
		return FullProofStudyReport{}, fmt.Errorf("nil proof")
	}
	if ringQ == nil {
		return FullProofStudyReport{}, fmt.Errorf("nil ring")
	}
	if proof.SigShortness == nil || proof.SigShortness.V6 == nil || proof.SigShortness.V6.HiddenProof == nil {
		return FullProofStudyReport{}, fmt.Errorf("full proof study requires hidden sig-shortness V6 on the baseline proof")
	}
	opts.applyDefaults()
	if normalizeShowingReplayMode(opts.ShowingReplayMode) != ShowingReplayModeFull {
		return FullProofStudyReport{}, fmt.Errorf("full proof study requires full replay mode")
	}
	if proof.PRFCompanion != nil && prfCompanionModeDefault(proof.PRFCompanion.Mode) != PRFCompanionModeOutputAudit {
		return FullProofStudyReport{}, fmt.Errorf("full proof study requires baseline PRF companion mode output_audit, got %q", proof.PRFCompanion.Mode)
	}
	rep, err := BuildProofReport(proof, opts, ringQ)
	if err != nil {
		return FullProofStudyReport{}, err
	}
	if rep.TranscriptFocus.StatementClass != string(ShowingStatementClassTheoremCleanFullReplay) {
		return FullProofStudyReport{}, fmt.Errorf("full proof study requires theorem-clean full replay, got %q", rep.TranscriptFocus.StatementClass)
	}
	selector := BuildShowingReplayActiveRowSelectorFromProof(proof)
	baseline := buildFullProofStudyBaselineSnapshot(proof, rep)
	witnessFamilies := buildFullProofStudyWitnessFamilies(proof, selector)
	hiddenShortness, err := buildFullProofStudyHiddenShortness(proof, pub, opts, ringQ)
	if err != nil {
		return FullProofStudyReport{}, err
	}
	constraintFamilies := buildFullProofStudyConstraintFamilies(proof)
	authenticatedSurfaces := buildFullProofStudyAuthenticatedSurfaces(proof, rep)
	leverMatrix := buildFullProofStudyLeverMatrix(proof)
	recommendations := buildFullProofStudyRecommendations(leverMatrix)
	return FullProofStudyReport{
		BaselineSnapshot:      baseline,
		WitnessFamilies:       witnessFamilies,
		HiddenShortness:       hiddenShortness,
		ConstraintFamilies:    constraintFamilies,
		AuthenticatedSurfaces: authenticatedSurfaces,
		LeverMatrix:           leverMatrix,
		Recommendations:       recommendations,
	}, nil
}

func buildFullProofStudyBaselineSnapshot(proof *Proof, rep ProofReport) FullProofStudyBaselineSnapshot {
	return FullProofStudyBaselineSnapshot{
		StatementClass:            rep.TranscriptFocus.StatementClass,
		ReplayMode:                rep.TranscriptFocus.ReplayMode,
		PRFMode:                   rep.TranscriptFocus.PRFMode,
		OptimizedBytes:            rep.PaperTranscript.OptimizedBytes,
		SigShortnessBytes:         rep.PaperTranscript.SigShortness.OptimizedBytes,
		PdecsBytes:                rep.PaperTranscript.Pdecs.OptimizedBytes,
		VTargetsBytes:             rep.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:              rep.PaperTranscript.BarSets.OptimizedBytes,
		QBytes:                    rep.PaperTranscript.Q.OptimizedBytes,
		SoundnessBits:             rep.Soundness.TotalBits,
		ReplayBlocks:              rep.TranscriptFocus.ReplayBlocks,
		WitnessRows:               rep.TranscriptFocus.WitnessRows,
		SelectorSelectedRows:      rep.ReplayAudit.Selector.SelectedRows,
		SelectorWitnessRows:       rep.ReplayAudit.Selector.WitnessRows,
		SelectorActiveBlocks:      rep.ReplayAudit.Selector.ActiveBlocks,
		SigShortnessSupportSlots:  rep.SigShortness.SupportSlotCount,
		SigShortnessOpenedBlocks:  rep.SigShortness.OpenedBlockCount,
		SigShortnessOpeningBytes:  rep.SigShortness.OpeningBytes,
		HiddenShortnessProofBytes: rep.SigShortness.HiddenProofBytes,
		MainLVCSNCols:             rep.TranscriptFocus.MainLVCSNCols,
		MainNLeaves:               rep.TranscriptFocus.MainNLeaves,
		PRFLVCSNCols:              rep.TranscriptFocus.PRFLVCSNCols,
		PRFNLeaves:                rep.TranscriptFocus.PRFNLeaves,
		HiddenShortnessLVCSNCols:  rep.TranscriptFocus.HiddenShortnessLVCSNCols,
		HiddenShortnessNLeaves:    rep.TranscriptFocus.HiddenShortnessNLeaves,
	}
}

type fullProofStudyWitnessSpec struct {
	name            string
	domain          string
	rows            []int
	authenticatedBy []string
	notes           string
}

func buildFullProofStudyWitnessFamilies(proof *Proof, selector []int) []FullProofStudyWitnessFamily {
	layout := proof.RowLayout
	mainSurfaces := []string{fullStudySurfaceMainRoot, fullStudySurfaceMainPCSRowOpening}
	sourceProductSurfaces := append([]string(nil), mainSurfaces...)
	sourceProductNotes := map[string]string{
		fullStudyWitnessMSigmaR1Source: "Committed omega-interpolated source-product row for (M1+M2)*R1. Still live in the baseline full proof.",
		fullStudyWitnessR0R1Source:     "Committed omega-interpolated source-product row for R0*R1. Still live in the baseline full proof.",
	}
	if sourceProductBridgeEnabledForProof(proof) {
		sourceProductSurfaces = []string{fullStudySurfaceMainRoot, fullStudySurfaceSourceProductBridge}
		sourceProductNotes[fullStudyWitnessMSigmaR1Source] = "Committed omega-interpolated source-product row for (M1+M2)*R1. On theorem-clean full replay it now leaves the active selector and is authenticated by the same-root source-product bridge."
		sourceProductNotes[fullStudyWitnessR0R1Source] = "Committed omega-interpolated source-product row for R0*R1. On theorem-clean full replay it now leaves the active selector and is authenticated by the same-root source-product bridge."
	}
	specs := []fullProofStudyWitnessSpec{
		{name: fullStudyWitnessCarrierM, domain: fullStudyDomainMain, rows: nonNegativeStudyRows(layout.IdxCarrierM), authenticatedBy: mainSurfaces, notes: "Packed message carrier row; decoded into m1/m2 and consumed directly by the main transform-bridge replay."},
		{name: fullStudyWitnessCarrierCtr, domain: fullStudyDomainMain, rows: nonNegativeStudyRows(layout.IdxCarrierCtr), authenticatedBy: mainSurfaces, notes: "Packed counter carrier row; decoded into r0/r1 and consumed directly by the main transform-bridge replay."},
		{name: fullStudyWitnessTSource, domain: fullStudyDomainMain, rows: studyRowRange(layout.IdxTSource, rowLayoutPostSignTSourceCount(layout)), authenticatedBy: mainSurfaces, notes: "Committed T-source rows are absent on the live theorem-clean full baseline; THat is derived directly from signature replay heads."},
		{name: fullStudyWitnessMHatSigma, domain: fullStudyDomainMain, rows: rowLayoutPostSignMHatSigmaRows(layout), authenticatedBy: mainSurfaces, notes: "Replay-image row family for M1+M2 over every full replay block."},
		{name: fullStudyWitnessRHat0, domain: fullStudyDomainMain, rows: rowLayoutPostSignRHat0Rows(layout), authenticatedBy: mainSurfaces, notes: "Replay-image row family for R0 over every full replay block."},
		{name: fullStudyWitnessRHat1, domain: fullStudyDomainMain, rows: rowLayoutPostSignRHat1Rows(layout), authenticatedBy: mainSurfaces, notes: "Replay-image row family for R1 over every full replay block."},
		{name: fullStudyWitnessMSigmaR1Source, domain: fullStudyDomainMain, rows: nonNegativeStudyRows(layout.IdxMSigmaR1), authenticatedBy: sourceProductSurfaces, notes: sourceProductNotes[fullStudyWitnessMSigmaR1Source]},
		{name: fullStudyWitnessR0R1Source, domain: fullStudyDomainMain, rows: nonNegativeStudyRows(layout.IdxR0R1), authenticatedBy: sourceProductSurfaces, notes: sourceProductNotes[fullStudyWitnessR0R1Source]},
		{name: fullStudyWitnessMSigmaR1Hat, domain: fullStudyDomainMain, rows: rowLayoutPostSignMSigmaR1HatRows(layout), authenticatedBy: mainSurfaces, notes: "Replay-image row family for the source-product polynomial (M1+M2)*R1 over all replay blocks."},
		{name: fullStudyWitnessR0R1Hat, domain: fullStudyDomainMain, rows: rowLayoutPostSignR0R1HatRows(layout), authenticatedBy: mainSurfaces, notes: "Replay-image row family for the source-product polynomial R0*R1 over all replay blocks."},
		{name: fullStudyWitnessTHat, domain: fullStudyDomainMain, rows: rowLayoutPostSignTHatRows(layout), authenticatedBy: []string{fullStudySurfaceMainRoot, fullStudySurfaceMainPCSRowOpening, fullStudySurfaceSigShortnessSubset}, notes: "Replay-image THat rows over all replay blocks. They are also re-opened through the outer sig-shortness same-root subset opening."},
		{name: fullStudyWitnessPRFKey, domain: fullStudyDomainMain, rows: prfCompanionKeyRowIndices(replayCompanionLayoutFromProof(proof)), authenticatedBy: mainSurfaces, notes: "Packed PRF key row retained for key binding and scalar opening checks in the baseline path."},
		{name: fullStudyWitnessPRFCheckpoint, domain: fullStudyDomainMain, rows: prfCompanionCheckpointRowIndices(replayCompanionLayoutFromProof(proof)), authenticatedBy: mainSurfaces, notes: "Packed PRF checkpoint rows consumed by the live Q-bridge and scalar opening checks."},
		{name: fullStudyWitnessPRFFinalTag, domain: fullStudyDomainMain, rows: prfCompanionFinalTagRowIndices(replayCompanionLayoutFromProof(proof)), authenticatedBy: mainSurfaces, notes: "Packed PRF final-tag rows consumed by the live Q-bridge and scalar opening checks."},
		{name: fullStudyWitnessPRFHelper, domain: fullStudyDomainMain, rows: prfCompanionHelperRowIndices(replayCompanionLayoutFromProof(proof)), authenticatedBy: mainSurfaces, notes: "Packed PRF helper rows still live in the baseline Q-bridge mix."},
		{name: fullStudyWitnessOuterSigShortness, domain: fullStudyDomainMain, rows: buildSigShortnessWitnessPolyIndicesForVersion(layout, proof.SigShortness.Version), authenticatedBy: []string{fullStudySurfaceMainRoot, fullStudySurfaceSigShortnessSubset}, notes: "Outer sig-shortness support rows authenticated by the same-root THat subset opening; on V6 these coincide with THat rows."},
	}
	out := make([]FullProofStudyWitnessFamily, 0, len(specs))
	pcsNCols := resolveProofPCSNCols(proof, 0)
	for _, spec := range specs {
		rows := sortedUniqueInts(spec.rows)
		selected := intersectSortedIntSlices(rows, selector)
		out = append(out, buildFullProofStudyWitnessFamily(spec.name, spec.domain, rows, selected, pcsNCols, spec.authenticatedBy, spec.notes))
	}
	return out
}

func buildFullProofStudyWitnessFamily(name, domain string, rows, selected []int, pcsNCols int, authenticatedBy []string, notes string) FullProofStudyWitnessFamily {
	rows = sortedUniqueInts(rows)
	selected = intersectSortedIntSlices(rows, selected)
	return FullProofStudyWitnessFamily{
		Name:               name,
		Domain:             domain,
		LogicalRows:        append([]int(nil), rows...),
		CommittedRows:      append([]int(nil), rows...),
		PhysicalBlocks:     studyBlocksForRows(rows, pcsNCols),
		LogicalRowCount:    len(rows),
		CommittedRowCount:  len(rows),
		PhysicalBlockCount: len(studyBlocksForRows(rows, pcsNCols)),
		SelectedRows:       append([]int(nil), selected...),
		SelectedRowCount:   len(selected),
		SelectedInReplay:   len(selected) > 0,
		AuthenticatedBy:    append([]string(nil), authenticatedBy...),
		Notes:              notes,
	}
}

func buildFullProofStudyHiddenShortness(proof *Proof, pub PublicInputs, opts SimOpts, ringQ *ring.Ring) (FullProofStudyHiddenShortness, error) {
	if proof == nil || proof.SigShortness == nil || proof.SigShortness.V6 == nil || proof.SigShortness.V6.HiddenProof == nil {
		return FullProofStudyHiddenShortness{}, nil
	}
	v6 := proof.SigShortness.V6
	hiddenProof := v6.HiddenProof
	hiddenLogicalRows := hiddenProof.PCSGeometry.LogicalWitnessPolys
	if hiddenLogicalRows <= 0 {
		hiddenLogicalRows = hiddenProof.RowLayout.SigCount
	}
	outerOmegaWitness, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0],
		proof.NLeavesUsed,
		proof.NColsUsed,
		resolveProofPCSNCols(proof, 0),
		len(proof.Tail),
		proof.HashRelation,
	)
	if err != nil {
		return FullProofStudyHiddenShortness{}, fmt.Errorf("derive outer witness omega for study: %w", err)
	}
	view, err := prepareSigShortnessV5THatView(proof, ringQ, outerOmegaWitness)
	if err != nil {
		return FullProofStudyHiddenShortness{}, fmt.Errorf("prepare outer sig-shortness view for study: %w", err)
	}
	tHatHeads := make([][]uint64, 0)
	if view != nil {
		tHatHeads, err = extractSigShortnessTHatHeadsFromView(proof, view)
		if err != nil {
			return FullProofStudyHiddenShortness{}, fmt.Errorf("extract T-hat heads for hidden study: %w", err)
		}
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   v6.Radix,
		SigShortnessL:       v6.Digits,
	})
	if err != nil {
		return FullProofStudyHiddenShortness{}, fmt.Errorf("hidden study signature spec: %w", err)
	}
	hiddenWitnessOmega, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0],
		hiddenProof.NLeavesUsed,
		hiddenProof.NColsUsed,
		resolveProofPCSNCols(hiddenProof, 0),
		len(hiddenProof.Tail),
		hiddenProof.HashRelation,
	)
	if err != nil {
		return FullProofStudyHiddenShortness{}, fmt.Errorf("hidden study witness omega: %w", err)
	}
	hiddenReplay, err := buildSigShortnessHiddenReplay(ringQ, hiddenProof, pub, hiddenWitnessOmega, tHatHeads, spec)
	if err != nil {
		return FullProofStudyHiddenShortness{}, fmt.Errorf("hidden study replay: %w", err)
	}
	hiddenOpts := buildSigShortnessHiddenOpts(opts, "", hiddenProof.NColsUsed, hiddenLogicalRows)
	hiddenReport, err := BuildProofReport(hiddenProof, hiddenOpts, ringQ)
	if err != nil {
		return FullProofStudyHiddenShortness{}, fmt.Errorf("hidden study proof report: %w", err)
	}
	digitRows := studyRowRange(0, hiddenLogicalRows)
	pcsNCols := resolveProofPCSNCols(hiddenProof, 0)
	hiddenWitnessFamily := buildFullProofStudyWitnessFamily(
		fullStudyWitnessHiddenLinfDigits,
		fullStudyDomainHiddenShortness,
		digitRows,
		nil,
		pcsNCols,
		[]string{fullStudySurfaceSigShortnessHiddenRoot},
		"Hidden sig-shortness witness rows carrying signed-digit limbs for every packed signature component/block/lane.",
	)
	publicTHatRows := studyRowRange(0, rowLayoutReplayTHatCount(proof.RowLayout))
	return FullProofStudyHiddenShortness{
		Enabled:               true,
		OuterSupportSlotCount: buildSigShortnessReport(proof).SupportSlotCount,
		WitnessNCols:          hiddenProof.NColsUsed,
		LVCSNCols:             resolveProofPCSNCols(hiddenProof, 0),
		NLeaves:               hiddenProof.NLeavesUsed,
		HiddenProofBytes:      hiddenReport.ProofBytes,
		OpeningBytes:          buildSigShortnessReport(proof).OpeningBytes,
		BindingBytes:          buildSigShortnessReport(proof).BindingBytes,
		PublicTHatRows:        publicTHatRows,
		WitnessFamilies:       []FullProofStudyWitnessFamily{hiddenWitnessFamily},
		FparFamilyCount:       len(hiddenReplay.FparCoeffs),
		FaggFamilyCount:       len(hiddenReplay.FaggCoeffs),
		QBytes:                hiddenReport.PaperTranscript.Q.OptimizedBytes,
		PdecsBytes:            hiddenReport.PaperTranscript.Pdecs.OptimizedBytes,
		VTargetsBytes:         hiddenReport.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:          hiddenReport.PaperTranscript.BarSets.OptimizedBytes,
		BindingSummary:        "The outer proof authenticates THat under the main root via a same-root subset opening. The hidden proof then receives the encoded THat heads, the main root, and the shortness spec as public inputs and proves the linf statement under its own root.",
	}, nil
}

func buildFullProofStudyConstraintFamilies(proof *Proof) []FullProofStudyConstraintFamily {
	sourceProductResidualAuth := []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceQOpening, fullStudySurfaceMainRoot}
	sourceProductBridgeAuth := []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceQOpening, fullStudySurfaceMainRoot}
	sourceProductLayer := "Fpar"
	sourceProductBridgeLayer := "Fagg"
	sourceProductResidualNotes := "Checks that the committed source-product rows equal the omega-interpolated products reconstructed from the carrier rows."
	sourceProductBridgeNotes := "Bridges committed source-product rows to their replay-image hats over every replay block."
	sourceProductResidualBuilder := "buildCredentialConstraintSetPostCoeffNativeTransformBridge / newTransformBridgePostSignConfig"
	sourceProductBridgeBuilder := "buildCredentialConstraintSetPostCoeffNativeTransformBridge / buildSourceProductBridge / newTransformBridgePostSignConfig / verifySourceProductBridgeChecks"
	if sourceProductBridgeEnabledForProof(proof) {
		sourceProductBridgeAuth = []string{fullStudySurfaceSourceProductBridge, fullStudySurfaceMainRoot}
		sourceProductBridgeLayer = "outer_verification"
		sourceProductResidualNotes = "The source-product residual still lives in Q because the current shipped main opening does not recover exact carrier heads strongly enough to move this identity into the same-root bridge path."
		sourceProductBridgeNotes = "Verifier-side same-root bridge check: compares bridge-authenticated source-product values against the committed replay hats over every replay block."
	}
	return []FullProofStudyConstraintFamily{
		{
			Name:                    fullStudyConstraintTransformHashResidual,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           "buildCredentialConstraintSetPostFromRows -> buildCredentialConstraintSetPostCoeffNativeTransformBridge / newTransformBridgePostSignConfig",
			Layer:                   "Fpar",
			ConsumedWitnessFamilies: []string{fullStudyWitnessMHatSigma, fullStudyWitnessRHat0, fullStudyWitnessRHat1, fullStudyWitnessMSigmaR1Hat, fullStudyWitnessR0R1Hat, fullStudyWitnessTHat},
			ConsumedPublicData:      []string{"public_B_rows", "hash_relation"},
			AuthenticatedBy:         []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceQOpening, fullStudySurfaceMainRoot},
			Notes:                   "All-block replay residual over the exact replay-image hats. This is the theorem-clean full replay core.",
		},
		{
			Name:                    fullStudyConstraintCarrierDecode,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           "buildCredentialConstraintSetPostCoeffNativeTransformBridge / newTransformBridgePostSignConfig",
			Layer:                   "Fpar",
			ConsumedWitnessFamilies: []string{fullStudyWitnessCarrierM, fullStudyWitnessCarrierCtr},
			ConsumedPublicData:      []string{"bound_B"},
			AuthenticatedBy:         []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceQOpening, fullStudySurfaceMainRoot},
			Notes:                   "Decodes carrier rows into message/counter source polynomials and enforces membership on the packed carriers.",
		},
		{
			Name:                    fullStudyConstraintNonSignBridge,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           "buildCredentialConstraintSetPostCoeffNativeTransformBridge / newTransformBridgePostSignConfig",
			Layer:                   "Fagg",
			ConsumedWitnessFamilies: []string{fullStudyWitnessCarrierM, fullStudyWitnessCarrierCtr, fullStudyWitnessMHatSigma, fullStudyWitnessRHat0, fullStudyWitnessRHat1},
			ConsumedPublicData:      []string{"transform_bridge_basis"},
			AuthenticatedBy:         []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceQOpening, fullStudySurfaceMainRoot},
			Notes:                   "Bridges carrier-derived non-sign source polynomials to the exact replay-image hats on every replay block.",
		},
		{
			Name:                    fullStudyConstraintSourceProductResidual,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           sourceProductResidualBuilder,
			Layer:                   sourceProductLayer,
			ConsumedWitnessFamilies: []string{fullStudyWitnessCarrierM, fullStudyWitnessCarrierCtr, fullStudyWitnessMSigmaR1Source, fullStudyWitnessR0R1Source},
			ConsumedPublicData:      []string{"bound_B"},
			AuthenticatedBy:         sourceProductResidualAuth,
			Notes:                   sourceProductResidualNotes,
		},
		{
			Name:                    fullStudyConstraintSourceProductBridge,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           sourceProductBridgeBuilder,
			Layer:                   sourceProductBridgeLayer,
			ConsumedWitnessFamilies: []string{fullStudyWitnessMSigmaR1Source, fullStudyWitnessR0R1Source, fullStudyWitnessMSigmaR1Hat, fullStudyWitnessR0R1Hat},
			ConsumedPublicData:      []string{"transform_bridge_basis"},
			AuthenticatedBy:         sourceProductBridgeAuth,
			Notes:                   sourceProductBridgeNotes,
		},
		{
			Name:                    fullStudyConstraintPRFQBridge,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           "buildPRFCompanionBridgeFamiliesFormal / PRFCompanionBridgeConfig",
			Layer:                   "Q",
			ConsumedWitnessFamilies: []string{fullStudyWitnessPRFKey, fullStudyWitnessPRFCheckpoint, fullStudyWitnessPRFFinalTag, fullStudyWitnessPRFHelper},
			ConsumedPublicData:      []string{"tag_public", "nonce_public", "checkpoint_samples", "bridge_seed2"},
			AuthenticatedBy:         []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceQOpening, fullStudySurfaceMainRoot},
			Notes:                   "Packed PRF bridge families aggregated into the main Q path under the baseline output_audit mode.",
		},
		{
			Name:                    fullStudyConstraintPRFScalarOpenings,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           "buildPRFCompanionOpeningPayload / verifyPRFCompanionOpenings",
			Layer:                   "outer_verification",
			ConsumedWitnessFamilies: []string{fullStudyWitnessPRFKey, fullStudyWitnessPRFCheckpoint, fullStudyWitnessPRFFinalTag},
			ConsumedPublicData:      []string{"tag_public", "nonce_public", "prf_params", "seed3"},
			AuthenticatedBy:         []string{fullStudySurfacePRFScalarPayload, fullStudySurfaceMainRoot},
			Notes:                   "Scalar direct-auth openings over checkpoint outputs, final tag, and key truncation. These validate scalar semantics but do not replace the packed Q-bridge on Ω_s.",
		},
		{
			Name:                    fullStudyConstraintOuterShortness,
			Domain:                  fullStudyDomainMain,
			SourceBuilder:           "buildSigShortnessV5THatOpening / prepareSigShortnessV5THatView / VerifySigShortnessProofV6",
			Layer:                   "outer_shortness_verification",
			ConsumedWitnessFamilies: []string{fullStudyWitnessTHat, fullStudyWitnessOuterSigShortness},
			ConsumedPublicData:      []string{"main_root", "sig_shortness_spec"},
			AuthenticatedBy:         []string{fullStudySurfaceSigShortnessSubset, fullStudySurfaceMainRoot},
			Notes:                   "Same-root subset opening that authenticates THat support rows for the outer V6 shortness binding.",
		},
		{
			Name:                    fullStudyConstraintHiddenTHatBridge,
			Domain:                  fullStudyDomainHiddenShortness,
			SourceBuilder:           "buildSigShortnessHiddenConstraintSet / buildSigShortnessHiddenTHatBridgeFormalCoeffs",
			Layer:                   "hidden_shortness_subproof",
			ConsumedWitnessFamilies: []string{fullStudyWitnessHiddenLinfDigits},
			ConsumedPublicData:      []string{"public_A_row", "hidden_public_t_hat_rows", "sig_shortness_spec", "main_root_digest"},
			AuthenticatedBy:         []string{fullStudySurfaceSigShortnessHiddenDigest, fullStudySurfaceSigShortnessHiddenRoot},
			Notes:                   "Bridges hidden digit rows to the public THat rows inside the nested hidden shortness proof.",
		},
		{
			Name:                    fullStudyConstraintHiddenLinf,
			Domain:                  fullStudyDomainHiddenShortness,
			SourceBuilder:           "buildLiteralPackedSignatureShortnessConstraintSet / buildSigShortnessHiddenConstraintSet",
			Layer:                   "hidden_shortness_subproof",
			ConsumedWitnessFamilies: []string{fullStudyWitnessHiddenLinfDigits},
			ConsumedPublicData:      []string{"sig_shortness_radix", "sig_shortness_digits"},
			AuthenticatedBy:         []string{fullStudySurfaceSigShortnessHiddenRoot},
			Notes:                   "Hidden linf certificate over packed signature digits inside the nested V6 proof.",
		},
	}
}

func buildFullProofStudyAuthenticatedSurfaces(proof *Proof, rep ProofReport) []FullProofStudyAuthenticatedSurface {
	allMainWitness := []string{
		fullStudyWitnessCarrierM,
		fullStudyWitnessCarrierCtr,
		fullStudyWitnessTSource,
		fullStudyWitnessMHatSigma,
		fullStudyWitnessRHat0,
		fullStudyWitnessRHat1,
		fullStudyWitnessMSigmaR1Source,
		fullStudyWitnessR0R1Source,
		fullStudyWitnessMSigmaR1Hat,
		fullStudyWitnessR0R1Hat,
		fullStudyWitnessTHat,
		fullStudyWitnessPRFKey,
		fullStudyWitnessPRFCheckpoint,
		fullStudyWitnessPRFFinalTag,
		fullStudyWitnessPRFHelper,
	}
	mainConstraintFamilies := []string{fullStudyConstraintTransformHashResidual, fullStudyConstraintCarrierDecode, fullStudyConstraintNonSignBridge, fullStudyConstraintSourceProductResidual, fullStudyConstraintPRFQBridge}
	mainRootConstraintFamilies := append([]string{}, mainConstraintFamilies...)
	mainRootConstraintFamilies = append(mainRootConstraintFamilies, fullStudyConstraintSourceProductBridge, fullStudyConstraintOuterShortness, fullStudyConstraintPRFScalarOpenings)
	surfaces := []FullProofStudyAuthenticatedSurface{
		{
			Name:                    fullStudySurfaceMainPCSRowOpening,
			Kind:                    "row_opening",
			Active:                  true,
			Bytes:                   sizeDECSOpening(resolveProofPCSOpening(proof)),
			BoundWitnessFamilies:    allMainWitness,
			BoundConstraintFamilies: mainConstraintFamilies,
			Notes:                   "Authenticated main PCS row opening reconstructed at mask/tail indices. It binds the main witness rows under the main root, but it does not expose exact witness-Ω_s values for every potential extraction lever.",
		},
		{
			Name:                    fullStudySurfaceQOpening,
			Kind:                    "q_opening",
			Active:                  true,
			Bytes:                   sizeDECSOpening(proof.QOpening),
			BoundWitnessFamilies:    nil,
			BoundConstraintFamilies: mainConstraintFamilies,
			Notes:                   "Authenticated Q opening for the aggregated formal constraint families in the main theorem-clean proof.",
		},
		{
			Name:                    fullStudySurfaceMainRoot,
			Kind:                    "root",
			Active:                  true,
			Bytes:                   len(proof.Root),
			BoundWitnessFamilies:    append([]string(nil), allMainWitness...),
			BoundConstraintFamilies: mainRootConstraintFamilies,
			Notes:                   "Main proof root authenticating the one-root baseline witness surface and the same-root subset openings derived from it.",
		},
		{
			Name:                    fullStudySurfaceSourceProductBridge,
			Kind:                    "same_root_subset_bridge",
			Active:                  proof.SourceProductBridge != nil,
			Bytes:                   sizeSourceProductBridge(proof.SourceProductBridge),
			BoundWitnessFamilies:    []string{fullStudyWitnessMSigmaR1Source, fullStudyWitnessR0R1Source},
			BoundConstraintFamilies: []string{fullStudyConstraintSourceProductResidual, fullStudyConstraintSourceProductBridge},
			Notes:                   "Same-root bridge authenticating exact omega_s source-product witness rows under the main root.",
		},
		{
			Name:                    fullStudySurfaceSigShortnessSubset,
			Kind:                    "same_root_subset_opening",
			Active:                  proof.SigShortness != nil && proof.SigShortness.V6 != nil && proof.SigShortness.V6.THatOpening != nil,
			Bytes:                   buildSigShortnessReport(proof).OpeningBytes,
			BoundWitnessFamilies:    []string{fullStudyWitnessTHat, fullStudyWitnessOuterSigShortness},
			BoundConstraintFamilies: []string{fullStudyConstraintOuterShortness},
			Notes:                   "Same-root subset opening over THat support rows used by the outer hidden shortness binding.",
		},
		{
			Name:                    fullStudySurfaceSigShortnessHiddenDigest,
			Kind:                    "public_input_digest",
			Active:                  proof.SigShortness != nil && proof.SigShortness.V6 != nil && proof.SigShortness.V6.HiddenProof != nil,
			Bytes:                   32,
			BoundWitnessFamilies:    []string{fullStudyWitnessTHat, fullStudyWitnessHiddenLinfDigits},
			BoundConstraintFamilies: []string{fullStudyConstraintHiddenTHatBridge},
			Notes:                   "Hidden-shortness public extras digest carrying the encoded THat heads, main root, and shortness spec into the nested proof.",
		},
		{
			Name:                    fullStudySurfaceSigShortnessHiddenRoot,
			Kind:                    "root",
			Active:                  proof.SigShortness != nil && proof.SigShortness.V6 != nil && proof.SigShortness.V6.HiddenProof != nil,
			Bytes:                   len(proof.SigShortness.V6.HiddenProof.Root),
			BoundWitnessFamilies:    []string{fullStudyWitnessHiddenLinfDigits},
			BoundConstraintFamilies: []string{fullStudyConstraintHiddenTHatBridge, fullStudyConstraintHiddenLinf},
			Notes:                   "Root of the nested hidden shortness proof; verified independently and bound back to the outer proof through the hidden public-input digest.",
		},
		{
			Name:                    fullStudySurfacePRFScalarPayload,
			Kind:                    "masked_scalar_openings",
			Active:                  proof.PRFCompanion != nil && prfCompanionHasOpeningPayload(proof.PRFCompanion),
			Bytes:                   sizePRFCompanionProof(proof.PRFCompanion),
			BoundWitnessFamilies:    []string{fullStudyWitnessPRFKey, fullStudyWitnessPRFCheckpoint, fullStudyWitnessPRFFinalTag},
			BoundConstraintFamilies: []string{fullStudyConstraintPRFScalarOpenings},
			Notes:                   "Masked scalar opening payload for PRF direct-auth checks. It validates scalar semantics but does not authenticate the packed bridge rows on Ω_s.",
		},
		{
			Name:                    fullStudySurfacePRFAuxSameRootBridge,
			Kind:                    "same_root_subset_bridge",
			Active:                  false,
			ControlOnly:             true,
			Bytes:                   rep.TranscriptFocus.PRFBridgeOpeningBytes,
			BoundWitnessFamilies:    []string{fullStudyWitnessPRFKey, fullStudyWitnessPRFCheckpoint, fullStudyWitnessPRFFinalTag, fullStudyWitnessPRFHelper},
			BoundConstraintFamilies: []string{fullStudyConstraintPRFQBridge, fullStudyConstraintPRFScalarOpenings},
			Notes:                   "Research-only control surface from the aux_instance path. It is sound, but the same-root bridge and stripe still make the total transcript larger than the baseline.",
		},
	}
	return surfaces
}

func buildFullProofStudyLeverMatrix(proof *Proof) []FullProofStudyLever {
	sourceProductStatus := FullProofStudyLeverNeedsSameRootSubsetBridge
	sourceProductSurfaces := []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceMainRoot}
	sourceProductRationale := "The current main-opening recovery path does not authenticate the omega-interpolated source-product polynomials strongly enough for live extraction. The failed direct-auth attempt shows this lever needs a dedicated same-root bridge object."
	sourceProductRank := 3
	if sourceProductBridgeEnabledForProof(proof) {
		sourceProductSurfaces = []string{fullStudySurfaceSourceProductBridge, fullStudySurfaceMainPCSRowOpening, fullStudySurfaceMainRoot}
		sourceProductRationale = "The shipped same-root bridge now removes the source-to-hat family and the selected source rows on theorem-clean full replay, but the source residual still stays in Q because the current main opening does not expose exact carrier heads."
	}
	levers := []FullProofStudyLever{
		{
			Name:                  fullStudyLeverTSource,
			Status:                FullProofStudyLeverAlreadyDerivedNow,
			WitnessFamilies:       []string{fullStudyWitnessTSource, fullStudyWitnessTHat},
			ConstraintFamilies:    []string{fullStudyConstraintTransformHashResidual, fullStudyConstraintNonSignBridge},
			AuthenticatedSurfaces: []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceMainRoot},
			FeasibilityRank:       1,
			ExpectedByteLeverage:  "none",
			RecommendationRank:    99,
			Rationale:             "The theorem-clean full baseline already derives THat directly from signature replay heads and no longer commits T-source rows. This lever is complete on the current baseline.",
		},
		{
			Name:                  fullStudyLeverHiddenShortnessGeometry,
			Status:                FullProofStudyLeverDoableWithCurrentOpenings,
			WitnessFamilies:       []string{fullStudyWitnessHiddenLinfDigits},
			ConstraintFamilies:    []string{fullStudyConstraintHiddenTHatBridge, fullStudyConstraintHiddenLinf},
			AuthenticatedSurfaces: []string{fullStudySurfaceSigShortnessHiddenDigest, fullStudySurfaceSigShortnessHiddenRoot},
			FeasibilityRank:       1,
			ExpectedByteLeverage:  "medium",
			RecommendationRank:    1,
			Rationale:             "The hidden V6 subproof is already separately factorized, independently authenticated, and tunable through its own SmallWood geometry without changing the main theorem-clean statement.",
		},
		{
			Name:                  fullStudyLeverHiddenShortnessOuterBridge,
			Status:                FullProofStudyLeverNeedsSameRootSubsetBridge,
			WitnessFamilies:       []string{fullStudyWitnessTHat, fullStudyWitnessOuterSigShortness},
			ConstraintFamilies:    []string{fullStudyConstraintOuterShortness},
			AuthenticatedSurfaces: []string{fullStudySurfaceSigShortnessSubset, fullStudySurfaceMainRoot},
			FeasibilityRank:       2,
			ExpectedByteLeverage:  "high",
			RecommendationRank:    2,
			Rationale:             "The outer THat opening is a large authenticated object on the current baseline. Shrinking it requires a new same-root subset-bridge shape, not local evaluator reuse.",
		},
		{
			Name:                  fullStudyLeverSourceProduct,
			Status:                sourceProductStatus,
			WitnessFamilies:       []string{fullStudyWitnessCarrierM, fullStudyWitnessCarrierCtr, fullStudyWitnessMSigmaR1Source, fullStudyWitnessR0R1Source, fullStudyWitnessMSigmaR1Hat, fullStudyWitnessR0R1Hat},
			ConstraintFamilies:    []string{fullStudyConstraintSourceProductResidual, fullStudyConstraintSourceProductBridge},
			AuthenticatedSurfaces: sourceProductSurfaces,
			FeasibilityRank:       3,
			ExpectedByteLeverage:  "medium_high",
			RecommendationRank:    sourceProductRank,
			Rationale:             sourceProductRationale,
		},
		{
			Name:                  fullStudyLeverPRFSameRootAux,
			Status:                FullProofStudyLeverNotWorthAfterMeasurement,
			WitnessFamilies:       []string{fullStudyWitnessPRFKey, fullStudyWitnessPRFCheckpoint, fullStudyWitnessPRFFinalTag, fullStudyWitnessPRFHelper},
			ConstraintFamilies:    []string{fullStudyConstraintPRFQBridge, fullStudyConstraintPRFScalarOpenings},
			AuthenticatedSurfaces: []string{fullStudySurfacePRFAuxSameRootBridge, fullStudySurfaceMainRoot},
			FeasibilityRank:       4,
			ExpectedByteLeverage:  "negative_after_measurement",
			RecommendationRank:    98,
			Rationale:             "The same-root PRF aux split is sound but still larger than the baseline after measurement. It should remain a control path, not the next optimization target.",
		},
		{
			Name:                  fullStudyLeverPRFMasterRoot,
			Status:                FullProofStudyLeverNeedsSeparateOracleOrMasterRoot,
			WitnessFamilies:       []string{fullStudyWitnessPRFKey, fullStudyWitnessPRFCheckpoint, fullStudyWitnessPRFFinalTag, fullStudyWitnessPRFHelper},
			ConstraintFamilies:    []string{fullStudyConstraintPRFQBridge, fullStudyConstraintPRFScalarOpenings},
			AuthenticatedSurfaces: []string{fullStudySurfaceMainRoot, fullStudySurfacePRFAuxSameRootBridge},
			FeasibilityRank:       5,
			ExpectedByteLeverage:  "medium",
			RecommendationRank:    4,
			Rationale:             "PRF packed rows can only become economically separate if their bridge geometry is decoupled from the main PCS. That requires a separate PRF oracle/subroot under one protocol-level master root.",
		},
		{
			Name:                  fullStudyLeverCarrier,
			Status:                FullProofStudyLeverChangesStatement,
			WitnessFamilies:       []string{fullStudyWitnessCarrierM, fullStudyWitnessCarrierCtr},
			ConstraintFamilies:    []string{fullStudyConstraintCarrierDecode, fullStudyConstraintNonSignBridge, fullStudyConstraintSourceProductResidual},
			AuthenticatedSurfaces: []string{fullStudySurfaceMainPCSRowOpening, fullStudySurfaceMainRoot},
			FeasibilityRank:       6,
			ExpectedByteLeverage:  "high_but_statement_changing",
			RecommendationRank:    97,
			Rationale:             "Carrier rows are still the live source of decoded message/counter semantics in the theorem-clean baseline. Removing them would change the implemented statement, not just the authenticated surface.",
		},
	}
	sort.SliceStable(levers, func(i, j int) bool {
		return levers[i].RecommendationRank < levers[j].RecommendationRank
	})
	return levers
}

func buildFullProofStudyRecommendations(levers []FullProofStudyLever) FullProofStudyRecommendations {
	out := FullProofStudyRecommendations{}
	for _, lever := range levers {
		out.Ordered = append(out.Ordered, lever.Name)
		switch lever.Status {
		case FullProofStudyLeverDoableWithCurrentOpenings:
			if out.NextBaselineDoable == "" {
				out.NextBaselineDoable = lever.Name
			}
		case FullProofStudyLeverNeedsSameRootSubsetBridge:
			if out.NextBridgeRequired == "" {
				out.NextBridgeRequired = lever.Name
			}
		case FullProofStudyLeverNeedsSeparateOracleOrMasterRoot:
			if out.NextArchitectureRequired == "" {
				out.NextArchitectureRequired = lever.Name
			}
		}
	}
	return out
}

func RenderFullProofStudyMarkdown(study FullProofStudyReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Full Baseline Proof Study\n\n")
	fmt.Fprintf(&b, "## Baseline Snapshot\n\n")
	fmt.Fprintf(&b, "- Statement: `%s`\n", study.BaselineSnapshot.StatementClass)
	fmt.Fprintf(&b, "- Replay mode: `%s`\n", study.BaselineSnapshot.ReplayMode)
	fmt.Fprintf(&b, "- PRF mode: `%s`\n", study.BaselineSnapshot.PRFMode)
	fmt.Fprintf(&b, "- Optimized transcript: `%d` bytes\n", study.BaselineSnapshot.OptimizedBytes)
	fmt.Fprintf(&b, "- Buckets: `SigShortness=%d`, `Pdecs=%d`, `VTargets=%d`, `BarSets=%d`, `Q=%d`\n", study.BaselineSnapshot.SigShortnessBytes, study.BaselineSnapshot.PdecsBytes, study.BaselineSnapshot.VTargetsBytes, study.BaselineSnapshot.BarSetsBytes, study.BaselineSnapshot.QBytes)
	fmt.Fprintf(&b, "- Soundness: `%.2f` bits\n", study.BaselineSnapshot.SoundnessBits)
	fmt.Fprintf(&b, "- Replay selector: `%d/%d` rows, `%d` active blocks, replay blocks `%d`\n", study.BaselineSnapshot.SelectorSelectedRows, study.BaselineSnapshot.SelectorWitnessRows, study.BaselineSnapshot.SelectorActiveBlocks, study.BaselineSnapshot.ReplayBlocks)
	fmt.Fprintf(&b, "- Hidden shortness: opening `%d` bytes, hidden proof `%d` bytes\n\n", study.BaselineSnapshot.SigShortnessOpeningBytes, study.BaselineSnapshot.HiddenShortnessProofBytes)

	fmt.Fprintf(&b, "## Main Witness Families\n\n")
	fmt.Fprintf(&b, "| Family | Rows | Selected | Blocks | Authenticated By | Notes |\n")
	fmt.Fprintf(&b, "| --- | ---: | ---: | ---: | --- | --- |\n")
	for _, fam := range study.WitnessFamilies {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | `%s` | %s |\n", fam.Name, fam.LogicalRowCount, fam.SelectedRowCount, fam.PhysicalBlockCount, strings.Join(fam.AuthenticatedBy, "`, `"), fam.Notes)
	}
	fmt.Fprintf(&b, "\n## Hidden Sig Shortness\n\n")
	fmt.Fprintf(&b, "- Witness geometry: `ncols=%d`, `lvcs_ncols=%d`, `nleaves=%d`\n", study.HiddenShortness.WitnessNCols, study.HiddenShortness.LVCSNCols, study.HiddenShortness.NLeaves)
	fmt.Fprintf(&b, "- Outer support slots: `%d`\n", study.HiddenShortness.OuterSupportSlotCount)
	fmt.Fprintf(&b, "- Hidden proof bytes: `%d`, outer opening bytes: `%d`\n", study.HiddenShortness.HiddenProofBytes, study.HiddenShortness.OpeningBytes)
	fmt.Fprintf(&b, "- Hidden footprint: `Fpar=%d`, `Fagg=%d`, `Q=%d`, `Pdecs=%d`, `VTargets=%d`, `BarSets=%d`\n", study.HiddenShortness.FparFamilyCount, study.HiddenShortness.FaggFamilyCount, study.HiddenShortness.QBytes, study.HiddenShortness.PdecsBytes, study.HiddenShortness.VTargetsBytes, study.HiddenShortness.BarSetsBytes)
	fmt.Fprintf(&b, "- Binding: %s\n\n", study.HiddenShortness.BindingSummary)

	fmt.Fprintf(&b, "## Constraint Families\n\n")
	fmt.Fprintf(&b, "| Constraint | Layer | Witness Families | Authenticated By | Notes |\n")
	fmt.Fprintf(&b, "| --- | --- | --- | --- | --- |\n")
	for _, fam := range study.ConstraintFamilies {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n", fam.Name, fam.Layer, strings.Join(fam.ConsumedWitnessFamilies, "`, `"), strings.Join(fam.AuthenticatedBy, "`, `"), fam.Notes)
	}
	fmt.Fprintf(&b, "\n## Authenticated Surfaces\n\n")
	fmt.Fprintf(&b, "| Surface | Kind | Active | Bytes | Witness Families | Notes |\n")
	fmt.Fprintf(&b, "| --- | --- | --- | ---: | --- | --- |\n")
	for _, surf := range study.AuthenticatedSurfaces {
		state := "yes"
		if !surf.Active {
			state = "no"
		}
		if surf.ControlOnly {
			state += " (control)"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %d | `%s` | %s |\n", surf.Name, surf.Kind, state, surf.Bytes, strings.Join(surf.BoundWitnessFamilies, "`, `"), surf.Notes)
	}
	fmt.Fprintf(&b, "\n## Lever Matrix\n\n")
	fmt.Fprintf(&b, "| Lever | Status | Feasibility | Byte Leverage | Witness Families | Rationale |\n")
	fmt.Fprintf(&b, "| --- | --- | ---: | --- | --- | --- |\n")
	for _, lever := range study.LeverMatrix {
		fmt.Fprintf(&b, "| `%s` | `%s` | %d | `%s` | `%s` | %s |\n", lever.Name, lever.Status, lever.FeasibilityRank, lever.ExpectedByteLeverage, strings.Join(lever.WitnessFamilies, "`, `"), lever.Rationale)
	}
	fmt.Fprintf(&b, "\n## Recommendations\n\n")
	fmt.Fprintf(&b, "- Next baseline-doable lever: `%s`\n", study.Recommendations.NextBaselineDoable)
	fmt.Fprintf(&b, "- Next bridge-required lever: `%s`\n", study.Recommendations.NextBridgeRequired)
	fmt.Fprintf(&b, "- Next architecture-required lever: `%s`\n", study.Recommendations.NextArchitectureRequired)
	return b.String()
}

func studyRowRange(start, count int) []int {
	if start < 0 || count <= 0 {
		return nil
	}
	out := make([]int, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, start+i)
	}
	return out
}

func nonNegativeStudyRows(rows ...int) []int {
	out := make([]int, 0, len(rows))
	for _, row := range rows {
		if row >= 0 {
			out = append(out, row)
		}
	}
	return sortedUniqueInts(out)
}

func studyBlocksForRows(rows []int, pcsNCols int) []int {
	if pcsNCols <= 0 || len(rows) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(rows))
	for _, row := range rows {
		if row < 0 {
			continue
		}
		seen[row/pcsNCols] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for block := range seen {
		out = append(out, block)
	}
	sort.Ints(out)
	return out
}
