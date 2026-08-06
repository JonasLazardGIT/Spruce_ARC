package PIOP

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	smallField2025LVCSProofVersionV2 = lvcs.SmallField2025MetadataVersionV2
	SmallField2025HeadDomainV2       = lvcs.SmallField2025HeadDomainV2
	SmallField2025StatusLive         = "smallwood_2025_1085_salted_tapes_v2_live"
	SmallField2025StatusRejected     = "smallwood_2025_1085_salted_tapes_v2_rejected"
	// V3 status labels are used by proof/evidence reporting. The embedded
	// SmallField2025 metadata schema remains version 2 and is reconstructed by
	// the canonical codec; changing its stored status would alter the transcript.
	SmallField2025StatusLiveV3     = "smallwood_2025_1085_salted_tapes_v3_live"
	SmallField2025StatusRejectedV3 = "smallwood_2025_1085_salted_tapes_v3_rejected"
	// V4 retains the structural-v3 proof schema but has a distinct aggregate-Q
	// CROM theorem and Fiat--Shamir domain. Reporting must preserve that policy
	// identity instead of collapsing it into the V3 label.
	SmallField2025StatusLiveV4     = "smallwood_2025_1085_aggregate_q_v4_live"
	SmallField2025StatusRejectedV4 = "smallwood_2025_1085_aggregate_q_v4_rejected"

	SmallField2025TranscriptOmissionModeDigestBoundV2 = "digest_bound_payload_v2"
	smallField2025TranscriptOmissionVersionV2         = 2
	SmallField2025TranscriptOmissionModeCanonicalV3   = "canonical_reconstruction_v3"
	smallField2025TranscriptOmissionVersionV3         = 3
)

// SmallField2025TranscriptOmission describes reconstructible paper-transcript
// payloads that are bound through the SmallField2025 payload digest. Matrix
// payload omission is intentionally rejected until a reconstruction theorem
// exists; the live descriptor is limited to existing DECS opening omissions.
type SmallField2025TranscriptOmission struct {
	Version                      int    `json:"version"`
	Mode                         string `json:"mode"`
	OmitVTargets                 bool   `json:"omit_vtargets,omitempty"`
	OmitBarSets                  bool   `json:"omit_barsets,omitempty"`
	OmitPdecsReconstructibleCols bool   `json:"omit_pdecs_reconstructible_cols,omitempty"`
	AuthMultiproofCompact        bool   `json:"auth_multiproof_compact,omitempty"`
}

// SmallField2025LVCSProof binds the paper-shaped small-field LVCS payload
// metadata. It is intentionally separate from codec metadata: when
// ReductionEnabled is true, the verifier must use the strict
// EvalStep2SmallField2025 branch and must not fall back to dense EvalStep2.
type SmallField2025LVCSProof struct {
	Version            int                               `json:"version"`
	Mode               string                            `json:"mode"`
	Status             string                            `json:"status"`
	ReductionEnabled   bool                              `json:"reduction_enabled"`
	HeadDomainMode     string                            `json:"head_domain_mode"`
	NRows              int                               `json:"nrows"`
	NCols              int                               `json:"ncols"`
	Theta              int                               `json:"theta"`
	WitnessLayers      int                               `json:"witness_layers"`
	MaskRows           int                               `json:"mask_rows"`
	QueryCount         int                               `json:"query_count"`
	VHeadRows          int                               `json:"vhead_rows"`
	VHeadCols          int                               `json:"vhead_cols"`
	VBarRows           int                               `json:"vbar_rows"`
	VBarCols           int                               `json:"vbar_cols"`
	POmitCols          []int                             `json:"p_omit_cols,omitempty"`
	MOmitCols          []int                             `json:"m_omit_cols,omitempty"`
	MatrixDigest       []byte                            `json:"matrix_digest,omitempty"`
	PayloadDigest      []byte                            `json:"payload_digest,omitempty"`
	TranscriptOmission *SmallField2025TranscriptOmission `json:"transcript_omission,omitempty"`
	Notes              string                            `json:"notes,omitempty"`
}

type smallField2025CoeffPlan struct {
	C             [][]uint64
	ReplayRows    int
	WitnessLayers int
	QueryCount    int
	POmitCols     []int
}

func smallField2025AllCols(n int) []int {
	if n <= 0 {
		return nil
	}
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func proofUsesSmallField2025LVCS(proof *Proof) bool {
	return proof != nil &&
		transcriptUsesStrictSmallField2025(proof.TranscriptVersion, proof.TranscriptProtocolMode) &&
		proof.SmallField2025 != nil &&
		proof.SmallField2025.ReductionEnabled
}

func ValidateSmallField2025Proof(proof *Proof) error {
	if proof == nil {
		return nil
	}
	mode := normalizeTranscriptProtocolMode(proof.TranscriptProtocolMode)
	if !transcriptUsesStrictSmallField2025(proof.TranscriptVersion, mode) {
		if proof.SmallField2025 != nil {
			return fmt.Errorf("smallfield2025 metadata present without a supported strict transcript tuple")
		}
		return nil
	}
	if proof.SmallField2025 == nil {
		return fmt.Errorf("%s requires SmallField2025 metadata", mode)
	}
	meta := proof.SmallField2025
	if meta.Version != smallField2025LVCSProofVersionV2 ||
		meta.Mode != mode ||
		meta.HeadDomainMode != SmallField2025HeadDomainV2 {
		return fmt.Errorf("smallfield2025 metadata header mismatch")
	}
	if proof.Theta <= 1 {
		return fmt.Errorf("%s requires theta>1", mode)
	}
	if proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV2 {
		return fmt.Errorf("%s requires %s geometry", mode, PCSGeometryKindSmallFieldMatrixV2)
	}
	if proofHasLegacyQDECS(proof) {
		return fmt.Errorf("%s requires paper Q payload only", mode)
	}
	if rows := proof.QPayloadMatrix(); len(rows) != proof.Theta {
		return fmt.Errorf("%s requires rho=1 Q payload rows=%d theta=%d", mode, len(rows), proof.Theta)
	}
	if len(proof.KPoint) != 1 {
		return fmt.Errorf("%s requires ell_prime=1 K point count, got %d", mode, len(proof.KPoint))
	}
	if !meta.ReductionEnabled {
		if meta.Status != SmallField2025StatusRejected {
			return fmt.Errorf("smallfield2025 disabled metadata must use status %q", SmallField2025StatusRejected)
		}
		return nil
	}
	if meta.Status != SmallField2025StatusLive {
		return fmt.Errorf("smallfield2025 live reduction must use status %q", SmallField2025StatusLive)
	}
	if meta.WitnessLayers <= 0 || meta.QueryCount != (meta.WitnessLayers+1)*meta.Theta {
		return fmt.Errorf("smallfield2025 query count=%d inconsistent with witness_layers=%d theta=%d", meta.QueryCount, meta.WitnessLayers, meta.Theta)
	}
	open := resolveProofPCSOpening(proof)
	if open == nil {
		return fmt.Errorf("smallfield2025 missing PCS opening")
	}
	if open.MaskCount != 0 {
		return fmt.Errorf("smallfield2025 opening must not serialize mask rows")
	}
	if len(proof.Tail) == 0 {
		return fmt.Errorf("smallfield2025 missing tail indices")
	}
	if open.EntryCount() != len(proof.Tail) {
		return fmt.Errorf("smallfield2025 opening entries=%d want tail count %d", open.EntryCount(), len(proof.Tail))
	}
	vHead := proof.VTargetsMatrix()
	vBar := proof.BarSetsMatrix()
	rows, headCols, ok := matrixShape(vHead)
	if !ok {
		return fmt.Errorf("smallfield2025 invalid VHead matrix")
	}
	barRows, barCols, ok := matrixShape(vBar)
	if !ok {
		return fmt.Errorf("smallfield2025 invalid VBar matrix")
	}
	if len(proof.CoeffMatrix) != rows || barRows != rows {
		return fmt.Errorf("smallfield2025 matrix row mismatch")
	}
	if meta.NRows != open.R ||
		meta.NCols != headCols ||
		meta.Theta != proof.Theta ||
		meta.MaskRows != barCols ||
		meta.QueryCount != rows ||
		meta.VHeadRows != rows ||
		meta.VHeadCols != headCols ||
		meta.VBarRows != barRows ||
		meta.VBarCols != barCols {
		return fmt.Errorf("smallfield2025 dimension metadata mismatch")
	}
	if open.FormatVersion != decs.OpeningFormatOmitCols && open.FormatVersion != decs.OpeningFormatColumnWidths {
		return fmt.Errorf("smallfield2025 requires omitted P opening format")
	}
	if open.PColsEncoded != open.R-meta.QueryCount {
		return fmt.Errorf("smallfield2025 PColsEncoded=%d want %d", open.PColsEncoded, open.R-meta.QueryCount)
	}
	if len(open.POmitCols) > 0 && len(open.POmitCols) != meta.QueryCount {
		return fmt.Errorf("smallfield2025 P omitted column count=%d want %d", len(open.POmitCols), meta.QueryCount)
	}
	if len(meta.POmitCols) > 0 && len(meta.POmitCols) != meta.QueryCount {
		return fmt.Errorf("smallfield2025 metadata P omitted column count=%d want %d", len(meta.POmitCols), meta.QueryCount)
	}
	if len(open.POmitCols) > 0 && len(meta.POmitCols) > 0 && !equalIntSlices(open.POmitCols, meta.POmitCols) {
		return fmt.Errorf("smallfield2025 P omitted columns mismatch")
	}
	if open.MFormatVersion != decs.OpeningFormatOmitCols && open.MFormatVersion != decs.OpeningFormatColumnWidths {
		return fmt.Errorf("smallfield2025 requires omitted M opening format")
	}
	if open.MColsEncoded != 0 {
		return fmt.Errorf("smallfield2025 MColsEncoded=%d want 0", open.MColsEncoded)
	}
	if len(open.MOmitCols) > 0 && !equalIntSlices(open.MOmitCols, smallField2025AllCols(open.Eta)) {
		return fmt.Errorf("smallfield2025 M omitted columns must be all M columns")
	}
	if len(meta.MOmitCols) > 0 && !equalIntSlices(meta.MOmitCols, smallField2025AllCols(open.Eta)) {
		return fmt.Errorf("smallfield2025 metadata M omitted columns must be all M columns")
	}
	if !equalByteSlices(meta.MatrixDigest, smallField2025MatrixDigest(proof.CoeffMatrix)) {
		return fmt.Errorf("smallfield2025 matrix digest mismatch")
	}
	if err := validateSmallField2025TranscriptOmission(proof, meta.TranscriptOmission); err != nil {
		return err
	}
	if !equalByteSlices(meta.PayloadDigest, smallField2025PayloadDigest(proof, meta)) {
		return fmt.Errorf("smallfield2025 payload digest mismatch")
	}
	return nil
}

func buildSmallField2025CoeffPlan(
	ringQ *ring.Ring,
	K *kf.Field,
	omegaWitness []uint64,
	rows [][]uint64,
	kPoint kf.Elem,
	omegaS1 kf.Elem,
	muDenomInv kf.Elem,
	replayWitnessRows, maskRowOffset, maskRowCount int,
) (smallField2025CoeffPlan, error) {
	if ringQ == nil {
		return smallField2025CoeffPlan{}, fmt.Errorf("nil ring")
	}
	if K == nil {
		return smallField2025CoeffPlan{}, fmt.Errorf("nil K field")
	}
	if K.Theta <= 1 {
		return smallField2025CoeffPlan{}, fmt.Errorf("theta must be >1")
	}
	if len(rows) == 0 {
		return smallField2025CoeffPlan{}, fmt.Errorf("empty row matrix")
	}
	q := ringQ.Modulus[0]
	base := buildKPointCoeffMatrix(ringQ, K, omegaWitness, rows, kPoint, omegaS1, muDenomInv, replayWitnessRows, maskRowOffset, maskRowCount)
	if len(base) == 0 || len(base)%K.Theta != 0 {
		return smallField2025CoeffPlan{}, fmt.Errorf("invalid base K replay rows=%d theta=%d", len(base), K.Theta)
	}
	if _, ok := compressionPivotCols(base, len(rows), q); !ok {
		return smallField2025CoeffPlan{}, fmt.Errorf("base K replay coefficient matrix is not full row rank")
	}
	witnessLayers := len(base) / K.Theta
	targetRows := (witnessLayers + 1) * K.Theta
	out := copyMatrix(base)
	for len(out) < targetRows {
		var appended bool
		for col := 0; col < len(rows); col++ {
			row := make([]uint64, len(rows))
			row[col] = 1
			candidate := append(copyMatrix(out), row)
			if _, ok := compressionPivotCols(candidate, len(rows), q); ok {
				out = candidate
				appended = true
				break
			}
		}
		if !appended {
			return smallField2025CoeffPlan{}, fmt.Errorf("failed to extend paper coefficient matrix to full row rank (rows=%d target=%d cols=%d)", len(out), targetRows, len(rows))
		}
	}
	omitCols, ok := compressionPivotCols(out, len(rows), q)
	if !ok || len(omitCols) != len(out) {
		return smallField2025CoeffPlan{}, fmt.Errorf("paper coefficient matrix is not full row rank")
	}
	return smallField2025CoeffPlan{
		C:             out,
		ReplayRows:    len(base),
		WitnessLayers: witnessLayers,
		QueryCount:    len(out),
		POmitCols:     omitCols,
	}, nil
}

func attachSmallField2025Proof(proof *Proof, plan smallField2025CoeffPlan, eta int, transcriptOmissionMode string) error {
	_ = eta // M omissions are deterministic in strict mode: every M column is omitted.
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	if !transcriptUsesStrictSmallField2025(proof.TranscriptVersion, proof.TranscriptProtocolMode) {
		return fmt.Errorf("smallfield2025 metadata requires a supported strict transcript tuple")
	}
	if len(plan.C) == 0 || len(plan.POmitCols) != len(plan.C) {
		return fmt.Errorf("invalid smallfield2025 plan")
	}
	vHead := proof.VTargetsMatrix()
	vBar := proof.BarSetsMatrix()
	vRows, vCols, ok := matrixShape(vHead)
	if !ok {
		return fmt.Errorf("invalid smallfield2025 VHead")
	}
	bRows, bCols, ok := matrixShape(vBar)
	if !ok {
		return fmt.Errorf("invalid smallfield2025 VBar")
	}
	if vRows != len(plan.C) || bRows != len(plan.C) {
		return fmt.Errorf("smallfield2025 payload rows mismatch C=%d VHead=%d VBar=%d", len(plan.C), vRows, bRows)
	}
	omission, err := newSmallField2025TranscriptOmission(transcriptOmissionMode)
	if err != nil {
		return err
	}
	meta := &SmallField2025LVCSProof{
		Version:            smallField2025LVCSProofVersionV2,
		Mode:               proof.TranscriptProtocolMode,
		Status:             SmallField2025StatusLive,
		ReductionEnabled:   true,
		HeadDomainMode:     SmallField2025HeadDomainV2,
		NRows:              len(plan.C[0]),
		NCols:              vCols,
		Theta:              proof.Theta,
		WitnessLayers:      plan.WitnessLayers,
		MaskRows:           bCols,
		QueryCount:         len(plan.C),
		VHeadRows:          vRows,
		VHeadCols:          vCols,
		VBarRows:           bRows,
		VBarCols:           bCols,
		MatrixDigest:       smallField2025MatrixDigest(plan.C),
		TranscriptOmission: omission,
		Notes:              "strict paper-shaped small-field LVCS payload",
	}
	proof.SmallField2025 = meta
	meta.PayloadDigest = smallField2025PayloadDigest(proof, meta)
	return nil
}

func applySmallField2025RowOpeningCompression(open *decs.DECSOpening, coeffMatrix [][]uint64, omitCols []int, mod uint64) error {
	if open == nil {
		return fmt.Errorf("nil opening")
	}
	maybeCompressRowOpeningPvals(open, coeffMatrix, mod)
	if open.FormatVersion != decs.OpeningFormatOmitCols && open.FormatVersion != decs.OpeningFormatColumnWidths {
		return fmt.Errorf("smallfield2025 opening was not P-compressed")
	}
	pivots, ok := compressionPivotCols(coeffMatrix, open.R, mod)
	if !ok || len(pivots) != len(coeffMatrix) {
		return fmt.Errorf("smallfield2025 opening coefficient matrix is not full row rank")
	}
	if len(omitCols) > 0 && !equalIntSlices(omitCols, pivots) {
		return fmt.Errorf("smallfield2025 expected POmitCols=%v want deterministic %v", omitCols, pivots)
	}
	if len(open.POmitCols) > 0 && !equalIntSlices(open.POmitCols, pivots) {
		return fmt.Errorf("smallfield2025 opening POmitCols=%v want deterministic %v", open.POmitCols, pivots)
	}
	if open.PColsEncoded != open.R-len(pivots) {
		return fmt.Errorf("smallfield2025 opening PColsEncoded=%d want %d", open.PColsEncoded, open.R-len(pivots))
	}
	open.POmitCols = nil
	return nil
}

func verifySmallField2025CoeffPlan(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, rowCount int, seed3 []byte) error {
	if proof == nil || !proofUsesSmallField2025LVCS(proof) {
		return nil
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if len(proof.KPoint) != 1 {
		return fmt.Errorf("strict smallfield2025 expects exactly one K point")
	}
	var (
		K     *kf.Field
		zeta  kf.Elem
		muInv kf.Elem
		err   error
	)
	if transcriptUsesSmallWood2025V3(proof.TranscriptVersion) {
		if len(proof.Chi) != 0 || len(proof.Zeta) != 0 {
			return fmt.Errorf("v3 proof must not transmit Chi or omegaExtra")
		}
		params, profileErr := deriveSmallFieldParamsNoRowsV3(ringQ, omegaWitness, proof.Theta)
		if profileErr != nil {
			return profileErr
		}
		K, zeta, muInv = params.K, params.OmegaS1, params.MuInv
	} else {
		K, err = kf.New(ringQ.Modulus[0], proof.Theta, proof.Chi)
		if err != nil {
			return fmt.Errorf("kfield.New: %w", err)
		}
		if len(proof.Zeta) != proof.Theta {
			return fmt.Errorf("invalid zeta limb count=%d theta=%d", len(proof.Zeta), proof.Theta)
		}
		zeta = K.Phi(proof.Zeta)
		muInv, err = smallFieldMuDenomInv(K, omegaWitness, zeta)
		if err != nil {
			return err
		}
	}
	expectedKPoints, expectedElems, err := sampleSmallFieldKPoints(K, omegaWitness, 1, newFSRNGForTranscript(proof.TranscriptVersion, "EvalKPoint", seed3))
	if err != nil {
		return err
	}
	if !matrixEqual(expectedKPoints, proof.KPoint) {
		return fmt.Errorf("smallfield2025 K point mismatch")
	}
	rows := make([][]uint64, rowCount)
	if transcriptUsesSmallWood2025V3(proof.TranscriptVersion) {
		// V3 derives the mask-query shape from the trusted PCS width. The
		// coefficient plan only needs the matrix dimensions here (its values
		// are irrelevant), so materialize zero rows with that exact width.
		if proof.PCSNColsUsed <= 0 {
			return fmt.Errorf("invalid v3 PCS width %d", proof.PCSNColsUsed)
		}
		for i := range rows {
			rows[i] = make([]uint64, proof.PCSNColsUsed)
		}
	}
	var plan smallField2025CoeffPlan
	if transcriptUsesSmallWood2025V3(proof.TranscriptVersion) {
		plan, err = buildSmallField2025CoeffPlanV3(
			ringQ, K, omegaWitness, rows, expectedElems[0], zeta, muInv,
			proof.PCSGeometry.ReplayWitnessRows, proof.MaskRowOffset,
			proof.MaskRowCount, proof.MaskDegreeBound,
		)
	} else {
		plan, err = buildSmallField2025CoeffPlan(
			ringQ, K, omegaWitness, rows, expectedElems[0], zeta, muInv,
			proof.PCSGeometry.ReplayWitnessRows, proof.MaskRowOffset, proof.MaskRowCount,
		)
	}
	if err != nil {
		return err
	}
	if !matrixEqual(plan.C, proof.CoeffMatrix) {
		return fmt.Errorf("smallfield2025 coefficient matrix mismatch")
	}
	open := resolveProofPCSOpening(proof)
	if open == nil {
		return fmt.Errorf("smallfield2025 missing PCS opening")
	}
	if open.PColsEncoded != open.R-len(plan.POmitCols) {
		return fmt.Errorf("smallfield2025 PColsEncoded=%d want %d", open.PColsEncoded, open.R-len(plan.POmitCols))
	}
	if len(open.POmitCols) > 0 && !equalIntSlices(plan.POmitCols, open.POmitCols) {
		return fmt.Errorf("smallfield2025 opening POmitCols mismatch")
	}
	if len(proof.SmallField2025.POmitCols) > 0 && !equalIntSlices(plan.POmitCols, proof.SmallField2025.POmitCols) {
		return fmt.Errorf("smallfield2025 metadata POmitCols mismatch")
	}
	if open.MColsEncoded != 0 {
		return fmt.Errorf("smallfield2025 MColsEncoded=%d want 0", open.MColsEncoded)
	}
	allMOmit := smallField2025AllCols(open.Eta)
	if len(open.MOmitCols) > 0 && !equalIntSlices(open.MOmitCols, allMOmit) {
		return fmt.Errorf("smallfield2025 opening MOmitCols mismatch")
	}
	if len(proof.SmallField2025.MOmitCols) > 0 && !equalIntSlices(proof.SmallField2025.MOmitCols, allMOmit) {
		return fmt.Errorf("smallfield2025 metadata MOmitCols mismatch")
	}
	return nil
}

func sampleSmallFieldKPoints(K *kf.Field, omega []uint64, count int, rng *fsRNG) ([][]uint64, []kf.Elem, error) {
	if K == nil {
		return nil, nil, fmt.Errorf("nil K field")
	}
	if rng == nil {
		return nil, nil, fmt.Errorf("nil RNG")
	}
	if count <= 0 {
		return nil, nil, fmt.Errorf("invalid K point count %d", count)
	}
	limbRows := make([][]uint64, 0, count)
	elems := make([]kf.Elem, 0, count)
	for len(elems) < count {
		limbs := make([]uint64, K.Theta)
		for i := 0; i < K.Theta; i++ {
			limbs[i] = rng.nextMod(K.Q)
		}
		// V2 historically sampled from K\F. V3 follows the paper's exact
		// challenge space K\Omega and therefore permits embedded base-field
		// elements that are not themselves in Omega.
		rejectEmbeddedBaseField := !rng.exact
		if rejectEmbeddedBaseField {
			zeroTail := true
			for i := 1; i < len(limbs); i++ {
				if limbs[i]%K.Q != 0 {
					zeroTail = false
					break
				}
			}
			if zeroTail {
				continue
			}
		}
		candidate := K.Phi(limbs)
		conflict := false
		for _, w := range omega {
			if elemEqual(K, candidate, K.EmbedF(w%K.Q)) {
				conflict = true
				break
			}
		}
		if !conflict {
			for _, prev := range elems {
				if elemEqual(K, candidate, prev) {
					conflict = true
					break
				}
			}
		}
		if conflict {
			continue
		}
		limbRows = append(limbRows, limbs)
		elems = append(elems, candidate)
	}
	return limbRows, elems, nil
}

func smallFieldMuDenomInv(K *kf.Field, omega []uint64, omegaS1 kf.Elem) (kf.Elem, error) {
	if K == nil {
		return kf.Elem{}, fmt.Errorf("nil K field")
	}
	denom := K.One()
	for _, w := range omega {
		diff := K.Sub(omegaS1, K.EmbedF(w%K.Q))
		if K.IsZero(diff) {
			return kf.Elem{}, fmt.Errorf("omegaS1 collides with omega point")
		}
		denom = K.Mul(denom, diff)
	}
	if K.IsZero(denom) {
		return kf.Elem{}, fmt.Errorf("zero smallfield denominator")
	}
	return K.Inv(denom), nil
}

func smallField2025EvalInput(proof *Proof, opening *decs.DECSOpening, coeffMatrix, vHead, vBar [][]uint64) lvcs.SmallField2025EvalInput {
	meta := proof.SmallField2025
	return lvcs.SmallField2025EvalInput{
		VHead:   vHead,
		VBar:    vBar,
		Tail:    append([]int(nil), proof.Tail...),
		Opening: opening,
		C:       coeffMatrix,
		Metadata: lvcs.SmallField2025EvalMetadata{
			Version:          meta.Version,
			Mode:             meta.Mode,
			HeadDomainMode:   meta.HeadDomainMode,
			ReductionEnabled: meta.ReductionEnabled,
			NRows:            meta.NRows,
			NCols:            meta.NCols,
			Theta:            meta.Theta,
			WitnessLayers:    meta.WitnessLayers,
			MaskRows:         meta.MaskRows,
			QueryCount:       meta.QueryCount,
			VHeadRows:        meta.VHeadRows,
			VHeadCols:        meta.VHeadCols,
			VBarRows:         meta.VBarRows,
			VBarCols:         meta.VBarCols,
			POmitCols:        append([]int(nil), meta.POmitCols...),
			MOmitCols:        append([]int(nil), meta.MOmitCols...),
			MatrixDigest:     append([]byte(nil), meta.MatrixDigest...),
			PayloadDigest:    append([]byte(nil), meta.PayloadDigest...),
		},
	}
}

func newSmallField2025TranscriptOmission(mode string) (*SmallField2025TranscriptOmission, error) {
	switch mode {
	case "", SmallField2025TranscriptOmissionModeDigestBoundV2:
		return &SmallField2025TranscriptOmission{
			Version:                      smallField2025TranscriptOmissionVersionV2,
			Mode:                         SmallField2025TranscriptOmissionModeDigestBoundV2,
			OmitPdecsReconstructibleCols: true,
		}, nil
	case SmallField2025TranscriptOmissionModeCanonicalV3:
		return &SmallField2025TranscriptOmission{
			Version:                      smallField2025TranscriptOmissionVersionV3,
			Mode:                         SmallField2025TranscriptOmissionModeCanonicalV3,
			OmitPdecsReconstructibleCols: true,
			AuthMultiproofCompact:        true,
		}, nil
	default:
		return nil, fmt.Errorf("unknown smallfield2025 transcript omission mode %q", mode)
	}
}

func isExactSmallField2025TranscriptOmissionV3(desc *SmallField2025TranscriptOmission) bool {
	return desc != nil &&
		desc.Version == smallField2025TranscriptOmissionVersionV3 &&
		desc.Mode == SmallField2025TranscriptOmissionModeCanonicalV3 &&
		!desc.OmitVTargets &&
		!desc.OmitBarSets &&
		desc.OmitPdecsReconstructibleCols &&
		desc.AuthMultiproofCompact
}

func isExactSmallField2025TranscriptOmissionV2(desc *SmallField2025TranscriptOmission) bool {
	return desc != nil &&
		desc.Version == smallField2025TranscriptOmissionVersionV2 &&
		desc.Mode == SmallField2025TranscriptOmissionModeDigestBoundV2 &&
		!desc.OmitVTargets &&
		!desc.OmitBarSets &&
		desc.OmitPdecsReconstructibleCols &&
		!desc.AuthMultiproofCompact
}

func proofHasExactSmallField2025LiveMetadata(proof *Proof) bool {
	if proof == nil || proof.SmallField2025 == nil {
		return false
	}
	meta := proof.SmallField2025
	omissionOK := isExactSmallField2025TranscriptOmissionV2(meta.TranscriptOmission)
	if transcriptUsesSmallWood2025V3(proof.TranscriptVersion) {
		omissionOK = isExactSmallField2025TranscriptOmissionV3(meta.TranscriptOmission)
	}
	return transcriptUsesStrictSmallField2025(proof.TranscriptVersion, proof.TranscriptProtocolMode) &&
		meta.Version == smallField2025LVCSProofVersionV2 &&
		meta.Mode == normalizeTranscriptProtocolMode(proof.TranscriptProtocolMode) &&
		meta.Status == SmallField2025StatusLive &&
		meta.ReductionEnabled &&
		meta.HeadDomainMode == SmallField2025HeadDomainV2 &&
		omissionOK
}

func validateSmallField2025TranscriptOmission(proof *Proof, desc *SmallField2025TranscriptOmission) error {
	if desc == nil {
		return fmt.Errorf("smallfield2025 live transcript requires an omission descriptor")
	}
	wantV3 := proof != nil && transcriptUsesSmallWood2025V3(proof.TranscriptVersion)
	if (wantV3 && !isExactSmallField2025TranscriptOmissionV3(desc)) ||
		(!wantV3 && !isExactSmallField2025TranscriptOmissionV2(desc)) {
		return fmt.Errorf("smallfield2025 transcript omission descriptor mismatch")
	}
	if desc.OmitPdecsReconstructibleCols {
		if proof == nil || proof.SmallField2025 == nil || !proof.SmallField2025.ReductionEnabled {
			return fmt.Errorf("smallfield2025 Pdecs omission requires live reduction metadata")
		}
		open := resolveProofPCSOpening(proof)
		if open == nil {
			return fmt.Errorf("smallfield2025 Pdecs omission needs PCS opening")
		}
		if open.FormatVersion != decs.OpeningFormatOmitCols && open.FormatVersion != decs.OpeningFormatColumnWidths {
			return fmt.Errorf("smallfield2025 Pdecs omission needs omitted-column opening")
		}
	}
	return nil
}

func smallField2025TranscriptOmissionBytes(desc *SmallField2025TranscriptOmission) []byte {
	if desc == nil {
		return nil
	}
	out := make([]byte, 0, 96)
	appendString := func(s string) {
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(s)))
		out = append(out, lenBuf[:]...)
		out = append(out, []byte(s)...)
	}
	appendU64 := func(v uint64) {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		out = append(out, buf[:]...)
	}
	domain := "smallfield_2025_transcript_omission_v2"
	if desc.Version == smallField2025TranscriptOmissionVersionV3 {
		domain = "smallfield_2025_transcript_omission_v3"
	}
	appendString(domain)
	appendString(desc.Mode)
	appendU64(uint64(desc.Version))
	appendU64(boolToUint64(desc.OmitVTargets))
	appendU64(boolToUint64(desc.OmitBarSets))
	appendU64(boolToUint64(desc.OmitPdecsReconstructibleCols))
	appendU64(boolToUint64(desc.AuthMultiproofCompact))
	return out
}

func smallField2025Round4DirectPayloads(proof *Proof) [][]byte {
	if proof == nil {
		return nil
	}
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	out := make([][]byte, 0, 2)
	out = append(out, proof.VTargetsBits)
	out = append(out, proof.BarSetsBits)
	return out
}

func smallField2025TranscriptBytes(meta *SmallField2025LVCSProof) []byte {
	if meta == nil {
		return nil
	}
	out := make([]byte, 0, 256)
	appendString := func(s string) {
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(s)))
		out = append(out, lenBuf[:]...)
		out = append(out, []byte(s)...)
	}
	appendBytes := func(b []byte) {
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(b)))
		out = append(out, lenBuf[:]...)
		out = append(out, b...)
	}
	appendInts := func(vals []int) {
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(vals)))
		out = append(out, lenBuf[:]...)
		for _, v := range vals {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(v))
			out = append(out, buf[:]...)
		}
	}
	appendU64s := func(vals ...uint64) {
		for _, v := range vals {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], v)
			out = append(out, buf[:]...)
		}
	}
	appendString("smallfield_2025_lvcs_proof_v2")
	appendString(meta.Mode)
	appendString(meta.Status)
	appendString(meta.HeadDomainMode)
	appendU64s(
		uint64(meta.Version),
		boolToUint64(meta.ReductionEnabled),
		uint64(meta.NRows),
		uint64(meta.NCols),
		uint64(meta.Theta),
		uint64(meta.WitnessLayers),
		uint64(meta.MaskRows),
		uint64(meta.QueryCount),
		uint64(meta.VHeadRows),
		uint64(meta.VHeadCols),
		uint64(meta.VBarRows),
		uint64(meta.VBarCols),
	)
	appendInts(meta.POmitCols)
	appendInts(meta.MOmitCols)
	appendBytes(meta.MatrixDigest)
	appendBytes(smallField2025TranscriptOmissionBytes(meta.TranscriptOmission))
	appendBytes(meta.PayloadDigest)
	return out
}

func sizeSmallField2025Proof(meta *SmallField2025LVCSProof) int {
	if meta == nil {
		return 0
	}
	return len(smallField2025TranscriptBytes(meta))
}

func smallField2025MatrixDigest(matrix [][]uint64) []byte {
	h := sha256.New()
	h.Write([]byte("smallfield_2025_matrix_v2"))
	h.Write(bytesFromUint64Matrix(matrix))
	return h.Sum(nil)
}

func smallField2025PayloadDigest(proof *Proof, meta *SmallField2025LVCSProof) []byte {
	h := sha256.New()
	h.Write([]byte("smallfield_2025_payload_v2"))
	var matrix [][]uint64
	if proof != nil {
		proof.ensureVTargetsPacked()
		proof.ensureBarSetsPacked()
		h.Write(proof.VTargetsBits)
		h.Write(proof.BarSetsBits)
		matrix = proof.CoeffMatrix
	}
	h.Write(smallField2025MatrixDigest(matrix))
	if meta != nil {
		h.Write(smallField2025TranscriptOmissionBytes(meta.TranscriptOmission))
	}
	h.Write([]byte("smallfield_deterministic_omit_v2"))
	return h.Sum(nil)
}

func boolToUint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func matrixShape(mat [][]uint64) (rows, cols int, ok bool) {
	if len(mat) == 0 || len(mat[0]) == 0 {
		return 0, 0, false
	}
	cols = len(mat[0])
	for i := range mat {
		if len(mat[i]) != cols {
			return 0, 0, false
		}
	}
	return len(mat), cols, true
}
