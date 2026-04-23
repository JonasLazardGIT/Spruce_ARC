package PIOP

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	sigShortnessProofVersionV2 = 2
	sigShortnessProofVersionV3 = 3
	sigShortnessProofVersionV4 = 4
	sigShortnessProofVersionV5 = 5
	sigShortnessProofVersionV6 = 6
	sigShortnessProofVersionV7 = 7

	sigShortnessV5ModeExactSigHeads   uint8 = 1
	sigShortnessV6ModeHiddenSmallWood uint8 = 1
	sigShortnessV7ModeInlinedMain     uint8 = 1
)

const (
	fsModeSigShortnessHidden         = "PACS-SigShortnessHidden"
	sigShortnessTHatExtraKey         = "sig_short_t_hat"
	sigShortnessMainRootExtraKey     = "sig_short_main_root"
	sigShortnessSpecExtraKey         = "sig_short_spec"
	sigShortnessHiddenPrimaryProfile = SigShortnessProfileR11L4Production
)

type sigShortnessHiddenCandidateShape struct {
	Label           string
	Profile         string
	RawOverride     bool
	Radix           int
	Digits          int
	HiddenLVCSNCols int
	HiddenNLeaves   int
}

type sigShortnessHiddenBuiltCandidate struct {
	Shape        sigShortnessHiddenCandidateShape
	Spec         LinfSpec
	HiddenOpts   SimOpts
	HiddenProof  *Proof
	HiddenReport ProofReport
}

func buildSigShortnessWitnessPolyIndices(layout RowLayout) []int {
	return buildSigShortnessWitnessPolyIndicesForVersion(layout, sigShortnessProofVersionV2)
}

func buildSigShortnessWitnessPolyIndicesForVersion(layout RowLayout, version int) []int {
	rows := make([]int, 0, rowLayoutReplayTHatCount(layout)+layout.CoeffNativeSig.PackedSigCount+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup)
	if version >= sigShortnessProofVersionV3 {
		rows = append(rows, buildSigShortnessTHatWitnessRows(layout)...)
	}
	if version < sigShortnessProofVersionV4 && layout.CoeffNativeSig.PackedSigBase >= 0 && layout.CoeffNativeSig.PackedSigCount > 0 {
		for i := 0; i < layout.CoeffNativeSig.PackedSigCount; i++ {
			rows = append(rows, layout.CoeffNativeSig.PackedSigBase+i)
		}
	}
	if version < sigShortnessProofVersionV5 && layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		chainRows := layout.PackedSigChainGroupCount * layout.PackedSigChainRowsPerGroup
		for i := 0; i < chainRows; i++ {
			rows = append(rows, layout.PackedSigChainBase+i)
		}
	}
	return rows
}

func buildSigShortnessTHatWitnessRows(layout RowLayout) []int {
	return rowLayoutPostSignTHatRows(layout)
}

func buildSigShortnessSupportSlotsForRows(rows []int, pcsNCols int) ([]int, error) {
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	seen := make(map[int]struct{}, len(rows))
	for _, row := range rows {
		if row < 0 {
			return nil, fmt.Errorf("invalid shortness witness index %d", row)
		}
		seen[row%pcsNCols] = struct{}{}
	}
	slots := make([]int, 0, len(seen))
	for slot := range seen {
		slots = append(slots, slot)
	}
	sort.Ints(slots)
	return slots, nil
}

func buildSigShortnessSupportSlots(layout RowLayout, pcsNCols int) ([]int, error) {
	return buildSigShortnessSupportSlotsForVersion(layout, pcsNCols, sigShortnessProofVersionV2)
}

func buildSigShortnessSupportSlotsForVersion(layout RowLayout, pcsNCols int, version int) ([]int, error) {
	return buildSigShortnessSupportSlotsForRows(buildSigShortnessWitnessPolyIndicesForVersion(layout, version), pcsNCols)
}

func appendSigShortnessUvarint(dst []byte, v int) []byte {
	if v < 0 {
		v = 0
	}
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(v))
	return append(dst, buf[:n]...)
}

func sigShortnessV5WitnessNColsFromProof(proof *Proof) int {
	if proof == nil {
		return 0
	}
	if proof.NColsUsed > 0 {
		return proof.NColsUsed
	}
	return proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth
}

func computeSigShortnessHiddenProofDigest(proof *Proof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil hidden shortness proof")
	}
	proof.syncPCSCompat()
	decs.PackOpening(resolveProofPCSOpening(proof))
	decs.PackOpening(proof.QOpening)
	payload, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("marshal hidden shortness proof: %w", err)
	}
	sum := sha256.Sum256(payload)
	return append([]byte(nil), sum[:]...), nil
}

func buildSigShortnessV5BindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV5 || sig.V5 == nil {
		return nil, nil
	}
	if sig.SupportSlots != nil || sig.Opening != nil {
		return nil, fmt.Errorf("sig shortness V5 must not populate legacy opening fields")
	}
	cfg := layout.CoeffNativeSig
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("missing witness ncols for sig shortness V5 binding")
	}
	if cfg.PackedSigComponents <= 0 || cfg.PackedSigBlocks <= 0 || cfg.PackedSigBlockWidth <= 0 {
		return nil, fmt.Errorf("invalid literal packed coeff-native layout: comps=%d blocks=%d width=%d", cfg.PackedSigComponents, cfg.PackedSigBlocks, cfg.PackedSigBlockWidth)
	}
	buf := make([]byte, 0, len(sig.V5.ExactHeads.Bits)+128)
	buf = append(buf, []byte("spruce.sig_shortness.v5/exact_sig_heads_v1")...)
	buf = appendSigShortnessUvarint(buf, int(sig.V5.Mode))
	buf = appendSigShortnessUvarint(buf, sig.V5.Radix)
	buf = appendSigShortnessUvarint(buf, sig.V5.Digits)
	buf = appendSigShortnessUvarint(buf, witnessNCols)
	buf = appendSigShortnessUvarint(buf, cfg.PackedSigComponents)
	buf = appendSigShortnessUvarint(buf, cfg.PackedSigBlocks)
	buf = appendSigShortnessUvarint(buf, cfg.PackedSigBlockWidth)
	buf = appendSigShortnessUvarint(buf, rowLayoutReplayTHatCount(layout))
	buf = append(buf, sig.V5.ExactHeads.BitWidth)
	buf = appendSigShortnessUvarint(buf, len(sig.V5.ExactHeads.Bits))
	buf = append(buf, sig.V5.ExactHeads.Bits...)
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...), nil
}

func buildSigShortnessV6BindingDigest(sig *SigShortnessProof) ([]byte, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV6 || sig.V6 == nil {
		return nil, nil
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil {
		return nil, fmt.Errorf("sig shortness V6 must not populate legacy or V5 fields")
	}
	hiddenDigest, err := computeSigShortnessHiddenProofDigest(sig.V6.HiddenProof)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(hiddenDigest)+64)
	buf = append(buf, []byte("spruce.sig_shortness.v6/hidden_smallwood_v1")...)
	buf = appendSigShortnessUvarint(buf, int(sig.V6.Mode))
	buf = appendSigShortnessUvarint(buf, sig.V6.Radix)
	buf = appendSigShortnessUvarint(buf, sig.V6.Digits)
	buf = append(buf, hiddenDigest...)
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...), nil
}

func buildSigShortnessBindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil {
		return nil, nil
	}
	switch sig.Version {
	case sigShortnessProofVersionV7:
		return nil, nil
	case sigShortnessProofVersionV5:
		return buildSigShortnessV5BindingDigest(sig, layout, witnessNCols)
	case sigShortnessProofVersionV6:
		return buildSigShortnessV6BindingDigest(sig)
	default:
		return nil, nil
	}
}

func packSigShortnessV5ExactHeads(sigHeads [][][]uint64) (SigShortnessPackedMatrix, error) {
	if len(sigHeads) == 0 {
		return SigShortnessPackedMatrix{}, fmt.Errorf("empty signature heads")
	}
	rows := make([][]uint64, 0, len(sigHeads)*len(sigHeads[0]))
	for comp := range sigHeads {
		for block := range sigHeads[comp] {
			rows = append(rows, append([]uint64(nil), sigHeads[comp][block]...))
		}
	}
	bits, _, _, width := decs.PackUintMatrix(rows)
	return SigShortnessPackedMatrix{
		Bits:     bits,
		BitWidth: uint8(width),
	}, nil
}

func unpackSigShortnessV5ExactHeads(layout RowLayout, packed SigShortnessPackedMatrix) ([][][]uint64, error) {
	cfg := layout.CoeffNativeSig
	if cfg.PackedSigComponents <= 0 || cfg.PackedSigBlocks <= 0 || cfg.PackedSigBlockWidth <= 0 {
		return nil, fmt.Errorf("invalid packed signature layout: comps=%d blocks=%d width=%d", cfg.PackedSigComponents, cfg.PackedSigBlocks, cfg.PackedSigBlockWidth)
	}
	rows, gotRows, gotCols, gotWidth, err := decs.UnpackUintMatrix(packed.Bits)
	if err != nil {
		return nil, fmt.Errorf("unpack exact sig heads: %w", err)
	}
	wantRows := cfg.PackedSigComponents * cfg.PackedSigBlocks
	wantCols := cfg.PackedSigBlockWidth
	if gotRows != wantRows || gotCols != wantCols {
		return nil, fmt.Errorf("exact sig heads dims=%dx%d want %dx%d", gotRows, gotCols, wantRows, wantCols)
	}
	if packed.BitWidth != 0 && uint8(gotWidth) != packed.BitWidth {
		return nil, fmt.Errorf("exact sig heads bit width=%d want %d", gotWidth, packed.BitWidth)
	}
	out := make([][][]uint64, cfg.PackedSigComponents)
	row := 0
	for comp := 0; comp < cfg.PackedSigComponents; comp++ {
		out[comp] = make([][]uint64, cfg.PackedSigBlocks)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			out[comp][block] = append([]uint64(nil), rows[row]...)
			row++
		}
	}
	return out, nil
}

func buildSigShortnessV5THatOpening(
	pk *lvcs.ProverKey,
	root [16]byte,
	layout RowLayout,
	pcsNCols int,
) ([]int, *decs.DECSOpening, error) {
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	rows := buildSigShortnessTHatWitnessRows(layout)
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("missing replay T-hat rows")
	}
	slots, err := buildSigShortnessSupportSlotsForRows(rows, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	opening := cloneDECSOpening(lvcs.EvalFinish(pk, slots).DECSOpen)
	// The reduced one-block path safely reconstructs omitted M-values from the
	// main proof's authenticated R rows. The full replay path currently needs
	// the explicit M-values to keep the multi-slot subset opening stable.
	if rowLayoutReplayTHatCount(layout) <= 1 {
		omitAllRowOpeningMvals(opening)
	}
	decs.PackOpening(opening)
	return slots, opening, nil
}

func validateSigShortnessV5Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV5 {
		return nil
	}
	if sig.V5 == nil {
		return fmt.Errorf("missing sig shortness V5 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil {
		return fmt.Errorf("sig shortness V5 must not populate legacy opening fields")
	}
	if sig.V5.Mode != sigShortnessV5ModeExactSigHeads {
		return fmt.Errorf("unsupported sig shortness V5 mode %d", sig.V5.Mode)
	}
	if sig.V5.THatOpening == nil {
		return fmt.Errorf("missing sig shortness V5 T-hat opening")
	}
	return nil
}

func validateSigShortnessV6Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV6 {
		return nil
	}
	if sig.V6 == nil {
		return fmt.Errorf("missing sig shortness V6 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil {
		return fmt.Errorf("sig shortness V6 must not populate legacy or V5 fields")
	}
	if sig.V6.Mode != sigShortnessV6ModeHiddenSmallWood {
		return fmt.Errorf("unsupported sig shortness V6 mode %d", sig.V6.Mode)
	}
	if sig.V6.HiddenProof == nil {
		return fmt.Errorf("missing sig shortness V6 hidden proof")
	}
	if sig.V6.THatOpening == nil {
		return fmt.Errorf("missing sig shortness V6 T-hat opening")
	}
	return nil
}

func validateSigShortnessV7Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV7 {
		return nil
	}
	if sig.V7 == nil {
		return fmt.Errorf("missing sig shortness V7 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil {
		return fmt.Errorf("sig shortness V7 must not populate legacy, V5, or V6 fields")
	}
	if sig.V7.Mode != sigShortnessV7ModeInlinedMain {
		return fmt.Errorf("unsupported sig shortness V7 mode %d", sig.V7.Mode)
	}
	if proof.RowLayout.PackedSigChainBase < 0 || proof.RowLayout.PackedSigChainGroupCount <= 0 || proof.RowLayout.PackedSigChainRowsPerGroup <= 0 {
		return fmt.Errorf("missing inlined packed shortness layout for V7")
	}
	return nil
}

func validateSortedUniqueIndices(label string, values []int) error {
	for i, v := range values {
		if v < 0 {
			return fmt.Errorf("%s[%d]=%d is negative", label, i, v)
		}
		if i == 0 {
			continue
		}
		if values[i-1] >= v {
			return fmt.Errorf("%s is not strictly increasing at %d (%d >= %d)", label, i, values[i-1], v)
		}
	}
	return nil
}

func deriveMainPCSSubsetParams(proof *Proof) (decs.Params, int, error) {
	if proof == nil {
		return decs.Params{}, 0, fmt.Errorf("nil proof")
	}
	pcsOpening := resolveProofPCSOpening(proof)
	if pcsOpening == nil {
		return decs.Params{}, 0, fmt.Errorf("missing PCS opening")
	}
	rowDegBound := proof.RowDegreeBound
	if rowDegBound <= 0 {
		rowDegBound = proof.MaskDegreeBound
	}
	if rowDegBound <= 0 {
		return decs.Params{}, 0, fmt.Errorf("missing row degree bound")
	}
	nonceBytes := 16
	if pcsOpening.NonceBytes > 0 {
		nonceBytes = pcsOpening.NonceBytes
	} else if len(pcsOpening.Nonces) > 0 && len(pcsOpening.Nonces[0]) > 0 {
		nonceBytes = len(pcsOpening.Nonces[0])
	}
	if pcsOpening.Eta <= 0 {
		return decs.Params{}, 0, fmt.Errorf("missing PCS eta")
	}
	if pcsOpening.R <= 0 {
		return decs.Params{}, 0, fmt.Errorf("missing PCS row count")
	}
	return decs.Params{
		Degree:     rowDegBound,
		Eta:        pcsOpening.Eta,
		NonceBytes: nonceBytes,
	}, pcsOpening.R, nil
}

func deriveMainPCSSubsetGamma(proof *Proof, rowCount int, q uint64) ([][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if rowCount <= 0 {
		return nil, fmt.Errorf("invalid row count %d", rowCount)
	}
	lambda := proof.Lambda
	if lambda <= 0 {
		lambda = 256
	}
	fs := NewFS(NewShake256XOF(fsDigestBytes), proof.Salt, FSParams{Lambda: lambda, Kappa: proof.Kappa})
	material0 := [][]byte{append([]byte(nil), proof.Root[:]...)}
	if len(proof.LabelsDigest) > 0 {
		material0 = append(material0, proof.LabelsDigest)
	}
	if digest, err := buildSigShortnessBindingDigest(proof.SigShortness, proof.RowLayout, sigShortnessV5WitnessNColsFromProof(proof)); err != nil {
		return nil, err
	} else if len(digest) > 0 {
		material0 = append(material0, digest)
	}
	seed, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0])
	if err != nil {
		return nil, fmt.Errorf("main FS round 0: %w", err)
	}
	pcsOpening := resolveProofPCSOpening(proof)
	return sampleFSMatrix(pcsOpening.Eta, rowCount, q, newFSRNG("Gamma", seed)), nil
}

func deriveProofExplicitDomainPoints(proof *Proof, q uint64, witnessNCols, pcsNCols int) ([]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if proof.DomainMode != DomainModeExplicit {
		return nil, fmt.Errorf("unsupported domain mode %d", proof.DomainMode)
	}
	ell := len(proof.Tail)
	if ell <= 0 {
		return nil, fmt.Errorf("missing proof tail for explicit domain derivation")
	}
	nLeaves := proof.NLeavesUsed
	if nLeaves <= 0 {
		return nil, fmt.Errorf("missing proof nleaves")
	}
	_, domainPoints, err := deriveExplicitDomainForRelation(q, nLeaves, witnessNCols, pcsNCols, ell, proof.HashRelation)
	if err != nil {
		return nil, err
	}
	return domainPoints, nil
}

func prepareSigShortnessOpeningForVerify(
	opening *decs.DECSOpening,
	gamma [][]uint64,
	rPolys []*ring.Poly,
	domainPoints []uint64,
	ringQ *ring.Ring,
	replayWitnessRows int,
) (*decs.DECSOpening, error) {
	if opening == nil {
		return nil, fmt.Errorf("missing sig shortness opening")
	}
	open := expandPackedOpening(opening)
	if open.FormatVersion == 1 {
		if err := reconstructSigShortnessOpeningPvals(open, replayWitnessRows); err != nil {
			return nil, fmt.Errorf("reconstruct sig shortness P values: %w", err)
		}
	}
	if open.MFormatVersion == 1 {
		if err := reconstructRowOpeningMvals(open, gamma, rPolys, domainPoints, ringQ); err != nil {
			return nil, fmt.Errorf("reconstruct sig shortness M values: %w", err)
		}
	}
	return open, nil
}

func sigShortnessReplayWitnessRows(proof *Proof) (int, error) {
	if proof == nil {
		return 0, fmt.Errorf("nil proof")
	}
	replayWitnessRows := proof.PCSGeometry.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = proof.MaskRowOffset
	}
	if replayWitnessRows <= 0 {
		return 0, fmt.Errorf("missing replay witness row count")
	}
	return replayWitnessRows, nil
}

func maybeCompressSigShortnessOpeningPvals(open *decs.DECSOpening, replayWitnessRows int) error {
	if open == nil || len(open.Pvals) == 0 {
		return nil
	}
	if open.R <= 0 {
		return fmt.Errorf("invalid shortness opening row count R=%d", open.R)
	}
	if replayWitnessRows <= 0 || replayWitnessRows >= open.R {
		return nil
	}
	omitCols := make([]int, open.R-replayWitnessRows)
	for i := range omitCols {
		omitCols[i] = replayWitnessRows + i
	}
	compressed := make([][]uint64, len(open.Pvals))
	canCompress := true
	for t := range open.Pvals {
		if len(open.Pvals[t]) != open.R {
			return fmt.Errorf("shortness opening P row %d width=%d want=%d", t, len(open.Pvals[t]), open.R)
		}
		for _, col := range omitCols {
			if open.Pvals[t][col] != 0 {
				canCompress = false
				break
			}
		}
		if !canCompress {
			break
		}
		compressed[t] = append([]uint64(nil), open.Pvals[t][:replayWitnessRows]...)
	}
	if !canCompress {
		return nil
	}
	open.FormatVersion = 1
	open.PColsEncoded = replayWitnessRows
	open.POmitCols = omitCols
	open.Pvals = compressed
	return nil
}

func reconstructSigShortnessOpeningPvals(open *decs.DECSOpening, replayWitnessRows int) error {
	if open == nil {
		return fmt.Errorf("nil opening")
	}
	if open.FormatVersion != 1 {
		return nil
	}
	if open.R <= 0 {
		return fmt.Errorf("invalid shortness opening row count R=%d", open.R)
	}
	if replayWitnessRows <= 0 || replayWitnessRows >= open.R {
		return fmt.Errorf("invalid shortness replay witness rows=%d for R=%d", replayWitnessRows, open.R)
	}
	expectedOmit := make([]int, open.R-replayWitnessRows)
	for i := range expectedOmit {
		expectedOmit[i] = replayWitnessRows + i
	}
	if !equalIntSlices(open.POmitCols, expectedOmit) {
		return fmt.Errorf("shortness opening POmitCols=%v want %v", open.POmitCols, expectedOmit)
	}
	if open.PColsEncoded != replayWitnessRows {
		return fmt.Errorf("shortness opening PColsEncoded=%d want %d", open.PColsEncoded, replayWitnessRows)
	}
	if len(open.Pvals) != open.EntryCount() {
		return fmt.Errorf("shortness opening P row count=%d want=%d", len(open.Pvals), open.EntryCount())
	}
	fullRows := make([][]uint64, open.EntryCount())
	for t := range open.Pvals {
		if len(open.Pvals[t]) != replayWitnessRows {
			return fmt.Errorf("shortness opening P row %d width=%d want=%d", t, len(open.Pvals[t]), replayWitnessRows)
		}
		full := make([]uint64, open.R)
		copy(full, open.Pvals[t])
		fullRows[t] = full
	}
	open.Pvals = fullRows
	open.PvalsBits = nil
	open.PvalsBitWidth = 0
	open.FormatVersion = 0
	open.PColsEncoded = 0
	open.POmitCols = nil
	return nil
}

type sigShortnessSupportView struct {
	opening           *decs.DECSOpening
	slotPos           map[int]int
	q                 uint64
	pcsNCols          int
	witnessNCols      int
	rowsPerBlock      int
	replayWitnessRows int
}

func newSigShortnessSupportView(proof *Proof, opening *decs.DECSOpening, supportSlots []int, witnessNCols, pcsNCols, theta int, q uint64) (*sigShortnessSupportView, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if opening == nil {
		return nil, fmt.Errorf("missing shortness opening")
	}
	if err := validateSortedUniqueIndices("sig shortness support slots", supportSlots); err != nil {
		return nil, err
	}
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("invalid witness ncols=%d", witnessNCols)
	}
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if theta <= 1 {
		return nil, fmt.Errorf("compressed-row sig shortness requires theta>1, got %d", theta)
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, err
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 {
		return nil, fmt.Errorf("invalid rows/block=%d", rowsPerBlock)
	}
	if replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("replay witness rows=%d not divisible by rows/block=%d", replayWitnessRows, rowsPerBlock)
	}
	open := expandPackedOpening(opening)
	if open.EntryCount() != len(supportSlots) {
		return nil, fmt.Errorf("shortness opening entry count=%d want %d", open.EntryCount(), len(supportSlots))
	}
	openSlots := open.AllIndices()
	if !equalIntSlices(openSlots, supportSlots) {
		return nil, fmt.Errorf("shortness opening slots mismatch")
	}
	if open.R < replayWitnessRows {
		return nil, fmt.Errorf("shortness opening row count=%d want >=%d", open.R, replayWitnessRows)
	}
	slotPos := make(map[int]int, len(supportSlots))
	for i, slot := range supportSlots {
		slotPos[slot] = i
	}
	return &sigShortnessSupportView{
		opening:           open,
		slotPos:           slotPos,
		q:                 q,
		pcsNCols:          pcsNCols,
		witnessNCols:      witnessNCols,
		rowsPerBlock:      rowsPerBlock,
		replayWitnessRows: replayWitnessRows,
	}, nil
}

func (v *sigShortnessSupportView) witnessValue(witnessPolyIdx, omegaRow int) (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("nil shortness support view")
	}
	if witnessPolyIdx < 0 {
		return 0, fmt.Errorf("invalid witness polynomial index %d", witnessPolyIdx)
	}
	if omegaRow < 0 || omegaRow >= v.witnessNCols {
		return 0, fmt.Errorf("invalid omega row %d", omegaRow)
	}
	block := witnessPolyIdx / v.pcsNCols
	slot := witnessPolyIdx % v.pcsNCols
	pos, ok := v.slotPos[slot]
	if !ok {
		return 0, fmt.Errorf("missing support slot %d", slot)
	}
	rowIdx := block*v.rowsPerBlock + omegaRow
	if rowIdx < 0 || rowIdx >= v.replayWitnessRows {
		return 0, fmt.Errorf("witness row overflow for poly=%d block=%d row=%d limit=%d", witnessPolyIdx, block, rowIdx, v.replayWitnessRows)
	}
	return decs.GetOpeningPval(v.opening, pos, rowIdx) % v.q, nil
}

func collectSigShortnessDigitHeads(proof *Proof, view *sigShortnessSupportView, spec LinfSpec) ([][][][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	if cfg.PackedSigComponents <= 0 || cfg.PackedSigBlocks <= 0 {
		return nil, fmt.Errorf("invalid packed signature layout: comps=%d blocks=%d", cfg.PackedSigComponents, cfg.PackedSigBlocks)
	}
	if spec.L <= 0 {
		return nil, fmt.Errorf("invalid shortness digit count=%d", spec.L)
	}
	out := make([][][][]uint64, cfg.PackedSigComponents)
	for comp := 0; comp < cfg.PackedSigComponents; comp++ {
		out[comp] = make([][][]uint64, cfg.PackedSigBlocks)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			out[comp][block] = make([][]uint64, spec.L)
			for lane := 0; lane < spec.L; lane++ {
				digitRow := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
				if digitRow < 0 {
					return nil, fmt.Errorf("invalid packed digit row for comp=%d block=%d lane=%d", comp, block, lane)
				}
				head := make([]uint64, view.witnessNCols)
				for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
					digitField, err := view.witnessValue(digitRow, omegaRow)
					if err != nil {
						return nil, fmt.Errorf("digit[%d,%d,%d,%d]: %w", comp, block, lane, omegaRow, err)
					}
					head[omegaRow] = digitField % view.q
				}
				out[comp][block][lane] = head
			}
		}
	}
	return out, nil
}

func verifySigShortnessDigitHeads(proof *Proof, spec LinfSpec, sigLimbHeads [][][][]uint64, q uint64) error {
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return fmt.Errorf("sig shortness requires literal packed v3 layout")
	}
	if spec.UsesAbsRow {
		return fmt.Errorf("packed raw signature shortness requires signed chain mode")
	}
	wantRowsPer, err := signaturePackedChainRowsPerGroupForOpts(spec, SimOpts{}, layout.PackedSigChainGroupSize)
	if err != nil {
		return fmt.Errorf("rows/group: %w", err)
	}
	if layout.PackedSigChainRowsPerGroup != wantRowsPer {
		return fmt.Errorf("packed shortness rows/group=%d want %d", layout.PackedSigChainRowsPerGroup, wantRowsPer)
	}
	wantGroups := cfg.PackedSigComponents * cfg.PackedSigBlocks
	if layout.PackedSigChainGroupCount != wantGroups {
		return fmt.Errorf("packed shortness group count=%d want %d", layout.PackedSigChainGroupCount, wantGroups)
	}
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			for omegaRow := 0; omegaRow < len(sigLimbHeads[comp][block][0]); omegaRow++ {
				digits := make([]int64, spec.L)
				rhs := uint64(0)
				for lane := 0; lane < spec.L; lane++ {
					if comp >= len(sigLimbHeads) || block >= len(sigLimbHeads[comp]) || lane >= len(sigLimbHeads[comp][block]) || omegaRow >= len(sigLimbHeads[comp][block][lane]) {
						return fmt.Errorf("missing digit head for comp=%d block=%d lane=%d omega=%d", comp, block, lane, omegaRow)
					}
					digitField := sigLimbHeads[comp][block][lane][omegaRow] % q
					digit := centeredLift(digitField, q)
					if digit < int64(spec.DigitLo[lane]) || digit > int64(spec.DigitHi[lane]) {
						return fmt.Errorf("digit[%d,%d,%d,%d]=%d outside [%d,%d]", comp, block, lane, omegaRow, digit, spec.DigitLo[lane], spec.DigitHi[lane])
					}
					if EvalPoly(spec.PDi[lane], digitField%q, q) != 0 {
						return fmt.Errorf("digit membership failed at comp=%d block=%d lane=%d omega=%d", comp, block, lane, omegaRow)
					}
					digits[lane] = digit
					rhs = lvcs.MulAddMod64(rhs, spec.RPows[lane]%q, digitField%q, q)
				}
				if recomposeLinfDigits(digits, spec) != centeredLift(rhs, q) {
					return fmt.Errorf("signed reconstruction mismatch at comp=%d block=%d omega=%d", comp, block, omegaRow)
				}
			}
		}
	}
	return nil
}

func verifySigShortnessPackedSourceValues(proof *Proof, view *sigShortnessSupportView, spec LinfSpec, sigLimbHeads [][][][]uint64) error {
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	if view == nil {
		return fmt.Errorf("nil support view")
	}
	if err := verifySigShortnessDigitHeads(proof, spec, sigLimbHeads, view.q); err != nil {
		return err
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	wantGroups := cfg.PackedSigComponents * cfg.PackedSigBlocks
	if cfg.PackedSigCount <= 0 || cfg.PackedSigBase < 0 {
		return nil
	}
	if cfg.PackedSigCount != wantGroups {
		return fmt.Errorf("packed signature source rows=%d want %d", cfg.PackedSigCount, wantGroups)
	}
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			sourceRow := rowLayoutCoeffNativePackedSigIndex(layout, comp, block)
			if sourceRow < 0 {
				return fmt.Errorf("invalid packed source row for comp=%d block=%d", comp, block)
			}
			for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
				sourceField, err := view.witnessValue(sourceRow, omegaRow)
				if err != nil {
					return fmt.Errorf("source[%d,%d,%d]: %w", comp, block, omegaRow, err)
				}
				rhs := uint64(0)
				for lane := 0; lane < spec.L; lane++ {
					rhs = lvcs.MulAddMod64(rhs, spec.RPows[lane]%view.q, sigLimbHeads[comp][block][lane][omegaRow]%view.q, view.q)
				}
				if rhs%view.q != sourceField%view.q {
					return fmt.Errorf("packed reconstruction failed at comp=%d block=%d omega=%d", comp, block, omegaRow)
				}
			}
		}
	}
	return nil
}

func deriveSigShortnessExpectedTHatHeads(proof *Proof, ringQ *ring.Ring, pub PublicInputs, omegaWitness []uint64, spec LinfSpec, sigLimbHeads [][][][]uint64) ([][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(sigLimbHeads) == 0 || len(sigLimbHeads[0]) == 0 || len(sigLimbHeads[0][0]) == 0 {
		return nil, fmt.Errorf("empty shortness digit heads")
	}
	ncols := len(sigLimbHeads[0][0][0])
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid shortness support width")
	}
	if len(omegaWitness) < ncols {
		return nil, fmt.Errorf("omega witness len=%d < support width=%d", len(omegaWitness), ncols)
	}
	layout := proof.RowLayout
	sourceBlocks := layout.CoeffNativeSig.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid packed signature block count=%d", sourceBlocks)
	}
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		return nil, fmt.Errorf("missing replay T-hat count")
	}
	packedSigHeads := reconstructPackedSigHeadsFromLimbHeads(sigLimbHeads, spec, ringQ.Modulus[0])
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(ringQ, packedSigHeads, ncols)
	if err != nil {
		return nil, fmt.Errorf("build signature hats from digit-backed source heads: %w", err)
	}
	tHatHeads, err := buildTHatHeadsFromSigHatHeads(ringQ, pub, omegaWitness[:ncols], sigHatHeads, replayTHatCount, sourceBlocks)
	if err != nil {
		return nil, fmt.Errorf("build T-hat heads from shortness digits: %w", err)
	}
	return tHatHeads, nil
}

func verifySigShortnessTHatSupportValues(proof *Proof, view *sigShortnessSupportView, expectedTHatHeads [][]uint64) error {
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	if view == nil {
		return fmt.Errorf("nil support view")
	}
	layout := proof.RowLayout
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		return fmt.Errorf("missing replay T-hat count")
	}
	if len(expectedTHatHeads) != replayTHatCount {
		return fmt.Errorf("expected T-hat block count=%d want %d", len(expectedTHatHeads), replayTHatCount)
	}
	for block := 0; block < replayTHatCount; block++ {
		tHatRow := rowLayoutPostSignTHatIndex(layout, block)
		if tHatRow < 0 {
			return fmt.Errorf("invalid T-hat row for block %d", block)
		}
		if len(expectedTHatHeads[block]) != view.witnessNCols {
			return fmt.Errorf("expected T-hat width=%d want %d for block %d", len(expectedTHatHeads[block]), view.witnessNCols, block)
		}
		for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
			got, err := view.witnessValue(tHatRow, omegaRow)
			if err != nil {
				return fmt.Errorf("T-hat[%d,%d]: %w", block, omegaRow, err)
			}
			want := expectedTHatHeads[block][omegaRow] % view.q
			if got%view.q != want {
				return fmt.Errorf("T-hat mismatch at block=%d omega=%d", block, omegaRow)
			}
		}
	}
	return nil
}

func verifySigShortnessSupportValues(proof *Proof, view *sigShortnessSupportView, spec LinfSpec) ([][][][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	sigLimbHeads, err := collectSigShortnessDigitHeads(proof, view, spec)
	if err != nil {
		return nil, err
	}
	if err := verifySigShortnessPackedSourceValues(proof, view, spec, sigLimbHeads); err != nil {
		return nil, err
	}
	return sigLimbHeads, nil
}

func verifySigShortnessDigitOnlySupportValues(proof *Proof, view *sigShortnessSupportView, spec LinfSpec) ([][][][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	sigLimbHeads, err := collectSigShortnessDigitHeads(proof, view, spec)
	if err != nil {
		return nil, err
	}
	if err := verifySigShortnessDigitHeads(proof, spec, sigLimbHeads, view.q); err != nil {
		return nil, err
	}
	return sigLimbHeads, nil
}

func encodeSigShortnessTHatHeads(tHatHeads [][]uint64) []byte {
	bits, _, _, _ := decs.PackUintMatrix(tHatHeads)
	return append([]byte(nil), bits...)
}

func encodeSigShortnessSpec(mode uint8, radix, digits int) []byte {
	buf := make([]byte, 0, 32)
	buf = append(buf, byte(mode))
	buf = appendSigShortnessUvarint(buf, radix)
	buf = appendSigShortnessUvarint(buf, digits)
	return buf
}

func extractSigShortnessTHatHeadsFromView(proof *Proof, view *sigShortnessSupportView) ([][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	replayTHatCount := rowLayoutReplayTHatCount(proof.RowLayout)
	if replayTHatCount <= 0 {
		return nil, fmt.Errorf("missing replay T-hat count")
	}
	out := make([][]uint64, replayTHatCount)
	for block := 0; block < replayTHatCount; block++ {
		rowIdx := rowLayoutPostSignTHatIndex(proof.RowLayout, block)
		if rowIdx < 0 {
			return nil, fmt.Errorf("invalid replay T-hat row for block %d", block)
		}
		head := make([]uint64, view.witnessNCols)
		for col := 0; col < view.witnessNCols; col++ {
			val, err := view.witnessValue(rowIdx, col)
			if err != nil {
				return nil, fmt.Errorf("extract T-hat[%d,%d]: %w", block, col, err)
			}
			head[col] = val % view.q
		}
		out[block] = head
	}
	return out, nil
}

func buildSigShortnessHiddenPublicInputs(mainPub PublicInputs, mainRoot [16]byte, tHatHeads [][]uint64, mode uint8, radix, digits int) PublicInputs {
	extras := map[string]interface{}{
		sigShortnessTHatExtraKey:     encodeSigShortnessTHatHeads(tHatHeads),
		sigShortnessMainRootExtraKey: append([]byte(nil), mainRoot[:]...),
		sigShortnessSpecExtraKey:     encodeSigShortnessSpec(mode, radix, digits),
	}
	return PublicInputs{
		A:            mainPub.A,
		HashRelation: mainPub.HashRelation,
		Extras:       extras,
	}
}

func defaultSigShortnessHiddenLVCSNCols(witnessNCols, logicalWitnessPolys int) int {
	hiddenLVCSNCols := logicalWitnessPolys
	if hiddenLVCSNCols <= 0 {
		hiddenLVCSNCols = witnessNCols
	}
	if hiddenLVCSNCols < witnessNCols {
		hiddenLVCSNCols = witnessNCols
	}
	if hiddenLVCSNCols > 256 {
		hiddenLVCSNCols = 256
	}
	return hiddenLVCSNCols
}

func defaultSigShortnessHiddenNLeaves(hiddenLVCSNCols int) int {
	hiddenTheta := 2
	minLeaves := hiddenLVCSNCols + 2
	hiddenLeaves := 1
	for hiddenLeaves < minLeaves {
		hiddenLeaves <<= 1
	}
	if hiddenLeaves < 512 {
		hiddenLeaves = 512
	}
	_ = hiddenTheta
	return hiddenLeaves
}

func buildSigShortnessHiddenOpts(baseOpts SimOpts, profile string, witnessNCols, logicalWitnessPolys int) SimOpts {
	shape := sigShortnessHiddenCandidateShape{Profile: profile}
	return buildSigShortnessHiddenOptsForShape(baseOpts, shape, witnessNCols, logicalWitnessPolys)
}

func buildSigShortnessHiddenOptsForShape(baseOpts SimOpts, shape sigShortnessHiddenCandidateShape, witnessNCols, logicalWitnessPolys int) SimOpts {
	hiddenLVCSNCols := shape.HiddenLVCSNCols
	if hiddenLVCSNCols <= 0 {
		hiddenLVCSNCols = defaultSigShortnessHiddenLVCSNCols(witnessNCols, logicalWitnessPolys)
	}
	hiddenLeaves := shape.HiddenNLeaves
	if hiddenLeaves <= 0 {
		hiddenLeaves = defaultSigShortnessHiddenNLeaves(hiddenLVCSNCols)
	}
	profile := shape.Profile
	if profile == "" {
		profile = sigShortnessHiddenPrimaryProfile
	}
	opts := SimOpts{
		Credential:          true,
		DomainMode:          DomainModeExplicit,
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: profile,
		ShowingPreset:       ShowingPresetCustom,
		NCols:               witnessNCols,
		PCSNCols:            hiddenLVCSNCols,
		LVCSNCols:           hiddenLVCSNCols,
		Theta:               2,
		Rho:                 1,
		Ell:                 2,
		EllPrime:            1,
		Eta:                 8,
		NLeaves:             hiddenLeaves,
		Kappa:               baseOpts.Kappa,
	}
	if shape.RawOverride {
		opts.SigShortnessRadix = shape.Radix
		opts.SigShortnessL = shape.Digits
	}
	opts.applyDefaults()
	return opts
}

func sigShortnessHiddenShapeLabel(shape sigShortnessHiddenCandidateShape) string {
	if shape.Label != "" {
		return shape.Label
	}
	if shape.RawOverride {
		return fmt.Sprintf("minimal_r%d_l%d", shape.Radix, shape.Digits)
	}
	if strings.TrimSpace(shape.Profile) != "" {
		return shape.Profile
	}
	return signatureShortnessProfileLabelFromMetrics(shape.Radix, shape.Digits)
}

func buildSigShortnessProfileSimOpts(shape sigShortnessHiddenCandidateShape) SimOpts {
	opts := SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: shape.Profile,
	}
	if shape.RawOverride {
		opts.SigShortnessRadix = shape.Radix
		opts.SigShortnessL = shape.Digits
	}
	return opts
}

func sigShortnessHiddenLogicalWitnessPolys(ringQ *ring.Ring, cn *CoeffNativeShowingWitness, witnessNCols int, digits int) int {
	if ringQ == nil || cn == nil || witnessNCols <= 0 || digits <= 0 {
		return 0
	}
	return len(cn.Sig) * (int(ringQ.N) / witnessNCols) * digits
}

func buildSigShortnessHiddenCandidateWithPolicy(
	ringQ *ring.Ring,
	root [16]byte,
	layout RowLayout,
	cn *CoeffNativeShowingWitness,
	pub PublicInputs,
	omegaWitness []uint64,
	witnessNCols int,
	mainOpts SimOpts,
	shape sigShortnessHiddenCandidateShape,
	enforceTheoremFloor bool,
) (*sigShortnessHiddenBuiltCandidate, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, fmt.Errorf("nil coeff-native showing witness")
	}
	specOpts := SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: shape.Profile,
	}
	if shape.RawOverride {
		specOpts.SigShortnessRadix = shape.Radix
		specOpts.SigShortnessL = shape.Digits
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], specOpts)
	if err != nil {
		return nil, err
	}
	logicalWitnessPolys := sigShortnessHiddenLogicalWitnessPolys(ringQ, cn, witnessNCols, spec.L)
	hiddenOpts := buildSigShortnessHiddenOptsForShape(mainOpts, shape, witnessNCols, logicalWitnessPolys)
	hiddenLVCSNCols := resolvePCSNCols(hiddenOpts, witnessNCols)
	if hiddenLVCSNCols <= 0 {
		hiddenLVCSNCols = witnessNCols
	}
	hiddenOmega, hiddenDomainPoints, err := deriveExplicitDomainForRelation(
		ringQ.Modulus[0],
		hiddenOpts.NLeaves,
		witnessNCols,
		hiddenLVCSNCols,
		hiddenOpts.Ell,
		pub.HashRelation,
	)
	if err != nil {
		return nil, fmt.Errorf("hidden shortness explicit domain: %w", err)
	}
	hiddenOmegaWitness, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0],
		hiddenOpts.NLeaves,
		witnessNCols,
		hiddenLVCSNCols,
		hiddenOpts.Ell,
		pub.HashRelation,
	)
	if err != nil {
		return nil, fmt.Errorf("hidden shortness witness omega: %w", err)
	}
	packedWitness, err := buildLiteralPackedPolyWitness(
		ringQ,
		cn,
		hiddenOmegaWitness,
		witnessNCols,
		CoeffNativeSigModelLiteralPackedAggregatedV3,
		hiddenOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("hidden literal packed witness: %w", err)
	}
	packedSigHeads := reconstructPackedSigHeadsFromLimbHeads(packedWitness.SigLimbHeads, spec, ringQ.Modulus[0])
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(ringQ, packedSigHeads, witnessNCols)
	if err != nil {
		return nil, fmt.Errorf("hidden sig hat heads: %w", err)
	}
	tHatHeads, err := buildTHatHeadsFromSigHatHeads(
		ringQ,
		pub,
		hiddenOmegaWitness,
		sigHatHeads,
		rowLayoutReplayTHatCount(layout),
		layout.CoeffNativeSig.PackedSigBlocks,
	)
	if err != nil {
		return nil, fmt.Errorf("hidden T-hat heads: %w", err)
	}
	hiddenLayout := buildSigShortnessHiddenLayout(layout, spec, witnessNCols)
	hiddenRowsNTT, err := flattenSigShortnessHiddenWitnessRows(hiddenLayout, packedWitness, spec)
	if err != nil {
		return nil, err
	}
	hiddenRows := make([]*ring.Poly, len(hiddenRowsNTT))
	for i := range hiddenRowsNTT {
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(hiddenRowsNTT[i], coeff)
		hiddenRows[i] = coeff
	}
	hiddenSet, err := buildSigShortnessHiddenConstraintSet(ringQ, hiddenLayout, pub, hiddenOmegaWitness, hiddenRowsNTT, tHatHeads, spec)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness constraint set: %w", err)
	}
	hiddenRowInputs, err := buildRowInputsExplicit(ringQ, hiddenRows, hiddenOmega, hiddenLVCSNCols)
	if err != nil {
		return nil, fmt.Errorf("hidden row inputs: %w", err)
	}
	hiddenWitnessCount := len(hiddenRows)
	if hiddenOpts.Theta <= 1 {
		for i := 0; i < hiddenOpts.Rho; i++ {
			hiddenRows = append(hiddenRows, ringQ.NewPoly())
			hiddenRowInputs = append(hiddenRowInputs, lvcs.RowInput{Head: make([]uint64, hiddenLVCSNCols)})
		}
	}
	hiddenPub := buildSigShortnessHiddenPublicInputs(pub, root, tHatHeads, sigShortnessV6ModeHiddenSmallWood, int(spec.R), spec.L)
	hiddenPrepared := &preparedCredentialBuild{
		rows:                  hiddenRows,
		rowInputs:             hiddenRowInputs,
		rowLayout:             hiddenLayout,
		witnessCount:          hiddenWitnessCount,
		witnessNCols:          witnessNCols,
		omega:                 hiddenOmega,
		omegaWitness:          append([]uint64(nil), hiddenOmegaWitness...),
		domainPoints:          hiddenDomainPoints,
		skipConstraintRebuild: true,
	}
	hiddenProof, err := buildWithConstraintsPrepared(hiddenPub, WitnessInputs{}, hiddenSet, hiddenOpts, fsModeSigShortnessHidden, hiddenPrepared)
	if err != nil {
		return nil, fmt.Errorf("build hidden sig shortness proof: %w", err)
	}
	stripHiddenSigShortnessProofDebug(hiddenProof)
	hiddenReplay, err := buildSigShortnessHiddenReplay(ringQ, hiddenProof, pub, hiddenOmegaWitness, tHatHeads, spec)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness replay: %w", err)
	}
	if err := verifySigShortnessHiddenProof(hiddenProof, hiddenPub, hiddenReplay); err != nil {
		return nil, fmt.Errorf("hidden sig shortness self-check: %w", err)
	}
	hiddenReport, err := BuildProofReport(hiddenProof, hiddenOpts, ringQ)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness report: %w", err)
	}
	if enforceTheoremFloor && hiddenReport.Soundness.TotalBits < 128 {
		return nil, fmt.Errorf("hidden sig shortness theorem floor %.2f < 128.00", hiddenReport.Soundness.TotalBits)
	}
	builtShape := shape
	builtShape.Label = sigShortnessHiddenShapeLabel(shape)
	builtShape.HiddenLVCSNCols = hiddenLVCSNCols
	builtShape.HiddenNLeaves = hiddenOpts.NLeaves
	builtShape.Radix = int(spec.R)
	builtShape.Digits = spec.L
	return &sigShortnessHiddenBuiltCandidate{
		Shape:        builtShape,
		Spec:         spec,
		HiddenOpts:   hiddenOpts,
		HiddenProof:  hiddenProof,
		HiddenReport: hiddenReport,
	}, nil
}

func chooseSigShortnessHiddenShapeLegacyFirstFit(
	ringQ *ring.Ring,
	cn *CoeffNativeShowingWitness,
	omegaWitness []uint64,
	witnessNCols int,
	mainOpts SimOpts,
) (sigShortnessHiddenCandidateShape, error) {
	if ringQ == nil {
		return sigShortnessHiddenCandidateShape{}, fmt.Errorf("nil ring")
	}
	candidates := []string{
		sigShortnessHiddenPrimaryProfile,
		SigShortnessProfileR24L3Compact,
		SigShortnessProfileR11L4Production,
		ResolveSignatureShortnessProfileLabelForOpts(mainOpts),
		SigShortnessProfileR12285L1Research,
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, profile := range candidates {
		if profile == "" {
			continue
		}
		if _, ok := seen[profile]; ok {
			continue
		}
		seen[profile] = struct{}{}
		specOpts := SimOpts{CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3, SigShortnessProfile: profile}
		spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], specOpts)
		if err != nil {
			continue
		}
		logicalWitnessPolys := sigShortnessHiddenLogicalWitnessPolys(ringQ, cn, witnessNCols, spec.L)
		shape := sigShortnessHiddenCandidateShape{
			Label:   profile,
			Profile: profile,
			Radix:   int(spec.R),
			Digits:  spec.L,
		}
		hiddenOpts := buildSigShortnessHiddenOptsForShape(mainOpts, shape, witnessNCols, logicalWitnessPolys)
		if _, err := buildLiteralPackedPolyWitness(ringQ, cn, omegaWitness, witnessNCols, CoeffNativeSigModelLiteralPackedAggregatedV3, hiddenOpts); err == nil {
			shape.HiddenLVCSNCols = resolvePCSNCols(hiddenOpts, witnessNCols)
			shape.HiddenNLeaves = hiddenOpts.NLeaves
			return shape, nil
		}
	}
	return sigShortnessHiddenCandidateShape{}, fmt.Errorf("no hidden shortness profile fit the current signature witness")
}


func buildSigShortnessHiddenLayout(mainLayout RowLayout, spec LinfSpec, witnessNCols int) RowLayout {
	cfgMain := mainLayout.CoeffNativeSig
	logicalWitnessPolys := cfgMain.PackedSigBlocks * cfgMain.PackedSigComponents * spec.L
	return RowLayout{
		SigCount:                   logicalWitnessPolys,
		HasExplicitBaseIdx:         true,
		IdxM1:                      -1,
		IdxM2:                      -1,
		IdxRU0:                     -1,
		IdxRU1:                     -1,
		IdxR:                       -1,
		IdxR0:                      -1,
		IdxR1:                      -1,
		IdxK0:                      -1,
		IdxK1:                      -1,
		IdxMSigmaR1:                -1,
		IdxR0R1:                    -1,
		IdxCarrierM:                -1,
		IdxCarrierCtr:              -1,
		IdxCarrierK:                -1,
		IdxCarrierPreRU:            -1,
		IdxCarrierPreR:             -1,
		IdxTSource:                 -1,
		IdxSigHatBase:              -1,
		SigHatExtraBase:            -1,
		IdxTHatBase:                -1,
		ReplayTHatCount:            0,
		ReplayBlockCount:           0,
		IdxMHatSigma:               -1,
		IdxMHat1:                   -1,
		IdxMHat2:                   -1,
		IdxRHat0:                   -1,
		IdxRHat1:                   -1,
		IdxMSigmaR1Hat:             -1,
		IdxR0R1Hat:                 -1,
		ChainBase:                  -1,
		ChainRowsPerSig:            0,
		PackedSigChainBase:         0,
		PackedSigChainGroupCount:   cfgMain.PackedSigBlocks * cfgMain.PackedSigComponents,
		PackedSigChainGroupSize:    1,
		PackedSigChainRowsPerGroup: spec.L,
		SigSignedChain:             false,
		MsgChainBase:               -1,
		RndChainBase:               -1,
		X1ChainBase:                -1,
		MsgRangeBase:               -1,
		RndRangeBase:               -1,
		X1RangeBase:                -1,
		SigBlocks:                  cfgMain.PackedSigBlocks,
		CoeffNativeSig: CoeffNativeSigLayout{
			Enabled:             true,
			Model:               CoeffNativeSigModelLiteralPackedAggregatedV3,
			SigBase:             -1,
			SigCount:            0,
			SigBlocks:           cfgMain.PackedSigBlocks,
			SigUCount:           0,
			SigComponentCount:   cfgMain.PackedSigComponents,
			SigCoeffCount:       cfgMain.SigCoeffCount,
			OutputBlocks:        rowLayoutReplayTHatCount(mainLayout),
			OutputBlockWidth:    witnessNCols,
			W1SigBase:           0,
			W1SigCount:          logicalWitnessPolys,
			PackedSigBase:       -1,
			PackedSigCount:      0,
			PackedSigBlocks:     cfgMain.PackedSigBlocks,
			PackedSigComponents: cfgMain.PackedSigComponents,
			PackedSigBlockWidth: witnessNCols,
			ScalarBundleBase:    -1,
			ScalarBundleCount:   0,
		},
	}
}

func flattenSigShortnessHiddenWitnessRows(layout RowLayout, packedWitness *literalPackedPolyWitness, spec LinfSpec) ([]*ring.Poly, error) {
	if packedWitness == nil {
		return nil, fmt.Errorf("nil packed shortness witness")
	}
	cfg := layout.CoeffNativeSig
	rows := make([]*ring.Poly, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			if comp >= len(packedWitness.SigLimbs) || block >= len(packedWitness.SigLimbs[comp]) {
				return nil, fmt.Errorf("missing hidden sig limbs for comp=%d block=%d", comp, block)
			}
			for lane := 0; lane < spec.L; lane++ {
				if lane >= len(packedWitness.SigLimbs[comp][block]) || packedWitness.SigLimbs[comp][block][lane] == nil {
					return nil, fmt.Errorf("missing hidden digit row for comp=%d block=%d lane=%d", comp, block, lane)
				}
				rows = append(rows, packedWitness.SigLimbs[comp][block][lane])
			}
		}
	}
	return rows, nil
}

func buildSigShortnessHiddenTHatPublicPolys(ringQ *ring.Ring, omegaWitness []uint64, tHatHeads [][]uint64) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	outPolys := make([]*ring.Poly, len(tHatHeads))
	outCoeffs := make([][]uint64, len(tHatHeads))
	q := ringQ.Modulus[0]
	for block := range tHatHeads {
		p := BuildThetaPrime(ringQ, tHatHeads[block], omegaWitness)
		coeff, err := coeffFromNTTPoly(ringQ, p)
		if err != nil {
			return nil, nil, fmt.Errorf("T-hat public coeffs block %d: %w", block, err)
		}
		outPolys[block] = p
		outCoeffs[block] = trimPoly(coeff, q)
	}
	return outPolys, outCoeffs, nil
}

func buildSigShortnessHiddenTHatBridgeFormalCoeffs(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	tHatHeads [][]uint64,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, nil, fmt.Errorf("hidden sig shortness expects one public A row")
	}
	cfg := layout.CoeffNativeSig
	replayTHatCount := len(tHatHeads)
	sourceBlocks := cfg.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, nil, fmt.Errorf("invalid hidden source blocks=%d", sourceBlocks)
	}
	ncols := len(omegaWitness)
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("empty witness omega")
	}
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return nil, nil, fmt.Errorf("hidden transform bridge basis: %w", err)
	}
	tHatPolys, tHatCoeffs, err := buildSigShortnessHiddenTHatPublicPolys(ringQ, omegaWitness, tHatHeads)
	if err != nil {
		return nil, nil, err
	}
	_ = tHatPolys
	digitCoeffs := make(map[[3]int][]uint64, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
	q := ringQ.Modulus[0]
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			for lane := 0; lane < spec.L; lane++ {
				rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
				if rowIdx < 0 || rowIdx >= len(rowsNTT) {
					return nil, nil, fmt.Errorf("hidden digit row idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
				}
				coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
				if err != nil {
					return nil, nil, fmt.Errorf("hidden digit coeffs comp=%d block=%d lane=%d: %w", comp, block, lane, err)
				}
				digitCoeffs[[3]int{comp, block, lane}] = trimPoly(coeff, q)
			}
		}
	}
	outPolys := make([]*ring.Poly, 0, replayTHatCount*ncols)
	outCoeffs := make([][]uint64, 0, replayTHatCount*ncols)
	for bOut := 0; bOut < replayTHatCount; bOut++ {
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
				if err != nil {
					return nil, nil, fmt.Errorf("hidden theta A comp=%d block=%d: %w", comp, bOut, err)
				}
				aScale := aHead[j] % q
				if aScale == 0 {
					continue
				}
				for block := 0; block < cfg.PackedSigBlocks; block++ {
					blockScale := bridgeBasis.BlockFactors[t][block] % q
					if blockScale == 0 {
						continue
					}
					for lane := 0; lane < spec.L; lane++ {
						scale := modMul(aScale, modMul(spec.RPows[lane]%q, blockScale, q), q)
						term := polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := polyMul(bridgeBasis.LagrangeBasis[j], tHatCoeffs[bOut], q)
			bridgeCoeff := trimPoly(polySub(leftCoeff, rightCoeff, q), q)
			outCoeffs = append(outCoeffs, bridgeCoeff)
			outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	return outPolys, outCoeffs, nil
}

func buildSigShortnessHiddenConstraintSet(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	tHatHeads [][]uint64,
	spec LinfSpec,
) (ConstraintSet, error) {
	shortSet, err := buildLiteralPackedSignatureShortnessConstraintSet(ringQ, layout, rowsNTT, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   int(spec.R),
		SigShortnessL:       spec.L,
	})
	if err != nil {
		return ConstraintSet{}, err
	}
	faggNorm, faggNormCoeffs, err := buildSigShortnessHiddenTHatBridgeFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, tHatHeads, spec)
	if err != nil {
		return ConstraintSet{}, err
	}
	shortSet.FaggNorm = append([]*ring.Poly{}, faggNorm...)
	shortSet.FaggNormCoeffs = append([][]uint64{}, faggNormCoeffs...)
	shortSet.AggregatedAlgDeg = 1
	return shortSet, nil
}

func buildSigShortnessHiddenReplay(
	ringQ *ring.Ring,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	tHatHeads [][]uint64,
	spec LinfSpec,
) (*ConstraintReplay, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil hidden proof")
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	logicalRows := proof.PCSGeometry.LogicalWitnessPolys
	if logicalRows <= 0 {
		logicalRows = layout.SigCount
	}
	if logicalRows <= 0 {
		return nil, fmt.Errorf("missing hidden logical witness row count")
	}
	ncols := proof.NColsUsed
	if ncols <= 0 {
		ncols = cfg.PackedSigBlockWidth
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("missing hidden witness ncols")
	}
	if len(omegaWitness) < ncols {
		return nil, fmt.Errorf("omega witness len=%d < hidden witness ncols=%d", len(omegaWitness), ncols)
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		pcsNCols = ncols
	}
	domainPoints, err := deriveProofExplicitDomainPoints(proof, ringQ.Modulus[0], ncols, pcsNCols)
	if err != nil {
		return nil, fmt.Errorf("hidden explicit domain points: %w", err)
	}
	sourceBlocks := cfg.PackedSigBlocks
	replayTHatCount := len(tHatHeads)
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness[:ncols], replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return nil, err
	}
	tHatPolys, tHatCoeffs, err := buildSigShortnessHiddenTHatPublicPolys(ringQ, omegaWitness[:ncols], tHatHeads)
	if err != nil {
		return nil, err
	}
	_ = tHatPolys
	aHeads := make([][][]uint64, replayTHatCount)
	for bOut := 0; bOut < replayTHatCount; bOut++ {
		aHeads[bOut] = make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			head, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness[:ncols], bOut, sourceBlocks)
			if err != nil {
				return nil, err
			}
			aHeads[bOut][comp] = head
		}
	}
	eval := func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if len(rows) < logicalRows {
			return nil, nil, fmt.Errorf("hidden row value count=%d want >=%d", len(rows), logicalRows)
		}
		q := ringQ.Modulus[0]
		fpar := make([]uint64, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				for lane := 0; lane < spec.L; lane++ {
					rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
					fpar = append(fpar, EvalPoly(spec.PDi[lane], rows[rowIdx]%q, q)%q)
				}
			}
		}
		if int(evalIdx) >= len(domainPoints) {
			return nil, nil, fmt.Errorf("hidden eval idx %d out of range (|E|=%d)", evalIdx, len(domainPoints))
		}
		x := domainPoints[int(evalIdx)] % q
		fagg := make([]uint64, 0, replayTHatCount*ncols)
		for bOut := 0; bOut < replayTHatCount; bOut++ {
			for j := 0; j < ncols; j++ {
				t := bOut*ncols + j
				hVal := EvalPoly(bridgeBasis.TransformH[t], x, q) % q
				lhs := uint64(0)
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					aScale := aHeads[bOut][comp][j] % q
					if aScale == 0 {
						continue
					}
					for block := 0; block < cfg.PackedSigBlocks; block++ {
						blockScale := bridgeBasis.BlockFactors[t][block] % q
						for lane := 0; lane < spec.L; lane++ {
							rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
							scale := modMul(aScale, modMul(spec.RPows[lane]%q, blockScale, q), q)
							term := modMul(scale, modMul(hVal, rows[rowIdx]%q, q), q)
							lhs = modAdd(lhs, term, q)
						}
					}
				}
				rhs := modMul(EvalPoly(bridgeBasis.LagrangeBasis[j], x, q)%q, EvalPoly(tHatCoeffs[bOut], x, q)%q, q)
				fagg = append(fagg, modSub(lhs, rhs, q))
			}
		}
		return fpar, fagg, nil
	}
	var evalK KConstraintEvaluator
	if proof.Theta > 1 {
		K, err := kf.New(ringQ.Modulus[0], proof.Theta, proof.Chi)
		if err != nil {
			return nil, err
		}
		evalK = func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
			if len(rows) < logicalRows {
				return nil, nil, fmt.Errorf("hidden K row count=%d want >=%d", len(rows), logicalRows)
			}
			fpar := make([]kf.Elem, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
			for block := 0; block < cfg.PackedSigBlocks; block++ {
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
						fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
					}
				}
			}
			fagg := make([]kf.Elem, 0, replayTHatCount*ncols)
			for bOut := 0; bOut < replayTHatCount; bOut++ {
				for j := 0; j < ncols; j++ {
					t := bOut*ncols + j
					hVal := K.EvalFPolyAtK(bridgeBasis.TransformH[t], e)
					lhs := K.Zero()
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						aScale := K.EmbedF(aHeads[bOut][comp][j] % K.Q)
						if K.IsZero(aScale) {
							continue
						}
						for block := 0; block < cfg.PackedSigBlocks; block++ {
							blockScale := K.EmbedF(bridgeBasis.BlockFactors[t][block] % K.Q)
							for lane := 0; lane < spec.L; lane++ {
								rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
								scale := K.Mul(aScale, K.Mul(K.EmbedF(spec.RPows[lane]%K.Q), blockScale))
								term := K.Mul(scale, K.Mul(hVal, rows[rowIdx]))
								lhs = K.Add(lhs, term)
							}
						}
					}
					rhs := K.Mul(K.EvalFPolyAtK(bridgeBasis.LagrangeBasis[j], e), K.EvalFPolyAtK(tHatCoeffs[bOut], e))
					fagg = append(fagg, K.Sub(lhs, rhs))
				}
			}
			return fpar, fagg, nil
		}
	}
	return &ConstraintReplay{
		Eval:       eval,
		EvalK:      evalK,
		RowCount:   logicalRows,
		FparCoeffs: nil,
		FaggCoeffs: nil,
	}, nil
}

func verifySigShortnessHiddenProof(
	proof *Proof,
	pub PublicInputs,
	replay *ConstraintReplay,
) error {
	if proof == nil {
		return fmt.Errorf("nil hidden sig shortness proof")
	}
	if replay == nil {
		return fmt.Errorf("nil hidden sig shortness replay")
	}
	labelsDigest := computeLabelsDigest(BuildPublicLabels(pub))
	if !equalByteSlices(labelsDigest, proof.LabelsDigest) {
		return fmt.Errorf("hidden sig shortness labels digest mismatch")
	}
	okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, replay)
	if err != nil {
		return err
	}
	if !(okLin && okEq4 && okSum) {
		return fmt.Errorf("hidden sig shortness proof rejected (lin=%v eq4=%v sum=%v)", okLin, okEq4, okSum)
	}
	return nil
}

func stripHiddenSigShortnessProofDebug(proof *Proof) {
	if proof == nil {
		return
	}
	proof.QCoeffDebug = nil
	proof.MaskCoeffDebug = nil
	proof.FparCoeffDebug = nil
	proof.FaggCoeffDebug = nil
}

func chooseSigShortnessHiddenProfile(
	ringQ *ring.Ring,
	cn *CoeffNativeShowingWitness,
	omegaWitness []uint64,
	witnessNCols int,
	mainOpts SimOpts,
) (*literalPackedPolyWitness, SimOpts, LinfSpec, error) {
	if ringQ == nil {
		return nil, SimOpts{}, LinfSpec{}, fmt.Errorf("nil ring")
	}
	shape, err := chooseSigShortnessHiddenShapeLegacyFirstFit(ringQ, cn, omegaWitness, witnessNCols, mainOpts)
	if err != nil {
		return nil, SimOpts{}, LinfSpec{}, err
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], buildSigShortnessProfileSimOpts(shape))
	if err != nil {
		return nil, SimOpts{}, LinfSpec{}, err
	}
	logicalWitnessPolys := sigShortnessHiddenLogicalWitnessPolys(ringQ, cn, witnessNCols, spec.L)
	hiddenOpts := buildSigShortnessHiddenOptsForShape(mainOpts, shape, witnessNCols, logicalWitnessPolys)
	packedWitness, err := buildLiteralPackedPolyWitness(
		ringQ,
		cn,
		omegaWitness,
		witnessNCols,
		CoeffNativeSigModelLiteralPackedAggregatedV3,
		hiddenOpts,
	)
	if err != nil {
		return nil, SimOpts{}, LinfSpec{}, err
	}
	return packedWitness, hiddenOpts, spec, nil
}

func buildSigShortnessProofBase(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	opts SimOpts,
	version int,
) (*SigShortnessProof, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) {
		return nil, nil
	}
	if proof.Theta <= 1 || proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		return nil, nil
	}
	if pk == nil {
		return nil, fmt.Errorf("nil prover key")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	if _, err := signaturePackedChainRowsPerGroupForOpts(spec, opts, proof.RowLayout.PackedSigChainGroupSize); err != nil {
		return nil, fmt.Errorf("rows/group: %w", err)
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols")
	}
	supportSlots, err := buildSigShortnessSupportSlotsForVersion(proof.RowLayout, pcsNCols, version)
	if err != nil {
		return nil, err
	}
	if len(supportSlots) == 0 {
		return nil, nil
	}
	opening := cloneDECSOpening(lvcs.EvalFinish(pk, supportSlots).DECSOpen)
	originalOpening := cloneDECSOpening(opening)
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, err
	}
	if err := maybeCompressSigShortnessOpeningPvals(opening, replayWitnessRows); err != nil {
		return nil, err
	}
	omitAllRowOpeningMvals(opening)
	decs.PackOpening(opening)
	restoreExplicitMerklePaths(opening, originalOpening)
	return &SigShortnessProof{
		Version:      version,
		SupportSlots: append([]int(nil), supportSlots...),
		Opening:      opening,
	}, nil
}

func restoreExplicitMerklePaths(dst, src *decs.DECSOpening) {
	if dst == nil || src == nil {
		return
	}
	if len(src.Nodes) == 0 || len(src.PathIndex) == 0 {
		return
	}
	dst.Nodes = make([][]byte, len(src.Nodes))
	for i := range src.Nodes {
		dst.Nodes[i] = append([]byte(nil), src.Nodes[i]...)
	}
	dst.PathIndex = make([][]int, len(src.PathIndex))
	for i := range src.PathIndex {
		dst.PathIndex[i] = append([]int(nil), src.PathIndex[i]...)
	}
	dst.PathBits = nil
	dst.PathBitWidth = 0
	dst.PathDepth = 0
	dst.FrontierNodes = nil
	dst.FrontierProof = nil
	dst.FrontierLR = nil
	dst.FrontierDepth = 0
	dst.FrontierRefsBits = nil
	dst.FrontierRefWidth = 0
	dst.FrontierRefCount = 0
}

func buildSigShortnessProofV2(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	omegaWitness []uint64,
	opts SimOpts,
) (*SigShortnessProof, error) {
	sig, err := buildSigShortnessProofBase(ringQ, pk, proof, opts, sigShortnessProofVersionV2)
	if err != nil || sig == nil {
		return sig, err
	}
	proofWithSig := *proof
	proofWithSig.SigShortness = sig
	if err := VerifySigShortnessProofV2(&proofWithSig, ringQ, omegaWitness, opts); err != nil {
		return nil, fmt.Errorf("compressed-row sig shortness verification failed: %w", err)
	}
	return sig, nil
}

func buildSigShortnessProofV3(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	opts SimOpts,
) (*SigShortnessProof, error) {
	sig, err := buildSigShortnessProofBase(ringQ, pk, proof, opts, sigShortnessProofVersionV3)
	if err != nil || sig == nil {
		return sig, err
	}
	proofWithSig := *proof
	proofWithSig.SigShortness = sig
	if err := VerifySigShortnessProof(&proofWithSig, ringQ, omegaWitness, pub, opts); err != nil {
		return nil, fmt.Errorf("compressed-row sig shortness verification failed: %w", err)
	}
	return sig, nil
}

func buildSigShortnessProofV4(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	opts SimOpts,
) (*SigShortnessProof, error) {
	sig, err := buildSigShortnessProofBase(ringQ, pk, proof, opts, sigShortnessProofVersionV4)
	if err != nil || sig == nil {
		return sig, err
	}
	proofWithSig := *proof
	proofWithSig.SigShortness = sig
	if err := VerifySigShortnessProof(&proofWithSig, ringQ, omegaWitness, pub, opts); err != nil {
		return nil, fmt.Errorf("compressed-row sig shortness verification failed: %w", err)
	}
	return sig, nil
}

func buildSigShortnessProofV5(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	root [16]byte,
	layout RowLayout,
	cn *CoeffNativeShowingWitness,
	omegaWitness []uint64,
	witnessNCols int,
	pcsNCols int,
	opts SimOpts,
) (*SigShortnessProof, []byte, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	if cn == nil {
		return nil, nil, fmt.Errorf("nil coeff-native showing witness")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, nil, fmt.Errorf("sig shortness V5 requires literal packed v3 layout")
	}
	if witnessNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid witness ncols=%d", witnessNCols)
	}
	if len(omegaWitness) != witnessNCols {
		return nil, nil, fmt.Errorf("omega witness len=%d want %d", len(omegaWitness), witnessNCols)
	}
	if pcsNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	model := layout.CoeffNativeSig.Model
	if model == "" {
		model = resolveCoeffNativeSigModel(opts)
	}
	packedWitness, err := buildLiteralPackedPolyWitness(ringQ, cn, omegaWitness, witnessNCols, model, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("literal packed witness: %w", err)
	}
	exactHeads, err := packSigShortnessV5ExactHeads(packedWitness.SigHeads)
	if err != nil {
		return nil, nil, err
	}
	radix, digits, _, _, err := ResolveSignatureShortnessMetricsForOpts(ringQ.Modulus[0], opts)
	if err != nil {
		return nil, nil, fmt.Errorf("signature shortness metrics: %w", err)
	}
	_, tHatOpening, err := buildSigShortnessV5THatOpening(pk, root, layout, pcsNCols)
	if err != nil {
		return nil, nil, fmt.Errorf("build sig shortness V5 T-hat opening: %w", err)
	}
	sig := &SigShortnessProof{
		Version: sigShortnessProofVersionV5,
		V5: &SigShortnessProofV5{
			Mode:        sigShortnessV5ModeExactSigHeads,
			Radix:       radix,
			Digits:      digits,
			ExactHeads:  exactHeads,
			THatOpening: tHatOpening,
		},
	}
	digest, err := buildSigShortnessV5BindingDigest(sig, layout, witnessNCols)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}

func buildSigShortnessProofV6(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	root [16]byte,
	layout RowLayout,
	cn *CoeffNativeShowingWitness,
	pub PublicInputs,
	omegaWitness []uint64,
	witnessNCols int,
	pcsNCols int,
	opts SimOpts,
) (*SigShortnessProof, []byte, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	if cn == nil {
		return nil, nil, fmt.Errorf("nil coeff-native showing witness")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, nil, fmt.Errorf("sig shortness V6 requires literal packed v3 layout")
	}
	if witnessNCols <= 0 || len(omegaWitness) != witnessNCols {
		return nil, nil, fmt.Errorf("invalid witness omega for sig shortness V6")
	}
	if pcsNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	var (
		chosen *sigShortnessHiddenBuiltCandidate
		err    error
	)
	legacyShape, err := chooseSigShortnessHiddenShapeLegacyFirstFit(ringQ, cn, omegaWitness, witnessNCols, opts)
	if err != nil {
		return nil, nil, err
	}
	chosen, err = buildSigShortnessHiddenCandidateWithPolicy(ringQ, root, layout, cn, pub, omegaWitness, witnessNCols, opts, legacyShape, false)
	if err != nil {
		return nil, nil, err
	}
	_, tHatOpening, err := buildSigShortnessV5THatOpening(pk, root, layout, pcsNCols)
	if err != nil {
		return nil, nil, fmt.Errorf("build sig shortness V6 T-hat opening: %w", err)
	}
	sig := &SigShortnessProof{
		Version: sigShortnessProofVersionV6,
		V6: &SigShortnessProofV6{
			Mode:        sigShortnessV6ModeHiddenSmallWood,
			Radix:       int(chosen.Spec.R),
			Digits:      chosen.Spec.L,
			HiddenProof: chosen.HiddenProof,
			THatOpening: tHatOpening,
		},
	}
	digest, err := buildSigShortnessV6BindingDigest(sig)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}

func buildSigShortnessProofV7Metadata(
	ringQ *ring.Ring,
	layout RowLayout,
	opts SimOpts,
) (*SigShortnessProof, error) {
	if !sigShortnessV7EnabledForOpts(opts) {
		return nil, nil
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, fmt.Errorf("sig shortness V7 requires literal packed v3 layout")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], layout, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	return &SigShortnessProof{
		Version: sigShortnessProofVersionV7,
		V7: &SigShortnessProofV7{
			Mode:   sigShortnessV7ModeInlinedMain,
			Radix:  int(spec.R),
			Digits: spec.L,
		},
	}, nil
}

func buildSigShortnessCommittedTHatBridgeFormalCoeffs(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, nil, fmt.Errorf("sig shortness V7 expects one public A row")
	}
	cfg := layout.CoeffNativeSig
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	sourceBlocks := cfg.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	ncols := len(omegaWitness)
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("empty witness omega")
	}
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return nil, nil, fmt.Errorf("sig shortness V7 transform bridge basis: %w", err)
	}
	q := ringQ.Modulus[0]
	tHatCoeffs := make([][]uint64, replayTHatCount)
	for block := 0; block < replayTHatCount; block++ {
		rowIdx := rowLayoutPostSignTHatIndex(layout, block)
		if rowIdx < 0 || rowIdx >= len(rowsNTT) {
			return nil, nil, fmt.Errorf("replay T-hat row idx out of range for block=%d", block)
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
		if err != nil {
			return nil, nil, fmt.Errorf("T-hat coeffs block %d: %w", block, err)
		}
		tHatCoeffs[block] = trimPoly(coeff, q)
	}
	digitCoeffs := make(map[[3]int][]uint64, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			for lane := 0; lane < spec.L; lane++ {
				rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
				if rowIdx < 0 || rowIdx >= len(rowsNTT) {
					return nil, nil, fmt.Errorf("digit row idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
				}
				coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
				if err != nil {
					return nil, nil, fmt.Errorf("digit coeffs comp=%d block=%d lane=%d: %w", comp, block, lane, err)
				}
				digitCoeffs[[3]int{comp, block, lane}] = trimPoly(coeff, q)
			}
		}
	}
	outPolys := make([]*ring.Poly, 0, replayTHatCount*ncols)
	outCoeffs := make([][]uint64, 0, replayTHatCount*ncols)
	for bOut := 0; bOut < replayTHatCount; bOut++ {
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
				if err != nil {
					return nil, nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
				}
				aScale := aHead[j] % q
				if aScale == 0 {
					continue
				}
				for block := 0; block < cfg.PackedSigBlocks; block++ {
					blockScale := bridgeBasis.BlockFactors[t][block] % q
					if blockScale == 0 {
						continue
					}
					for lane := 0; lane < spec.L; lane++ {
						scale := modMul(aScale, modMul(spec.RPows[lane]%q, blockScale, q), q)
						term := polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := polyMul(bridgeBasis.LagrangeBasis[j], tHatCoeffs[bOut], q)
			bridgeCoeff := trimPoly(polySub(leftCoeff, rightCoeff, q), q)
			outCoeffs = append(outCoeffs, bridgeCoeff)
			outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	return outPolys, outCoeffs, nil
}

func buildSigShortnessV7ConstraintSet(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	opts SimOpts,
) (ConstraintSet, error) {
	if !sigShortnessV7EnabledForOpts(opts) {
		return ConstraintSet{}, nil
	}
	shortSet, err := buildLiteralPackedSignatureShortnessConstraintSet(ringQ, layout, rowsNTT, opts)
	if err != nil {
		return ConstraintSet{}, err
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], layout, opts)
	if err != nil {
		return ConstraintSet{}, err
	}
	faggNorm, faggNormCoeffs, err := buildSigShortnessCommittedTHatBridgeFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, spec)
	if err != nil {
		return ConstraintSet{}, err
	}
	shortSet.FaggNorm = append(shortSet.FaggNorm, faggNorm...)
	shortSet.FaggNormCoeffs = append(shortSet.FaggNormCoeffs, faggNormCoeffs...)
	if len(faggNorm) > 0 && shortSet.AggregatedAlgDeg < 1 {
		shortSet.AggregatedAlgDeg = 1
	}
	return shortSet, nil
}

func buildSigShortnessV7Replay(
	ringQ *ring.Ring,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	domainPoints []uint64,
	opts SimOpts,
) (*ConstraintReplay, error) {
	if proof == nil || proof.SigShortness == nil || proof.SigShortness.V7 == nil {
		return nil, fmt.Errorf("missing V7 sig shortness proof metadata")
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	logicalRows := proof.PCSGeometry.LogicalWitnessPolys
	if logicalRows <= 0 {
		logicalRows = layout.SigCount
	}
	if logicalRows <= 0 {
		return nil, fmt.Errorf("missing logical witness row count")
	}
	ncols := len(omegaWitness)
	if ncols <= 0 {
		return nil, fmt.Errorf("empty witness omega")
	}
	if len(domainPoints) == 0 {
		return nil, fmt.Errorf("empty domain points")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, fmt.Errorf("sig shortness V7 expects one public A row")
	}
	sourceBlocks := cfg.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	specOpts := opts
	specOpts.CoeffNativeSigModel = layout.CoeffNativeSig.Model
	specOpts.SigShortnessProfile = ""
	specOpts.SigShortnessRadix = proof.SigShortness.V7.Radix
	specOpts.SigShortnessL = proof.SigShortness.V7.Digits
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], specOpts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return nil, fmt.Errorf("sig shortness V7 transform bridge basis: %w", err)
	}
	aHeads := make([][][]uint64, replayTHatCount)
	for bOut := 0; bOut < replayTHatCount; bOut++ {
		aHeads[bOut] = make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			head, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			aHeads[bOut][comp] = head
		}
	}
	eval := func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if len(rows) < logicalRows {
			return nil, nil, fmt.Errorf("row value count=%d want >=%d", len(rows), logicalRows)
		}
		if int(evalIdx) >= len(domainPoints) {
			return nil, nil, fmt.Errorf("eval idx %d out of range (|E|=%d)", evalIdx, len(domainPoints))
		}
		q := ringQ.Modulus[0]
		fpar := make([]uint64, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				for lane := 0; lane < spec.L; lane++ {
					rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
					fpar = append(fpar, EvalPoly(spec.PDi[lane], rows[rowIdx]%q, q)%q)
				}
			}
		}
		x := domainPoints[int(evalIdx)] % q
		fagg := make([]uint64, 0, replayTHatCount*ncols)
		for bOut := 0; bOut < replayTHatCount; bOut++ {
			tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
			if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
				return nil, nil, fmt.Errorf("T-hat row idx out of range for block=%d", bOut)
			}
			tHatVal := rows[tHatRowIdx] % q
			for j := 0; j < ncols; j++ {
				t := bOut*ncols + j
				hVal := EvalPoly(bridgeBasis.TransformH[t], x, q) % q
				lhs := uint64(0)
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					aScale := aHeads[bOut][comp][j] % q
					if aScale == 0 {
						continue
					}
					for block := 0; block < cfg.PackedSigBlocks; block++ {
						blockScale := bridgeBasis.BlockFactors[t][block] % q
						if blockScale == 0 {
							continue
						}
						for lane := 0; lane < spec.L; lane++ {
							rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
							scale := modMul(aScale, modMul(spec.RPows[lane]%q, blockScale, q), q)
							term := modMul(scale, modMul(hVal, rows[rowIdx]%q, q), q)
							lhs = modAdd(lhs, term, q)
						}
					}
				}
				rhs := modMul(EvalPoly(bridgeBasis.LagrangeBasis[j], x, q)%q, tHatVal, q)
				fagg = append(fagg, modSub(lhs, rhs, q))
			}
		}
		return fpar, fagg, nil
	}
	var evalK KConstraintEvaluator
	if proof.Theta > 1 {
		K, err := kf.New(ringQ.Modulus[0], proof.Theta, proof.Chi)
		if err != nil {
			return nil, err
		}
		evalK = func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
			if len(rows) < logicalRows {
				return nil, nil, fmt.Errorf("K row value count=%d want >=%d", len(rows), logicalRows)
			}
			fpar := make([]kf.Elem, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
			for block := 0; block < cfg.PackedSigBlocks; block++ {
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
						fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
					}
				}
			}
			fagg := make([]kf.Elem, 0, replayTHatCount*ncols)
			for bOut := 0; bOut < replayTHatCount; bOut++ {
				tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
				if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("T-hat K row idx out of range for block=%d", bOut)
				}
				tHatVal := rows[tHatRowIdx]
				for j := 0; j < ncols; j++ {
					t := bOut*ncols + j
					hVal := K.EvalFPolyAtK(bridgeBasis.TransformH[t], e)
					lhs := K.Zero()
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						aScale := K.EmbedF(aHeads[bOut][comp][j] % K.Q)
						if K.IsZero(aScale) {
							continue
						}
						for block := 0; block < cfg.PackedSigBlocks; block++ {
							blockScale := K.EmbedF(bridgeBasis.BlockFactors[t][block] % K.Q)
							if K.IsZero(blockScale) {
								continue
							}
							for lane := 0; lane < spec.L; lane++ {
								rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
								scale := K.Mul(aScale, K.Mul(K.EmbedF(spec.RPows[lane]%K.Q), blockScale))
								term := K.Mul(scale, K.Mul(hVal, rows[rowIdx]))
								lhs = K.Add(lhs, term)
							}
						}
					}
					rhs := K.Mul(K.EvalFPolyAtK(bridgeBasis.LagrangeBasis[j], e), tHatVal)
					fagg = append(fagg, K.Sub(lhs, rhs))
				}
			}
			return fpar, fagg, nil
		}
	}
	return &ConstraintReplay{
		Eval:     eval,
		EvalK:    evalK,
		RowCount: logicalRows,
	}, nil
}

func prepareSigShortnessV5THatView(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64) (*sigShortnessSupportView, error) {
	if proof == nil || proof.SigShortness == nil {
		return nil, nil
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV5:
		if err := validateSigShortnessV5Shape(proof); err != nil {
			return nil, err
		}
	case sigShortnessProofVersionV6:
		if err := validateSigShortnessV6Shape(proof); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported sig shortness T-hat view version %d", proof.SigShortness.Version)
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) {
		return nil, fmt.Errorf("sig shortness T-hat view requires literal packed v3 layout")
	}
	if proof.Theta <= 1 || proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		return nil, fmt.Errorf("sig shortness T-hat view requires compressed-row small-field geometry")
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = len(omegaWitness)
	}
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("missing witness support width")
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols")
	}
	slots, err := buildSigShortnessSupportSlotsForRows(buildSigShortnessTHatWitnessRows(proof.RowLayout), pcsNCols)
	if err != nil {
		return nil, err
	}
	params, rowCount, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, rowCount, ringQ.Modulus[0])
	if err != nil {
		return nil, err
	}
	domainPoints, err := deriveProofExplicitDomainPoints(proof, ringQ.Modulus[0], witnessNCols, pcsNCols)
	if err != nil {
		return nil, err
	}
	rPolys := make([]*ring.Poly, len(proof.R))
	for i := range proof.R {
		rPolys[i] = coeffsToNTTIfFits(ringQ, proof.R[i])
		if rPolys[i] == nil {
			return nil, fmt.Errorf("R polynomial %d too large to materialize", i)
		}
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, err
	}
	var tHatOpening *decs.DECSOpening
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV5:
		tHatOpening = proof.SigShortness.V5.THatOpening
	case sigShortnessProofVersionV6:
		tHatOpening = proof.SigShortness.V6.THatOpening
	}
	opening, err := prepareSigShortnessOpeningForVerify(tHatOpening, gamma, rPolys, domainPoints, ringQ, replayWitnessRows)
	if err != nil {
		return nil, err
	}
	if err := verifyDECSSubset(ringQ, proof.Root, params, gamma, rPolys, opening, slots, domainPoints); err != nil {
		return nil, fmt.Errorf("sig shortness T-hat opening rejected: %w", err)
	}
	theta := proof.Theta
	if theta <= 1 {
		theta = proof.PCSGeometry.Theta
	}
	return newSigShortnessSupportView(proof, opening, slots, witnessNCols, pcsNCols, theta, ringQ.Modulus[0])
}

func prepareSigShortnessVerifyBase(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, opts SimOpts, version int) (*sigShortnessSupportView, LinfSpec, error) {
	if proof == nil || proof.SigShortness == nil {
		return nil, LinfSpec{}, nil
	}
	sig := proof.SigShortness
	if sig.Version != version {
		return nil, LinfSpec{}, fmt.Errorf("unsupported sig shortness version %d", sig.Version)
	}
	if ringQ == nil {
		return nil, LinfSpec{}, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness V%d requires literal packed v3 layout", version)
	}
	if proof.Theta <= 1 || proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness V%d requires compressed-row small-field geometry", version)
	}
	if sig.Opening == nil {
		return nil, LinfSpec{}, fmt.Errorf("missing sig shortness opening")
	}
	if err := validateSortedUniqueIndices("sig shortness support slots", sig.SupportSlots); err != nil {
		return nil, LinfSpec{}, err
	}
	q := ringQ.Modulus[0]
	spec, err := signatureChainSpecForLayoutAndOpts(q, proof.RowLayout, opts)
	if err != nil {
		return nil, LinfSpec{}, fmt.Errorf("signature chain spec: %w", err)
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, LinfSpec{}, fmt.Errorf("missing pcs ncols")
	}
	expectedSlots, err := buildSigShortnessSupportSlotsForVersion(proof.RowLayout, pcsNCols, version)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	if !equalIntSlices(expectedSlots, sig.SupportSlots) {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness support slots mismatch")
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = len(omegaWitness)
	}
	if witnessNCols <= 0 {
		return nil, LinfSpec{}, fmt.Errorf("missing witness support width")
	}
	params, rowCount, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, rowCount, q)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	domainPoints, err := deriveProofExplicitDomainPoints(proof, q, witnessNCols, pcsNCols)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	rPolys := make([]*ring.Poly, len(proof.R))
	for i := range proof.R {
		rPolys[i] = coeffsToNTTIfFits(ringQ, proof.R[i])
		if rPolys[i] == nil {
			return nil, LinfSpec{}, fmt.Errorf("R polynomial %d too large to materialize", i)
		}
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	opening, err := prepareSigShortnessOpeningForVerify(sig.Opening, gamma, rPolys, domainPoints, ringQ, replayWitnessRows)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	if err := verifyDECSSubset(ringQ, proof.Root, params, gamma, rPolys, opening, sig.SupportSlots, domainPoints); err != nil {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness opening rejected: %w", err)
	}
	theta := proof.Theta
	if theta <= 1 {
		theta = proof.PCSGeometry.Theta
	}
	view, err := newSigShortnessSupportView(proof, opening, sig.SupportSlots, witnessNCols, pcsNCols, theta, q)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	return view, spec, nil
}

func VerifySigShortnessProof(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV2:
		return VerifySigShortnessProofV2(proof, ringQ, omegaWitness, opts)
	case sigShortnessProofVersionV3:
		return VerifySigShortnessProofV3(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV4:
		return VerifySigShortnessProofV4(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV5:
		return VerifySigShortnessProofV5(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV6:
		return VerifySigShortnessProofV6(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV7:
		return VerifySigShortnessProofV7(proof, ringQ, omegaWitness, pub, opts)
	default:
		return fmt.Errorf("unsupported sig shortness version %d", proof.SigShortness.Version)
	}
}

func VerifySigShortnessProofV2(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, opts SimOpts) error {
	view, spec, err := prepareSigShortnessVerifyBase(proof, ringQ, omegaWitness, opts, sigShortnessProofVersionV2)
	if err != nil {
		return err
	}
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	if _, err := verifySigShortnessSupportValues(proof, view, spec); err != nil {
		return fmt.Errorf("sig shortness values rejected: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV3(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	view, spec, err := prepareSigShortnessVerifyBase(proof, ringQ, omegaWitness, opts, sigShortnessProofVersionV3)
	if err != nil {
		return err
	}
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sigLimbHeads, err := verifySigShortnessSupportValues(proof, view, spec)
	if err != nil {
		return fmt.Errorf("sig shortness values rejected: %w", err)
	}
	expectedTHatHeads, err := deriveSigShortnessExpectedTHatHeads(proof, ringQ, pub, omegaWitness, spec, sigLimbHeads)
	if err != nil {
		return fmt.Errorf("sig shortness T-hat derivation failed: %w", err)
	}
	if err := verifySigShortnessTHatSupportValues(proof, view, expectedTHatHeads); err != nil {
		return fmt.Errorf("sig shortness T-hat values rejected: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV4(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	view, spec, err := prepareSigShortnessVerifyBase(proof, ringQ, omegaWitness, opts, sigShortnessProofVersionV4)
	if err != nil {
		return err
	}
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sigLimbHeads, err := verifySigShortnessDigitOnlySupportValues(proof, view, spec)
	if err != nil {
		return fmt.Errorf("sig shortness values rejected: %w", err)
	}
	expectedTHatHeads, err := deriveSigShortnessExpectedTHatHeads(proof, ringQ, pub, omegaWitness, spec, sigLimbHeads)
	if err != nil {
		return fmt.Errorf("sig shortness T-hat derivation failed: %w", err)
	}
	if err := verifySigShortnessTHatSupportValues(proof, view, expectedTHatHeads); err != nil {
		return fmt.Errorf("sig shortness T-hat values rejected: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV5(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	if err := validateSigShortnessV5Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	spec, err := signatureChainSpecForLayoutAndOpts(q, proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("signature chain spec: %w", err)
	}
	v5 := proof.SigShortness.V5
	if v5.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V5 radix=%d want %d", v5.Radix, spec.R)
	}
	if v5.Digits != spec.L {
		return fmt.Errorf("sig shortness V5 digits=%d want %d", v5.Digits, spec.L)
	}
	sigHeads, err := unpackSigShortnessV5ExactHeads(proof.RowLayout, v5.ExactHeads)
	if err != nil {
		return err
	}
	for comp := range sigHeads {
		for block := range sigHeads[comp] {
			for col, value := range sigHeads[comp][block] {
				if _, err := decomposeLinfDigitsSigned(centeredLift(value, q), spec); err != nil {
					return fmt.Errorf("sig shortness V5 exact head[%d,%d,%d] rejected: %w", comp, block, col, err)
				}
			}
		}
	}
	view, err := prepareSigShortnessV5THatView(proof, ringQ, omegaWitness)
	if err != nil {
		return err
	}
	if view == nil {
		return nil
	}
	if len(omegaWitness) < view.witnessNCols {
		return fmt.Errorf("omega witness len=%d want >=%d", len(omegaWitness), view.witnessNCols)
	}
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(ringQ, sigHeads, view.witnessNCols)
	if err != nil {
		return fmt.Errorf("sig shortness V5 sig-hat derivation failed: %w", err)
	}
	sourceBlocks := proof.RowLayout.CoeffNativeSig.PackedSigBlocks
	expectedTHatHeads, err := buildTHatHeadsFromSigHatHeads(ringQ, pub, omegaWitness[:view.witnessNCols], sigHatHeads, rowLayoutReplayTHatCount(proof.RowLayout), sourceBlocks)
	if err != nil {
		return fmt.Errorf("sig shortness V5 T-hat derivation failed: %w", err)
	}
	for block := 0; block < len(expectedTHatHeads); block++ {
		tHatRow := rowLayoutPostSignTHatIndex(proof.RowLayout, block)
		if tHatRow < 0 {
			return fmt.Errorf("invalid replay T-hat row for block %d", block)
		}
		for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
			got, err := view.witnessValue(tHatRow, omegaRow)
			if err != nil {
				return fmt.Errorf("sig shortness V5 T-hat[%d,%d]: %w", block, omegaRow, err)
			}
			want := expectedTHatHeads[block][omegaRow] % q
			if got != want {
				return fmt.Errorf("sig shortness V5 T-hat[%d,%d]=%d want %d", block, omegaRow, got, want)
			}
		}
	}
	return nil
}

func VerifySigShortnessProofV6(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = opts
	if err := validateSigShortnessV6Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	v6 := proof.SigShortness.V6
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   v6.Radix,
		SigShortnessL:       v6.Digits,
	})
	if err != nil {
		return fmt.Errorf("sig shortness V6 spec: %w", err)
	}
	view, err := prepareSigShortnessV5THatView(proof, ringQ, omegaWitness)
	if err != nil {
		return err
	}
	if view == nil {
		return nil
	}
	tHatHeads, err := extractSigShortnessTHatHeadsFromView(proof, view)
	if err != nil {
		return err
	}
	hiddenProof := v6.HiddenProof
	if hiddenProof == nil {
		return fmt.Errorf("missing hidden sig shortness proof")
	}
	if hiddenProof.SigShortness != nil {
		return fmt.Errorf("hidden sig shortness proof must not carry nested shortness")
	}
	if hiddenProof.NColsUsed > 0 && hiddenProof.NColsUsed != view.witnessNCols {
		return fmt.Errorf("hidden sig shortness witness ncols=%d want %d", hiddenProof.NColsUsed, view.witnessNCols)
	}
	hiddenWitnessOmega, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0],
		hiddenProof.NLeavesUsed,
		view.witnessNCols,
		resolveProofPCSNCols(hiddenProof, 0),
		len(hiddenProof.Tail),
		hiddenProof.HashRelation,
	)
	if err != nil {
		return fmt.Errorf("hidden sig shortness witness omega: %w", err)
	}
	hiddenPub := buildSigShortnessHiddenPublicInputs(pub, proof.Root, tHatHeads, v6.Mode, v6.Radix, v6.Digits)
	hiddenReplay, err := buildSigShortnessHiddenReplay(ringQ, hiddenProof, pub, hiddenWitnessOmega, tHatHeads, spec)
	if err != nil {
		return fmt.Errorf("hidden sig shortness replay: %w", err)
	}
	if err := verifySigShortnessHiddenProof(hiddenProof, hiddenPub, hiddenReplay); err != nil {
		return fmt.Errorf("hidden sig shortness verification failed: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV7(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = omegaWitness
	_ = pub
	if err := validateSigShortnessV7Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if !sigShortnessV7EnabledForOpts(opts) {
		return fmt.Errorf("sig shortness V7 not enabled for opts")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("sig shortness V7 spec: %w", err)
	}
	v7 := proof.SigShortness.V7
	if v7.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V7 radix=%d want %d", v7.Radix, spec.R)
	}
	if v7.Digits != spec.L {
		return fmt.Errorf("sig shortness V7 digits=%d want %d", v7.Digits, spec.L)
	}
	return nil
}
