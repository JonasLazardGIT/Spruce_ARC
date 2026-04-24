package PIOP

import (
	"bytes"
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
	sigShortnessProofVersionV2  = 2
	sigShortnessProofVersionV3  = 3
	sigShortnessProofVersionV4  = 4
	sigShortnessProofVersionV5  = 5
	sigShortnessProofVersionV6  = 6
	sigShortnessProofVersionV7  = 7
	sigShortnessProofVersionV8  = 8
	sigShortnessProofVersionV9  = 9
	sigShortnessProofVersionV10 = 10
	sigShortnessProofVersionV11 = 11
	sigShortnessProofVersionV12 = 12
	sigShortnessProofVersionV13 = 13

	sigShortnessV5ModeExactSigHeads     uint8 = 1
	sigShortnessV6ModeHiddenSmallWood   uint8 = 1
	sigShortnessV7ModeInlinedMain       uint8 = 1
	sigShortnessV8ModeConstraintBound   uint8 = 1
	sigShortnessV9ModePrivateHeadBridge uint8 = 1
	sigShortnessV10ModeGroupedInlined   uint8 = 1
	sigShortnessV11ModeDirectTarget     uint8 = 1
	sigShortnessV12ModeSigDomain        uint8 = 1
	sigShortnessV13ModeLookup           uint8 = 1
)

const (
	fsModeSigShortnessHidden         = "PACS-SigShortnessHidden"
	sigShortnessTHatExtraKey         = "sig_short_t_hat"
	sigShortnessMainRootExtraKey     = "sig_short_main_root"
	sigShortnessSpecExtraKey         = "sig_short_spec"
	sigShortnessV9CommitmentExtraKey = "sig_short_v9_ajtai_commitment"
	sigShortnessV9ParamsExtraKey     = "sig_short_v9_ajtai_params"
	sigShortnessHiddenPrimaryProfile = SigShortnessProfileR11L4Production
)

const (
	sigShortnessV9AjtaiCommitRows = 2
	sigShortnessV9AjtaiRandRows   = 24
	sigShortnessV9AjtaiRandBound  = 15
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
	THatHeads    [][]uint64
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

func buildSigShortnessLookupTableDigest(spec LinfSpec) []byte {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], spec.Q)
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], spec.R)
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(spec.L))
	h.Write(buf[:])
	for lane := 0; lane < spec.L; lane++ {
		binary.LittleEndian.PutUint64(buf[:], uint64(lane))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(int64(spec.DigitLo[lane])))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(int64(spec.DigitHi[lane])))
		h.Write(buf[:])
	}
	return h.Sum(nil)
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

func buildSigShortnessV8BindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV8 || sig.V8 == nil {
		return nil, nil
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V7 != nil {
		return nil, fmt.Errorf("sig shortness V8 must not populate legacy, V5, V6, or V7 fields")
	}
	if _, err := unpackSigShortnessV8THatHeads(layout, witnessNCols, sig.V8.THatHeads); err != nil {
		return nil, err
	}
	hiddenDigest, err := computeSigShortnessHiddenProofDigest(sig.V8.HiddenProof)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(hiddenDigest)+len(sig.V8.THatHeads.Bits)+96)
	buf = append(buf, []byte("spruce.sig_shortness.v8/constraint_bound_t_hat_heads_v1")...)
	buf = appendSigShortnessUvarint(buf, int(sig.V8.Mode))
	buf = appendSigShortnessUvarint(buf, sig.V8.Radix)
	buf = appendSigShortnessUvarint(buf, sig.V8.Digits)
	buf = appendSigShortnessUvarint(buf, witnessNCols)
	buf = appendSigShortnessUvarint(buf, rowLayoutReplayTHatCount(layout))
	buf = append(buf, hiddenDigest...)
	buf = append(buf, sig.V8.THatHeads.BitWidth)
	buf = appendSigShortnessUvarint(buf, len(sig.V8.THatHeads.Bits))
	buf = append(buf, sig.V8.THatHeads.Bits...)
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...), nil
}

func buildSigShortnessV9BindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV9 || sig.V9 == nil {
		return nil, nil
	}
	_, _ = layout, witnessNCols
	return nil, fmt.Errorf("sig shortness V9 is no longer a live protocol family")
}

func buildSigShortnessBindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil {
		return nil, nil
	}
	switch sig.Version {
	case sigShortnessProofVersionV7:
		return nil, nil
	case sigShortnessProofVersionV10:
		return nil, nil
	case sigShortnessProofVersionV11:
		return nil, nil
	case sigShortnessProofVersionV5:
		return buildSigShortnessV5BindingDigest(sig, layout, witnessNCols)
	case sigShortnessProofVersionV6:
		return buildSigShortnessV6BindingDigest(sig)
	case sigShortnessProofVersionV8:
		return buildSigShortnessV8BindingDigest(sig, layout, witnessNCols)
	case sigShortnessProofVersionV9:
		return buildSigShortnessV9BindingDigest(sig, layout, witnessNCols)
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

func packSigShortnessV8THatHeads(tHatHeads [][]uint64) (SigShortnessPackedMatrix, error) {
	if len(tHatHeads) == 0 {
		return SigShortnessPackedMatrix{}, fmt.Errorf("empty V8 T-hat heads")
	}
	width := len(tHatHeads[0])
	if width == 0 {
		return SigShortnessPackedMatrix{}, fmt.Errorf("empty V8 T-hat head width")
	}
	rows := make([][]uint64, len(tHatHeads))
	for i := range tHatHeads {
		if len(tHatHeads[i]) != width {
			return SigShortnessPackedMatrix{}, fmt.Errorf("V8 T-hat head row %d width=%d want %d", i, len(tHatHeads[i]), width)
		}
		rows[i] = append([]uint64(nil), tHatHeads[i]...)
	}
	bits, _, _, bitWidth := decs.PackUintMatrix(rows)
	return SigShortnessPackedMatrix{Bits: bits, BitWidth: uint8(bitWidth)}, nil
}

func unpackSigShortnessV8THatHeads(layout RowLayout, witnessNCols int, packed SigShortnessPackedMatrix) ([][]uint64, error) {
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		return nil, fmt.Errorf("missing replay T-hat count")
	}
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("invalid V8 witness ncols=%d", witnessNCols)
	}
	rows, gotRows, gotCols, gotWidth, err := decs.UnpackUintMatrix(packed.Bits)
	if err != nil {
		return nil, fmt.Errorf("unpack V8 T-hat heads: %w", err)
	}
	if gotRows != replayTHatCount || gotCols != witnessNCols {
		return nil, fmt.Errorf("V8 T-hat head dims=%dx%d want %dx%d", gotRows, gotCols, replayTHatCount, witnessNCols)
	}
	if packed.BitWidth != 0 && uint8(gotWidth) != packed.BitWidth {
		return nil, fmt.Errorf("V8 T-hat head bit width=%d want %d", gotWidth, packed.BitWidth)
	}
	out := make([][]uint64, len(rows))
	for i := range rows {
		out[i] = append([]uint64(nil), rows[i]...)
	}
	return out, nil
}

func buildSigShortnessV5THatOpening(
	pk *lvcs.ProverKey,
	root [16]byte,
	layout RowLayout,
	pcsNCols int,
	replayWitnessRows int,
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
	originalOpening := cloneDECSOpening(opening)
	if replayWitnessRows > 0 {
		if err := maybeCompressSigShortnessOpeningPvals(opening, replayWitnessRows); err != nil {
			return nil, nil, err
		}
	}
	omitAllRowOpeningMvals(opening)
	decs.PackOpening(opening)
	restoreExplicitMerklePaths(opening, originalOpening)
	return slots, opening, nil
}

func sigShortnessReplayWitnessRowsForLayout(layout RowLayout, witnessNCols, pcsNCols, theta int) (int, error) {
	logicalRows := literalPackedPostSignReplayRowCount(layout)
	if logicalRows <= 0 {
		return 0, fmt.Errorf("missing logical replay rows")
	}
	if pcsNCols <= 0 {
		return 0, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if theta <= 1 {
		return logicalRows, nil
	}
	if witnessNCols <= 0 {
		return 0, fmt.Errorf("invalid witness ncols=%d", witnessNCols)
	}
	return ceilDiv(logicalRows, pcsNCols) * (witnessNCols + theta), nil
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
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V6 != nil || sig.V7 != nil || sig.V8 != nil || sig.V9 != nil || sig.V10 != nil || sig.V11 != nil {
		return fmt.Errorf("sig shortness V5 must not populate legacy opening fields or other version payloads")
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
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V7 != nil || sig.V8 != nil || sig.V9 != nil || sig.V10 != nil || sig.V11 != nil {
		return fmt.Errorf("sig shortness V6 must not populate legacy, V5, V7, V8, V9, V10, or V11 fields")
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
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V8 != nil || sig.V9 != nil || sig.V10 != nil || sig.V11 != nil {
		return fmt.Errorf("sig shortness V7 must not populate legacy, V5, V6, V8, V9, V10, or V11 fields")
	}
	if sig.V7.Mode != sigShortnessV7ModeInlinedMain {
		return fmt.Errorf("unsupported sig shortness V7 mode %d", sig.V7.Mode)
	}
	if proof.RowLayout.PackedSigChainBase < 0 || proof.RowLayout.PackedSigChainGroupCount <= 0 || proof.RowLayout.PackedSigChainRowsPerGroup <= 0 {
		return fmt.Errorf("missing inlined packed shortness layout for V7")
	}
	return nil
}

func validateSigShortnessV10Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV10 {
		return nil
	}
	if sig.V10 == nil {
		return fmt.Errorf("missing sig shortness V10 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V7 != nil || sig.V8 != nil || sig.V9 != nil || sig.V11 != nil || sig.V12 != nil || sig.V13 != nil {
		return fmt.Errorf("sig shortness V10 must not populate legacy, V5, V6, V7, V8, V9, V11, V12, or V13 fields")
	}
	if sig.V10.Mode != sigShortnessV10ModeGroupedInlined {
		return fmt.Errorf("unsupported sig shortness V10 mode %d", sig.V10.Mode)
	}
	if proof.RowLayout.PackedSigChainBase < 0 || proof.RowLayout.PackedSigChainGroupCount <= 0 || proof.RowLayout.PackedSigChainRowsPerGroup <= 0 {
		return fmt.Errorf("missing grouped inlined packed shortness layout for V10")
	}
	if sig.V10.GroupSize != proof.RowLayout.PackedSigChainGroupSize {
		return fmt.Errorf("V10 group_size=%d want %d", sig.V10.GroupSize, proof.RowLayout.PackedSigChainGroupSize)
	}
	if sig.V10.BlockWidth != proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth {
		return fmt.Errorf("V10 block_width=%d want %d", sig.V10.BlockWidth, proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth)
	}
	return nil
}

func validateSigShortnessV11Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV11 {
		return nil
	}
	if sig.V11 == nil {
		return fmt.Errorf("missing sig shortness V11 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V7 != nil || sig.V8 != nil || sig.V9 != nil || sig.V10 != nil || sig.V12 != nil || sig.V13 != nil {
		return fmt.Errorf("sig shortness V11 must not populate legacy, V5, V6, V7, V8, V9, V10, V12, or V13 fields")
	}
	if sig.V11.Mode != sigShortnessV11ModeDirectTarget {
		return fmt.Errorf("unsupported sig shortness V11 mode %d", sig.V11.Mode)
	}
	if proof.RowLayout.PackedSigChainBase < 0 || proof.RowLayout.PackedSigChainGroupCount <= 0 || proof.RowLayout.PackedSigChainRowsPerGroup <= 0 {
		return fmt.Errorf("missing direct-target inlined packed shortness layout for V11")
	}
	if rowLayoutReplayTHatCount(proof.RowLayout) != 0 || len(rowLayoutPostSignTHatRows(proof.RowLayout)) != 0 || rowLayoutPostSignTHatBase(proof.RowLayout) >= 0 {
		return fmt.Errorf("sig shortness V11 must not materialize replay T-hat rows")
	}
	replayBlocks := rowLayoutReplayBlockCount(proof.RowLayout)
	if replayBlocks <= 0 || len(rowLayoutPostSignTargetMR0HatRows(proof.RowLayout)) != replayBlocks {
		return fmt.Errorf("sig shortness V11 requires one target-MR0 replay row per block")
	}
	if len(rowLayoutPostSignMHatSigmaRows(proof.RowLayout)) != 0 || len(rowLayoutPostSignR0B2HatRows(proof.RowLayout)) != 0 {
		return fmt.Errorf("sig shortness V11 must not materialize separate M-hat-sigma or R0-B2 replay rows")
	}
	if sig.V11.GroupSize != proof.RowLayout.PackedSigChainGroupSize {
		return fmt.Errorf("V11 group_size=%d want %d", sig.V11.GroupSize, proof.RowLayout.PackedSigChainGroupSize)
	}
	if sig.V11.BlockWidth != proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth {
		return fmt.Errorf("V11 block_width=%d want %d", sig.V11.BlockWidth, proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth)
	}
	return nil
}

func validateSigShortnessV12Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV12 {
		return nil
	}
	if sig.V12 == nil {
		return fmt.Errorf("missing sig shortness V12 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V7 != nil || sig.V8 != nil || sig.V9 != nil || sig.V10 != nil || sig.V11 != nil || sig.V13 != nil {
		return fmt.Errorf("sig shortness V12 must not populate legacy, V5, V6, V7, V8, V9, V10, V11, or V13 fields")
	}
	if sig.V12.Mode != sigShortnessV12ModeSigDomain {
		return fmt.Errorf("unsupported sig shortness V12 mode %d", sig.V12.Mode)
	}
	if err := validateSigShortnessDirectTargetLayout(proof.RowLayout, "V12"); err != nil {
		return err
	}
	if sig.V12.GroupSize != proof.RowLayout.PackedSigChainGroupSize {
		return fmt.Errorf("V12 group_size=%d want %d", sig.V12.GroupSize, proof.RowLayout.PackedSigChainGroupSize)
	}
	if sig.V12.BlockWidth != rowLayoutPackedSigChainBlockWidth(proof.RowLayout) {
		return fmt.Errorf("V12 block_width=%d want %d", sig.V12.BlockWidth, rowLayoutPackedSigChainBlockWidth(proof.RowLayout))
	}
	if sig.V12.MainBlockWidth != proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth {
		return fmt.Errorf("V12 main_block_width=%d want %d", sig.V12.MainBlockWidth, proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth)
	}
	if sig.V12.EffectiveBlocks != rowLayoutPackedSigChainEffectiveBlocks(proof.RowLayout) {
		return fmt.Errorf("V12 effective_blocks=%d want %d", sig.V12.EffectiveBlocks, rowLayoutPackedSigChainEffectiveBlocks(proof.RowLayout))
	}
	return nil
}

func validateSigShortnessV13Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV13 {
		return nil
	}
	if sig.V13 == nil {
		return fmt.Errorf("missing sig shortness V13 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V7 != nil || sig.V8 != nil || sig.V9 != nil || sig.V10 != nil || sig.V11 != nil || sig.V12 != nil {
		return fmt.Errorf("sig shortness V13 must not populate legacy, V5, V6, V7, V8, V9, V10, V11, or V12 fields")
	}
	if sig.V13.Mode != sigShortnessV13ModeLookup {
		return fmt.Errorf("unsupported sig shortness V13 mode %d", sig.V13.Mode)
	}
	if len(sig.V13.LookupTableDigest) == 0 {
		return fmt.Errorf("sig shortness V13 lookup table digest is required")
	}
	if err := validateSigShortnessDirectTargetLayout(proof.RowLayout, "V13"); err != nil {
		return err
	}
	if sig.V13.GroupSize != proof.RowLayout.PackedSigChainGroupSize {
		return fmt.Errorf("V13 group_size=%d want %d", sig.V13.GroupSize, proof.RowLayout.PackedSigChainGroupSize)
	}
	if sig.V13.BlockWidth != rowLayoutPackedSigChainBlockWidth(proof.RowLayout) {
		return fmt.Errorf("V13 block_width=%d want %d", sig.V13.BlockWidth, rowLayoutPackedSigChainBlockWidth(proof.RowLayout))
	}
	if sig.V13.MainBlockWidth != proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth {
		return fmt.Errorf("V13 main_block_width=%d want %d", sig.V13.MainBlockWidth, proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth)
	}
	if sig.V13.EffectiveBlocks != rowLayoutPackedSigChainEffectiveBlocks(proof.RowLayout) {
		return fmt.Errorf("V13 effective_blocks=%d want %d", sig.V13.EffectiveBlocks, rowLayoutPackedSigChainEffectiveBlocks(proof.RowLayout))
	}
	return nil
}

func validateSigShortnessDirectTargetLayout(layout RowLayout, label string) error {
	if layout.PackedSigChainBase < 0 || layout.PackedSigChainGroupCount <= 0 || layout.PackedSigChainRowsPerGroup <= 0 {
		return fmt.Errorf("missing direct-target inlined packed shortness layout for %s", label)
	}
	if rowLayoutReplayTHatCount(layout) != 0 || len(rowLayoutPostSignTHatRows(layout)) != 0 || rowLayoutPostSignTHatBase(layout) >= 0 {
		return fmt.Errorf("sig shortness %s must not materialize replay T-hat rows", label)
	}
	replayBlocks := rowLayoutReplayBlockCount(layout)
	if replayBlocks <= 0 || len(rowLayoutPostSignTargetMR0HatRows(layout)) != replayBlocks {
		return fmt.Errorf("sig shortness %s requires one target-MR0 replay row per block", label)
	}
	if len(rowLayoutPostSignMHatSigmaRows(layout)) != 0 || len(rowLayoutPostSignR0B2HatRows(layout)) != 0 {
		return fmt.Errorf("sig shortness %s must not materialize separate M-hat-sigma or R0-B2 replay rows", label)
	}
	return nil
}

func validateSigShortnessV8Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV8 {
		return nil
	}
	if sig.V8 == nil {
		return fmt.Errorf("missing sig shortness V8 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil || sig.V5 != nil || sig.V6 != nil || sig.V7 != nil || sig.V9 != nil || sig.V10 != nil || sig.V11 != nil {
		return fmt.Errorf("sig shortness V8 must not populate legacy, V5, V6, V7, V9, V10, or V11 fields")
	}
	if sig.V8.Mode != sigShortnessV8ModeConstraintBound {
		return fmt.Errorf("unsupported sig shortness V8 mode %d", sig.V8.Mode)
	}
	if sig.V8.HiddenProof == nil {
		return fmt.Errorf("missing sig shortness V8 hidden proof")
	}
	if len(sig.V8.THatHeads.Bits) == 0 {
		return fmt.Errorf("missing sig shortness V8 T-hat heads")
	}
	return nil
}

func validateSigShortnessV9Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV9 {
		return nil
	}
	return fmt.Errorf("sig shortness V9 is no longer a live protocol family")
}

func validateSigShortnessV9CommitmentShape(layout RowLayout, witnessNCols int, commitment SigShortnessAjtaiCommitment) error {
	_, _, _ = layout, witnessNCols, commitment
	return fmt.Errorf("sig shortness V9 Ajtai commitment is no longer supported")
}

func rowLayoutSigShortnessV9RandRows(layout RowLayout) []int {
	if layout.SigShortnessV9RandBase < 0 || layout.SigShortnessV9RandCount <= 0 {
		return nil
	}
	return contiguousRowIndices(layout.SigShortnessV9RandBase, layout.SigShortnessV9RandCount)
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
	rCoeffRows [][]uint64,
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
		if err := reconstructRowOpeningMvalsFormal(open, gamma, rCoeffRows, domainPoints, ringQ.Modulus[0]); err != nil {
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

func buildSigShortnessHiddenPublicInputsV9(mainPub PublicInputs, mainRoot [16]byte, commitment SigShortnessAjtaiCommitment, paramsDigest []byte, mode uint8, radix, digits int) PublicInputs {
	extras := map[string]interface{}{
		sigShortnessMainRootExtraKey:     append([]byte(nil), mainRoot[:]...),
		sigShortnessSpecExtraKey:         encodeSigShortnessSpec(mode, radix, digits),
		sigShortnessV9CommitmentExtraKey: append([]byte(nil), commitment.Heads.Bits...),
		sigShortnessV9ParamsExtraKey:     append([]byte(nil), paramsDigest...),
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
	hiddenMode uint8,
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
	if hiddenMode == 0 {
		hiddenMode = sigShortnessV6ModeHiddenSmallWood
	}
	hiddenPub := buildSigShortnessHiddenPublicInputs(pub, root, tHatHeads, hiddenMode, int(spec.R), spec.L)
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
	hiddenReplay, err := buildSigShortnessHiddenReplay(ringQ, hiddenProof, pub, hiddenOmegaWitness, tHatHeads, spec)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness replay: %w", err)
	}
	if err := verifySigShortnessHiddenProof(hiddenProof, hiddenPub, hiddenReplay); err != nil {
		return nil, fmt.Errorf("hidden sig shortness self-check: %w", err)
	}
	stripHiddenSigShortnessProofDebug(hiddenProof)
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
		THatHeads:    copyMatrix(tHatHeads),
	}, nil
}

func buildSigShortnessHiddenCandidateV9(
	ringQ *ring.Ring,
	root [16]byte,
	layout RowLayout,
	cn *CoeffNativeShowingWitness,
	pub PublicInputs,
	witnessNCols int,
	mainOpts SimOpts,
	shape sigShortnessHiddenCandidateShape,
	tHatHeads [][]uint64,
	randHeads [][]uint64,
	commitment SigShortnessAjtaiCommitment,
	paramsDigest []byte,
) (*sigShortnessHiddenBuiltCandidate, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, fmt.Errorf("nil coeff-native showing witness")
	}
	specOpts := buildSigShortnessProfileSimOpts(shape)
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], specOpts)
	if err != nil {
		return nil, err
	}
	logicalWitnessPolys := sigShortnessHiddenLogicalWitnessPolys(ringQ, cn, witnessNCols, spec.L) + rowLayoutReplayTHatCount(layout) + sigShortnessV9AjtaiRandRows
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
	hiddenLayout := buildSigShortnessHiddenLayoutV9(layout, spec, witnessNCols)
	hiddenRowsNTT, err := flattenSigShortnessHiddenWitnessRowsV9(ringQ, hiddenLayout, packedWitness, spec, hiddenOmegaWitness, tHatHeads, randHeads)
	if err != nil {
		return nil, err
	}
	hiddenRows := make([]*ring.Poly, len(hiddenRowsNTT))
	for i := range hiddenRowsNTT {
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(hiddenRowsNTT[i], coeff)
		hiddenRows[i] = coeff
	}
	hiddenSet, err := buildSigShortnessHiddenConstraintSetV9(ringQ, hiddenLayout, pub, hiddenOmegaWitness, hiddenRowsNTT, commitment, spec)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness V9 constraint set: %w", err)
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
	hiddenPub := buildSigShortnessHiddenPublicInputsV9(pub, root, commitment, paramsDigest, sigShortnessV9ModePrivateHeadBridge, int(spec.R), spec.L)
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
		return nil, fmt.Errorf("build hidden sig shortness V9 proof: %w", err)
	}
	hiddenReplay, err := buildSigShortnessHiddenReplayV9(ringQ, hiddenProof, pub, hiddenOmegaWitness, commitment, spec)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness V9 replay: %w", err)
	}
	if err := verifySigShortnessHiddenProof(hiddenProof, hiddenPub, hiddenReplay); err != nil {
		return nil, fmt.Errorf("hidden sig shortness V9 self-check: %w", err)
	}
	stripHiddenSigShortnessProofDebug(hiddenProof)
	hiddenReport, err := BuildProofReport(hiddenProof, hiddenOpts, ringQ)
	if err != nil {
		return nil, fmt.Errorf("hidden sig shortness report: %w", err)
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
		THatHeads:    copyMatrix(tHatHeads),
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
		IdxZ:                       -1,
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
		IdxR0B2Hat:                 -1,
		IdxRHat1:                   -1,
		IdxZHat:                    -1,
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

func buildSigShortnessHiddenLayoutV9(mainLayout RowLayout, spec LinfSpec, witnessNCols int) RowLayout {
	layout := buildSigShortnessHiddenLayout(mainLayout, spec, witnessNCols)
	replayTHatCount := rowLayoutReplayTHatCount(mainLayout)
	tHatBase := layout.SigCount
	layout.IdxTHatBase = tHatBase
	layout.ReplayTHatRows = contiguousRowIndices(tHatBase, replayTHatCount)
	layout.ReplayTHatCount = replayTHatCount
	layout.ReplayBlockCount = replayTHatCount
	layout.SigShortnessV9RandBase = tHatBase + replayTHatCount
	layout.SigShortnessV9RandCount = sigShortnessV9AjtaiRandRows
	layout.SigShortnessV9RandBound = sigShortnessV9AjtaiRandBound
	layout.SigCount = tHatBase + replayTHatCount + sigShortnessV9AjtaiRandRows
	return layout
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

func flattenSigShortnessHiddenWitnessRowsV9(ringQ *ring.Ring, layout RowLayout, packedWitness *literalPackedPolyWitness, spec LinfSpec, omegaWitness []uint64, tHatHeads [][]uint64, randHeads [][]uint64) ([]*ring.Poly, error) {
	rows, err := flattenSigShortnessHiddenWitnessRows(layout, packedWitness, spec)
	if err != nil {
		return nil, err
	}
	if len(tHatHeads) != rowLayoutReplayTHatCount(layout) {
		return nil, fmt.Errorf("V9 hidden T-hat heads=%d want %d", len(tHatHeads), rowLayoutReplayTHatCount(layout))
	}
	makeRow := func(head []uint64) *ring.Poly {
		return BuildThetaPrime(ringQ, head, omegaWitness)
	}
	for i := range tHatHeads {
		rows = append(rows, makeRow(tHatHeads[i]))
	}
	if len(randHeads) != sigShortnessV9AjtaiRandRows {
		return nil, fmt.Errorf("V9 hidden randomness rows=%d want %d", len(randHeads), sigShortnessV9AjtaiRandRows)
	}
	for i := range randHeads {
		rows = append(rows, makeRow(randHeads[i]))
	}
	if len(rows) != layout.SigCount {
		return nil, fmt.Errorf("V9 hidden row count=%d want layout sig count=%d", len(rows), layout.SigCount)
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
		thetaAHeads := make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, nil, fmt.Errorf("hidden theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			thetaAHeads[comp] = aHead
		}
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aScale := thetaAHeads[comp][j] % q
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
						term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q), int(ringQ.N), q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], tHatCoeffs[bOut], q), int(ringQ.N), q)
			bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
			outCoeffs = append(outCoeffs, bridgeCoeff)
			outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	return outPolys, outCoeffs, nil
}

func buildSigShortnessHiddenTHatRowBridgeFormalCoeffs(
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
		return nil, nil, fmt.Errorf("hidden sig shortness expects one public A row")
	}
	cfg := layout.CoeffNativeSig
	replayTHatCount := rowLayoutReplayTHatCount(layout)
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
	tHatCoeffs := make([][]uint64, replayTHatCount)
	for block := 0; block < replayTHatCount; block++ {
		rowIdx := rowLayoutPostSignTHatIndex(layout, block)
		if rowIdx < 0 || rowIdx >= len(rowsNTT) || rowsNTT[rowIdx] == nil {
			return nil, nil, fmt.Errorf("hidden V9 T-hat row idx out of range for block=%d", block)
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
		if err != nil {
			return nil, nil, fmt.Errorf("hidden V9 T-hat coeffs block %d: %w", block, err)
		}
		tHatCoeffs[block] = trimPoly(coeff, q)
	}
	outPolys := make([]*ring.Poly, 0, replayTHatCount*ncols)
	outCoeffs := make([][]uint64, 0, replayTHatCount*ncols)
	for bOut := 0; bOut < replayTHatCount; bOut++ {
		thetaAHeads := make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, nil, fmt.Errorf("hidden theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			thetaAHeads[comp] = aHead
		}
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aScale := thetaAHeads[comp][j] % q
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
						term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q), int(ringQ.N), q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], tHatCoeffs[bOut], q), int(ringQ.N), q)
			bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
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

func buildSigShortnessHiddenConstraintSetV9(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	commitment SigShortnessAjtaiCommitment,
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
	faggNorm, faggNormCoeffs, err := buildSigShortnessHiddenTHatRowBridgeFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, spec)
	if err != nil {
		return ConstraintSet{}, err
	}
	ajtaiSet, err := buildSigShortnessV9AjtaiConstraintSet(ringQ, pub.HashRelation, layout, rowsNTT, omegaWitness, commitment, rowLayoutPostSignTHatRows(layout), rowLayoutSigShortnessV9RandRows(layout))
	if err != nil {
		return ConstraintSet{}, err
	}
	shortSet.FparNorm = append(shortSet.FparNorm, ajtaiSet.FparInt...)
	shortSet.FparNormCoeffs = append(shortSet.FparNormCoeffs, ajtaiSet.FparIntCoeffs...)
	shortSet.FaggNorm = append([]*ring.Poly{}, faggNorm...)
	shortSet.FaggNormCoeffs = append([][]uint64{}, faggNormCoeffs...)
	if ajtaiSet.ParallelAlgDeg > shortSet.ParallelAlgDeg {
		shortSet.ParallelAlgDeg = ajtaiSet.ParallelAlgDeg
	}
	shortSet.ParallelAlgDeg = maxInt(shortSet.ParallelAlgDeg, maxDegreeFromCoeffRows(shortSet.FparNormCoeffs))
	shortSet.AggregatedAlgDeg = maxInt(1, maxDegreeFromCoeffRows(faggNormCoeffs))
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

func buildSigShortnessHiddenReplayV9(
	ringQ *ring.Ring,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	commitment SigShortnessAjtaiCommitment,
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
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness[:ncols], replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return nil, err
	}
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
	tHatRows := rowLayoutPostSignTHatRows(layout)
	randRows := rowLayoutSigShortnessV9RandRows(layout)
	eval := func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if len(rows) < logicalRows {
			return nil, nil, fmt.Errorf("hidden row value count=%d want >=%d", len(rows), logicalRows)
		}
		q := ringQ.Modulus[0]
		fpar := make([]uint64, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L+commitment.Rows+len(randRows))
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
		ajtaiVals, err := evalSigShortnessV9AjtaiF(ringQ, pub.HashRelation, omegaWitness[:ncols], x, rows, commitment, tHatRows, randRows)
		if err != nil {
			return nil, nil, err
		}
		fpar = append(fpar, ajtaiVals...)
		fagg := make([]uint64, 0, replayTHatCount*ncols)
		for bOut := 0; bOut < replayTHatCount; bOut++ {
			tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
			if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
				return nil, nil, fmt.Errorf("hidden V9 T-hat row idx out of range for block=%d", bOut)
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
				return nil, nil, fmt.Errorf("hidden K row count=%d want >=%d", len(rows), logicalRows)
			}
			fpar := make([]kf.Elem, 0, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L+commitment.Rows+len(randRows))
			for block := 0; block < cfg.PackedSigBlocks; block++ {
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
						fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
					}
				}
			}
			ajtaiVals, err := evalSigShortnessV9AjtaiK(ringQ, K, pub.HashRelation, omegaWitness[:ncols], e, rows, commitment, tHatRows, randRows)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, ajtaiVals...)
			fagg := make([]kf.Elem, 0, replayTHatCount*ncols)
			for bOut := 0; bOut < replayTHatCount; bOut++ {
				tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
				if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("hidden V9 T-hat K row idx out of range for block=%d", bOut)
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
	replayWitnessRows, err := sigShortnessReplayWitnessRowsForLayout(layout, witnessNCols, pcsNCols, opts.Theta)
	if err != nil {
		return nil, nil, fmt.Errorf("derive sig shortness replay witness rows: %w", err)
	}
	_, tHatOpening, err := buildSigShortnessV5THatOpening(pk, root, layout, pcsNCols, replayWitnessRows)
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
	chosen, err = buildSigShortnessHiddenCandidateWithPolicy(ringQ, root, layout, cn, pub, omegaWitness, witnessNCols, opts, legacyShape, sigShortnessV6ModeHiddenSmallWood, false)
	if err != nil {
		return nil, nil, err
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRowsForLayout(layout, witnessNCols, pcsNCols, opts.Theta)
	if err != nil {
		return nil, nil, fmt.Errorf("derive sig shortness replay witness rows: %w", err)
	}
	_, tHatOpening, err := buildSigShortnessV5THatOpening(pk, root, layout, pcsNCols, replayWitnessRows)
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

func buildSigShortnessProofV8(
	ringQ *ring.Ring,
	root [16]byte,
	layout RowLayout,
	cn *CoeffNativeShowingWitness,
	pub PublicInputs,
	omegaWitness []uint64,
	witnessNCols int,
	opts SimOpts,
) (*SigShortnessProof, []byte, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, nil, fmt.Errorf("nil coeff-native showing witness")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, nil, fmt.Errorf("sig shortness V8 requires literal packed v3 layout")
	}
	if witnessNCols <= 0 || len(omegaWitness) != witnessNCols {
		return nil, nil, fmt.Errorf("invalid witness omega for sig shortness V8")
	}
	legacyShape, err := chooseSigShortnessHiddenShapeLegacyFirstFit(ringQ, cn, omegaWitness, witnessNCols, opts)
	if err != nil {
		return nil, nil, err
	}
	chosen, err := buildSigShortnessHiddenCandidateWithPolicy(ringQ, root, layout, cn, pub, omegaWitness, witnessNCols, opts, legacyShape, sigShortnessV8ModeConstraintBound, false)
	if err != nil {
		return nil, nil, err
	}
	packedHeads, err := packSigShortnessV8THatHeads(chosen.THatHeads)
	if err != nil {
		return nil, nil, err
	}
	sig := &SigShortnessProof{
		Version: sigShortnessProofVersionV8,
		V8: &SigShortnessProofV8{
			Mode:        sigShortnessV8ModeConstraintBound,
			Radix:       int(chosen.Spec.R),
			Digits:      chosen.Spec.L,
			HiddenProof: chosen.HiddenProof,
			THatHeads:   packedHeads,
		},
	}
	digest, err := buildSigShortnessV8BindingDigest(sig, layout, witnessNCols)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}

func buildSigShortnessProofV9(
	ringQ *ring.Ring,
	root [16]byte,
	layout RowLayout,
	mainRowsNTT []*ring.Poly,
	cn *CoeffNativeShowingWitness,
	pub PublicInputs,
	omegaWitness []uint64,
	witnessNCols int,
	opts SimOpts,
) (*SigShortnessProof, []byte, error) {
	if !sigShortnessV9EnabledForOpts(opts) {
		return nil, nil, nil
	}
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, nil, fmt.Errorf("sig shortness V9 requires literal packed v3 layout")
	}
	if len(omegaWitness) != witnessNCols {
		return nil, nil, fmt.Errorf("V9 witness omega width=%d want %d", len(omegaWitness), witnessNCols)
	}
	shape := sigShortnessHiddenCandidateShape{Profile: ResolveSignatureShortnessProfileLabelForOpts(opts)}
	if sigShortnessRawOverrideActive(opts) {
		shape = sigShortnessHiddenCandidateShape{
			RawOverride: true,
			Radix:       opts.SigShortnessRadix,
			Digits:      opts.SigShortnessL,
		}
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], buildSigShortnessProfileSimOpts(shape))
	if err != nil {
		return nil, nil, err
	}
	logicalWitnessPolys := sigShortnessHiddenLogicalWitnessPolys(ringQ, cn, witnessNCols, spec.L) + rowLayoutReplayTHatCount(layout) + sigShortnessV9AjtaiRandRows
	hiddenOpts := buildSigShortnessHiddenOptsForShape(opts, shape, witnessNCols, logicalWitnessPolys)
	hiddenLVCSNCols := resolvePCSNCols(hiddenOpts, witnessNCols)
	if hiddenLVCSNCols <= 0 {
		hiddenLVCSNCols = witnessNCols
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
		return nil, nil, fmt.Errorf("V9 hidden witness omega: %w", err)
	}
	hiddenPackedWitness, err := buildLiteralPackedPolyWitness(
		ringQ,
		cn,
		hiddenOmegaWitness,
		witnessNCols,
		CoeffNativeSigModelLiteralPackedAggregatedV3,
		hiddenOpts,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("V9 hidden literal packed witness: %w", err)
	}
	packedSigHeads := reconstructPackedSigHeadsFromLimbHeads(hiddenPackedWitness.SigLimbHeads, spec, ringQ.Modulus[0])
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(ringQ, packedSigHeads, witnessNCols)
	if err != nil {
		return nil, nil, fmt.Errorf("V9 hidden sig hat heads: %w", err)
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
		return nil, nil, fmt.Errorf("V9 T-hat heads: %w", err)
	}
	randRows := rowLayoutSigShortnessV9RandRows(layout)
	randHeads, err := sigShortnessV9HeadsFromRows(ringQ, mainRowsNTT, omegaWitness, randRows, "V9 main randomness")
	if err != nil {
		return nil, nil, err
	}
	commitment, paramsDigest, err := buildSigShortnessV9AjtaiCommitment(ringQ.Modulus[0], pub.HashRelation, tHatHeads, randHeads)
	if err != nil {
		return nil, nil, err
	}
	chosen, err := buildSigShortnessHiddenCandidateV9(
		ringQ,
		root,
		layout,
		cn,
		pub,
		witnessNCols,
		opts,
		shape,
		tHatHeads,
		randHeads,
		commitment,
		paramsDigest,
	)
	if err != nil {
		return nil, nil, err
	}
	hiddenOpeningDigest := sigShortnessV9OpeningDigest("hidden", chosen.HiddenProof.Root, chosen.HiddenProof.RowLayout, commitment, paramsDigest)
	sig := &SigShortnessProof{
		Version: sigShortnessProofVersionV9,
		V9: &SigShortnessProofV9{
			Mode:                   sigShortnessV9ModePrivateHeadBridge,
			Radix:                  int(chosen.Spec.R),
			Digits:                 chosen.Spec.L,
			HiddenProof:            chosen.HiddenProof,
			THatCommitment:         commitment,
			CommitmentParamsDigest: append([]byte(nil), paramsDigest...),
			MainOpeningDigest:      sigShortnessV9OpeningDigest("main", root, layout, commitment, paramsDigest),
			HiddenOpeningDigest:    hiddenOpeningDigest,
		},
	}
	digest, err := buildSigShortnessV9BindingDigest(sig, layout, witnessNCols)
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
	if !sigShortnessInlinedTargetHidingEnabledForOpts(opts) {
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
	if sigShortnessV10EnabledForOpts(opts) {
		return &SigShortnessProof{
			Version: sigShortnessProofVersionV10,
			V10: &SigShortnessProofV10{
				Mode:       sigShortnessV10ModeGroupedInlined,
				Radix:      int(spec.R),
				Digits:     spec.L,
				GroupSize:  layout.PackedSigChainGroupSize,
				BlockWidth: layout.CoeffNativeSig.PackedSigBlockWidth,
			},
		}, nil
	}
	if sigShortnessV11EnabledForOpts(opts) {
		return &SigShortnessProof{
			Version: sigShortnessProofVersionV11,
			V11: &SigShortnessProofV11{
				Mode:       sigShortnessV11ModeDirectTarget,
				Radix:      int(spec.R),
				Digits:     spec.L,
				GroupSize:  layout.PackedSigChainGroupSize,
				BlockWidth: layout.CoeffNativeSig.PackedSigBlockWidth,
			},
		}, nil
	}
	if sigShortnessV12EnabledForOpts(opts) {
		return &SigShortnessProof{
			Version: sigShortnessProofVersionV12,
			V12: &SigShortnessProofV12{
				Mode:            sigShortnessV12ModeSigDomain,
				Radix:           int(spec.R),
				Digits:          spec.L,
				GroupSize:       layout.PackedSigChainGroupSize,
				BlockWidth:      rowLayoutPackedSigChainBlockWidth(layout),
				MainBlockWidth:  layout.CoeffNativeSig.PackedSigBlockWidth,
				EffectiveBlocks: rowLayoutPackedSigChainEffectiveBlocks(layout),
			},
		}, nil
	}
	if sigShortnessV13EnabledForOpts(opts) {
		return &SigShortnessProof{
			Version: sigShortnessProofVersionV13,
			V13: &SigShortnessProofV13{
				Mode:              sigShortnessV13ModeLookup,
				Radix:             int(spec.R),
				Digits:            spec.L,
				GroupSize:         layout.PackedSigChainGroupSize,
				BlockWidth:        rowLayoutPackedSigChainBlockWidth(layout),
				MainBlockWidth:    layout.CoeffNativeSig.PackedSigBlockWidth,
				EffectiveBlocks:   rowLayoutPackedSigChainEffectiveBlocks(layout),
				LookupTableDigest: buildSigShortnessLookupTableDigest(spec),
			},
		}, nil
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
		thetaAHeads := make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			thetaAHeads[comp] = aHead
		}
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aScale := thetaAHeads[comp][j] % q
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
						term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q), int(ringQ.N), q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], tHatCoeffs[bOut], q), int(ringQ.N), q)
			bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
			outCoeffs = append(outCoeffs, bridgeCoeff)
			outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	return outPolys, outCoeffs, nil
}

func buildSigShortnessDirectTargetFormalCoeffs(
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
		return nil, nil, fmt.Errorf("sig shortness V11 expects one public A row")
	}
	if !publicUsesBBTran(pub) {
		return nil, nil, fmt.Errorf("sig shortness V11 direct target requires bb_tran relation")
	}
	if len(pub.B) < 4 {
		return nil, nil, fmt.Errorf("sig shortness V11 requires B rows")
	}
	cfg := layout.CoeffNativeSig
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	sourceBlocks := cfg.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	if replayBlockCount <= 0 {
		return nil, nil, fmt.Errorf("invalid replay blocks=%d", replayBlockCount)
	}
	ncols := len(omegaWitness)
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("empty witness omega")
	}
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, replayBlockCount*ncols, sourceBlocks)
	if err != nil {
		return nil, nil, fmt.Errorf("sig shortness V11 transform bridge basis: %w", err)
	}
	q := ringQ.Modulus[0]
	getRowCoeff := func(idx int) ([]uint64, error) {
		if idx < 0 || idx >= len(rowsNTT) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
		if err != nil {
			return nil, err
		}
		return trimPoly(coeff, q), nil
	}
	targetMR0Coeffs := make([][]uint64, replayBlockCount)
	zHatCoeffs := make([][]uint64, replayBlockCount)
	thetaB0Coeffs := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		targetCoeff, err := getRowCoeff(rowLayoutPostSignTargetMR0HatIndex(layout, block))
		if err != nil {
			return nil, nil, fmt.Errorf("target-MR0 coeffs block %d: %w", block, err)
		}
		zCoeff, err := getRowCoeff(rowLayoutPostSignZHatIndex(layout, block))
		if err != nil {
			return nil, nil, fmt.Errorf("Z-hat coeffs block %d: %w", block, err)
		}
		thetaB0, err := thetaPolyFromNTTBlock(ringQ, pub.B[0], omegaWitness, block, sourceBlocks)
		if err != nil {
			return nil, nil, fmt.Errorf("theta B0 block %d: %w", block, err)
		}
		b0Coeff, err := coeffFromNTTPoly(ringQ, thetaB0)
		if err != nil {
			return nil, nil, fmt.Errorf("theta B0 coeffs block %d: %w", block, err)
		}
		targetMR0Coeffs[block] = targetCoeff
		zHatCoeffs[block] = zCoeff
		thetaB0Coeffs[block] = trimPoly(b0Coeff, q)
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
	outPolys := make([]*ring.Poly, 0, replayBlockCount*ncols)
	outCoeffs := make([][]uint64, 0, replayBlockCount*ncols)
	for bOut := 0; bOut < replayBlockCount; bOut++ {
		thetaAHeads := make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			thetaAHeads[comp] = aHead
		}
		rhsCoeff := polyAdd(thetaB0Coeffs[bOut], targetMR0Coeffs[bOut], q)
		rhsCoeff = polyAdd(rhsCoeff, zHatCoeffs[bOut], q)
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aScale := thetaAHeads[comp][j] % q
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
						term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q), int(ringQ.N), q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], rhsCoeff, q), int(ringQ.N), q)
			bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
			outCoeffs = append(outCoeffs, bridgeCoeff)
			outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	return outPolys, outCoeffs, nil
}

func deriveSigShortnessGroupedOmega(ringQ *ring.Ring, layout RowLayout, pub PublicInputs, opts SimOpts) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	width := rowLayoutPackedSigChainBlockWidth(layout)
	if width <= 0 {
		return nil, fmt.Errorf("invalid signature shortness width=%d", width)
	}
	resolved := opts
	resolved.applyDefaults()
	nLeaves := resolved.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	return deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, width, resolved.LVCSNCols, resolved.Ell, pub.HashRelation)
}

func buildSigShortnessGroupedDirectTargetFormalCoeffs(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	opts SimOpts,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, nil, fmt.Errorf("sig shortness V12 expects one public A row")
	}
	if !publicUsesBBTran(pub) {
		return nil, nil, fmt.Errorf("sig shortness V12 direct target requires bb_tran relation")
	}
	if len(pub.B) < 4 {
		return nil, nil, fmt.Errorf("sig shortness V12 requires B rows")
	}
	cfg := layout.CoeffNativeSig
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	sourceBlocks := cfg.PackedSigBlocks
	mainNCols := len(omegaWitness)
	groupSize := layout.PackedSigChainGroupSize
	sigNCols := rowLayoutPackedSigChainBlockWidth(layout)
	effectiveBlocks := rowLayoutPackedSigChainEffectiveBlocks(layout)
	if sourceBlocks <= 0 || replayBlockCount <= 0 || mainNCols <= 0 || groupSize <= 0 || sigNCols <= 0 || effectiveBlocks <= 0 {
		return nil, nil, fmt.Errorf("invalid V12 geometry source_blocks=%d replay_blocks=%d main_ncols=%d group_size=%d sig_ncols=%d effective_blocks=%d", sourceBlocks, replayBlockCount, mainNCols, groupSize, sigNCols, effectiveBlocks)
	}
	if replayBlockCount != sourceBlocks {
		return nil, nil, fmt.Errorf("V12 direct target currently expects replay_blocks=%d == source_blocks=%d", replayBlockCount, sourceBlocks)
	}
	if sigNCols != mainNCols*groupSize {
		return nil, nil, fmt.Errorf("V12 signature width=%d want main_ncols(%d)*group_size(%d)", sigNCols, mainNCols, groupSize)
	}
	if effectiveBlocks*groupSize != sourceBlocks {
		return nil, nil, fmt.Errorf("V12 effective blocks=%d group_size=%d source_blocks=%d", effectiveBlocks, groupSize, sourceBlocks)
	}
	sigOmega, err := deriveSigShortnessGroupedOmega(ringQ, layout, pub, opts)
	if err != nil {
		return nil, nil, err
	}
	sigLagrange, err := buildLagrangeBasisCoeffs(sigOmega, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, fmt.Errorf("V12 signature lagrange basis: %w", err)
	}
	mainLagrange, err := buildLagrangeBasisCoeffs(omegaWitness, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, fmt.Errorf("V12 main lagrange basis: %w", err)
	}
	q := ringQ.Modulus[0]
	getRowCoeff := func(idx int) ([]uint64, error) {
		if idx < 0 || idx >= len(rowsNTT) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
		if err != nil {
			return nil, err
		}
		return trimPoly(coeff, q), nil
	}
	targetMR0Coeffs := make([][]uint64, replayBlockCount)
	zHatCoeffs := make([][]uint64, replayBlockCount)
	thetaB0Coeffs := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		targetCoeff, err := getRowCoeff(rowLayoutPostSignTargetMR0HatIndex(layout, block))
		if err != nil {
			return nil, nil, fmt.Errorf("target-MR0 coeffs block %d: %w", block, err)
		}
		zCoeff, err := getRowCoeff(rowLayoutPostSignZHatIndex(layout, block))
		if err != nil {
			return nil, nil, fmt.Errorf("Z-hat coeffs block %d: %w", block, err)
		}
		thetaB0, err := thetaPolyFromNTTBlock(ringQ, pub.B[0], omegaWitness, block, sourceBlocks)
		if err != nil {
			return nil, nil, fmt.Errorf("theta B0 block %d: %w", block, err)
		}
		b0Coeff, err := coeffFromNTTPoly(ringQ, thetaB0)
		if err != nil {
			return nil, nil, fmt.Errorf("theta B0 coeffs block %d: %w", block, err)
		}
		targetMR0Coeffs[block] = targetCoeff
		zHatCoeffs[block] = zCoeff
		thetaB0Coeffs[block] = trimPoly(b0Coeff, q)
	}
	digitCoeffs := make(map[[3]int][]uint64, cfg.PackedSigComponents*effectiveBlocks*spec.L)
	for sigGroup := 0; sigGroup < effectiveBlocks; sigGroup++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			group := sigGroup*cfg.PackedSigComponents + comp
			for lane := 0; lane < spec.L; lane++ {
				rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
				if rowIdx < 0 || rowIdx >= len(rowsNTT) {
					return nil, nil, fmt.Errorf("digit row idx out of range for comp=%d group=%d lane=%d", comp, sigGroup, lane)
				}
				coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
				if err != nil {
					return nil, nil, fmt.Errorf("digit coeffs comp=%d group=%d lane=%d: %w", comp, sigGroup, lane, err)
				}
				digitCoeffs[[3]int{comp, sigGroup, lane}] = trimPoly(coeff, q)
			}
		}
	}
	outPolys := make([]*ring.Poly, 0, replayBlockCount*mainNCols)
	outCoeffs := make([][]uint64, 0, replayBlockCount*mainNCols)
	for bOut := 0; bOut < replayBlockCount; bOut++ {
		thetaAHeads := make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			thetaAHeads[comp] = aHead
		}
		rhsCoeff := polyAdd(thetaB0Coeffs[bOut], targetMR0Coeffs[bOut], q)
		rhsCoeff = polyAdd(rhsCoeff, zHatCoeffs[bOut], q)
		sigGroup := bOut / groupSize
		sigSubBlock := bOut % groupSize
		for j := 0; j < mainNCols; j++ {
			sigCol := sigSubBlock*mainNCols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aScale := thetaAHeads[comp][j] % q
				if aScale == 0 {
					continue
				}
				for lane := 0; lane < spec.L; lane++ {
					scale := modMul(aScale, spec.RPows[lane]%q, q)
					term := reducePolyModXN1(polyMul(sigLagrange[sigCol], digitCoeffs[[3]int{comp, sigGroup, lane}], q), int(ringQ.N), q)
					if scale != 1 {
						term = scalePoly(term, scale, q)
					}
					leftCoeff = polyAdd(leftCoeff, term, q)
				}
			}
			rightCoeff := reducePolyModXN1(polyMul(mainLagrange[j], rhsCoeff, q), int(ringQ.N), q)
			bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
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
	if !sigShortnessInlinedTargetHidingEnabledForOpts(opts) {
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
	var faggNorm []*ring.Poly
	var faggNormCoeffs [][]uint64
	if sigShortnessV12EnabledForOpts(opts) || sigShortnessV13EnabledForOpts(opts) {
		faggNorm, faggNormCoeffs, err = buildSigShortnessGroupedDirectTargetFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, opts, spec)
	} else if sigShortnessV11EnabledForOpts(opts) {
		faggNorm, faggNormCoeffs, err = buildSigShortnessDirectTargetFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, spec)
	} else {
		faggNorm, faggNormCoeffs, err = buildSigShortnessCommittedTHatBridgeFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, spec)
	}
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
	if proof == nil || proof.SigShortness == nil {
		return nil, fmt.Errorf("missing inlined sig shortness proof metadata")
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	radix := 0
	digits := 0
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV7:
		if proof.SigShortness.V7 == nil {
			return nil, fmt.Errorf("missing V7 sig shortness proof metadata")
		}
		radix = proof.SigShortness.V7.Radix
		digits = proof.SigShortness.V7.Digits
	case sigShortnessProofVersionV10:
		if proof.SigShortness.V10 == nil {
			return nil, fmt.Errorf("missing V10 sig shortness proof metadata")
		}
		radix = proof.SigShortness.V10.Radix
		digits = proof.SigShortness.V10.Digits
	case sigShortnessProofVersionV11:
		if proof.SigShortness.V11 == nil {
			return nil, fmt.Errorf("missing V11 sig shortness proof metadata")
		}
		radix = proof.SigShortness.V11.Radix
		digits = proof.SigShortness.V11.Digits
	case sigShortnessProofVersionV12:
		if proof.SigShortness.V12 == nil {
			return nil, fmt.Errorf("missing V12 sig shortness proof metadata")
		}
		radix = proof.SigShortness.V12.Radix
		digits = proof.SigShortness.V12.Digits
	case sigShortnessProofVersionV13:
		if proof.SigShortness.V13 == nil {
			return nil, fmt.Errorf("missing V13 sig shortness proof metadata")
		}
		radix = proof.SigShortness.V13.Radix
		digits = proof.SigShortness.V13.Digits
	default:
		return nil, fmt.Errorf("unsupported inlined sig shortness version %d", proof.SigShortness.Version)
	}
	directTarget := proof.SigShortness.Version == sigShortnessProofVersionV11 || proof.SigShortness.Version == sigShortnessProofVersionV12 || proof.SigShortness.Version == sigShortnessProofVersionV13
	groupedSigDomain := proof.SigShortness.Version == sigShortnessProofVersionV12 || proof.SigShortness.Version == sigShortnessProofVersionV13
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
	specOpts.SigShortnessRadix = radix
	specOpts.SigShortnessL = digits
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], specOpts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	replayOutputBlocks := rowLayoutReplayTHatCount(layout)
	if directTarget {
		replayOutputBlocks = rowLayoutReplayBlockCount(layout)
	}
	if replayOutputBlocks <= 0 {
		return nil, fmt.Errorf("invalid inlined shortness replay output blocks=%d", replayOutputBlocks)
	}
	var bridgeBasis *transformBridgeBasisCache
	var mainLagrange [][]uint64
	var sigLagrange [][]uint64
	if groupedSigDomain {
		mainLagrange, err = buildLagrangeBasisCoeffs(omegaWitness, ringQ.Modulus[0])
		if err != nil {
			return nil, fmt.Errorf("sig shortness V12 main lagrange basis: %w", err)
		}
		sigOmega, err := deriveSigShortnessGroupedOmega(ringQ, layout, pub, opts)
		if err != nil {
			return nil, err
		}
		sigLagrange, err = buildLagrangeBasisCoeffs(sigOmega, ringQ.Modulus[0])
		if err != nil {
			return nil, fmt.Errorf("sig shortness V12 signature lagrange basis: %w", err)
		}
	} else {
		bridgeBasis, err = newTransformBridgeBasisCache(ringQ, omegaWitness, replayOutputBlocks*ncols, sourceBlocks)
		if err != nil {
			return nil, fmt.Errorf("sig shortness V7 transform bridge basis: %w", err)
		}
	}
	aHeads := make([][][]uint64, replayOutputBlocks)
	for bOut := 0; bOut < replayOutputBlocks; bOut++ {
		aHeads[bOut] = make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			head, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			aHeads[bOut][comp] = head
		}
	}
	var b0Coeffs [][]uint64
	if directTarget {
		b0Coeffs = make([][]uint64, replayOutputBlocks)
		for block := 0; block < replayOutputBlocks; block++ {
			thetaB0, err := thetaPolyFromNTTBlock(ringQ, pub.B[0], omegaWitness, block, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta B0 block %d: %w", block, err)
			}
			coeff, err := coeffFromNTTPoly(ringQ, thetaB0)
			if err != nil {
				return nil, fmt.Errorf("theta B0 coeff block %d: %w", block, err)
			}
			b0Coeffs[block] = trimPoly(coeff, ringQ.Modulus[0])
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
		fparGroups := cfg.PackedSigBlocks * cfg.PackedSigComponents
		if groupedSigDomain {
			fparGroups = layout.PackedSigChainGroupCount
		}
		fpar := make([]uint64, 0, fparGroups*spec.L)
		if groupedSigDomain {
			for group := 0; group < layout.PackedSigChainGroupCount; group++ {
				for lane := 0; lane < spec.L; lane++ {
					rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
					fpar = append(fpar, EvalPoly(spec.PDi[lane], rows[rowIdx]%q, q)%q)
				}
			}
		} else {
			for block := 0; block < cfg.PackedSigBlocks; block++ {
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
						fpar = append(fpar, EvalPoly(spec.PDi[lane], rows[rowIdx]%q, q)%q)
					}
				}
			}
		}
		x := domainPoints[int(evalIdx)] % q
		fagg := make([]uint64, 0, replayOutputBlocks*ncols)
		var mainLagrangeVals []uint64
		var sigLagrangeVals []uint64
		if groupedSigDomain {
			mainLagrangeVals = make([]uint64, len(mainLagrange))
			for j := range mainLagrange {
				mainLagrangeVals[j] = EvalPoly(mainLagrange[j], x, q) % q
			}
			sigLagrangeVals = make([]uint64, len(sigLagrange))
			for j := range sigLagrange {
				sigLagrangeVals[j] = EvalPoly(sigLagrange[j], x, q) % q
			}
		}
		for bOut := 0; bOut < replayOutputBlocks; bOut++ {
			var rhsBase uint64
			if directTarget {
				targetRowIdx := rowLayoutPostSignTargetMR0HatIndex(layout, bOut)
				zHatRowIdx := rowLayoutPostSignZHatIndex(layout, bOut)
				if targetRowIdx < 0 || targetRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("target-MR0 row idx out of range for block=%d", bOut)
				}
				if zHatRowIdx < 0 || zHatRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("Z-hat row idx out of range for block=%d", bOut)
				}
				rhsBase = modAdd(EvalPoly(b0Coeffs[bOut], x, q)%q, rows[targetRowIdx]%q, q)
				rhsBase = modAdd(rhsBase, rows[zHatRowIdx]%q, q)
			} else {
				tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
				if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("T-hat row idx out of range for block=%d", bOut)
				}
				rhsBase = rows[tHatRowIdx] % q
			}
			for j := 0; j < ncols; j++ {
				lhs := uint64(0)
				if groupedSigDomain {
					groupSize := layout.PackedSigChainGroupSize
					sigCol := (bOut%groupSize)*ncols + j
					lambdaSig := sigLagrangeVals[sigCol]
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						aScale := aHeads[bOut][comp][j] % q
						if aScale == 0 {
							continue
						}
						for lane := 0; lane < spec.L; lane++ {
							rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, bOut, lane)
							scale := modMul(aScale, spec.RPows[lane]%q, q)
							term := modMul(scale, modMul(lambdaSig, rows[rowIdx]%q, q), q)
							lhs = modAdd(lhs, term, q)
						}
					}
					rhs := modMul(mainLagrangeVals[j], rhsBase, q)
					fagg = append(fagg, modSub(lhs, rhs, q))
					continue
				}
				t := bOut*ncols + j
				hVal := EvalPoly(bridgeBasis.TransformH[t], x, q) % q
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
				rhs := modMul(EvalPoly(bridgeBasis.LagrangeBasis[j], x, q)%q, rhsBase, q)
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
			fparGroups := cfg.PackedSigBlocks * cfg.PackedSigComponents
			if groupedSigDomain {
				fparGroups = layout.PackedSigChainGroupCount
			}
			fpar := make([]kf.Elem, 0, fparGroups*spec.L)
			if groupedSigDomain {
				for group := 0; group < layout.PackedSigChainGroupCount; group++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
						fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
					}
				}
			} else {
				for block := 0; block < cfg.PackedSigBlocks; block++ {
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						for lane := 0; lane < spec.L; lane++ {
							rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
							fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
						}
					}
				}
			}
			var mainLagrangeVals []kf.Elem
			var sigLagrangeVals []kf.Elem
			if groupedSigDomain {
				mainLagrangeVals = make([]kf.Elem, len(mainLagrange))
				for j := range mainLagrange {
					mainLagrangeVals[j] = K.EvalFPolyAtK(mainLagrange[j], e)
				}
				sigLagrangeVals = make([]kf.Elem, len(sigLagrange))
				for j := range sigLagrange {
					sigLagrangeVals[j] = K.EvalFPolyAtK(sigLagrange[j], e)
				}
			}
			fagg := make([]kf.Elem, 0, replayOutputBlocks*ncols)
			for bOut := 0; bOut < replayOutputBlocks; bOut++ {
				var rhsBase kf.Elem
				if directTarget {
					targetRowIdx := rowLayoutPostSignTargetMR0HatIndex(layout, bOut)
					zHatRowIdx := rowLayoutPostSignZHatIndex(layout, bOut)
					if targetRowIdx < 0 || targetRowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("target-MR0 K row idx out of range for block=%d", bOut)
					}
					if zHatRowIdx < 0 || zHatRowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("Z-hat K row idx out of range for block=%d", bOut)
					}
					rhsBase = K.Add(K.EvalFPolyAtK(b0Coeffs[bOut], e), rows[targetRowIdx])
					rhsBase = K.Add(rhsBase, rows[zHatRowIdx])
				} else {
					tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
					if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("T-hat K row idx out of range for block=%d", bOut)
					}
					rhsBase = rows[tHatRowIdx]
				}
				for j := 0; j < ncols; j++ {
					lhs := K.Zero()
					if groupedSigDomain {
						groupSize := layout.PackedSigChainGroupSize
						sigCol := (bOut%groupSize)*ncols + j
						lambdaSig := sigLagrangeVals[sigCol]
						for comp := 0; comp < cfg.PackedSigComponents; comp++ {
							aScale := K.EmbedF(aHeads[bOut][comp][j] % K.Q)
							if K.IsZero(aScale) {
								continue
							}
							for lane := 0; lane < spec.L; lane++ {
								rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, bOut, lane)
								scale := K.Mul(aScale, K.EmbedF(spec.RPows[lane]%K.Q))
								term := K.Mul(scale, K.Mul(lambdaSig, rows[rowIdx]))
								lhs = K.Add(lhs, term)
							}
						}
						rhs := K.Mul(mainLagrangeVals[j], rhsBase)
						fagg = append(fagg, K.Sub(lhs, rhs))
						continue
					}
					t := bOut*ncols + j
					hVal := K.EvalFPolyAtK(bridgeBasis.TransformH[t], e)
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
					rhs := K.Mul(K.EvalFPolyAtK(bridgeBasis.LagrangeBasis[j], e), rhsBase)
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
	rCoeffRows := make([][]uint64, len(proof.R))
	for i := range proof.R {
		rCoeffRows[i] = trimPoly(append([]uint64(nil), proof.R[i]...), ringQ.Modulus[0])
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
	opening, err := prepareSigShortnessOpeningForVerify(tHatOpening, gamma, rCoeffRows, domainPoints, ringQ, replayWitnessRows)
	if err != nil {
		return nil, err
	}
	if err := verifyDECSSubsetFormal(proof.Root, params, gamma, rCoeffRows, opening, slots, domainPoints, ringQ.Modulus[0]); err != nil {
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
	rCoeffRows := make([][]uint64, len(proof.R))
	for i := range proof.R {
		rCoeffRows[i] = trimPoly(append([]uint64(nil), proof.R[i]...), q)
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	opening, err := prepareSigShortnessOpeningForVerify(sig.Opening, gamma, rCoeffRows, domainPoints, ringQ, replayWitnessRows)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	if err := verifyDECSSubsetFormal(proof.Root, params, gamma, rCoeffRows, opening, sig.SupportSlots, domainPoints, q); err != nil {
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
	case sigShortnessProofVersionV8:
		return VerifySigShortnessProofV8(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV9:
		return VerifySigShortnessProofV9(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV10:
		return VerifySigShortnessProofV10(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV11:
		return VerifySigShortnessProofV11(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV12:
		return VerifySigShortnessProofV12(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV13:
		return VerifySigShortnessProofV13(proof, ringQ, omegaWitness, pub, opts)
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

func VerifySigShortnessProofV10(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = omegaWitness
	_ = pub
	if err := validateSigShortnessV10Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if !sigShortnessV10EnabledForOpts(opts) {
		return fmt.Errorf("sig shortness V10 not enabled for opts")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("sig shortness V10 spec: %w", err)
	}
	v10 := proof.SigShortness.V10
	if v10.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V10 radix=%d want %d", v10.Radix, spec.R)
	}
	if v10.Digits != spec.L {
		return fmt.Errorf("sig shortness V10 digits=%d want %d", v10.Digits, spec.L)
	}
	return nil
}

func VerifySigShortnessProofV11(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = omegaWitness
	_ = pub
	if err := validateSigShortnessV11Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if !sigShortnessV11EnabledForOpts(opts) {
		return fmt.Errorf("sig shortness V11 not enabled for opts")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("sig shortness V11 spec: %w", err)
	}
	v11 := proof.SigShortness.V11
	if v11.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V11 radix=%d want %d", v11.Radix, spec.R)
	}
	if v11.Digits != spec.L {
		return fmt.Errorf("sig shortness V11 digits=%d want %d", v11.Digits, spec.L)
	}
	return nil
}

func VerifySigShortnessProofV12(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = omegaWitness
	_ = pub
	if err := validateSigShortnessV12Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if !sigShortnessV12EnabledForOpts(opts) {
		return fmt.Errorf("sig shortness V12 not enabled for opts")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("sig shortness V12 spec: %w", err)
	}
	v12 := proof.SigShortness.V12
	if v12.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V12 radix=%d want %d", v12.Radix, spec.R)
	}
	if v12.Digits != spec.L {
		return fmt.Errorf("sig shortness V12 digits=%d want %d", v12.Digits, spec.L)
	}
	return nil
}

func VerifySigShortnessProofV13(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = omegaWitness
	_ = pub
	if err := validateSigShortnessV13Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if !sigShortnessV13EnabledForOpts(opts) {
		return fmt.Errorf("sig shortness V13 not enabled for opts")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("sig shortness V13 spec: %w", err)
	}
	v13 := proof.SigShortness.V13
	if v13.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V13 radix=%d want %d", v13.Radix, spec.R)
	}
	if v13.Digits != spec.L {
		return fmt.Errorf("sig shortness V13 digits=%d want %d", v13.Digits, spec.L)
	}
	wantDigest := buildSigShortnessLookupTableDigest(spec)
	if !bytes.Equal(v13.LookupTableDigest, wantDigest) {
		return fmt.Errorf("sig shortness V13 lookup table digest mismatch")
	}
	return nil
}

func VerifySigShortnessProofV8(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = opts
	if err := validateSigShortnessV8Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	v8 := proof.SigShortness.V8
	witnessNCols := sigShortnessV5WitnessNColsFromProof(proof)
	if witnessNCols <= 0 {
		return fmt.Errorf("missing V8 witness ncols")
	}
	if len(omegaWitness) < witnessNCols {
		return fmt.Errorf("omega witness len=%d < V8 witness ncols=%d", len(omegaWitness), witnessNCols)
	}
	tHatHeads, err := unpackSigShortnessV8THatHeads(proof.RowLayout, witnessNCols, v8.THatHeads)
	if err != nil {
		return err
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   v8.Radix,
		SigShortnessL:       v8.Digits,
	})
	if err != nil {
		return fmt.Errorf("sig shortness V8 spec: %w", err)
	}
	hiddenProof := v8.HiddenProof
	if hiddenProof == nil {
		return fmt.Errorf("missing hidden sig shortness proof")
	}
	if hiddenProof.SigShortness != nil {
		return fmt.Errorf("hidden sig shortness proof must not carry nested shortness")
	}
	if hiddenProof.NColsUsed > 0 && hiddenProof.NColsUsed != witnessNCols {
		return fmt.Errorf("hidden sig shortness witness ncols=%d want %d", hiddenProof.NColsUsed, witnessNCols)
	}
	hiddenWitnessOmega, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0],
		hiddenProof.NLeavesUsed,
		witnessNCols,
		resolveProofPCSNCols(hiddenProof, 0),
		len(hiddenProof.Tail),
		hiddenProof.HashRelation,
	)
	if err != nil {
		return fmt.Errorf("hidden sig shortness witness omega: %w", err)
	}
	hiddenPub := buildSigShortnessHiddenPublicInputs(pub, proof.Root, tHatHeads, v8.Mode, v8.Radix, v8.Digits)
	hiddenReplay, err := buildSigShortnessHiddenReplay(ringQ, hiddenProof, pub, hiddenWitnessOmega, tHatHeads, spec)
	if err != nil {
		return fmt.Errorf("hidden sig shortness replay: %w", err)
	}
	if err := verifySigShortnessHiddenProof(hiddenProof, hiddenPub, hiddenReplay); err != nil {
		return fmt.Errorf("hidden sig shortness verification failed: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV9(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = opts
	if err := validateSigShortnessV9Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	v9 := proof.SigShortness.V9
	witnessNCols := sigShortnessV5WitnessNColsFromProof(proof)
	if witnessNCols <= 0 {
		return fmt.Errorf("missing V9 witness ncols")
	}
	if len(omegaWitness) < witnessNCols {
		return fmt.Errorf("omega witness len=%d < V9 witness ncols=%d", len(omegaWitness), witnessNCols)
	}
	commitment := v9.THatCommitment
	if err := validateSigShortnessV9CommitmentShape(proof.RowLayout, witnessNCols, commitment); err != nil {
		return err
	}
	paramsDigest := sigShortnessV9AjtaiParamsDigest(
		ringQ.Modulus[0],
		pub.HashRelation,
		commitment.Cols,
		commitment.THatRows,
		commitment.RandRows,
		commitment.RandBound,
		commitment.Rows,
	)
	if !equalByteSlices(v9.CommitmentParamsDigest, paramsDigest) {
		return fmt.Errorf("sig shortness V9 commitment parameter digest mismatch")
	}
	mainOpeningDigest := sigShortnessV9OpeningDigest("main", proof.Root, proof.RowLayout, commitment, paramsDigest)
	if !equalByteSlices(v9.MainOpeningDigest, mainOpeningDigest) {
		return fmt.Errorf("sig shortness V9 main opening digest mismatch")
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessRadix:   v9.Radix,
		SigShortnessL:       v9.Digits,
	})
	if err != nil {
		return fmt.Errorf("sig shortness V9 spec: %w", err)
	}
	hiddenProof := v9.HiddenProof
	if hiddenProof == nil {
		return fmt.Errorf("missing hidden sig shortness proof")
	}
	if hiddenProof.SigShortness != nil {
		return fmt.Errorf("hidden sig shortness proof must not carry nested shortness")
	}
	if hiddenProof.NColsUsed > 0 && hiddenProof.NColsUsed != witnessNCols {
		return fmt.Errorf("hidden sig shortness witness ncols=%d want %d", hiddenProof.NColsUsed, witnessNCols)
	}
	if err := validateSigShortnessV9CommitmentShape(hiddenProof.RowLayout, witnessNCols, commitment); err != nil {
		return fmt.Errorf("hidden sig shortness V9 commitment shape: %w", err)
	}
	hiddenOpeningDigest := sigShortnessV9OpeningDigest("hidden", hiddenProof.Root, hiddenProof.RowLayout, commitment, paramsDigest)
	if !equalByteSlices(v9.HiddenOpeningDigest, hiddenOpeningDigest) {
		return fmt.Errorf("sig shortness V9 hidden opening digest mismatch")
	}
	hiddenWitnessOmega, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0],
		hiddenProof.NLeavesUsed,
		witnessNCols,
		resolveProofPCSNCols(hiddenProof, 0),
		len(hiddenProof.Tail),
		hiddenProof.HashRelation,
	)
	if err != nil {
		return fmt.Errorf("hidden sig shortness witness omega: %w", err)
	}
	hiddenPub := buildSigShortnessHiddenPublicInputsV9(pub, proof.Root, commitment, paramsDigest, v9.Mode, v9.Radix, v9.Digits)
	hiddenReplay, err := buildSigShortnessHiddenReplayV9(ringQ, hiddenProof, pub, hiddenWitnessOmega, commitment, spec)
	if err != nil {
		return fmt.Errorf("hidden sig shortness replay: %w", err)
	}
	if err := verifySigShortnessHiddenProof(hiddenProof, hiddenPub, hiddenReplay); err != nil {
		return fmt.Errorf("hidden sig shortness verification failed: %w", err)
	}
	return nil
}

func buildSigShortnessV8MainBindingConstraints(ringQ *ring.Ring, layout RowLayout, rowsNTT []*ring.Poly, omegaWitness []uint64, sig *SigShortnessProof) (ConstraintSet, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV8 || sig.V8 == nil {
		return ConstraintSet{}, nil
	}
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omegaWitness) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega witness")
	}
	tHatHeads, err := unpackSigShortnessV8THatHeads(layout, len(omegaWitness), sig.V8.THatHeads)
	if err != nil {
		return ConstraintSet{}, err
	}
	q := ringQ.Modulus[0]
	fpar := make([]*ring.Poly, 0, len(tHatHeads))
	fparCoeffs := make([][]uint64, 0, len(tHatHeads))
	for block, head := range tHatHeads {
		rowIdx := rowLayoutPostSignTHatIndex(layout, block)
		if rowIdx < 0 || rowIdx >= len(rowsNTT) || rowsNTT[rowIdx] == nil {
			return ConstraintSet{}, fmt.Errorf("V8 T-hat row index block %d=%d out of range", block, rowIdx)
		}
		rowCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("V8 T-hat row coeff block %d: %w", block, err)
		}
		headNTT := BuildThetaPrime(ringQ, head, omegaWitness)
		headCoeff, err := coeffFromNTTPoly(ringQ, headNTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("V8 T-hat head coeff block %d: %w", block, err)
		}
		residual := reducePolyModXN1(polySub(rowCoeff, headCoeff, q), int(ringQ.N), q)
		fparCoeffs = append(fparCoeffs, residual)
		fpar = append(fpar, nttPolyFromFormalCoeffsIfFits(ringQ, residual))
	}
	return ConstraintSet{
		FparInt:        fpar,
		FparIntCoeffs:  fparCoeffs,
		ParallelAlgDeg: 1,
	}, nil
}

func buildSigShortnessV9MainBindingConstraints(ringQ *ring.Ring, relation string, layout RowLayout, rowsNTT []*ring.Poly, omegaWitness []uint64, sig *SigShortnessProof) (ConstraintSet, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV9 || sig.V9 == nil {
		return ConstraintSet{}, nil
	}
	_, _, _, _, _ = ringQ, relation, layout, rowsNTT, omegaWitness
	return ConstraintSet{}, fmt.Errorf("sig shortness V9 is no longer a live protocol family")
}

func buildSigShortnessV9AjtaiConstraintSet(ringQ *ring.Ring, relation string, layout RowLayout, rowsNTT []*ring.Poly, omegaWitness []uint64, commitment SigShortnessAjtaiCommitment, tHatRows, randRows []int) (ConstraintSet, error) {
	_, _, _, _, _, _, _, _ = ringQ, relation, layout, rowsNTT, omegaWitness, commitment, tHatRows, randRows
	return ConstraintSet{}, fmt.Errorf("sig shortness V9 Ajtai commitment is no longer supported")
}

func evalSigShortnessV9AjtaiF(ringQ *ring.Ring, relation string, omega []uint64, x uint64, rows []uint64, commitment SigShortnessAjtaiCommitment, tHatRows, randRows []int) ([]uint64, error) {
	_, _, _, _, _, _, _, _ = ringQ, relation, omega, x, rows, commitment, tHatRows, randRows
	return nil, fmt.Errorf("sig shortness V9 Ajtai commitment is no longer supported")
}

func evalSigShortnessV9AjtaiK(ringQ *ring.Ring, K *kf.Field, relation string, omega []uint64, e kf.Elem, rows []kf.Elem, commitment SigShortnessAjtaiCommitment, tHatRows, randRows []int) ([]kf.Elem, error) {
	_, _, _, _, _, _, _, _, _ = ringQ, K, relation, omega, e, rows, commitment, tHatRows, randRows
	return nil, fmt.Errorf("sig shortness V9 Ajtai commitment is no longer supported")
}

func sigShortnessV9HeadsFromRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, omega []uint64, rows []int, label string) ([][]uint64, error) {
	_, _, _, _, _ = ringQ, rowsNTT, omega, rows, label
	return nil, fmt.Errorf("sig shortness V9 Ajtai commitment is no longer supported")
}

func buildSigShortnessV9AjtaiCommitment(q uint64, relation string, tHatHeads [][]uint64, randHeads [][]uint64) (SigShortnessAjtaiCommitment, []byte, error) {
	_, _, _, _ = q, relation, tHatHeads, randHeads
	return SigShortnessAjtaiCommitment{}, nil, fmt.Errorf("sig shortness V9 Ajtai commitment is no longer supported")
}

func sigShortnessV9OpeningDigest(label string, root [16]byte, layout RowLayout, commitment SigShortnessAjtaiCommitment, paramsDigest []byte) []byte {
	_, _, _, _, _ = label, root, layout, commitment, paramsDigest
	return nil
}

func sigShortnessV9AjtaiParamsDigest(q uint64, relation string, cols, tHatRows, randRows, randBound, rows int) []byte {
	_, _, _, _, _, _, _ = q, relation, cols, tHatRows, randRows, randBound, rows
	return nil
}
