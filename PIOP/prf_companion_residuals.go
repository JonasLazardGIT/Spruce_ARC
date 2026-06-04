package PIOP

import (
	"fmt"
	"sort"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const prfCompanionOpeningGroupRounds = 2

type prfCompanionOpeningSource uint8

const (
	prfCompanionPackedSource prfCompanionOpeningSource = iota
)

type prfCompanionOpeningTerm struct {
	Source            prfCompanionOpeningSource
	Row               int
	RowMixCoeff       uint64
	CoordinateWeights []uint64
}

type prfCompanionOpeningDescriptor struct {
	Label    string
	Terms    []prfCompanionOpeningTerm
	Constant uint64
	MaskSlot int
}

type prfCompanionAuditPlan struct {
	Checkpoint int
	ZLabel     string
	WireLabel  string
}

type prfCompanionOpeningPlan struct {
	Mode        PRFCompanionMode
	Descriptors []prfCompanionOpeningDescriptor
	Masks       []uint64
	PublicTag   uint64
	Audits      []prfCompanionAuditPlan
	Checkpoint  int
	Q           uint64
}

type prfCompanionOpeningPayload struct {
	CheckpointAudits []PRFCheckpointAuditOpening
	TagFinal         PRFCompanionOpening
	KeyTrunc         PRFCompanionOpening
}

func prfCompanionModeDefault(mode PRFCompanionMode) PRFCompanionMode {
	mode = normalizePRFCompanionMode(mode)
	if mode == "" {
		return PRFCompanionModeDirectFull
	}
	return mode
}

func prfCompanionOpeningLabels(mode PRFCompanionMode, checkpointSamples int) []string {
	if checkpointSamples <= 0 {
		checkpointSamples = 1
	}
	out := make([]string, 0, 2*checkpointSamples+2)
	for i := 0; i < checkpointSamples; i++ {
		out = append(out, fmt.Sprintf("audit_z_%d", i), fmt.Sprintf("audit_wire_%d", i))
	}
	out = append(out, "tag_final", "key_trunc")
	return out
}

func prfCompanionOpeningRNG(seed3, coordDigest []byte, mode PRFCompanionMode, checkpointSamples int) *fsRNG {
	return newFSRNG(
		"PRFCompanionOpenings",
		seed3,
		coordDigest,
		bytesFromStrings(prfCompanionOpeningLabels(mode, checkpointSamples)),
	)
}

func bytesFromStrings(vals []string) []byte {
	out := make([]byte, 0)
	for _, v := range vals {
		out = append(out, []byte(v)...)
		out = append(out, 0)
	}
	return out
}

func nextNonZeroChallenge(rng *fsRNG, q uint64) uint64 {
	if q == 0 {
		return 0
	}
	v := rng.nextU64() % q
	if v == 0 {
		return 1
	}
	return v
}

func compressFieldElems(vals []uint64, tau uint64, q uint64) uint64 {
	acc := uint64(0)
	pow := uint64(1)
	for _, v := range vals {
		acc = modAdd(acc, modMul(v%q, pow, q), q)
		pow = modMul(pow, tau%q, q)
	}
	return acc
}

func rowHeadOnOmega(ringQ *ring.Ring, omegaWitness []uint64, row *ring.Poly, width int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if row == nil {
		return nil, fmt.Errorf("nil row polynomial")
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty omega witness")
	}
	if width <= 0 {
		return nil, fmt.Errorf("invalid row width=%d", width)
	}
	if len(omegaWitness) < width {
		return nil, fmt.Errorf("omega witness len=%d < width=%d", len(omegaWitness), width)
	}
	q := ringQ.Modulus[0]
	coeff := trimPoly(append([]uint64(nil), row.Coeffs[0]...), q)
	head := make([]uint64, width)
	for i := 0; i < width; i++ {
		head[i] = EvalPoly(coeff, omegaWitness[i]%q, q)
	}
	return head, nil
}

func publicNonceElems(noncePublic [][]int64, q uint64) ([]prf.Elem, error) {
	out := make([]prf.Elem, len(noncePublic))
	for i := range noncePublic {
		if len(noncePublic[i]) == 0 {
			return nil, fmt.Errorf("public nonce lane %d is empty", i)
		}
		out[i] = prf.Elem(liftToField(q, noncePublic[i][0]))
	}
	return out, nil
}

func compressPublicTag(tagPublic [][]int64, tau uint64, q uint64) (uint64, error) {
	vals := make([]uint64, len(tagPublic))
	for i := range tagPublic {
		if len(tagPublic[i]) == 0 {
			return 0, fmt.Errorf("public tag lane %d is empty", i)
		}
		vals[i] = liftToField(q, tagPublic[i][0])
	}
	return compressFieldElems(vals, tau, q), nil
}

func cloneUint64Vec(src []uint64) []uint64 {
	return append([]uint64(nil), src...)
}

func appendSlotWeight(slotWeights map[int][]uint64, packWidth int, row int, coeff int, weight uint64, q uint64) {
	if weight%q == 0 {
		return
	}
	if slotWeights[row] == nil {
		slotWeights[row] = make([]uint64, packWidth)
	}
	slotWeights[row][coeff] = modAdd(slotWeights[row][coeff], weight%q, q)
}

func buildPackedTerms(layout *PRFCompanionLayout, slotWeights map[int][]uint64, q uint64) []prfCompanionOpeningTerm {
	rows := make([]int, 0, len(slotWeights))
	for row := range slotWeights {
		rows = append(rows, row)
	}
	sort.Ints(rows)
	terms := make([]prfCompanionOpeningTerm, 0, len(rows))
	for _, row := range rows {
		terms = append(terms, prfCompanionOpeningTerm{
			Source:            prfCompanionPackedSource,
			Row:               row,
			RowMixCoeff:       1,
			CoordinateWeights: cloneUint64Vec(slotWeights[row]),
		})
	}
	return terms
}

func buildDescriptor(
	label string,
	terms []prfCompanionOpeningTerm,
	constant uint64,
	maskSlot int,
	q uint64,
) prfCompanionOpeningDescriptor {
	outTerms := make([]prfCompanionOpeningTerm, len(terms))
	for i := range terms {
		outTerms[i] = prfCompanionOpeningTerm{
			Source:            terms[i].Source,
			Row:               terms[i].Row,
			RowMixCoeff:       terms[i].RowMixCoeff % q,
			CoordinateWeights: cloneUint64Vec(terms[i].CoordinateWeights),
		}
	}
	return prfCompanionOpeningDescriptor{
		Label:    label,
		Terms:    outTerms,
		Constant: constant % q,
		MaskSlot: maskSlot,
	}
}

func descriptorFromPackedSlots(
	label string,
	layout *PRFCompanionLayout,
	slots []CoeffSlot,
	tau uint64,
	maskSlot int,
	q uint64,
) (prfCompanionOpeningDescriptor, error) {
	if layout == nil {
		return prfCompanionOpeningDescriptor{}, fmt.Errorf("nil layout")
	}
	slotWeights := make(map[int][]uint64)
	pow := uint64(1)
	for _, slot := range slots {
		appendSlotWeight(slotWeights, layout.PackWidth, slot.Row, slot.Coeff, pow, q)
		pow = modMul(pow, tau%q, q)
	}
	return buildDescriptor(label, buildPackedTerms(layout, slotWeights, q), 0, maskSlot, q), nil
}

func extractCheckpointWires(grouped *prf.GroupedWitness) []prf.LinearForm {
	out := make([]prf.LinearForm, len(grouped.Checkpoints))
	for i := range grouped.Checkpoints {
		out[i] = grouped.Checkpoints[i].Wire
	}
	return out
}

func descriptorFromCheckpointWire(
	label string,
	layout *PRFCompanionLayout,
	wire prf.LinearForm,
	maskSlot int,
	q uint64,
) (prfCompanionOpeningDescriptor, error) {
	if layout == nil {
		return prfCompanionOpeningDescriptor{}, fmt.Errorf("nil layout")
	}
	if len(layout.KeySlots) == 0 {
		return prfCompanionOpeningDescriptor{}, fmt.Errorf("missing companion key slots")
	}
	if len(layout.CheckpointSlots) == 0 {
		return prfCompanionOpeningDescriptor{}, fmt.Errorf("missing companion checkpoint slots")
	}
	slotWeights := make(map[int][]uint64)
	for i, coeff := range wire.KeyCoeffs {
		if i >= len(layout.KeySlots) || coeff == 0 {
			continue
		}
		slot := layout.KeySlots[i]
		appendSlotWeight(slotWeights, layout.PackWidth, slot.Row, slot.Coeff, uint64(coeff)%q, q)
	}
	for i, coeff := range wire.CheckpointCoeffs {
		if i >= len(layout.CheckpointSlots) || coeff == 0 {
			continue
		}
		slot := layout.CheckpointSlots[i]
		appendSlotWeight(slotWeights, layout.PackWidth, slot.Row, slot.Coeff, uint64(coeff)%q, q)
	}
	return buildDescriptor(label, buildPackedTerms(layout, slotWeights, q), uint64(wire.Const)%q, maskSlot, q), nil
}

func sampleDistinctCheckpointIndices(rng *fsRNG, checkpointCount int, want int) []int {
	if checkpointCount <= 0 || want <= 0 {
		return nil
	}
	if want > checkpointCount {
		want = checkpointCount
	}
	seen := make(map[int]struct{}, want)
	out := make([]int, 0, want)
	for len(out) < want {
		idx := int(rng.nextU64() % uint64(checkpointCount))
		if _, exists := seen[idx]; exists {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
	}
	return out
}

func buildPRFCompanionOpeningPlan(
	layout *PRFCompanionLayout,
	params *prf.Params,
	mode PRFCompanionMode,
	checkpointSamples int,
	seed3 []byte,
	coordDigest []byte,
	tagPublic [][]int64,
	noncePublic [][]int64,
) (*prfCompanionOpeningPlan, error) {
	if layout == nil {
		return nil, nil
	}
	if params == nil {
		return nil, fmt.Errorf("nil prf params")
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	mode = prfCompanionModeDefault(mode)
	rng := prfCompanionOpeningRNG(seed3, coordDigest, mode, checkpointSamples)
	q := params.Q
	nonceElems, err := publicNonceElems(noncePublic, q)
	if err != nil {
		return nil, err
	}
	zeroKey := make([]prf.Elem, params.LenKey)
	grouped, err := prf.TraceGroupedWitness(zeroKey, nonceElems, params, prfCompanionOpeningGroupRounds)
	if err != nil {
		return nil, err
	}
	checkpointWires := extractCheckpointWires(grouped)
	if len(checkpointWires) == 0 || len(layout.CheckpointSlots) == 0 {
		return nil, fmt.Errorf("missing checkpoint companion metadata")
	}
	tauTag := nextNonZeroChallenge(rng, q)
	publicTag, err := compressPublicTag(tagPublic, tauTag, q)
	if err != nil {
		return nil, err
	}
	descriptors := make([]prfCompanionOpeningDescriptor, 0)
	audits := make([]prfCompanionAuditPlan, 0)
	if checkpointSamples <= 0 {
		checkpointSamples = 1
	}
	samples := sampleDistinctCheckpointIndices(rng, len(layout.CheckpointSlots), checkpointSamples)
	for _, checkpoint := range samples {
		zLabel := fmt.Sprintf("audit_z_%d", len(audits))
		wireLabel := fmt.Sprintf("audit_wire_%d", len(audits))
		zDesc, err := descriptorFromPackedSlots(zLabel, layout, []CoeffSlot{layout.CheckpointSlots[checkpoint]}, 1, len(descriptors), q)
		if err != nil {
			return nil, err
		}
		descriptors = append(descriptors, zDesc)
		wireDesc, err := descriptorFromCheckpointWire(wireLabel, layout, checkpointWires[checkpoint], len(descriptors), q)
		if err != nil {
			return nil, err
		}
		descriptors = append(descriptors, wireDesc)
		audits = append(audits, prfCompanionAuditPlan{
			Checkpoint: checkpoint,
			ZLabel:     zLabel,
			WireLabel:  wireLabel,
		})
	}
	tagFinal, err := descriptorFromPackedSlots("tag_final", layout, layout.FinalTagSlots, tauTag, len(descriptors), q)
	if err != nil {
		return nil, err
	}
	descriptors = append(descriptors, tagFinal)
	limit := params.LenTag
	if limit <= 0 || limit > len(layout.KeySlots) {
		limit = len(layout.KeySlots)
	}
	keyTrunc, err := descriptorFromPackedSlots("key_trunc", layout, layout.KeySlots[:limit], tauTag, len(descriptors), q)
	if err != nil {
		return nil, err
	}
	descriptors = append(descriptors, keyTrunc)
	masks := make([]uint64, len(descriptors))
	for i := range masks {
		masks[i] = rng.nextU64() % q
	}
	return &prfCompanionOpeningPlan{
		Mode:        mode,
		Descriptors: descriptors,
		Masks:       masks,
		PublicTag:   publicTag,
		Audits:      audits,
		Q:           q,
	}, nil
}

func evalPRFCompanionDescriptor(
	desc prfCompanionOpeningDescriptor,
	layout *PRFCompanionLayout,
	packedHeads [][]uint64,
	q uint64,
) (uint64, error) {
	acc := desc.Constant % q
	for _, term := range desc.Terms {
		scale := term.RowMixCoeff % q
		var head []uint64
		switch term.Source {
		case prfCompanionPackedSource:
			rel := term.Row - layout.StartRow
			if rel < 0 || rel >= len(packedHeads) {
				return 0, fmt.Errorf("descriptor %s row=%d outside packed companion window", desc.Label, term.Row)
			}
			head = packedHeads[rel]
		default:
			return 0, fmt.Errorf("descriptor %s has unknown source %d", desc.Label, term.Source)
		}
		if len(term.CoordinateWeights) > len(head) {
			return 0, fmt.Errorf("descriptor %s weights=%d exceed head width=%d", desc.Label, len(term.CoordinateWeights), len(head))
		}
		for col, weight := range term.CoordinateWeights {
			if weight%q == 0 {
				continue
			}
			acc = modAdd(acc, modMul(scale, modMul(weight%q, head[col]%q, q), q), q)
		}
	}
	return acc % q, nil
}

func buildPRFCompanionOpeningPayload(
	layout *PRFCompanionLayout,
	mode PRFCompanionMode,
	checkpointSamples int,
	rows []*ring.Poly,
	ringQ *ring.Ring,
	omegaWitness []uint64,
	params *prf.Params,
	seed3 []byte,
	coordDigest []byte,
	tagPublic [][]int64,
	noncePublic [][]int64,
) (*prfCompanionOpeningPayload, *prfCompanionOpeningPlan, error) {
	if layout == nil {
		return nil, nil, nil
	}
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if layout.StartRow < 0 || layout.StartRow+layout.PackedRows > len(rows) {
		return nil, nil, fmt.Errorf("companion row window [%d,%d) out of range for rows=%d", layout.StartRow, layout.StartRow+layout.PackedRows, len(rows))
	}
	plan, err := buildPRFCompanionOpeningPlan(layout, params, mode, checkpointSamples, seed3, coordDigest, tagPublic, noncePublic)
	if err != nil {
		return nil, nil, err
	}
	packedHeads, _, err := packedHeadsFromRowsOnOmega(ringQ, omegaWitness, rows, layout)
	if err != nil {
		return nil, nil, err
	}
	openings := make(map[string]PRFCompanionOpening, len(plan.Descriptors))
	for i, desc := range plan.Descriptors {
		raw, err := evalPRFCompanionDescriptor(desc, layout, packedHeads, plan.Q)
		if err != nil {
			return nil, nil, err
		}
		mask := uint64(0)
		if i < len(plan.Masks) {
			mask = plan.Masks[i] % plan.Q
		}
		openings[desc.Label] = PRFCompanionOpening{
			Masked: []uint64{modAdd(raw, mask, plan.Q)},
			Mask:   []uint64{mask},
		}
	}
	payload := &prfCompanionOpeningPayload{
		TagFinal: clonePRFCompanionOpening(openings["tag_final"]),
		KeyTrunc: clonePRFCompanionOpening(openings["key_trunc"]),
	}
	payload.CheckpointAudits = make([]PRFCheckpointAuditOpening, len(plan.Audits))
	for i := range plan.Audits {
		payload.CheckpointAudits[i] = PRFCheckpointAuditOpening{
			Z:    clonePRFCompanionOpening(openings[plan.Audits[i].ZLabel]),
			Wire: clonePRFCompanionOpening(openings[plan.Audits[i].WireLabel]),
		}
	}
	return payload, plan, nil
}

func recoverPRFCompanionOpening(
	label string,
	opening PRFCompanionOpening,
	expectedMask uint64,
	q uint64,
) (uint64, error) {
	if len(opening.Masked) != 1 {
		return 0, fmt.Errorf("opening %s masked len=%d want 1", label, len(opening.Masked))
	}
	if len(opening.Mask) != 1 {
		return 0, fmt.Errorf("opening %s mask len=%d want 1", label, len(opening.Mask))
	}
	if opening.Mask[0]%q != expectedMask%q {
		return 0, fmt.Errorf("opening %s mask mismatch", label)
	}
	return modSub(opening.Masked[0]%q, opening.Mask[0]%q, q), nil
}

func verifyPRFCompanionOpenings(
	layout *PRFCompanionLayout,
	proof *Proof,
	params *prf.Params,
	tagPublic [][]int64,
	noncePublic [][]int64,
) error {
	if layout == nil || proof == nil || proof.PRFCompanion == nil {
		return nil
	}
	mode := prfCompanionModeDefault(proof.PRFCompanion.Mode)
	if mode == PRFCompanionModeDirectFull {
		if len(proof.PRFCompanion.CheckpointAudits) != 0 || prfCompanionHasOpeningPayload(proof.PRFCompanion) {
			return fmt.Errorf("direct_full companion proof carries legacy opening payload")
		}
		return nil
	}
	plan, err := buildPRFCompanionOpeningPlan(
		layout,
		params,
		mode,
		proof.PRFCompanion.CheckpointSamples,
		proof.Digests[2],
		proof.PRFCompanion.CoordDigest,
		tagPublic,
		noncePublic,
	)
	if err != nil {
		return err
	}
	if len(proof.PRFCompanion.CheckpointAudits) != len(plan.Audits) {
		return fmt.Errorf("checkpoint audit count=%d want %d", len(proof.PRFCompanion.CheckpointAudits), len(plan.Audits))
	}
	maskIdx := 0
	for i := range plan.Audits {
		zVal, err := recoverPRFCompanionOpening(plan.Audits[i].ZLabel, proof.PRFCompanion.CheckpointAudits[i].Z, plan.Masks[maskIdx], plan.Q)
		if err != nil {
			return err
		}
		maskIdx++
		wireVal, err := recoverPRFCompanionOpening(plan.Audits[i].WireLabel, proof.PRFCompanion.CheckpointAudits[i].Wire, plan.Masks[maskIdx], plan.Q)
		if err != nil {
			return err
		}
		maskIdx++
		if zVal != powMod(wireVal, uint64(params.D), plan.Q) {
			return fmt.Errorf("prf companion checkpoint power failed at sample %d checkpoint %d", i, plan.Audits[i].Checkpoint)
		}
	}
	tagFinal, err := recoverPRFCompanionOpening("tag_final", proof.PRFCompanion.TagFinal, plan.Masks[maskIdx], plan.Q)
	if err != nil {
		return err
	}
	maskIdx++
	keyTrunc, err := recoverPRFCompanionOpening("key_trunc", proof.PRFCompanion.KeyTrunc, plan.Masks[maskIdx], plan.Q)
	if err != nil {
		return err
	}
	if modAdd(tagFinal, keyTrunc, plan.Q) != plan.PublicTag {
		return fmt.Errorf("prf companion tag binding failed: tag_final=%d key_trunc=%d public_tag=%d q=%d", tagFinal, keyTrunc, plan.PublicTag, plan.Q)
	}
	return nil
}

func powMod(base uint64, exp uint64, q uint64) uint64 {
	acc := uint64(1)
	base %= q
	for exp > 0 {
		if exp&1 == 1 {
			acc = modMul(acc, base, q)
		}
		base = modMul(base, base, q)
		exp >>= 1
	}
	return acc
}
