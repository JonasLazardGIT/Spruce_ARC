package PIOP

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const prfCompanionBridgeChecks = signatureNTTBridgeChecks

type prfCompanionBridgeCache struct {
	q            uint64
	alpha        [][]uint64
	beta         [][]uint64
	betaSelCoeff [][]uint64
}

type prfCompanionBridgeBuild struct {
	Families     []*ring.Poly
	Coeffs       [][]uint64
	BridgeChecks [][]uint64
	CoordDigest  []byte
}

func prfCompanionBridgeRNG(seed2 []byte, layout *PRFCompanionLayout, checks int) *fsRNG {
	return newFSRNG(
		"PRFCompanionBridge",
		seed2,
		prfCompanionLayoutDigest(layout),
		bytesU64Vec([]uint64{uint64(layout.PackWidth), uint64(layout.PackedRows), uint64(checks)}),
	)
}

func buildPRFCompanionBridgeCache(ringQ *ring.Ring, omega []uint64, layout *PRFCompanionLayout, seed2 []byte, checks int) (*prfCompanionBridgeCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if layout == nil {
		return nil, nil
	}
	witnessRows := layout.StartRow + layout.PackedRows
	for _, slot := range layout.KeySourceSlots {
		if slot.Row >= witnessRows {
			witnessRows = slot.Row + 1
		}
	}
	if err := ValidatePRFCompanionLayout(layout, witnessRows); err != nil {
		return nil, err
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if checks <= 0 {
		return nil, fmt.Errorf("invalid bridge checks=%d", checks)
	}
	_, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
	if err != nil {
		return nil, err
	}
	q := ringQ.Modulus[0]
	rng := prfCompanionBridgeRNG(seed2, layout, checks)
	out := &prfCompanionBridgeCache{
		q:            q,
		alpha:        make([][]uint64, checks),
		beta:         make([][]uint64, checks),
		betaSelCoeff: make([][]uint64, checks),
	}
	for t := 0; t < checks; t++ {
		alpha := make([]uint64, layout.PackedRows)
		for i := range alpha {
			alpha[i] = rng.nextU64() % q
		}
		out.alpha[t] = alpha
		beta := make([]uint64, layout.PackWidth)
		betaSel := make([]uint64, 1)
		for col := 0; col < layout.PackWidth; col++ {
			b := rng.nextU64() % q
			beta[col] = b
			if b == 0 {
				continue
			}
			term := polyScale(selectorCoeff[col], b, q)
			betaSel = polyAddMod(betaSel, term, q)
		}
		out.beta[t] = beta
		out.betaSelCoeff[t] = trimPoly(betaSel, q)
	}
	return out, nil
}

func packedHeadsFromRowsOnOmega(ringQ *ring.Ring, omegaWitness []uint64, rows []*ring.Poly, layout *PRFCompanionLayout) ([][]uint64, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if layout == nil {
		return nil, nil, nil
	}
	if len(omegaWitness) != layout.PackWidth {
		return nil, nil, fmt.Errorf("omega witness len=%d want pack width=%d", len(omegaWitness), layout.PackWidth)
	}
	if layout.StartRow < 0 || layout.StartRow+layout.PackedRows > len(rows) {
		return nil, nil, fmt.Errorf("companion row window [%d,%d) out of range for witness rows=%d", layout.StartRow, layout.StartRow+layout.PackedRows, len(rows))
	}
	q := ringQ.Modulus[0]
	heads := make([][]uint64, layout.PackedRows)
	coeffs := make([][]uint64, layout.PackedRows)
	for i := 0; i < layout.PackedRows; i++ {
		rowPoly := rows[layout.StartRow+i]
		if rowPoly == nil {
			return nil, nil, fmt.Errorf("nil companion row polynomial at witness row %d", layout.StartRow+i)
		}
		rowCoeff := trimPoly(append([]uint64(nil), rowPoly.Coeffs[0]...), q)
		head := make([]uint64, layout.PackWidth)
		for col := 0; col < layout.PackWidth; col++ {
			head[col] = EvalPoly(rowCoeff, omegaWitness[col]%q, q)
		}
		heads[i] = head
		coeffs[i] = rowCoeff
	}
	return heads, coeffs, nil
}

func subsetOpeningRowsForIndices(base *decs.DECSOpening, indices []int) (*decs.DECSOpening, error) {
	if base == nil {
		return nil, fmt.Errorf("nil base opening")
	}
	posByIdx := make(map[int]int, base.EntryCount())
	for i := 0; i < base.EntryCount(); i++ {
		posByIdx[base.IndexAt(i)] = i
	}
	sub := cloneDECSOpening(base)
	sub.Indices = make([]int, len(indices))
	sub.Pvals = make([][]uint64, len(indices))
	if len(base.Mvals) > 0 {
		sub.Mvals = make([][]uint64, len(indices))
	} else {
		sub.Mvals = nil
	}
	if len(base.Nonces) > 0 {
		sub.Nonces = make([][]byte, len(indices))
	} else {
		sub.Nonces = nil
	}
	if len(base.PathIndex) > 0 {
		sub.PathIndex = make([][]int, len(indices))
	} else {
		sub.PathIndex = nil
	}
	sub.TailCount = len(indices)
	sub.IndexBits = nil
	sub.MaskBase = 0
	sub.MaskCount = 0
	for i, idx := range indices {
		pos, ok := posByIdx[idx]
		if !ok {
			return nil, fmt.Errorf("opening missing index %d", idx)
		}
		sub.Indices[i] = idx
		sub.Pvals[i] = append([]uint64(nil), base.Pvals[pos]...)
		if len(base.Mvals) > pos {
			sub.Mvals[i] = append([]uint64(nil), base.Mvals[pos]...)
		}
		if len(base.Nonces) > pos {
			sub.Nonces[i] = append([]byte(nil), base.Nonces[pos]...)
		}
		if len(base.PathIndex) > pos {
			sub.PathIndex[i] = append([]int(nil), base.PathIndex[pos]...)
		}
	}
	return sub, nil
}

func preparePRFCompanionBridgeOpening(
	ringQ *ring.Ring,
	proof *Proof,
	omegaWitness []uint64,
	domainPoints []uint64,
) (*decs.DECSOpening, error) {
	prepared, err := prepareMaskSubsetRowRecovery(ringQ, proof, omegaWitness, domainPoints)
	if err != nil {
		return nil, err
	}
	return prepared.Opening, nil
}

func buildPRFCompanionCoordDigest(layout *PRFCompanionLayout, seed2 []byte, bridgeChecks [][]uint64, checks int, mode PRFCompanionMode, checkpointSamples int) []byte {
	if layout == nil {
		return nil
	}
	mode = prfCompanionModeDefault(mode)
	h := sha256.New()
	h.Write(prfCompanionLayoutDigest(layout))
	h.Write(bytesU64Vec([]uint64{uint64(checks), uint64(checkpointSamples)}))
	h.Write([]byte(mode))
	h.Write(bytesFromStrings(prfCompanionOpeningLabels(mode, checkpointSamples)))
	h.Write(seed2)
	h.Write(bytesFromUint64Matrix(bridgeChecks))
	return h.Sum(nil)
}

func buildPRFCompanionBridgeFamiliesFormal(
	ringQ *ring.Ring,
	omegaWitness []uint64,
	layout *PRFCompanionLayout,
	_ []lvcs.RowInput,
	rows []*ring.Poly,
	seed2 []byte,
	checks int,
	mode PRFCompanionMode,
	checkpointSamples int,
) (*prfCompanionBridgeBuild, error) {
	if layout == nil {
		return nil, nil
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if checks <= 0 {
		return nil, fmt.Errorf("invalid bridge checks=%d", checks)
	}
	if len(omegaWitness) != layout.PackWidth {
		return nil, fmt.Errorf("omega witness len=%d want pack width=%d", len(omegaWitness), layout.PackWidth)
	}
	packedHeads, rowCoeffs, err := packedHeadsFromRowsOnOmega(ringQ, omegaWitness, rows, layout)
	if err != nil {
		return nil, err
	}
	cache, err := buildPRFCompanionBridgeCache(ringQ, omegaWitness, layout, seed2, checks)
	if err != nil {
		return nil, err
	}
	q := ringQ.Modulus[0]
	out := &prfCompanionBridgeBuild{
		Families:     make([]*ring.Poly, 0, checks),
		Coeffs:       make([][]uint64, 0, checks),
		BridgeChecks: make([][]uint64, 0, checks),
	}
	for t := 0; t < checks; t++ {
		mixHead := make([]uint64, layout.PackWidth)
		mixCoeff := make([]uint64, 1)
		for r := 0; r < layout.PackedRows; r++ {
			a := cache.alpha[t][r] % q
			if a == 0 {
				continue
			}
			for col := 0; col < layout.PackWidth; col++ {
				mixHead[col] = modAdd(mixHead[col], modMul(a, packedHeads[r][col]%q, q), q)
			}
			mixCoeff = polyAddMod(mixCoeff, polyScale(rowCoeffs[r], a, q), q)
		}
		hHead := make([]uint64, layout.PackWidth)
		for col := 0; col < layout.PackWidth; col++ {
			hHead[col] = modMul(cache.beta[t][col]%q, mixHead[col], q)
		}
		hCoeff := trimPoly(Interpolate(omegaWitness, hHead, q), q)
		fCoeff := polySubMod(polyMul(cache.betaSelCoeff[t], mixCoeff, q), hCoeff, q)
		out.Families = append(out.Families, nttPolyFromFormalCoeffsIfFits(ringQ, fCoeff))
		out.Coeffs = append(out.Coeffs, trimPoly(fCoeff, q))
		out.BridgeChecks = append(out.BridgeChecks, hHead)
	}
	out.CoordDigest = buildPRFCompanionCoordDigest(layout, seed2, out.BridgeChecks, checks, mode, checkpointSamples)
	return out, nil
}

type PRFCompanionBridgeConfig struct {
	Ring         *ring.Ring
	Layout       *PRFCompanionLayout
	DomainPoints []uint64
	OmegaWitness []uint64
	Seed2        []byte
	BridgeChecks [][]uint64
}

func (cfg PRFCompanionBridgeConfig) verifyDigest(proof *PRFCompanionProof) error {
	if proof == nil {
		return fmt.Errorf("nil prf companion proof")
	}
	if proof.Layout == nil {
		return fmt.Errorf("missing prf companion layout")
	}
	layout, err := prfCompanionBridgeLayout(proof)
	if err != nil {
		return err
	}
	expected := buildPRFCompanionCoordDigest(layout, cfg.Seed2, proof.BridgeChecks, len(proof.BridgeChecks), proof.Mode, proof.CheckpointSamples)
	if !bytes.Equal(expected, proof.CoordDigest) {
		return fmt.Errorf("prf companion coord digest mismatch")
	}
	return nil
}

func (cfg PRFCompanionBridgeConfig) companionEvaluator(evalPoint func(evalIdx uint64, q uint64) (uint64, error)) ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		if cfg.Layout == nil {
			return nil, nil, nil
		}
		cache, err := buildPRFCompanionBridgeCache(cfg.Ring, cfg.OmegaWitness, cfg.Layout, cfg.Seed2, len(cfg.BridgeChecks))
		if err != nil {
			return nil, nil, err
		}
		q := cfg.Ring.Modulus[0]
		x, err := evalPoint(evalIdx, q)
		if err != nil {
			return nil, nil, err
		}
		hCoeff := make([][]uint64, len(cfg.BridgeChecks))
		for i := range cfg.BridgeChecks {
			if len(cfg.BridgeChecks[i]) != cfg.Layout.PackWidth {
				return nil, nil, fmt.Errorf("bridge check %d width=%d want %d", i, len(cfg.BridgeChecks[i]), cfg.Layout.PackWidth)
			}
			hCoeff[i] = trimPoly(Interpolate(cfg.OmegaWitness, cfg.BridgeChecks[i], q), q)
		}
		fagg := make([]uint64, 0, len(cfg.BridgeChecks))
		for t := 0; t < len(cfg.BridgeChecks); t++ {
			mix := uint64(0)
			for r := 0; r < cfg.Layout.PackedRows; r++ {
				rowIdx := cfg.Layout.StartRow + r
				if rowIdx < 0 || rowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("companion row idx %d out of range (rows=%d)", rowIdx, len(rows))
				}
				mix = modAdd(mix, modMul(cache.alpha[t][r]%q, rows[rowIdx]%q, q), q)
			}
			betaSel := EvalPoly(cache.betaSelCoeff[t], x, q)
			hVal := EvalPoly(hCoeff[t], x, q)
			fagg = append(fagg, modSub(modMul(betaSel, mix, q), hVal, q))
		}
		return nil, fagg, nil
	}
}

func (cfg PRFCompanionBridgeConfig) Evaluator() ConstraintEvaluator {
	if len(cfg.DomainPoints) == 0 {
		return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("prf companion replay config: missing domain points")
		}
	}
	return cfg.companionEvaluator(func(evalIdx uint64, q uint64) (uint64, error) {
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return 0, fmt.Errorf("companion eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		return cfg.DomainPoints[ptIdx] % q, nil
	})
}

func (cfg PRFCompanionBridgeConfig) KEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cfg.Layout == nil {
		return nil, nil
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	cache, err := buildPRFCompanionBridgeCache(cfg.Ring, cfg.OmegaWitness, cfg.Layout, cfg.Seed2, len(cfg.BridgeChecks))
	if err != nil {
		return nil, err
	}
	q := cfg.Ring.Modulus[0]
	hCoeff := make([][]uint64, len(cfg.BridgeChecks))
	for i := range cfg.BridgeChecks {
		if len(cfg.BridgeChecks[i]) != cfg.Layout.PackWidth {
			return nil, fmt.Errorf("bridge check %d width=%d want %d", i, len(cfg.BridgeChecks[i]), cfg.Layout.PackWidth)
		}
		hCoeff[i] = trimPoly(Interpolate(cfg.OmegaWitness, cfg.BridgeChecks[i], q), q)
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		fagg := make([]kf.Elem, 0, len(cfg.BridgeChecks))
		for t := 0; t < len(cfg.BridgeChecks); t++ {
			mix := K.Zero()
			for r := 0; r < cfg.Layout.PackedRows; r++ {
				rowIdx := cfg.Layout.StartRow + r
				if rowIdx < 0 || rowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("companion row idx %d out of range (rows=%d)", rowIdx, len(rows))
				}
				K.AddMulBaseInto(&mix, rows[rowIdx], cache.alpha[t][r]%q)
			}
			betaSel := K.EvalFPolyAtK(cache.betaSelCoeff[t], e)
			hVal := K.EvalFPolyAtK(hCoeff[t], e)
			fagg = append(fagg, K.Sub(K.Mul(betaSel, mix), hVal))
		}
		return nil, fagg, nil
	}, nil
}

func verifyPRFCompanionBridgeFromOpening(
	ringQ *ring.Ring,
	layout *PRFCompanionLayout,
	proof *Proof,
	omegaWitness []uint64,
	domainPoints []uint64,
) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if layout == nil || proof == nil || proof.PRFCompanion == nil {
		return nil
	}
	if len(domainPoints) == 0 {
		return fmt.Errorf("missing domain points for direct-auth bridge verification")
	}
	opening, err := preparePRFCompanionBridgeOpening(ringQ, proof, omegaWitness, domainPoints)
	if err != nil {
		return err
	}
	if len(opening.Pvals) == 0 || len(opening.Indices) == 0 {
		return fmt.Errorf("empty row opening payload for direct-auth bridge verification")
	}
	cfg := PRFCompanionBridgeConfig{
		Ring:         ringQ,
		Layout:       layout,
		OmegaWitness: omegaWitness,
		Seed2:        append([]byte(nil), proof.Digests[1]...),
		BridgeChecks: copyMatrix(proof.PRFCompanion.BridgeChecks),
	}
	if err := cfg.verifyDigest(proof.PRFCompanion); err != nil {
		return err
	}
	cache, err := buildPRFCompanionBridgeCache(ringQ, omegaWitness, layout, cfg.Seed2, len(cfg.BridgeChecks))
	if err != nil {
		return err
	}
	rowIndices := make([]int, layout.PackedRows)
	for rel := 0; rel < layout.PackedRows; rel++ {
		rowIndices[rel] = layout.StartRow + rel
	}
	witnessView, err := prepareMaskSubsetWitnessView(ringQ, proof, rowIndices, omegaWitness, domainPoints)
	if err != nil {
		return err
	}
	rowHeads := make([][]uint64, layout.PackedRows)
	for rel, rowIdx := range rowIndices {
		head, err := witnessView.witnessHead(rowIdx)
		if err != nil {
			return err
		}
		rowHeads[rel] = head
	}
	for t := range proof.PRFCompanion.BridgeChecks {
		if len(proof.PRFCompanion.BridgeChecks[t]) != layout.PackWidth {
			return fmt.Errorf("bridge check %d width=%d want %d", t, len(proof.PRFCompanion.BridgeChecks[t]), layout.PackWidth)
		}
		mixHead := make([]uint64, layout.PackWidth)
		for rel := 0; rel < layout.PackedRows; rel++ {
			alpha := cache.alpha[t][rel] % ringQ.Modulus[0]
			if alpha == 0 {
				continue
			}
			for col := 0; col < layout.PackWidth; col++ {
				val := rowHeads[rel][col] % ringQ.Modulus[0]
				mixHead[col] = modAdd(mixHead[col], modMul(alpha, val, ringQ.Modulus[0]), ringQ.Modulus[0])
			}
		}
		for col := 0; col < layout.PackWidth; col++ {
			want := modMul(cache.beta[t][col]%ringQ.Modulus[0], mixHead[col], ringQ.Modulus[0])
			if proof.PRFCompanion.BridgeChecks[t][col]%ringQ.Modulus[0] != want {
				return fmt.Errorf("direct-auth companion bridge mismatch at family=%d omega_col=%d", t, col)
			}
		}
	}
	return nil
}
