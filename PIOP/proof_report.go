package PIOP

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ProofReport captures proof size and soundness metrics for a built proof.
type ProofReport struct {
	ProofBytes      int
	ProofKB         float64
	Soundness       SoundnessBudget
	PaperTranscript PaperTranscriptReport
	Derived         *DerivedGrindingReport
	Packing         ProofPackingAudit
	Geometry        WitnessGeometrySnapshot
	Split           *SplitProofReport
	NCols           int
	PCSNCols        int
	LVCSNCols       int
	Ell             int
	EllPrime        int
	Rho             int
	Theta           int
	Eta             int
	DQ              int
	Lambda          int
	Kappa           [4]int
}

type SplitProofReport struct {
	PostSign *ProofReport `json:"post_sign,omitempty"`
	PRF      *ProofReport `json:"prf,omitempty"`
}

// DerivedGrindingReport records the minimal extra grinding needed to bring a
// split proof back to a target theorem-level soundness.
type DerivedGrindingReport struct {
	TargetBits       float64 `json:"target_bits"`
	RawCombinedTotal float64 `json:"raw_combined_total"`
	RawCombinedBits  float64 `json:"raw_combined_bits"`
	DerivedKappa     [4]int  `json:"derived_kappa"`
	DerivedTotal     float64 `json:"derived_total"`
	DerivedTotalBits float64 `json:"derived_total_bits"`
	Achievable       bool    `json:"achievable"`
}

// BuildProofReport derives proof size + soundness metrics for a given proof/options.
// This is intended for credential issuance/showing runs.
func BuildProofReport(proof *Proof, opts SimOpts, ringQ *ring.Ring) (ProofReport, error) {
	if proof == nil {
		return ProofReport{}, fmt.Errorf("nil proof")
	}
	if ringQ == nil {
		return ProofReport{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	reportOpts := opts
	if proof.Lambda > 0 {
		reportOpts.Lambda = proof.Lambda
	}
	if proof.ShowingSplit != nil {
		postOpts, prfOpts := resolveShowingSplitSliceOpts(reportOpts)
		var split SplitProofReport
		if proof.ShowingSplit.PostSign != nil && proof.ShowingSplit.PostSign.Proof != nil {
			rep, err := BuildProofReport(proof.ShowingSplit.PostSign.Proof, postOpts, ringQ)
			if err != nil {
				return ProofReport{}, err
			}
			split.PostSign = &rep
		}
		if proof.ShowingSplit.PRF != nil && proof.ShowingSplit.PRF.Proof != nil {
			rep, err := BuildProofReport(proof.ShowingSplit.PRF.Proof, prfOpts, ringQ)
			if err != nil {
				return ProofReport{}, err
			}
			split.PRF = &rep
		}
		size := MeasureProofSize(proof)
		packing, err := BuildProofPackingAudit(proof, ringQ.Modulus[0])
		if err != nil {
			return ProofReport{}, fmt.Errorf("packing audit: %w", err)
		}
		soundness := aggregateSplitSoundness(reportOpts, split)
		dQ := 0
		if split.PostSign != nil && split.PostSign.DQ > dQ {
			dQ = split.PostSign.DQ
		}
		if split.PRF != nil && split.PRF.DQ > dQ {
			dQ = split.PRF.DQ
		}
		return ProofReport{
			ProofBytes:      size.Total,
			ProofKB:         float64(size.Total) / 1024.0,
			Soundness:       soundness,
			PaperTranscript: mergeSplitPaperTranscriptReports(split),
			Derived:         deriveGrindingReportForSplit(split, 128),
			Packing:         packing,
			Geometry:        BuildWitnessGeometrySnapshotFromProof(proof),
			Split:           &split,
			NCols:           reportOpts.NCols,
			PCSNCols:        0,
			LVCSNCols:       0,
			Ell:             reportOpts.Ell,
			EllPrime:        reportOpts.EllPrime,
			Rho:             reportOpts.Rho,
			Theta:           reportOpts.Theta,
			Eta:             reportOpts.Eta,
			DQ:              dQ,
			Lambda:          reportOpts.Lambda,
			Kappa:           reportOpts.Kappa,
		}, nil
	}
	reportOpts.Kappa = proof.Kappa
	if proof.Theta > 0 {
		reportOpts.Theta = proof.Theta
	}

	ncols := proof.NColsUsed
	if ncols <= 0 {
		ncols = reportOpts.NCols
	}
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	lvcsNCols := resolveProofPCSNCols(proof, reportOpts.PCSNCols)
	if lvcsNCols <= 0 {
		lvcsNCols = reportOpts.LVCSNCols
	}
	if lvcsNCols <= 0 {
		lvcsNCols = ncols
	}
	ell := reportOpts.Ell
	ellPrime := reportOpts.EllPrime
	rho := reportOpts.Rho
	eta := reportOpts.Eta
	theta := reportOpts.Theta

	dQ := proof.QDegreeBound
	if dQ <= 0 {
		dQ = proof.MaskDegreeBound
	}
	if dQ <= 0 {
		dQ = reportOpts.DQOverride
	}
	if dQ <= 0 {
		return ProofReport{}, fmt.Errorf("missing dQ/QDegreeBound in proof")
	}

	geometry := BuildWitnessGeometrySnapshotFromProof(proof)
	witnessPolys := geometry.ActualWitnessPolys
	if witnessPolys <= 0 {
		witnessPolys = proof.MaskRowOffset
	}
	if witnessPolys <= 0 {
		if proof.RowLayout.SigCount > 0 {
			witnessPolys = proof.RowLayout.SigCount
		} else {
			witnessPolys = ncols
		}
	}

	nLeaves := proof.NLeavesUsed
	if nLeaves <= 0 {
		nLeaves = reportOpts.NLeaves
	}
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}

	q := ringQ.Modulus[0]
	fieldSize := float64(q)
	if theta > 1 {
		fieldSize = math.Pow(float64(q), float64(theta))
	}
	sb := computeSoundnessBudget(reportOpts, q, fieldSize, fsCollisionSpaceBits(reportOpts.Lambda, len(proof.Salt)), dQ, ncols, lvcsNCols, ell, ellPrime, eta, nLeaves, witnessPolys)
	size := MeasureProofSize(proof)
	packing, err := BuildProofPackingAudit(proof, q)
	if err != nil {
		return ProofReport{}, fmt.Errorf("packing audit: %w", err)
	}
	return ProofReport{
		ProofBytes: size.Total,
		ProofKB:    float64(size.Total) / 1024.0,
		Soundness:  sb,
		PaperTranscript: buildPaperTranscriptReportLeaf(proof, q, paperTranscriptParams{
			Lambda:   reportOpts.Lambda,
			Eta:      eta,
			Ell:      ell,
			EllPrime: ellPrime,
			Rho:      rho,
			Theta:    theta,
			DQ:       dQ,
			DDECS:    lvcsNCols + ell - 1,
		}),
		Packing:   packing,
		Geometry:  geometry,
		NCols:     ncols,
		PCSNCols:  lvcsNCols,
		LVCSNCols: lvcsNCols,
		Ell:       ell,
		EllPrime:  ellPrime,
		Rho:       rho,
		Theta:     theta,
		Eta:       eta,
		DQ:        dQ,
		Lambda:    reportOpts.Lambda,
		Kappa:     reportOpts.Kappa,
	}, nil
}

func mergeSplitPaperTranscriptReports(split SplitProofReport) PaperTranscriptReport {
	out := PaperTranscriptReport{}
	if split.PostSign != nil {
		out = mergePaperTranscriptReports(out, split.PostSign.PaperTranscript)
	}
	if split.PRF != nil {
		out = mergePaperTranscriptReports(out, split.PRF.PaperTranscript)
	}
	return out
}

func probabilityBits(p float64) float64 {
	switch {
	case p <= 0:
		return math.Inf(1)
	case p >= 1:
		return 0
	default:
		return -math.Log2(p)
	}
}

func aggregateSplitSoundness(opts SimOpts, split SplitProofReport) SoundnessBudget {
	opts.applyDefaults()
	sb := SoundnessBudget{
		QueryCaps: opts.ROQueryCaps,
	}
	children := []*ProofReport{split.PostSign, split.PRF}
	for _, child := range children {
		if child == nil {
			continue
		}
		if sb.WitnessSupportCols == 0 || (child.Soundness.WitnessSupportCols > 0 && child.Soundness.WitnessSupportCols < sb.WitnessSupportCols) {
			sb.WitnessSupportCols = child.Soundness.WitnessSupportCols
		}
		if child.DQ > sb.DQ {
			sb.DQ = child.DQ
		}
		if child.Soundness.DDECS > sb.DDECS {
			sb.DDECS = child.Soundness.DDECS
		}
		if child.Soundness.CommittedCols > sb.CommittedCols {
			sb.CommittedCols = child.Soundness.CommittedCols
		}
		if sb.CollisionSpaceBits == 0 || (child.Soundness.CollisionSpaceBits > 0 && child.Soundness.CollisionSpaceBits < sb.CollisionSpaceBits) {
			sb.CollisionSpaceBits = child.Soundness.CollisionSpaceBits
		}
		sb.NRows += child.Soundness.NRows
		sb.M += child.Soundness.M
		sb.Collision += child.Soundness.Collision
		for i := 0; i < 4; i++ {
			sb.Eps[i] += child.Soundness.Eps[i]
			sb.TheoremTerms[i] += child.Soundness.TheoremTerms[i]
		}
	}
	for i := 0; i < 4; i++ {
		sb.RawBits[i] = probabilityBits(sb.Eps[i])
		sb.Bits[i] = sb.RawBits[i]
		sb.TheoremBits[i] = probabilityBits(sb.TheoremTerms[i])
		sb.GrindingBits[i] = float64(opts.Kappa[i])
		sb.Grinding[i] = math.Pow(2, -float64(opts.Kappa[i]))
	}
	sb.Eq8Total = sb.Eps[0] + sb.Eps[1] + sb.Eps[2] + sb.Eps[3]
	sb.Eq8TotalBits = probabilityBits(sb.Eq8Total)
	if sb.Collision > 0 {
		if sb.Collision > 1 {
			sb.Collision = 1
		}
		sb.CollisionBits = probabilityBits(sb.Collision)
	} else {
		sb.CollisionBits = math.Inf(1)
	}
	sb.Total = sb.Collision
	for _, term := range sb.TheoremTerms {
		sb.Total += term
	}
	sb.TotalBits = probabilityBits(sb.Total)
	return sb
}

func deriveGrindingReportForSplit(split SplitProofReport, targetBits float64) *DerivedGrindingReport {
	children := []*ProofReport{split.PostSign, split.PRF}
	var rawTerms [4]float64
	collision := 0.0
	for _, child := range children {
		if child == nil {
			continue
		}
		collision += child.Soundness.Collision
		for i := 0; i < 4; i++ {
			queryCap := child.Soundness.QueryCaps[i+1]
			rawTerm, _ := theoremTerm(queryCap, child.Soundness.Eps[i], 0)
			rawTerms[i] += rawTerm
		}
	}
	target := math.Pow(2, -targetBits)
	out := &DerivedGrindingReport{
		TargetBits:       targetBits,
		RawCombinedTotal: collision,
		Achievable:       true,
	}
	for _, term := range rawTerms {
		out.RawCombinedTotal += term
	}
	out.RawCombinedBits = probabilityBits(out.RawCombinedTotal)
	if collision > target {
		out.Achievable = false
		out.DerivedTotal = collision
		out.DerivedTotalBits = probabilityBits(collision)
		return out
	}
	currentTerms := rawTerms
	out.DerivedTotal = collision
	for _, term := range currentTerms {
		out.DerivedTotal += term
	}
	for out.DerivedTotal > target {
		bestIdx := 0
		bestTerm := currentTerms[0]
		for i := 1; i < len(currentTerms); i++ {
			if currentTerms[i] > bestTerm {
				bestTerm = currentTerms[i]
				bestIdx = i
			}
		}
		out.DerivedKappa[bestIdx]++
		currentTerms[bestIdx] *= 0.5
		out.DerivedTotal = collision
		for _, term := range currentTerms {
			out.DerivedTotal += term
		}
	}
	out.DerivedTotalBits = probabilityBits(out.DerivedTotal)
	return out
}
