package PIOP

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ProofReport captures proof size and soundness metrics for a built proof.
type ProofReport struct {
	ProofBytes int
	ProofKB    float64
	Soundness  SoundnessBudget
	Packing    ProofPackingAudit
	Geometry   WitnessGeometrySnapshot
	Split      *SplitProofReport
	NCols      int
	PCSNCols   int
	LVCSNCols  int
	Ell        int
	EllPrime   int
	Rho        int
	Theta      int
	Eta        int
	DQ         int
	Lambda     int
	Kappa      [4]int
}

type SplitProofReport struct {
	PostSign *ProofReport `json:"post_sign,omitempty"`
	PRF      *ProofReport `json:"prf,omitempty"`
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
			ProofBytes: size.Total,
			ProofKB:    float64(size.Total) / 1024.0,
			Soundness:  soundness,
			Packing:    packing,
			Geometry:   BuildWitnessGeometrySnapshotFromProof(proof),
			Split:      &split,
			NCols:      reportOpts.NCols,
			PCSNCols:   0,
			LVCSNCols:  0,
			Ell:        reportOpts.Ell,
			EllPrime:   reportOpts.EllPrime,
			Rho:        reportOpts.Rho,
			Theta:      reportOpts.Theta,
			Eta:        reportOpts.Eta,
			DQ:         dQ,
			Lambda:     reportOpts.Lambda,
			Kappa:      reportOpts.Kappa,
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
		Packing:    packing,
		Geometry:   geometry,
		NCols:      ncols,
		PCSNCols:   lvcsNCols,
		LVCSNCols:  lvcsNCols,
		Ell:        ell,
		EllPrime:   ellPrime,
		Rho:        rho,
		Theta:      theta,
		Eta:        eta,
		DQ:         dQ,
		Lambda:     reportOpts.Lambda,
		Kappa:      reportOpts.Kappa,
	}, nil
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
		QueryCaps:          opts.ROQueryCaps,
		CollisionSpaceBits: fsCollisionSpaceBits(opts.Lambda, 0),
		WitnessSupportCols: opts.NCols,
	}
	children := []*ProofReport{split.PostSign, split.PRF}
	for _, child := range children {
		if child == nil {
			continue
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
		sb.NRows += child.Soundness.NRows
		sb.M += child.Soundness.M
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
	querySquares := 0.0
	for _, cap := range opts.ROQueryCaps {
		if cap > 0 {
			querySquares += float64(cap) * float64(cap)
		}
	}
	if querySquares > 0 {
		sb.Collision = querySquares * math.Pow(2, -float64(sb.CollisionSpaceBits))
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
