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
	Packing         ProofPackingAudit
	Geometry        WitnessGeometrySnapshot
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
