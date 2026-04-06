package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// MaskConfig captures masking and degree knobs shared across retained builders.
type MaskConfig struct {
	Rho      int
	EllPrime int
	Ell      int
	Eta      int
	DQ       int
}

// MaskConfigFromOpts derives a MaskConfig from SimOpts.
func MaskConfigFromOpts(o SimOpts) MaskConfig {
	return MaskConfig{
		Rho:      o.Rho,
		EllPrime: o.EllPrime,
		Ell:      o.Ell,
		Eta:      o.Eta,
		DQ:       o.DQOverride,
	}
}

// deriveMaskingConfig computes masking parameters and degree targets from the
// active constraint families.
func deriveMaskingConfig(ringQ *ring.Ring, opts SimOpts, parallelAlgDeg, aggAlgDeg int, omega []uint64) (parallelDeg, aggDeg, maskDegreeTarget, maskDegreeBound int, cfg MaskConfig, err error) {
	opts.applyDefaults()
	cfg = MaskConfigFromOpts(opts)
	if cfg.Rho <= 0 {
		cfg.Rho = 1
	}
	if cfg.EllPrime <= 0 {
		cfg.EllPrime = 1
	}
	parallelDeg = parallelAlgDeg
	aggDeg = aggAlgDeg
	if parallelDeg <= 0 {
		parallelDeg = 2
	}
	if aggDeg <= 0 {
		aggDeg = 1
	}
	if len(omega) == 0 {
		err = fmt.Errorf("empty omega")
		return
	}
	if cfg.Ell <= 0 {
		cfg.Ell = 1
	}
	if cfg.DQ <= 0 {
		cfg.DQ = computeDQFromConstraintDegrees(parallelDeg, aggDeg, len(omega), cfg.Ell)
	}
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	if cfg.DQ < 0 {
		err = fmt.Errorf("invalid dQ=%d", cfg.DQ)
		return
	}
	if opts.DomainMode != DomainModeExplicit && cfg.DQ >= int(ringQ.N) {
		err = fmt.Errorf("computed dQ=%d exceeds ring dimension N=%d; explicit PCS needs a non-NTT backend for degrees > N-1", cfg.DQ, ringQ.N)
		return
	}
	maskDegreeBound = cfg.DQ
	maskDegreeTarget = cfg.DQ
	return
}

// MaskingFSInput carries the data needed for the masking/Merkle/FS stage.
type MaskingFSInput struct {
	RingQ *ring.Ring
	Opts  SimOpts
	Omega []uint64
	// OmegaWitness is the witness packing domain Ω_s.
	OmegaWitness       []uint64
	DomainPoints       []uint64
	Root               [16]byte
	PK                 *lvcs.ProverKey
	OracleLayout       lvcs.OracleLayout
	RowLayout          RowLayout
	FparInt            []*ring.Poly
	FparNorm           []*ring.Poly
	FaggInt            []*ring.Poly
	FaggNorm           []*ring.Poly
	FparIntCoeffs      [][]uint64
	FparNormCoeffs     [][]uint64
	FaggIntCoeffs      [][]uint64
	FaggNormCoeffs     [][]uint64
	PRFCompanionLayout *PRFCompanionLayout
	PRFCompanionRows   []lvcs.RowInput
	PRFTagPublic       [][]int64
	PRFNoncePublic     [][]int64
	RowInputs          []lvcs.RowInput
	WitnessPolys       []*ring.Poly // layout base (w1)
	MaskPolys          []*ring.Poly // independent masks (optional; can be empty)
	MaskPolyCoeffs     [][]uint64   // formal coeff rows for independent masks
	MaskPolysK         []*KPoly     // independent K masks (theta>1)
	MaskRowOffset      int
	MaskRowCount       int
	PCSGeometry        PCSGeometry
	MaskDegreeTarget   int
	MaskDegreeBound    int
	Personalization    string // FS personalization label (e.g., FSModeCredential)
	NCols              int    // witness packing width s
	PCSNCols           int    // PCS row width; 0 => LVCSNCols => NCols
	LVCSNCols          int    // LVCS row width; 0 => NCols
	DecsParams         decs.Params
	LabelsDigest       []byte // hash of public labels included in FS binding
	// Small-field (theta>1) parameters
	SmallFieldChi     []uint64
	SmallFieldOmegaS1 []uint64
	SmallFieldMuInv   []uint64
	SmallFieldK       *kf.Field
}

func alignConstraintCoeffOverrides(polys []*ring.Poly, coeffs [][]uint64) [][]uint64 {
	if len(polys) == 0 {
		return nil
	}
	out := make([][]uint64, len(polys))
	limit := len(coeffs)
	if limit > len(polys) {
		limit = len(polys)
	}
	for i := 0; i < limit; i++ {
		if len(coeffs[i]) == 0 {
			continue
		}
		out[i] = append([]uint64(nil), coeffs[i]...)
	}
	return out
}

func copyInt64Matrix(src [][]int64) [][]int64 {
	if len(src) == 0 {
		return nil
	}
	out := make([][]int64, len(src))
	for i := range src {
		out[i] = append([]int64(nil), src[i]...)
	}
	return out
}

// RunMaskingFS executes the masking, commitment, Fiat-Shamir, and opening
// stages from explicit row and constraint inputs.
func RunMaskingFS(in MaskingFSInput) (*Proof, error) {
	o := in.Opts
	o.applyDefaults()
	args := maskFSArgs{
		ringQ:              in.RingQ,
		omega:              in.Omega,
		domainPoints:       in.DomainPoints,
		q:                  in.RingQ.Modulus[0],
		rho:                o.Rho,
		ell:                o.Ell,
		ellPrime:           o.EllPrime,
		opts:               o,
		ncols:              in.NCols,
		witnessNCols:       in.NCols,
		root:               in.Root,
		PK:                 in.PK,
		w1:                 in.WitnessPolys,
		origW1Len:          len(in.WitnessPolys),
		FparInt:            in.FparInt,
		FparNorm:           in.FparNorm,
		FaggInt:            in.FaggInt,
		FaggNorm:           in.FaggNorm,
		FparIntCoeffs:      in.FparIntCoeffs,
		FparNormCoeffs:     in.FparNormCoeffs,
		FaggIntCoeffs:      in.FaggIntCoeffs,
		FaggNormCoeffs:     in.FaggNormCoeffs,
		prfCompanionLayout: in.PRFCompanionLayout,
		prfCompanionRows:   append([]lvcs.RowInput(nil), in.PRFCompanionRows...),
		prfTagPublic:       copyInt64Matrix(in.PRFTagPublic),
		prfNoncePublic:     copyInt64Matrix(in.PRFNoncePublic),
		FparAll:            append(append([]*ring.Poly{}, in.FparInt...), in.FparNorm...),
		FaggAll:            append(append([]*ring.Poly{}, in.FaggInt...), in.FaggNorm...),
		FparAllCoeffs: append(
			alignConstraintCoeffOverrides(in.FparInt, in.FparIntCoeffs),
			alignConstraintCoeffOverrides(in.FparNorm, in.FparNormCoeffs)...,
		),
		FaggAllCoeffs: append(
			alignConstraintCoeffOverrides(in.FaggInt, in.FaggIntCoeffs),
			alignConstraintCoeffOverrides(in.FaggNorm, in.FaggNormCoeffs)...,
		),
		maskDegreeTarget:      in.MaskDegreeTarget,
		maskDegreeBound:       in.MaskDegreeBound,
		pcsGeometry:           in.PCSGeometry,
		rowInputs:             in.RowInputs,
		independentMasks:      in.MaskPolys,
		independentMaskCoeffs: copyMatrix(in.MaskPolyCoeffs),
		independentMasksK: func() []*KPoly {
			if len(in.MaskPolysK) == 0 {
				return nil
			}
			out := make([]*KPoly, len(in.MaskPolysK))
			for i := range in.MaskPolysK {
				out[i] = deepCopyKPoly(in.MaskPolysK[i])
			}
			return out
		}(),
		rowLayout:     in.RowLayout,
		oracleLayout:  in.OracleLayout,
		maskRowOffset: in.MaskRowOffset,
		maskRowCount:  in.MaskRowCount,
		decsParams:    in.DecsParams,
		ncolsOverride: in.NCols,
		labelsDigest:  append([]byte(nil), in.LabelsDigest...),
	}
	if in.PRFCompanionLayout != nil {
		args.prfCompanionBridgeChecks = prfCompanionBridgeChecks
	}
	if args.witnessNCols <= 0 {
		args.witnessNCols = len(in.Omega)
	}
	lvcsNCols := in.PCSNCols
	if lvcsNCols <= 0 {
		lvcsNCols = in.LVCSNCols
	}
	if lvcsNCols <= 0 {
		lvcsNCols = resolvePCSNCols(o, args.witnessNCols)
	}
	if lvcsNCols < args.witnessNCols {
		return nil, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", lvcsNCols, args.witnessNCols)
	}
	args.ncols = lvcsNCols
	args.ncolsOverride = lvcsNCols
	if len(in.OmegaWitness) > 0 {
		if len(in.OmegaWitness) != args.witnessNCols {
			return nil, fmt.Errorf("omega witness len=%d != witness ncols=%d", len(in.OmegaWitness), args.witnessNCols)
		}
		args.omegaWitness = append([]uint64(nil), in.OmegaWitness...)
	} else {
		if len(in.Omega) < args.witnessNCols {
			return nil, fmt.Errorf("omega len=%d < witness ncols=%d", len(in.Omega), args.witnessNCols)
		}
		args.omegaWitness = append([]uint64(nil), in.Omega[:args.witnessNCols]...)
	}
	if o.Theta > 1 {
		args.smallFieldChi = append([]uint64(nil), in.SmallFieldChi...)
		args.smallFieldK = in.SmallFieldK
		args.smallFieldOmegaS1 = kf.Elem{Limb: append([]uint64(nil), in.SmallFieldOmegaS1...)}
		args.smallFieldMuInv = kf.Elem{Limb: append([]uint64(nil), in.SmallFieldMuInv...)}
		if in.OracleLayout == (lvcs.OracleLayout{}) {
			return nil, fmt.Errorf("missing oracle layout for theta>1")
		}
		oracleResp, err := lvcs.EvalOracle(in.RingQ, in.PK, in.Omega, in.OracleLayout)
		if err != nil {
			return nil, fmt.Errorf("eval oracle rows on omega: %w", err)
		}
		totalRows := len(in.RowInputs)
		if totalRows <= 0 {
			return nil, fmt.Errorf("missing row inputs")
		}
		args.rows = make([][]uint64, totalRows)
		for i := 0; i < in.OracleLayout.Witness.Count; i++ {
			rowIdx := in.OracleLayout.Witness.Offset + i
			if rowIdx < 0 || rowIdx >= totalRows {
				return nil, fmt.Errorf("invalid witness row index %d (total=%d)", rowIdx, totalRows)
			}
			args.rows[rowIdx] = append([]uint64(nil), oracleResp.Witness[i]...)
		}
		for i := 0; i < in.OracleLayout.Mask.Count; i++ {
			rowIdx := in.OracleLayout.Mask.Offset + i
			if rowIdx < 0 || rowIdx >= totalRows {
				return nil, fmt.Errorf("invalid mask row index %d (total=%d)", rowIdx, totalRows)
			}
			args.rows[rowIdx] = append([]uint64(nil), oracleResp.Mask[i]...)
		}
		for i := 0; i < totalRows; i++ {
			if len(args.rows[i]) == 0 {
				return nil, fmt.Errorf("missing oracle evaluation row %d", i)
			}
		}
		args.omega = in.Omega
	} else {
		args.rows = evalRowsAt(in.RingQ, in.WitnessPolys, in.Omega)
		args.omegaWitness = append([]uint64(nil), in.Omega...)
	}
	out, err := runMaskFS(args)
	if err != nil {
		return nil, err
	}
	return out.proof, nil
}
