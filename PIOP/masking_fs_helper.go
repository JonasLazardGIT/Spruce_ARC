package PIOP

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// local helpers copied from run.go for eval point sampling
func sampleEvalPoints(r *ring.Ring, m int, omega []uint64, seed []byte) []byte {
	fsRNG := newFSRNG("EvalPoints", seed)
	points := make([]uint64, m)
	q := r.Modulus[0]
	for i := 0; i < m; i++ {
		points[i] = fsRNG.nextU64() % q
	}
	return encodeUint64Slice(points)
}

func decodeUint64Slice(b []byte) []uint64 {
	if len(b)%8 != 0 {
		return nil
	}
	out := make([]uint64, len(b)/8)
	for i := 0; i < len(out); i++ {
		out[i] = binary.LittleEndian.Uint64(b[8*i : 8*(i+1)])
	}
	return out
}

// evalRowsAt evaluates a slice of polys (NTT or coeff) at given points in F_q.
func evalRowsAt(r *ring.Ring, polys []*ring.Poly, points []uint64) [][]uint64 {
	if r == nil {
		return nil
	}
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		if p == nil {
			continue
		}
		coeff := r.NewPoly()
		r.InvNTT(p, coeff)
		row := make([]uint64, len(points))
		for j, x := range points {
			row[j] = evalAt(r, coeff, x)
		}
		out[i] = row
	}
	return out
}

// maskFSArgs carries all inputs needed to run the masking/Merkle/FS loop.
type maskFSArgs struct {
	ringQ *ring.Ring
	omega []uint64
	// omegaWitness is the witness packing domain Ω_s.
	omegaWitness []uint64
	// domainPoints is the explicit DECS evaluation domain.
	domainPoints []uint64
	q            uint64
	rho          int
	ell          int
	ellPrime     int
	opts         SimOpts
	ncols        int
	witnessNCols int
	pcsGeometry  PCSGeometry
	root         [16]byte

	// Small-field parameters (Theta > 1)
	smallFieldK       *kf.Field
	smallFieldChi     []uint64
	smallFieldOmegaS1 kf.Elem
	smallFieldMuInv   kf.Elem

	// Public tables / commit key
	PK  *lvcs.ProverKey
	A   [][]*ring.Poly
	b1  []*ring.Poly
	B0c []*ring.Poly
	B0m [][]*ring.Poly
	B0r [][]*ring.Poly

	// Witness
	w1        []*ring.Poly
	w2        *ring.Poly
	w3        []*ring.Poly
	origW1Len int
	mSig      int

	// Range offsets
	msgRangeOffset int
	rndRangeOffset int
	x1RangeOffset  int

	// Constraints
	FparInt        []*ring.Poly
	FparNorm       []*ring.Poly
	FaggInt        []*ring.Poly
	FaggNorm       []*ring.Poly
	FparIntCoeffs  [][]uint64
	FparNormCoeffs [][]uint64
	FaggIntCoeffs  [][]uint64
	FaggNormCoeffs [][]uint64
	FparAll        []*ring.Poly
	FaggAll        []*ring.Poly
	FparAllCoeffs  [][]uint64
	FaggAllCoeffs  [][]uint64
	parallelDeg    int
	aggDeg         int

	// Mask configuration
	maskDegreeTarget      int
	maskDegreeBound       int
	independentMasks      []*ring.Poly
	independentMaskCoeffs [][]uint64
	independentMasksK     []*KPoly

	// Rows/layout
	rows            [][]uint64
	rowInputs       []lvcs.RowInput
	witnessRowCount int
	maskRowOffset   int
	maskRowCount    int
	rowLayout       RowLayout
	oracleLayout    lvcs.OracleLayout
	decsParams      decs.Params

	labelsDigest []byte

	// Optional ncols override (head length) for theta>1
	ncolsOverride int

	// Optional deterministic salt override for tests.
	salt []byte
}

// maskFSOutput captures the artefacts produced by the masking/FS loop.
type maskFSOutput struct {
	proof *Proof

	Gamma       [][]uint64
	GammaPrime  [][][]uint64
	GammaAgg    [][]uint64
	GammaPrimeK [][][]KScalar
	GammaAggK   [][]KScalar

	M       []*ring.Poly
	MCoeffs [][]uint64
	MK      []*KPoly
	Q       []*ring.Poly
	QCoeffs [][]uint64
	QK      []*KPoly

	Rpolys          []*ring.Poly
	barSets         [][]uint64
	coeffMatrix     [][]uint64
	kPoint          [][]uint64
	evalPoints      []uint64
	smallFieldEvals []kf.Elem
	barSetsRows     int
	barSetsCols     int
	barSetsBitWidth uint8
	maskPolyCount   int

	vTargets       [][]uint64
	vTargetsPacked []byte
	tailIndices    []int
	gammaQ         [][]uint64

	// Openings/placeholders as needed
	openMask        *lvcs.Opening
	openTail        *lvcs.Opening
	combinedOpen    *decs.DECSOpening
	qOpeningRaw     *decs.DECSOpening
	rowLayout       RowLayout
	maskRowOffset   int
	maskRowCount    int
	maskDegreeBound int
	Root            [16]byte
	evalReqs        []lvcs.EvalRequest
	Tail            []int
}

// runMaskFS executes the masking/Merkle/FS round 1 scaffold and prepares the proof header.
// It is intentionally minimal for the staged extraction.
func runMaskFS(args maskFSArgs) (maskFSOutput, error) {
	var out maskFSOutput
	if args.ringQ == nil {
		return out, fmt.Errorf("nil ring")
	}
	if args.PK == nil {
		return out, fmt.Errorf("nil prover key")
	}
	o := args.opts
	o.applyDefaults()
	ringQ := args.ringQ
	q := args.q
	if q == 0 && ringQ != nil {
		q = ringQ.Modulus[0]
	}
	stage := func(label string, fn func() error) error {
		err := fn()
		return err
	}
	// FS initialization
	baseXOF := NewShake256XOF(fsDigestBytes)
	salt := append([]byte(nil), args.salt...)
	if len(salt) == 0 {
		salt = make([]byte, fsSaltBytes(o.Lambda))
		if _, err := cryptoRand.Read(salt); err != nil {
			return out, fmt.Errorf("rand salt: %w", err)
		}
	}
	fs := NewFS(baseXOF, salt, FSParams{Lambda: o.Lambda, Kappa: o.Kappa})
	proof := &Proof{
		Root:            args.root,
		Salt:            append([]byte(nil), salt...),
		Lambda:          o.Lambda,
		Theta:           o.Theta,
		Kappa:           o.Kappa,
		RowLayout:       args.rowLayout,
		MaskRowOffset:   args.maskRowOffset,
		MaskRowCount:    args.maskRowCount,
		RowDegreeBound:  args.decsParams.Degree,
		MaskDegreeBound: args.maskDegreeBound,
		NColsUsed:       args.witnessNCols,
		PCSNColsUsed:    args.ncols,
		LVCSNColsUsed:   args.ncols,
		PCSGeometry:     args.pcsGeometry,
		LabelsDigest:    append([]byte(nil), args.labelsDigest...),
	}
	proof.syncPCSCompat()
	domainPoints := args.domainPoints
	if o.DomainMode != DomainModeExplicit {
		return out, fmt.Errorf("unsupported domain mode %d (only explicit mode is supported)", o.DomainMode)
	}
	if len(domainPoints) == 0 {
		return out, fmt.Errorf("explicit-domain mode requires non-empty domain points")
	}
	proof.DomainMode = DomainModeExplicit
	proof.NLeavesUsed = len(domainPoints)
	if o.Theta > 1 {
		proof.Chi = append([]uint64(nil), args.smallFieldChi...)
		proof.Zeta = append([]uint64(nil), args.smallFieldOmegaS1.Limb...)
	}
	// Verifier init
	vrf := lvcs.NewVerifierWithParamsAndPoints(ringQ, len(args.rowInputs), args.decsParams, args.ncols, domainPoints)
	vrf.Root = args.root
	var (
		Gamma       [][]uint64
		gammaBytes  []byte
		rTranscript []byte
	)
	// Round 1: Gamma
	if err := stage("RunMaskFS.Round1Gamma", func() error {
		material0 := [][]byte{args.root[:]}
		if len(args.labelsDigest) > 0 {
			material0 = append(material0, args.labelsDigest)
		}
		round1 := fsRound(fs, proof, 0, "Gamma", material0...)
		gammaRNG := round1.RNG
		Gamma = sampleFSMatrix(o.Eta, len(args.rowInputs), q, gammaRNG)
		gammaBytes = bytesFromUint64Matrix(Gamma)
		vrf.AcceptGamma(Gamma)
		rFormal := args.PK.DecsProver.CommitStep2Formal(Gamma)
		proof.R = copyMatrix(rFormal)
		rTranscript = bytesFromUint64Matrix(proof.R)
		if !vrf.CommitStep2Formal(rFormal) {
			return fmt.Errorf("deg-check R failed")
		}
		return nil
	}); err != nil {
		return out, err
	}
	// Round 2: GammaPrime/GammaAgg
	var GammaPrime [][][]uint64
	var GammaAgg [][]uint64
	var GammaPrimeK [][][]KScalar
	var GammaAggK [][]KScalar
	if err := stage("RunMaskFS.Round2GammaPrime", func() error {
		totalParallel := len(args.FparAll)
		totalAgg := len(args.FaggAll)
		transcript2 := [][]byte{args.root[:], gammaBytes, rTranscript}
		if len(args.labelsDigest) > 0 {
			transcript2 = append(transcript2, args.labelsDigest)
		}
		if proof.Theta > 1 {
			transcript2 = append(transcript2, encodeUint64Slice(proof.Chi), encodeUint64Slice(proof.Zeta))
		}
		round2 := fsRound(fs, proof, 1, "GammaPrime", transcript2...)
		seed2 := round2.Seed
		gammaPrimeRNG := round2.RNG
		gammaAggRNG := newFSRNG("GammaPrimeAgg", seed2, []byte{1})
		if proof.Theta > 1 {
			GammaPrimeK = sampleFSPolyTensorK(args.rho, totalParallel, args.witnessNCols, proof.Theta, q, gammaPrimeRNG)
			GammaAggK = sampleFSVectorK(args.rho, totalAgg, proof.Theta, q, gammaAggRNG)
			GammaPrime = kPolyTensorFirstLimb(GammaPrimeK)
			GammaAgg = kMatrixFirstLimb(GammaAggK)
			proof.GammaPrimeK = copyKTensor3(GammaPrimeK)
			proof.GammaAggK = copyKMatrix(GammaAggK)
		} else {
			GammaPrime = sampleFSPolyTensor(args.rho, totalParallel, args.witnessNCols, q, gammaPrimeRNG)
			GammaAgg = sampleFSMatrix(args.rho, totalAgg, q, gammaAggRNG)
		}
		proof.GammaPrime = copyTensor3(GammaPrime)
		proof.GammaAgg = copyMatrix(GammaAgg)
		return nil
	}); err != nil {
		return out, err
	}

	out.proof = proof
	out.Gamma = Gamma
	out.GammaPrime = GammaPrime
	out.GammaAgg = GammaAgg
	out.GammaPrimeK = GammaPrimeK
	out.GammaAggK = GammaAggK
	out.Rpolys = nil
	out.maskRowOffset = args.maskRowOffset
	out.maskRowCount = args.maskRowCount
	out.maskDegreeBound = args.maskDegreeBound
	out.rowLayout = args.rowLayout

	var qProver *decs.Prover
	var qDomainPoints []uint64
	qDecsParams := decs.Params{
		Degree:     args.maskDegreeBound,
		Eta:        args.decsParams.Eta,
		NonceBytes: args.decsParams.NonceBytes,
	}

	// Masks and Q/QK generation.
	if err := stage("RunMaskFS.BuildQAndMasks", func() error {
		if proof.Theta > 1 {
			// Base-field masks (used by Q and the ΣΩ check) must be committed inside the main
			// oracle so the verifier can read them from RowOpening at tail indices.
			if len(args.independentMasks) != args.rho {
				return fmt.Errorf("expected %d committed base-field masks, got %d", args.rho, len(args.independentMasks))
			}
			out.M = clonePolys(args.independentMasks)
			if len(args.independentMaskCoeffs) > 0 {
				out.MCoeffs = copyMatrix(args.independentMaskCoeffs)
			} else {
				out.MCoeffs = make([][]uint64, len(out.M))
				for i := range out.M {
					coeff := ringQ.NewPoly()
					if out.M[i] != nil {
						ringQ.InvNTT(out.M[i], coeff)
						out.MCoeffs[i] = trimCoeffsCopy(coeff.Coeffs[0], q)
					}
				}
			}

			// Small-field branch: use K-masks for QK (paper §4.2 / §6.2).
			MK := args.independentMasksK
			if len(MK) == 0 {
				maskOmega := args.omegaWitness
				if len(maskOmega) == 0 {
					maskOmega = args.omega
				}
				MK = SampleIndependentMaskPolynomialsK(ringQ, args.smallFieldK, args.rho, args.maskDegreeTarget, maskOmega)
			}
			if len(MK) != args.rho {
				return fmt.Errorf("expected %d K masks, got %d", args.rho, len(MK))
			}
			out.MK = MK
			proof.MKData = snapshotKPolys(MK)
			// Q and QK
			qLayout := BuildQLayout{
				WitnessPolys: args.w1[:args.origW1Len],
				MaskPolys:    out.M,
			}
			maskCoeffs := make([][]uint64, len(out.M))
			for i := range out.M {
				switch {
				case i < len(out.MCoeffs) && len(out.MCoeffs[i]) > 0:
					maskCoeffs[i] = append([]uint64(nil), out.MCoeffs[i]...)
				case out.M[i] != nil:
					coeff := ringQ.NewPoly()
					ringQ.InvNTT(out.M[i], coeff)
					maskCoeffs[i] = trimCoeffsCopy(coeff.Coeffs[0], q)
				default:
					return fmt.Errorf("missing mask coefficients for row %d", i)
				}
			}
			qLayout.MaskCoeffs = maskCoeffs
			qCoeffs, qErr := BuildQCoeffsChecked(
				ringQ,
				qLayout,
				args.FparInt,
				args.FparNorm,
				args.FaggInt,
				args.FaggNorm,
				args.FparIntCoeffs,
				args.FparNormCoeffs,
				args.FaggIntCoeffs,
				args.FaggNormCoeffs,
				GammaPrime,
				GammaAgg,
			)
			if qErr != nil {
				return qErr
			}
			out.QCoeffs = qCoeffs
			if deg := maxDegreeFromCoeffRows(qCoeffs); deg > qDecsParams.Degree {
				qDecsParams.Degree = deg
			}
			proof.QDegreeBound = qDecsParams.Degree
			qDomainPoints = domainPoints
			if len(qDomainPoints) == 0 {
				return fmt.Errorf("explicit-domain mode requires non-empty Q domain points")
			}
			qProver, qErr = decs.NewProverWithParamsAndPointsFormalChecked(ringQ, qCoeffs, qDecsParams, qDomainPoints)
			if qErr != nil {
				return fmt.Errorf("build q prover: %w", qErr)
			}
			qRoot, qErr := qProver.CommitInit()
			if qErr != nil {
				return fmt.Errorf("commit Q: %w", qErr)
			}
			proof.QRoot = qRoot
			out.QK = BuildQK(
				ringQ,
				args.opts.DomainMode,
				args.smallFieldK,
				MK,
				args.FparAll,
				args.FaggAll,
				args.FparAllCoeffs,
				args.FaggAllCoeffs,
				GammaPrimeK,
				GammaAggK,
			)
			proof.QKData = snapshotKPolys(out.QK)
			// Mask degree check
			maskDegreeMax := -1
			for _, kp := range MK {
				if kp != nil && kp.Degree > maskDegreeMax {
					maskDegreeMax = kp.Degree
				}
			}
			if maskDegreeMax > args.maskDegreeBound {
				return fmt.Errorf("mask degree %d exceeds bound %d", maskDegreeMax, args.maskDegreeBound)
			}
		}
		return nil
	}); err != nil {
		return out, err
	}

	var coeffMatrix [][]uint64
	var kPointLimbs [][]uint64
	var barSets [][]uint64
	var vTargets [][]uint64
	var gammaQ [][]uint64
	// Round 3 eval points (no proof population; outputs for caller)
	if err := stage("RunMaskFS.Round3Eval", func() error {
		ellPrime := args.ellPrime
		if ellPrime <= 0 {
			ellPrime = 1
		}
		// If caller provided an override for ncols (head length), enforce it for omega/rows/degree expectations.
		if args.ncolsOverride > 0 && args.ncolsOverride < len(args.omega) {
			args.omega = append([]uint64(nil), args.omega[:args.ncolsOverride]...)
		}
		gammaBytes = bytesFromUint64Matrix(Gamma)
		gammaPrimeBytes := bytesFromUint64Tensor3(GammaPrime)
		gammaAggBytes := bytesFromUint64Matrix(GammaAgg)
		if proof.Theta > 1 {
			gammaPrimeBytes = bytesFromKScalarTensor3(GammaPrimeK)
			gammaAggBytes = bytesFromKScalarMat(GammaAggK)
		}
		round3Material := [][]byte{args.root[:], gammaBytes, gammaPrimeBytes, gammaAggBytes, proof.QRoot[:]}
		if len(args.labelsDigest) > 0 {
			round3Material = append(round3Material, args.labelsDigest)
		}
		round3 := fsRound(fs, proof, 2, func() string {
			if proof.Theta > 1 {
				return "EvalKPoint"
			}
			return "EvalPoints"
		}(), round3Material...)
		seed3 := round3.Seed

		// CommitStep2 for Q: derive Γ_Q after QRoot is bound in FS round 2.
		if qProver == nil {
			return fmt.Errorf("missing Q prover")
		}
		gammaQRNG := newFSRNG("GammaQ", seed3)
		gammaQ = sampleFSMatrix(args.decsParams.Eta, args.rho, q, gammaQRNG)
		out.gammaQ = copyMatrix(gammaQ)
		proof.setQR(qProver.CommitStep2Formal(gammaQ))

		if proof.Theta > 1 {
			kPointRNG := round3.RNG
			coeffMatrix = make([][]uint64, 0, ellPrime*proof.Theta)
			kPointLimbs = make([][]uint64, 0, ellPrime)
			barSets = [][]uint64{}
			evalReqs := make([]lvcs.EvalRequest, 0, ellPrime*proof.Theta)
			smallFieldEvals := make([]kf.Elem, 0, ellPrime)
			for len(smallFieldEvals) < ellPrime {
				limbs := make([]uint64, proof.Theta)
				for i := 0; i < proof.Theta; i++ {
					limbs[i] = kPointRNG.nextU64() % q
				}
				zeroTail := true
				for i := 1; i < len(limbs); i++ {
					if limbs[i]%q != 0 {
						zeroTail = false
						break
					}
				}
				candidate := args.smallFieldK.Phi(limbs)
				conflict := false
				omegaWitness := args.omegaWitness
				if len(omegaWitness) == 0 {
					omegaWitness = args.omega
				}
				for _, w := range omegaWitness {
					if elemEqual(args.smallFieldK, candidate, args.smallFieldK.EmbedF(w%q)) {
						conflict = true
						break
					}
				}
				if !conflict {
					for _, prev := range smallFieldEvals {
						if elemEqual(args.smallFieldK, candidate, prev) {
							conflict = true
							break
						}
					}
				}
				if zeroTail || conflict {
					continue
				}
				coeffBlock := buildKPointCoeffMatrix(ringQ, args.smallFieldK, omegaWitness, args.rows, candidate, args.smallFieldOmegaS1, args.smallFieldMuInv, args.maskRowOffset, args.maskRowCount)
				coeffMatrix = append(coeffMatrix, coeffBlock...)
				for i := range coeffBlock {
					rowCopy := append([]uint64(nil), coeffBlock[i]...)
					evalReqs = append(evalReqs, lvcs.EvalRequest{
						Coeffs: rowCopy,
						KPoint: append([]uint64(nil), candidate.Limb...),
					})
				}
				smallFieldEvals = append(smallFieldEvals, candidate)
				kPointLimbs = append(kPointLimbs, append([]uint64(nil), candidate.Limb...))
			}
			if len(evalReqs) > 0 {
				bs, evalErr := lvcs.EvalInitManyChecked(ringQ, args.PK, evalReqs)
				if evalErr != nil {
					return fmt.Errorf("EvalInitMany: %w", evalErr)
				}
				barSets = bs
			}
			vTargets := computeVTargets(q, args.rows, coeffMatrix)
			proof.setBarSets(barSets)
			proof.setVTargets(vTargets)
			proof.CoeffMatrix = copyMatrix(coeffMatrix)
			proof.KPoint = copyMatrix(kPointLimbs)
			out.barSets = barSets
			out.coeffMatrix = coeffMatrix
			out.kPoint = kPointLimbs
			out.smallFieldEvals = smallFieldEvals
			out.vTargets = vTargets
			out.vTargetsPacked = append([]byte(nil), proof.VTargetsBits...)
			out.barSetsRows = proof.BarSetsRows
			out.barSetsCols = proof.BarSetsCols
			out.barSetsBitWidth = proof.BarSetsBitWidth
			out.evalReqs = evalReqs
		} else {
			evalPointBytes := sampleEvalPoints(ringQ, ellPrime, args.omega, seed3)
			out.evalPoints = decodeUint64Slice(evalPointBytes)
		}
		return nil
	}); err != nil {
		return out, err
	}

	// Round 4: tail sampling and openings (use same FS state) – only for θ>1
	if err := stage("RunMaskFS.Round4TailOpen", func() error {
		if proof.Theta <= 1 {
			return fmt.Errorf("runMaskFS currently supports theta>1 only")
		}
		tailStart := args.ncols + args.ell
		tailDomainSize := int(ringQ.N)
		if domainPoints != nil {
			tailDomainSize = len(domainPoints)
		}
		tailLen := tailDomainSize - tailStart
		if tailLen < args.ell {
			return fmt.Errorf("insufficient tail: tailLen=%d ell=%d", tailLen, args.ell)
		}
		transcript4 := [][]byte{
			args.root[:],
			gammaBytes,
			bytesFromKScalarTensor3(GammaPrimeK),
			bytesFromKScalarMat(GammaAggK),
			proof.QRoot[:],
			proof.QRBytes(),
			bytesFromUint64Matrix(kPointLimbs),
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
		proof.TailTranscript = flattenBytes(transcript4)
		round4 := fsRound(fs, proof, 3, "TailPoints", transcript4...)
		tailRNG := round4.RNG
		E := sampleDistinctIndices(tailStart, tailLen, args.ell, tailRNG)
		proof.Tail = append([]int(nil), E...)

		maskIdx := make([]int, args.ell)
		for i := 0; i < args.ell; i++ {
			maskIdx[i] = args.ncols + i
		}
		openMask := lvcs.EvalFinish(args.PK, maskIdx)
		openTail := lvcs.EvalFinish(args.PK, E)
		combinedOpen := combineOpenings(openMask.DECSOpen, openTail.DECSOpen)
		proof.PCSOpening = cloneDECSOpening(combinedOpen)
		proof.PCSOpening.R = len(args.rowInputs)
		proof.PCSOpening.Eta = args.decsParams.Eta
		maybeCompressRowOpeningPvals(proof.PCSOpening, coeffMatrix, args.q)
		decs.PackOpening(proof.PCSOpening)
		proof.RowOpening = proof.PCSOpening

		// Open Q on Ω, Ω′, and the sampled tail indices so the verifier can
		// (1) run the DECS degree check for Q and (2) compute ΣΩ for Eq.(7).
		qPrefix := args.witnessNCols + args.ell
		qIdx := make([]int, 0, qPrefix+args.ell)
		for i := 0; i < qPrefix; i++ {
			qIdx = append(qIdx, i)
		}
		qIdx = append(qIdx, E...)
		qOpen := qProver.EvalOpen(qIdx)
		out.qOpeningRaw = cloneDECSOpening(qOpen)
		proof.QOpening = cloneDECSOpening(qOpen)
		maybeCompressQOpening(proof.QOpening, gammaQ, q, true)
		decs.PackOpening(proof.QOpening)

		out.openMask = openMask
		out.openTail = openTail
		out.combinedOpen = combinedOpen
		out.tailIndices = append([]int(nil), E...)
		return nil
	}); err != nil {
		return out, err
	}
	out.maskDegreeBound = args.maskDegreeBound
	out.maskRowOffset = args.maskRowOffset
	out.maskRowCount = args.maskRowCount
	out.maskPolyCount = len(out.M)

	return out, nil
}
