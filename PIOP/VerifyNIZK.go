package PIOP

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// VerifyNIZK requires verifier-side constraint replay.
func VerifyNIZK(proof *Proof) (okLin, okEq4, okSum bool, err error) {
	return false, false, false, errors.New("VerifyNIZK: constraint replay required; use VerifyNIZKWithReplay")
}

// VerifyNIZKWithReplay replays the verifier transcript and constraint checks.
func VerifyNIZKWithReplay(proof *Proof, replay *ConstraintReplay) (okLin, okEq4, okSum bool, err error) {
	return verifyNIZK(proof, replay)
}

func verifyNIZK(proof *Proof, replay *ConstraintReplay) (okLin, okEq4, okSum bool, err error) {
	if proof == nil {
		return false, false, false, errors.New("VerifyNIZK: nil proof")
	}
	defer func() {
		if proof != nil {
			decs.PackOpening(resolveProofPCSOpening(proof))
			decs.PackOpening(proof.QOpening)
		}
	}()
	proof.syncPCSCompat()
	vTargets := proof.VTargetsMatrix()
	if len(vTargets) == 0 || len(vTargets[0]) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing VTargets")
	}
	barSets := proof.BarSetsMatrix()
	if len(barSets) == 0 || len(barSets[0]) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing BarSets")
	}
	if resolveProofPCSOpening(proof) == nil {
		return false, false, false, errors.New("VerifyNIZK: missing PCS opening")
	}
	if len(proof.Digests[0]) == 0 || len(proof.Digests[1]) == 0 || len(proof.Digests[3]) == 0 {
		return false, false, false, errors.New("VerifyNIZK: incomplete transcript digests")
	}

	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: load parameters: %w", err)
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: ring.NewRing: %w", err)
	}
	q := ringQ.Modulus[0]
	ncols := len(vTargets[0])
	if proof.LVCSNColsUsed > 0 {
		ncols = proof.LVCSNColsUsed
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = ncols
	}
	pcsNCols := ncols
	if proof.PCSNColsUsed > 0 {
		pcsNCols = proof.PCSNColsUsed
	}
	if pcsNCols < witnessNCols {
		return false, false, false, fmt.Errorf("VerifyNIZK: invalid pcs_ncols (pcs=%d < witness=%d)", pcsNCols, witnessNCols)
	}
	ell := len(proof.Tail)
	if proof.DomainMode != DomainModeExplicit {
		return false, false, false, fmt.Errorf("VerifyNIZK: unsupported domain mode %d (only explicit mode is supported)", proof.DomainMode)
	}

	nLeaves := proof.NLeavesUsed
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	if pcsNCols+ell > int(ringQ.N) {
		return false, false, false, fmt.Errorf("VerifyNIZK: explicit domain requires pcs_ncols+ell <= ring dimension (pcs_ncols=%d, ell=%d, ringN=%d)", pcsNCols, ell, ringQ.N)
	}
	omega, domainPoints, derr := deriveExplicitDomainForRelation(q, nLeaves, witnessNCols, pcsNCols, ell, proof.HashRelation)
	if derr != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: explicit domain: %w", derr)
	}
	if err := checkOmega(omega, q); err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: invalid Ω: %w", err)
	}
	pcsOpening := resolveProofPCSOpening(proof)
	rRows := pcsOpening.R
	eta := pcsOpening.Eta
	unpackUint64Matrix(proof.PvalsEvalBits, proof.PvalsEvalRows, proof.PvalsEvalCols)
	unpackUint64Matrix(proof.MvalsEvalBits, proof.MvalsEvalRows, proof.MvalsEvalCols)

	// ----------------------------------------------------------------- FS round 0
	lambda := proof.Lambda
	if lambda <= 0 {
		lambda = 256
	}
	fs := NewFS(NewShake256XOF(fsDigestBytes), proof.Salt, FSParams{Lambda: lambda, Kappa: proof.Kappa})
	rootBytes := append([]byte(nil), proof.Root[:]...)
	material0 := [][]byte{rootBytes}
	if len(proof.LabelsDigest) > 0 {
		material0 = append(material0, proof.LabelsDigest)
	}
	if digest, derr := buildSigShortnessBindingDigest(proof.SigShortness, proof.RowLayout, sigShortnessV5WitnessNColsFromProof(proof)); derr != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: sig shortness binding digest: %w", derr)
	} else if len(digest) > 0 {
		material0 = append(material0, digest)
	}
	h1, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 0: %w", err)
	}
	seed1 := h1
	gammaRNG := newFSRNG("Gamma", seed1)
	Gamma := sampleFSMatrix(eta, rRows, q, gammaRNG)

	// LVCS degree check binds Γ to Root.
	if len(proof.R) != eta {
		return false, false, false, fmt.Errorf("VerifyNIZK: expected %d R-polynomials, got %d", eta, len(proof.R))
	}

	rowDegBound := proof.RowDegreeBound
	if rowDegBound <= 0 {
		rowDegBound = proof.MaskDegreeBound
	}
	if rowDegBound <= 0 {
		return false, false, false, errors.New("VerifyNIZK: missing row degree bound")
	}
	if rowDegBound < 0 {
		return false, false, false, fmt.Errorf("VerifyNIZK: invalid row degree bound %d (ringN=%d)", rowDegBound, ringQ.N)
	}
	nonceBytes := 16
	if pcsOpening.NonceBytes > 0 {
		nonceBytes = pcsOpening.NonceBytes
	} else if len(pcsOpening.Nonces) > 0 && len(pcsOpening.Nonces[0]) > 0 {
		nonceBytes = len(pcsOpening.Nonces[0])
	}
	lvcsParams := decs.Params{Degree: rowDegBound, Eta: eta, NonceBytes: nonceBytes}
	vrf := lvcs.NewVerifierWithParamsAndPoints(ringQ, rRows, lvcsParams, ncols, domainPoints)
	vrf.Root = proof.Root
	vrf.AcceptGamma(Gamma)
	if !vrf.CommitStep2Formal(proof.R) {
		return false, false, false, errors.New("VerifyNIZK: LVCS CommitStep2 rejected R polynomials")
	}

	// ----------------------------------------------------------------- FS round 1
	gammaBytes := bytesFromUint64Matrix(Gamma)
	rBytes := bytesFromUint64Matrix(proof.R)
	transcript2 := [][]byte{rootBytes, gammaBytes, rBytes}
	if len(proof.LabelsDigest) > 0 {
		transcript2 = append(transcript2, proof.LabelsDigest)
	}
	if proof.Theta > 1 {
		if len(proof.Chi) == 0 || len(proof.Zeta) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing Chi/Zeta for θ>1")
		}
		transcript2 = append(transcript2, encodeUint64Slice(proof.Chi), encodeUint64Slice(proof.Zeta))
	}
	h2, err := verifyRoundDigest(fs, 1, proof.Ctr[1], transcript2, proof.Digests[1], proof.Kappa[1])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 1: %w", err)
	}
	seed2 := h2
	if proof.PRFCompanion != nil {
		if proof.PRFCompanion.Layout == nil {
			return false, false, false, errors.New("VerifyNIZK: missing prf companion layout")
		}
		companionWitnessRows := proof.RowLayout.SigCount
		if companionWitnessRows <= 0 {
			companionWitnessRows = proof.MaskRowOffset
		}
		if err := ValidatePRFCompanionLayout(proof.PRFCompanion.Layout, companionWitnessRows); err != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: invalid prf companion layout: %w", err)
		}
		bridgeLayout, derr := prfCompanionBridgeLayout(proof.PRFCompanion)
		if derr != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: resolve prf companion bridge layout: %w", derr)
		}
		expectedCoordDigest := buildPRFCompanionCoordDigest(
			bridgeLayout,
			seed2,
			proof.PRFCompanion.BridgeChecks,
			len(proof.PRFCompanion.BridgeChecks),
			proof.PRFCompanion.Mode,
			proof.PRFCompanion.CheckpointSamples,
		)
		if !bytes.Equal(expectedCoordDigest, proof.PRFCompanion.CoordDigest) {
			return false, false, false, errors.New("VerifyNIZK: prf companion digest mismatch")
		}
	}

	if proof.QRoot == ([16]byte{}) {
		return false, false, false, errors.New("VerifyNIZK: missing QRoot commitment")
	}

	var (
		gammaPrimeBytes []byte
		gammaAggBytes   []byte
	)

	if proof.Theta > 1 {
		if len(proof.GammaPrimeK) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing GammaPrimeK for θ>1")
		}
		rows := len(proof.GammaPrimeK)
		cols := len(proof.GammaPrimeK[0])
		s := witnessNCols
		if s == 0 {
			return false, false, false, errors.New("VerifyNIZK: empty witness omega")
		}
		fsGammaPrime := sampleFSPolyTensorK(rows, cols, s, proof.Theta, q, newFSRNG("GammaPrime", seed2))
		if !kTensor3Equal(fsGammaPrime, proof.GammaPrimeK) {
			return false, false, false, errors.New("VerifyNIZK: GammaPrimeK mismatch")
		}
		gammaPrimeBytes = bytesFromKScalarTensor3(fsGammaPrime)
		aggRows := len(proof.GammaAggK)
		aggCols := 0
		if aggRows > 0 {
			aggCols = len(proof.GammaAggK[0])
		}
		fsGammaAgg := sampleFSVectorK(aggRows, aggCols, proof.Theta, q, newFSRNG("GammaPrimeAgg", seed2, []byte{1}))
		if !kMatrixEqual(fsGammaAgg, proof.GammaAggK) {
			return false, false, false, errors.New("VerifyNIZK: GammaAggK mismatch")
		}
		gammaAggBytes = bytesFromKScalarMat(fsGammaAgg)
	} else {
		if len(proof.GammaPrime) == 0 || len(proof.GammaPrime[0]) == 0 || len(proof.GammaPrime[0][0]) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing GammaPrime")
		}
		rows := len(proof.GammaPrime)
		cols := len(proof.GammaPrime[0])
		s := witnessNCols
		if s == 0 {
			return false, false, false, errors.New("VerifyNIZK: empty witness omega")
		}
		fsGammaPrime := sampleFSPolyTensor(rows, cols, s, q, newFSRNG("GammaPrime", seed2))
		if !tensor3Equal(fsGammaPrime, proof.GammaPrime) {
			return false, false, false, errors.New("VerifyNIZK: GammaPrime mismatch")
		}
		gammaPrimeBytes = bytesFromUint64Tensor3(fsGammaPrime)
		rowsAgg := len(proof.GammaAgg)
		colsAgg := 0
		if rowsAgg > 0 {
			colsAgg = len(proof.GammaAgg[0])
		}
		fsGammaAgg := sampleFSMatrix(rowsAgg, colsAgg, q, newFSRNG("GammaPrimeAgg", seed2, []byte{1}))
		if !matrixEqual(fsGammaAgg, proof.GammaAgg) {
			return false, false, false, errors.New("VerifyNIZK: GammaAgg mismatch")
		}
		gammaAggBytes = bytesFromUint64Matrix(fsGammaAgg)
	}

	var (
		coeffMatrix [][]uint64
		transcript4 [][]byte
	)

	transcript3 := [][]byte{
		rootBytes,
		gammaBytes,
		gammaPrimeBytes,
		gammaAggBytes,
		proof.QRoot[:],
	}
	if proof.PRFCompanion != nil && len(proof.PRFCompanion.CoordDigest) > 0 {
		transcript3 = append(transcript3, proof.PRFCompanion.CoordDigest)
	}
	if len(proof.LabelsDigest) > 0 {
		transcript3 = append(transcript3, proof.LabelsDigest)
	}
	h3, err := verifyRoundDigest(fs, 2, proof.Ctr[2], transcript3, proof.Digests[2], proof.Kappa[2])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 2: %w", err)
	}
	seed3 := h3

	qr := proof.QRMatrix()
	if len(qr) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing QR (Q degree-check polynomials)")
	}
	qrBytes := proof.QRBytes()
	if len(qrBytes) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing packed QR payload")
	}

	if proof.Theta > 1 {
		if len(proof.CoeffMatrix) == 0 || len(proof.KPoint) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing coefficient matrix or K points for θ>1")
		}
		coeffMatrix = copyMatrix(proof.CoeffMatrix)
		transcript4 = [][]byte{
			rootBytes,
			gammaBytes,
			bytesFromKScalarTensor3(proof.GammaPrimeK),
			bytesFromKScalarMat(proof.GammaAggK),
			proof.QRoot[:],
			qrBytes,
			bytesFromUint64Matrix(proof.KPoint),
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
	} else {
		ellPrime := len(barSets)
		if ellPrime == 0 {
			return false, false, false, errors.New("VerifyNIZK: empty bar sets")
		}
		points := sampleDistinctFieldElemsAvoid(ellPrime, q, newFSRNG("EvalPoints", seed3), omega)
		coeffMatrix = make([][]uint64, ellPrime)
		coeffRNG := newFSRNG("EvalCoeffs", seed3, []byte{1})
		maskStart := proof.MaskRowOffset
		maskEnd := proof.MaskRowOffset + proof.MaskRowCount
		if maskStart < 0 || maskEnd < maskStart || maskEnd > rRows {
			return false, false, false, fmt.Errorf("VerifyNIZK: invalid mask layout offset=%d count=%d rows=%d", proof.MaskRowOffset, proof.MaskRowCount, rRows)
		}
		for i := 0; i < ellPrime; i++ {
			row := make([]uint64, rRows)
			for j := 0; j < rRows; j++ {
				if j >= maskStart && j < maskEnd {
					row[j] = 0
				} else {
					row[j] = coeffRNG.nextU64() % q
				}
			}
			coeffMatrix[i] = row
		}
		if len(proof.CoeffMatrix) > 0 && !matrixEqual(coeffMatrix, proof.CoeffMatrix) {
			return false, false, false, errors.New("VerifyNIZK: coefficient matrix mismatch")
		}
		transcript4 = [][]byte{
			rootBytes,
			gammaBytes,
			gammaPrimeBytes,
			proof.QRoot[:],
			qrBytes,
			encodeUint64Slice(points),
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
		if proof.PRFCompanion != nil && prfCompanionHasOpeningPayload(proof.PRFCompanion) {
			transcript4 = append(transcript4, prfCompanionOpeningPayloadBytes(proof.PRFCompanion))
		}
	}
	transcriptForRound3 := transcript4
	if len(proof.TailTranscript) > 0 {
		transcriptForRound3 = [][]byte{proof.TailTranscript}
	}
	_, err = verifyRoundDigest(fs, 3, proof.Ctr[3], transcriptForRound3, proof.Digests[3], proof.Kappa[3])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 3: %w", err)
	}
	tailStart := ncols + ell
	tailDomainSize := len(domainPoints)
	tailLen := tailDomainSize - tailStart
	if tailLen < ell {
		return false, false, false, errors.New("VerifyNIZK: insufficient tail region")
	}
	if err := validateDistinctIndicesInRange(proof.Tail, tailStart, tailStart+tailLen); err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: invalid tail indices: %w", err)
	}

	// ----------------------------------------------------------------- LVCS EvalStep2
	opening := expandPackedOpening(pcsOpening)
	if opening == nil {
		return false, false, false, errors.New("VerifyNIZK: invalid packed row opening")
	}
	expectedEvalEntries := len(proof.Tail) + ell
	if opening.EntryCount() != expectedEvalEntries {
		maskIdx := make([]int, ell)
		for i := 0; i < ell; i++ {
			maskIdx[i] = ncols + i
		}
		Qvals, qErr := interpolateReplayQRows(ringQ, vTargets, barSets, ncols)
		if qErr != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: replay Q rows for subset opening: %w", qErr)
		}
		rPolys := make([]*ring.Poly, len(proof.R))
		for i := range proof.R {
			rPolys[i] = coeffsToNTTIfFits(ringQ, proof.R[i])
			if rPolys[i] == nil {
				return false, false, false, fmt.Errorf("VerifyNIZK: R polynomial %d too large to materialize", i)
			}
		}
		preparedBase, prepErr := prepareRowOpeningForVerify(opening, Gamma, rPolys, coeffMatrix, Qvals, barSets, maskIdx, proof.Tail, ncols, domainPoints, ringQ)
		if prepErr != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: prepare subset row opening: %w", prepErr)
		}
		subsetIdx := append(append([]int(nil), maskIdx...), proof.Tail...)
		opening, err = buildSubsetOpening(preparedBase, subsetIdx, preparedBase.R, preparedBase.Eta)
		if err != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: subset row opening: %w", err)
		}
	}
	okLin = vrf.EvalStep2(barSets, proof.Tail, opening, coeffMatrix, vTargets)
	if !okLin {
		return false, false, false, errors.New("VerifyNIZK: LVCS EvalStep2 rejected")
	}

	// ----------------------------------------------------------------- Q commitment + ΣΩ check (Eq.7)
	if proof.QOpening == nil {
		return okLin, false, false, errors.New("VerifyNIZK: missing Q opening")
	}
	// Recompute Γ_Q from the FS round-2 digest and verify the DECS opening against QRoot.
	rhoQ := 0
	// In θ>1 paper mode, mask-row layout and repetition count ρ are decoupled:
	// ρ is carried by Γ′ dimensions, while mask rows encode A_{n+1}.
	if proof.Theta > 1 && len(proof.GammaPrimeK) > 0 {
		rhoQ = len(proof.GammaPrimeK)
	} else if len(proof.GammaPrime) > 0 {
		rhoQ = len(proof.GammaPrime)
	}
	if rhoQ <= 0 && proof.QOpening != nil {
		rhoQ = proof.QOpening.R
	}
	if rhoQ <= 0 {
		return okLin, false, false, errors.New("VerifyNIZK: invalid rho for Q commitment")
	}
	if proof.QOpening.R != rhoQ {
		return okLin, false, false, fmt.Errorf("VerifyNIZK: Q opening row count R=%d want %d", proof.QOpening.R, rhoQ)
	}
	if len(qr) != eta {
		return okLin, false, false, fmt.Errorf("VerifyNIZK: QR count mismatch: got %d want %d", len(qr), eta)
	}
	gammaQRNG := newFSRNG("GammaQ", seed3)
	GammaQ := sampleFSMatrix(eta, rhoQ, q, gammaQRNG)
	qNonceBytes := 16
	if proof.QOpening.NonceBytes > 0 {
		qNonceBytes = proof.QOpening.NonceBytes
	} else if len(proof.QOpening.Nonces) > 0 && len(proof.QOpening.Nonces[0]) > 0 {
		qNonceBytes = len(proof.QOpening.Nonces[0])
	}
	qDegBound := proof.QDegreeBound
	if qDegBound <= 0 {
		qDegBound = proof.MaskDegreeBound
	}
	if qDegBound <= 0 {
		qDegBound = rowDegBound
	}
	qParams := decs.Params{Degree: qDegBound, Eta: eta, NonceBytes: qNonceBytes}
	qVrf, err := decs.NewVerifierWithParamsAndPointsChecked(ringQ, rhoQ, qParams, domainPoints)
	if err != nil {
		return okLin, false, false, fmt.Errorf("VerifyNIZK: invalid Q verifier params: %w", err)
	}
	for i := range qr {
		row := qr[i]
		for d := qDegBound + 1; d < len(row); d++ {
			if row[d]%q != 0 {
				return okLin, false, false, fmt.Errorf("VerifyNIZK: QR[%d] exceeds degree bound %d", i, qDegBound)
			}
		}
	}
	qPrefix := witnessNCols + ell
	qIdx := make([]int, 0, qPrefix+ell)
	for i := 0; i < qPrefix; i++ {
		qIdx = append(qIdx, i)
	}
	qIdx = append(qIdx, proof.Tail...)
	qOpeningPrepared, qPrepErr := prepareQOpeningForVerify(expandPackedOpening(proof.QOpening), GammaQ, qr, domainPoints, q)
	if qPrepErr != nil {
		return okLin, false, false, fmt.Errorf("VerifyNIZK: prepare Q opening: %w", qPrepErr)
	}
	if !qVrf.VerifyEvalAtFormal(proof.QRoot, GammaQ, qr, qOpeningPrepared, qIdx) {
		return okLin, false, false, errors.New("VerifyNIZK: Q DECS opening rejected")
	}
	okSum, badRow, badSum := verifySumOnQOpening(qOpeningPrepared, rhoQ, witnessNCols, q)
	if !okSum {
		if badRow >= 0 && badRow < len(proof.QCoeffDebug) {
			dbgSum := uint64(0)
			for i := 0; i < witnessNCols && i < len(domainPoints); i++ {
				dbgSum = lvcs.MulAddMod64(dbgSum, 1, EvalPoly(proof.QCoeffDebug[badRow], domainPoints[i]%q, q)%q, q)
			}
			faggBad := make([]string, 0, 4)
			fparBad := make([]string, 0, 4)
			describeFagg := func(idx int) string {
				layout := proof.RowLayout
				if rowLayoutHasCoeffNativeSig(layout) && rowLayoutCoeffNativeUsesTransformBridge(layout) {
					replayBlocks := rowLayoutReplayBlockCount(layout)
					span := replayBlocks * witnessNCols
					x0Len := rowLayoutX0Len(layout)
					if span > 0 {
						switch {
						case idx < span:
							return fmt.Sprintf("mSigma[b=%d,j=%d]", idx/witnessNCols, idx%witnessNCols)
						case idx < 2*span:
							idx -= span
							return fmt.Sprintf("r1[b=%d,j=%d]", idx/witnessNCols, idx%witnessNCols)
						case idx < (2+x0Len)*span:
							idx -= 2 * span
							comp := idx / span
							off := idx % span
							return fmt.Sprintf("r0[%d][b=%d,j=%d]", comp, off/witnessNCols, off%witnessNCols)
						}
					}
				}
				return "other"
			}
			for i := 0; i < len(proof.FaggCoeffDebug) && len(faggBad) < 4; i++ {
				sum := uint64(0)
				for j := 0; j < witnessNCols && j < len(domainPoints); j++ {
					sum = lvcs.MulAddMod64(sum, 1, EvalPoly(proof.FaggCoeffDebug[i], domainPoints[j]%q, q)%q, q)
				}
				if sum%q != 0 {
					faggBad = append(faggBad, fmt.Sprintf("%d:%s:%d", i, describeFagg(i), sum%q))
				}
			}
			for i := 0; i < len(proof.FparCoeffDebug) && len(fparBad) < 4; i++ {
				sum := uint64(0)
				for j := 0; j < witnessNCols && j < len(domainPoints); j++ {
					sum = lvcs.MulAddMod64(sum, 1, EvalPoly(proof.FparCoeffDebug[i], domainPoints[j]%q, q)%q, q)
				}
				if sum%q != 0 {
					fparBad = append(fparBad, fmt.Sprintf("%d:%d", i, sum%q))
				}
			}
			return okLin, false, false, fmt.Errorf("VerifyNIZK: ΣΩ failed (row=%d sum=%d qcoeff_sum=%d deg=%d bad_fpar=%v bad_fagg=%v)", badRow, badSum, dbgSum, len(proof.QCoeffDebug[badRow])-1, fparBad, faggBad)
		}
		return okLin, false, false, fmt.Errorf("VerifyNIZK: ΣΩ failed (row=%d sum=%d)", badRow, badSum)
	}

	var smallFieldK *kf.Field
	var QK []*KPoly
	var MK []*KPoly
	if proof.Theta > 1 {
		if len(proof.Chi) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing Chi for θ>1")
		}
		field, fieldErr := kf.New(q, proof.Theta, proof.Chi)
		if fieldErr != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: kfield.New: %w", fieldErr)
		}
		smallFieldK = field
		if len(proof.QKData) == 0 || len(proof.MKData) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing QK/MK data for θ>1")
		}
		QK = restoreKPolys(proof.QKData)
		MK = restoreKPolys(proof.MKData)
	}
	if replay != nil && replay.Eval != nil {
		// Ensure the FS-sampled Γ′/γ′ tensor dimensions match the constraint evaluator,
		// so no constraints can be silently dropped during replay.
		if len(proof.Tail) == 0 {
			return okLin, false, false, errors.New("VerifyNIZK: missing tail indices for replay")
		}
		probeRowCount := replay.RowCount
		if probeRowCount <= 0 {
			probeRowCount = proof.RowLayout.SigCount
		}
		if probeRowCount <= 0 {
			probeRowCount = opening.R
		}
		if probeRowCount <= 0 {
			return okLin, false, false, errors.New("VerifyNIZK: invalid rowCount for replay")
		}
		posByIdxRow := make(map[int]int, opening.EntryCount())
		for pos := 0; pos < opening.EntryCount(); pos++ {
			posByIdxRow[opening.IndexAt(pos)] = pos
		}
		firstIdx := proof.Tail[0]
		posRow, hasRow := posByIdxRow[firstIdx]
		if !hasRow {
			return okLin, false, false, fmt.Errorf("VerifyNIZK: row opening missing idx %d", firstIdx)
		}
		rowVals := make([]uint64, probeRowCount)
		for j := 0; j < probeRowCount; j++ {
			rowVals[j] = decs.GetOpeningPval(opening, posRow, j) % q
		}
		fparProbe, faggProbe, probeErr := replay.Eval(uint64(firstIdx), rowVals)
		if probeErr != nil {
			return okLin, false, false, fmt.Errorf("VerifyNIZK: constraint probe failed: %w", probeErr)
		}
		wantPar := len(fparProbe)
		wantAgg := len(faggProbe)
		rho := len(proof.GammaPrime)
		if proof.Theta > 1 && len(proof.GammaPrimeK) > 0 {
			rho = len(proof.GammaPrimeK)
		}
		if rho == 0 {
			return okLin, false, false, errors.New("VerifyNIZK: missing GammaPrime for replay")
		}
		for i := 0; i < len(proof.GammaPrime); i++ {
			if len(proof.GammaPrime[i]) != wantPar {
				return okLin, false, false, fmt.Errorf("VerifyNIZK: GammaPrime[%d] constraint count %d want %d", i, len(proof.GammaPrime[i]), wantPar)
			}
		}
		for i := 0; i < len(proof.GammaPrimeK); i++ {
			if len(proof.GammaPrimeK[i]) != wantPar {
				return okLin, false, false, fmt.Errorf("VerifyNIZK: GammaPrimeK[%d] constraint count %d want %d", i, len(proof.GammaPrimeK[i]), wantPar)
			}
		}
		aggCols := 0
		if len(proof.GammaAgg) > 0 {
			aggCols = len(proof.GammaAgg[0])
		} else if len(proof.GammaAggK) > 0 {
			aggCols = len(proof.GammaAggK[0])
		}
		if aggCols != wantAgg {
			return okLin, false, false, fmt.Errorf("VerifyNIZK: GammaAgg constraint count %d want %d", aggCols, wantAgg)
		}
		for i := 0; i < len(proof.GammaAgg); i++ {
			if len(proof.GammaAgg[i]) != wantAgg {
				return okLin, false, false, fmt.Errorf("VerifyNIZK: GammaAgg[%d] constraint count %d want %d", i, len(proof.GammaAgg[i]), wantAgg)
			}
		}
		for i := 0; i < len(proof.GammaAggK); i++ {
			if len(proof.GammaAggK[i]) != wantAgg {
				return okLin, false, false, fmt.Errorf("VerifyNIZK: GammaAggK[%d] constraint count %d want %d", i, len(proof.GammaAggK[i]), wantAgg)
			}
		}

		// θ>1 replay at K-points (primary) when available.
		if proof.Theta > 1 {
			if replay.EvalK == nil {
				return okLin, false, false, errors.New("VerifyNIZK: missing K evaluator for θ>1 replay")
			}
			vTargets := proof.VTargetsMatrix()
			witnessCount := replay.RowCount
			if witnessCount <= 0 {
				witnessCount = proof.RowLayout.SigCount
			}
			if witnessCount <= 0 {
				if len(vTargets) == 0 {
					return okLin, false, false, errors.New("VerifyNIZK: missing VTargets for θ>1 replay")
				}
				witnessCount = len(vTargets[0])
			}
			ok, err := EvaluateConstraintsOnKPoints(replay.EvalK, EvalKInput{
				K:                smallFieldK,
				KPoints:          proof.KPoint,
				VTargets:         vTargets,
				QK:               QK,
				MK:               MK,
				GammaPrimeK:      proof.GammaPrimeK,
				GammaAggK:        proof.GammaAggK,
				WitnessCount:     witnessCount,
				Ring:             ringQ,
				Fpar:             replay.Fpar,
				Fagg:             replay.Fagg,
				FparCoeffs:       replay.FparCoeffs,
				FaggCoeffs:       replay.FaggCoeffs,
				FparOverrideIdxs: replay.FparOverrideIdxs,
				BoundRows:        replay.BoundRows,
				CarryRows:        replay.CarryRows,
				BoundB:           replay.BoundB,
				CarryBound:       replay.CarryBound,
			})
			if err != nil || !ok {
				if err == nil {
					err = errors.New("VerifyNIZK: K-point constraint replay failed")
				}
				return okLin, false, false, err
			}
		}

		// Tail/E′ replay is only applied in θ==1 mode. In θ>1 mode replay uses
		// K-point reconstruction from VTargets.
		if proof.Theta <= 1 {
			rowCount := replay.RowCount
			if rowCount <= 0 {
				rowCount = proof.RowLayout.SigCount
			}
			ok, err := EvaluateConstraintsOnTailOpen(replay.Eval, EvalTailInput{
				Tail:             proof.Tail,
				RowOpen:          opening,
				QOpen:            qOpeningPrepared,
				GammaPrime:       proof.GammaPrime,
				GammaAgg:         proof.GammaAgg,
				Ring:             ringQ,
				FparCoeffs:       replay.FparCoeffs,
				FparOverrideIdxs: replay.FparOverrideIdxs,
				DomainPoints:     domainPoints,
				RowCount:         rowCount,
				MaskRowOffset:    proof.MaskRowOffset,
				MaskRowCount:     proof.MaskRowCount,
			})
			if err != nil || !ok {
				if err == nil {
					err = errors.New("VerifyNIZK: tail constraint replay failed")
				}
				return okLin, false, false, err
			}
		}
		okEq4 = true
	} else {
		return okLin, false, false, errors.New("VerifyNIZK: missing constraint replay; use VerifyNIZKWithReplay")
	}

	return okLin, okEq4, okSum, nil
}

func verifyRoundDigest(fs *FS, round int, ctr uint64, material [][]byte, expected []byte, kappa int) ([]byte, error) {
	if fs == nil {
		return nil, errors.New("nil FS state")
	}
	if round < 0 || round >= len(fs.labels) {
		return nil, fmt.Errorf("invalid FS round %d", round)
	}
	input := append([]byte(nil), fs.salt...)
	for _, m := range material {
		input = append(input, m...)
	}
	input = append(input, u64le(ctr)...)
	digest := fs.xof.Expand(fs.labels[round], input)
	if !bytes.Equal(digest, expected) {
		return nil, fmt.Errorf("digest mismatch in round %d", round)
	}
	if !hasZeroPrefix(digest, kappa) {
		return nil, fmt.Errorf("grinding predicate failed in round %d", round)
	}
	return digest, nil
}

func deg(p *ring.Poly) int {
	if p == nil || len(p.Coeffs) == 0 || len(p.Coeffs[0]) == 0 {
		return -1
	}
	c := p.Coeffs[0]
	for i := len(c) - 1; i >= 0; i-- {
		if c[i] != 0 {
			return i
		}
	}
	return -1
}

func prepareQOpeningForVerify(open *decs.DECSOpening, gammaQ, qr [][]uint64, points []uint64, q uint64) (*decs.DECSOpening, error) {
	if open == nil {
		return nil, errors.New("nil opening")
	}
	if open.R <= 0 || open.Eta <= 0 {
		return nil, fmt.Errorf("invalid opening dimensions R=%d Eta=%d", open.R, open.Eta)
	}
	if len(gammaQ) < open.Eta {
		return nil, fmt.Errorf("gammaQ rows=%d < eta=%d", len(gammaQ), open.Eta)
	}
	for k := 0; k < open.Eta; k++ {
		if len(gammaQ[k]) < open.R {
			return nil, fmt.Errorf("gammaQ row %d width=%d < R=%d", k, len(gammaQ[k]), open.R)
		}
	}
	if len(qr) < open.Eta {
		return nil, fmt.Errorf("QR rows=%d < eta=%d", len(qr), open.Eta)
	}

	if open.FormatVersion == 1 {
		omitCols, eqRows, ok := qCompressionPOmitPlan(gammaQ, open.R, q)
		if !ok || len(omitCols) == 0 {
			return nil, errors.New("compressed Q opening is not reconstructible (P)")
		}
		if !equalIntSlices(open.POmitCols, omitCols) {
			return nil, fmt.Errorf("compressed Q opening POmitCols mismatch got=%v want=%v", open.POmitCols, omitCols)
		}
		keepCols := compressionKeepCols(open.R, omitCols)
		if open.PColsEncoded != len(keepCols) {
			return nil, fmt.Errorf("compressed Q opening PColsEncoded=%d want=%d", open.PColsEncoded, len(keepCols))
		}
		if len(open.Pvals) != open.EntryCount() {
			return nil, fmt.Errorf("compressed Q opening P row count=%d want=%d", len(open.Pvals), open.EntryCount())
		}
		for i := range open.Pvals {
			if len(open.Pvals[i]) != len(keepCols) {
				return nil, fmt.Errorf("compressed Q opening P row %d width=%d want=%d", i, len(open.Pvals[i]), len(keepCols))
			}
		}
		var mKeepCols []int
		mPosByLogical := make([]int, open.Eta)
		for i := range mPosByLogical {
			mPosByLogical[i] = -1
		}
		if open.MFormatVersion == 1 {
			mKeepCols = compressionKeepCols(open.Eta, open.MOmitCols)
			if open.MColsEncoded != len(mKeepCols) {
				return nil, fmt.Errorf("compressed Q opening MColsEncoded=%d want=%d", open.MColsEncoded, len(mKeepCols))
			}
			if len(open.Mvals) != open.EntryCount() {
				return nil, fmt.Errorf("compressed Q opening M row count=%d want=%d", len(open.Mvals), open.EntryCount())
			}
			for t := range open.Mvals {
				if len(open.Mvals[t]) != len(mKeepCols) {
					return nil, fmt.Errorf("compressed Q opening M row %d width=%d want=%d", t, len(open.Mvals[t]), len(mKeepCols))
				}
			}
			for pos, logical := range mKeepCols {
				mPosByLogical[logical] = pos
			}
			for _, eq := range eqRows {
				if eq < 0 || eq >= open.Eta || mPosByLogical[eq] < 0 {
					return nil, fmt.Errorf("compressed Q opening missing M value for reconstruction row %d", eq)
				}
			}
		}
		a := make([][]uint64, len(eqRows))
		for i := range eqRows {
			rowIdx := eqRows[i]
			a[i] = make([]uint64, len(omitCols))
			for j, col := range omitCols {
				a[i][j] = gammaQ[rowIdx][col] % q
			}
		}
		aInv, ok := invertSquareMatrixMod(a, q)
		if !ok {
			return nil, errors.New("compressed Q opening P system is singular")
		}
		fullRows := make([][]uint64, open.EntryCount())
		for t := 0; t < open.EntryCount(); t++ {
			idx := open.IndexAt(t)
			if idx < 0 || idx >= len(points) {
				return nil, fmt.Errorf("opening index %d out of range for domain points", idx)
			}
			x := points[idx] % q
			rhs := make([]uint64, len(eqRows))
			for i, rowIdx := range eqRows {
				target := EvalPoly(qr[rowIdx], x, q) % q
				mVal := uint64(0)
				if open.MFormatVersion == 1 {
					pos := mPosByLogical[rowIdx]
					if pos < 0 {
						return nil, fmt.Errorf("compressed Q opening M missing row %d", rowIdx)
					}
					mVal = open.Mvals[t][pos] % q
				} else {
					mVal = decs.GetOpeningMval(open, t, rowIdx) % q
				}
				target = qSubMod(target, mVal, q)
				known := uint64(0)
				for j, col := range keepCols {
					known = lvcs.MulAddMod64(known, gammaQ[rowIdx][col]%q, open.Pvals[t][j]%q, q)
				}
				rhs[i] = qSubMod(target, known, q)
			}
			missing := mulMatVecMod(aInv, rhs, q)
			full := make([]uint64, open.R)
			for j, col := range keepCols {
				full[col] = open.Pvals[t][j] % q
			}
			for j, col := range omitCols {
				full[col] = missing[j] % q
			}
			fullRows[t] = full
		}
		open.Pvals = fullRows
	}

	if open.MFormatVersion == 1 {
		omitCols := append([]int(nil), open.MOmitCols...)
		for _, col := range omitCols {
			if col < 0 || col >= open.Eta {
				return nil, fmt.Errorf("compressed Q opening MOmitCols contains out-of-range col %d", col)
			}
		}
		// Require deterministic ordering to avoid prover-controlled ambiguity.
		sortedOmit := append([]int(nil), omitCols...)
		sort.Ints(sortedOmit)
		if !equalIntSlices(omitCols, sortedOmit) {
			return nil, fmt.Errorf("compressed Q opening MOmitCols not sorted: got=%v want=%v", omitCols, sortedOmit)
		}
		keepCols := compressionKeepCols(open.Eta, omitCols)
		if open.MColsEncoded != len(keepCols) {
			return nil, fmt.Errorf("compressed Q opening MColsEncoded=%d want=%d", open.MColsEncoded, len(keepCols))
		}
		if len(open.Mvals) != open.EntryCount() {
			return nil, fmt.Errorf("compressed Q opening M row count=%d want=%d", len(open.Mvals), open.EntryCount())
		}
		for i := range open.Mvals {
			if len(open.Mvals[i]) != len(keepCols) {
				return nil, fmt.Errorf("compressed Q opening M row %d width=%d want=%d", i, len(open.Mvals[i]), len(keepCols))
			}
		}
		fullRows := make([][]uint64, open.EntryCount())
		for t := 0; t < open.EntryCount(); t++ {
			idx := open.IndexAt(t)
			if idx < 0 || idx >= len(points) {
				return nil, fmt.Errorf("opening index %d out of range for domain points", idx)
			}
			x := points[idx] % q
			full := make([]uint64, open.Eta)
			for j, col := range keepCols {
				full[col] = open.Mvals[t][j] % q
			}
			for _, k := range omitCols {
				mk := EvalPoly(qr[k], x, q) % q
				sum := uint64(0)
				for j := 0; j < open.R; j++ {
					sum = lvcs.MulAddMod64(sum, gammaQ[k][j]%q, decs.GetOpeningPval(open, t, j)%q, q)
				}
				full[k] = qSubMod(mk, sum, q)
			}
			fullRows[t] = full
		}
		open.Mvals = fullRows
	}

	return open, nil
}

func interpolateReplayQRows(ringQ *ring.Ring, vTargets, barSets [][]uint64, ncols int) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, errors.New("nil ring")
	}
	if len(vTargets) == 0 || len(barSets) == 0 {
		return nil, errors.New("missing replay matrices")
	}
	if len(vTargets) != len(barSets) {
		return nil, fmt.Errorf("VTargets rows=%d != BarSets rows=%d", len(vTargets), len(barSets))
	}
	ell := len(barSets[0])
	qVals := make([]*ring.Poly, len(barSets))
	for k := 0; k < len(barSets); k++ {
		poly, interpErr := interpolateRowLocal(ringQ, vTargets[k], barSets[k], ncols, ell)
		if interpErr != nil {
			return nil, fmt.Errorf("interpolateRow(%d): %w", k, interpErr)
		}
		qVals[k] = ringQ.NewPoly()
		ringQ.NTT(poly, qVals[k])
	}
	return qVals, nil
}

func prepareRowOpeningForVerify(
	base *decs.DECSOpening,
	gamma [][]uint64,
	rPolys []*ring.Poly,
	coeffMatrix [][]uint64,
	qVals []*ring.Poly,
	barSets [][]uint64,
	maskIdx []int,
	tail []int,
	ncols int,
	domainPoints []uint64,
	ringQ *ring.Ring,
) (*decs.DECSOpening, error) {
	if base == nil {
		return nil, errors.New("nil opening")
	}
	if ringQ == nil {
		return nil, errors.New("nil ring")
	}
	open := expandPackedOpening(base)
	if open == nil {
		return nil, errors.New("failed to expand opening")
	}
	if open.R <= 0 || open.Eta <= 0 {
		return nil, fmt.Errorf("invalid opening dimensions R=%d Eta=%d", open.R, open.Eta)
	}
	if len(gamma) < open.Eta {
		return nil, fmt.Errorf("gamma rows=%d < eta=%d", len(gamma), open.Eta)
	}
	for k := 0; k < open.Eta; k++ {
		if len(gamma[k]) < open.R {
			return nil, fmt.Errorf("gamma row %d width=%d < R=%d", k, len(gamma[k]), open.R)
		}
	}
	if open.FormatVersion == 1 {
		if err := reconstructRowOpeningPvals(open, coeffMatrix, qVals, barSets, maskIdx, tail, ncols, domainPoints, ringQ); err != nil {
			return nil, err
		}
	}
	if open.MFormatVersion == 1 {
		if err := reconstructRowOpeningMvals(open, gamma, rPolys, domainPoints, ringQ); err != nil {
			return nil, err
		}
	}
	return open, nil
}

func reconstructRowOpeningPvals(
	open *decs.DECSOpening,
	coeffMatrix [][]uint64,
	qVals []*ring.Poly,
	barSets [][]uint64,
	maskIdx []int,
	tail []int,
	ncols int,
	domainPoints []uint64,
	ringQ *ring.Ring,
) error {
	if open == nil {
		return errors.New("nil opening")
	}
	if ringQ == nil {
		return errors.New("nil ring")
	}
	q := ringQ.Modulus[0]
	if len(coeffMatrix) == 0 {
		return errors.New("missing coefficient matrix")
	}
	omitCols, ok := compressionPivotCols(coeffMatrix, open.R, q)
	if !ok || len(omitCols) == 0 {
		return errors.New("compressed row opening is not reconstructible (P)")
	}
	if !equalIntSlices(open.POmitCols, omitCols) {
		return fmt.Errorf("compressed row opening POmitCols mismatch got=%v want=%v", open.POmitCols, omitCols)
	}
	keepCols := compressionKeepCols(open.R, omitCols)
	if open.PColsEncoded != len(keepCols) {
		return fmt.Errorf("compressed row opening PColsEncoded=%d want=%d", open.PColsEncoded, len(keepCols))
	}
	if len(open.Pvals) != open.EntryCount() {
		return fmt.Errorf("compressed row opening P row count=%d want=%d", len(open.Pvals), open.EntryCount())
	}
	for i := range open.Pvals {
		if len(open.Pvals[i]) != len(keepCols) {
			return fmt.Errorf("compressed row opening P row %d width=%d want=%d", i, len(open.Pvals[i]), len(keepCols))
		}
	}
	a := make([][]uint64, len(coeffMatrix))
	for i := range coeffMatrix {
		if len(coeffMatrix[i]) < open.R {
			return fmt.Errorf("compressed row opening coeff row %d width=%d < R=%d", i, len(coeffMatrix[i]), open.R)
		}
		a[i] = make([]uint64, len(omitCols))
		for j, col := range omitCols {
			a[i][j] = coeffMatrix[i][col] % q
		}
	}
	if len(a) != len(omitCols) {
		return fmt.Errorf("compressed row opening system rows=%d want %d", len(a), len(omitCols))
	}
	if len(qVals) < len(coeffMatrix) {
		return fmt.Errorf("compressed row opening Q row count=%d < coeff rows=%d", len(qVals), len(coeffMatrix))
	}
	qCoeffRows := make([][]uint64, len(qVals))
	tmp := ringQ.NewPoly()
	for k := 0; k < len(qVals); k++ {
		if qVals[k] == nil {
			return fmt.Errorf("missing replay Q row %d", k)
		}
		ringQ.InvNTT(qVals[k], tmp)
		qCoeffRows[k] = append([]uint64(nil), tmp.Coeffs[0]...)
	}
	if len(barSets) < len(coeffMatrix) {
		return fmt.Errorf("compressed row opening BarSets rows=%d < coeff rows=%d", len(barSets), len(coeffMatrix))
	}
	aInv, ok := invertSquareMatrixMod(a, q)
	if !ok {
		return errors.New("compressed row opening P system is singular")
	}
	maskPosByIdx := make(map[int]int, len(maskIdx))
	for pos, idx := range maskIdx {
		maskPosByIdx[idx] = pos
	}
	maskEnd := ncols + len(maskIdx)
	fullRows := make([][]uint64, open.EntryCount())
	for t := 0; t < open.EntryCount(); t++ {
		idx := open.IndexAt(t)
		target := make([]uint64, len(coeffMatrix))
		if pos, ok := maskPosByIdx[idx]; ok {
			for k := 0; k < len(coeffMatrix); k++ {
				if pos < 0 || pos >= len(barSets[k]) {
					return fmt.Errorf("mask target pos=%d out of range for row %d", pos, k)
				}
				target[k] = barSets[k][pos] % q
			}
		} else if idx >= maskEnd {
			if idx < 0 || idx >= len(domainPoints) {
				return fmt.Errorf("tail index %d out of explicit domain range", idx)
			}
			x := domainPoints[idx] % q
			for k := 0; k < len(coeffMatrix); k++ {
				target[k] = EvalPoly(qCoeffRows[k], x, q)
			}
		} else {
			return fmt.Errorf("compressed row opening index %d is neither mask nor tail", idx)
		}
		rhs := make([]uint64, len(coeffMatrix))
		for k := 0; k < len(coeffMatrix); k++ {
			known := uint64(0)
			for j, col := range keepCols {
				known = lvcs.MulAddMod64(known, coeffMatrix[k][col]%q, open.Pvals[t][j]%q, q)
			}
			rhs[k] = qSubMod(target[k], known, q)
		}
		missing := mulMatVecMod(aInv, rhs, q)
		full := make([]uint64, open.R)
		for j, col := range keepCols {
			full[col] = open.Pvals[t][j] % q
		}
		for j, col := range omitCols {
			full[col] = missing[j] % q
		}
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

func reconstructRowOpeningMvals(open *decs.DECSOpening, gamma [][]uint64, rPolys []*ring.Poly, domainPoints []uint64, ringQ *ring.Ring) error {
	if open == nil {
		return errors.New("nil opening")
	}
	if ringQ == nil {
		return errors.New("nil ring")
	}
	if len(rPolys) < open.Eta {
		return fmt.Errorf("row polynomial count=%d < eta=%d", len(rPolys), open.Eta)
	}
	rCoeffRows := make([][]uint64, open.Eta)
	tmp := ringQ.NewPoly()
	for k := 0; k < open.Eta; k++ {
		if rPolys[k] == nil {
			return fmt.Errorf("missing row polynomial %d", k)
		}
		ringQ.InvNTT(rPolys[k], tmp)
		rCoeffRows[k] = trimPoly(append([]uint64(nil), tmp.Coeffs[0]...), ringQ.Modulus[0])
	}
	return reconstructRowOpeningMvalsFormal(open, gamma, rCoeffRows, domainPoints, ringQ.Modulus[0])
}

func reconstructRowOpeningMvalsFormal(open *decs.DECSOpening, gamma [][]uint64, rCoeffRows [][]uint64, domainPoints []uint64, q uint64) error {
	if open == nil {
		return errors.New("nil opening")
	}
	if len(rCoeffRows) < open.Eta {
		return fmt.Errorf("row coefficient count=%d < eta=%d", len(rCoeffRows), open.Eta)
	}
	omitCols := append([]int(nil), open.MOmitCols...)
	for _, col := range omitCols {
		if col < 0 || col >= open.Eta {
			return fmt.Errorf("compressed row opening MOmitCols contains out-of-range col %d", col)
		}
	}
	sortedOmit := append([]int(nil), omitCols...)
	sort.Ints(sortedOmit)
	if !equalIntSlices(omitCols, sortedOmit) {
		return fmt.Errorf("compressed row opening MOmitCols not sorted: got=%v want=%v", omitCols, sortedOmit)
	}
	keepCols := compressionKeepCols(open.Eta, omitCols)
	if open.MColsEncoded != len(keepCols) {
		return fmt.Errorf("compressed row opening MColsEncoded=%d want=%d", open.MColsEncoded, len(keepCols))
	}
	if len(open.Mvals) != 0 && len(open.Mvals) != open.EntryCount() {
		return fmt.Errorf("compressed row opening M row count=%d want=%d", len(open.Mvals), open.EntryCount())
	}
	for i := range open.Mvals {
		if len(open.Mvals[i]) != len(keepCols) {
			return fmt.Errorf("compressed row opening M row %d width=%d want=%d", i, len(open.Mvals[i]), len(keepCols))
		}
	}
	fullRows := make([][]uint64, open.EntryCount())
	for t := 0; t < open.EntryCount(); t++ {
		idx := open.IndexAt(t)
		full := make([]uint64, open.Eta)
		for j, col := range keepCols {
			full[col] = open.Mvals[t][j] % q
		}
		for _, k := range omitCols {
			if idx < 0 || idx >= len(domainPoints) {
				return fmt.Errorf("compressed row opening index %d out of explicit domain range", idx)
			}
			sum := uint64(0)
			for j := 0; j < open.R; j++ {
				sum = lvcs.MulAddMod64(sum, gamma[k][j]%q, open.Pvals[t][j]%q, q)
			}
			rEval := EvalPoly(rCoeffRows[k], domainPoints[idx]%q, q)
			full[k] = qSubMod(rEval, sum, q)
		}
		fullRows[t] = full
	}
	open.Mvals = fullRows
	open.MvalsBits = nil
	open.MvalsBitWidth = 0
	open.MFormatVersion = 0
	open.MColsEncoded = 0
	open.MOmitCols = nil
	return nil
}

func verifyDECSSubsetFormal(root [16]byte, params decs.Params, Gamma [][]uint64, rCoeffRows [][]uint64, open *decs.DECSOpening, indices []int, points []uint64, q uint64) error {
	entryCount := open.EntryCount()
	if len(indices) != entryCount {
		return fmt.Errorf("DECS subset: index length mismatch")
	}
	rowCount := len(Gamma[0])
	if rowCount <= 0 {
		return fmt.Errorf("DECS subset: empty Gamma rows")
	}
	if len(rCoeffRows) != params.Eta {
		return fmt.Errorf("DECS subset: R count mismatch")
	}
	for k := 0; k < params.Eta; k++ {
		rCoeffRows[k] = trimPoly(append([]uint64(nil), rCoeffRows[k]...), q)
	}
	for t, idx := range indices {
		if idx < 0 || idx >= len(points) {
			return fmt.Errorf("DECS subset: point index %d out of range (points=%d)", idx, len(points))
		}
		buf := make([]byte, 4*(rowCount+params.Eta)+2+params.NonceBytes)
		off := 0
		pvals := make([]uint64, rowCount)
		for j := 0; j < rowCount; j++ {
			pv := decs.GetOpeningPval(open, t, j) % q
			pvals[j] = pv
			binary.LittleEndian.PutUint32(buf[off:], uint32(pv))
			off += 4
		}
		mvals := make([]uint64, params.Eta)
		for k := 0; k < params.Eta; k++ {
			mv := decs.GetOpeningMval(open, t, k) % q
			mvals[k] = mv
			binary.LittleEndian.PutUint32(buf[off:], uint32(mv))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(idx))
		off += 2
		var nonce []byte
		if len(open.Nonces) > t && len(open.Nonces[t]) > 0 {
			nonce = open.Nonces[t]
		} else if len(open.NonceSeed) > 0 && open.NonceBytes > 0 {
			nonce = decs.DeriveNonce(open.NonceSeed, idx, open.NonceBytes)
		}
		if len(nonce) != params.NonceBytes {
			return fmt.Errorf("DECS subset: nonce length mismatch at t=%d", t)
		}
		copy(buf[off:], nonce[:params.NonceBytes])
		path, err := extractPathNodes(open, t)
		if err != nil {
			return fmt.Errorf("DECS subset: %w", err)
		}
		if !decs.VerifyPath(buf, path, root, idx) {
			return fmt.Errorf("DECS subset: Merkle verification failed at idx=%d", idx)
		}
		x := points[idx] % q
		for k := 0; k < params.Eta; k++ {
			lhs := EvalPoly(rCoeffRows[k], x, q)
			rhs := mvals[k]
			for j := 0; j < rowCount; j++ {
				rhs = lvcs.MulAddMod64(rhs, Gamma[k][j], pvals[j], q)
			}
			if lhs != rhs%q {
				return fmt.Errorf("DECS subset: relation mismatch k=%d idx=%d lhs=%d rhs=%d", k, idx, lhs, rhs%q)
			}
		}
	}
	return nil
}

func invertSquareMatrixMod(a [][]uint64, mod uint64) ([][]uint64, bool) {
	n := len(a)
	if n == 0 {
		return nil, false
	}
	aug := make([][]uint64, n)
	for i := 0; i < n; i++ {
		if len(a[i]) != n {
			return nil, false
		}
		row := make([]uint64, 2*n)
		for j := 0; j < n; j++ {
			row[j] = a[i][j] % mod
		}
		row[n+i] = 1
		aug[i] = row
	}
	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if aug[r][col]%mod != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return nil, false
		}
		if pivot != col {
			aug[col], aug[pivot] = aug[pivot], aug[col]
		}
		invPivot := ring.ModExp(aug[col][col]%mod, mod-2, mod)
		for c := col; c < 2*n; c++ {
			aug[col][c] = lvcs.MulMod64(aug[col][c], invPivot, mod)
		}
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			factor := aug[r][col] % mod
			if factor == 0 {
				continue
			}
			for c := col; c < 2*n; c++ {
				term := lvcs.MulMod64(factor, aug[col][c], mod)
				aug[r][c] = qSubMod(aug[r][c], term, mod)
			}
		}
	}
	inv := make([][]uint64, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]uint64, n)
		copy(inv[i], aug[i][n:])
	}
	return inv, true
}

func mulMatVecMod(a [][]uint64, x []uint64, mod uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		acc := uint64(0)
		for j := range x {
			acc = lvcs.MulAddMod64(acc, a[i][j]%mod, x[j]%mod, mod)
		}
		out[i] = acc
	}
	return out
}

func qSubMod(a, b, mod uint64) uint64 {
	if a >= mod {
		a %= mod
	}
	if b >= mod {
		b %= mod
	}
	if a >= b {
		return a - b
	}
	return a + mod - b
}

func verifySumOnQOpening(open *decs.DECSOpening, rho, ncols int, q uint64) (ok bool, badRow int, badSum uint64) {
	if open == nil || rho <= 0 || ncols <= 0 {
		return false, -1, 0
	}
	if open.R != rho {
		return false, -1, 0
	}
	sum := make([]uint64, rho)
	for pos := 0; pos < open.EntryCount(); pos++ {
		idx := open.IndexAt(pos)
		if idx < 0 || idx >= ncols {
			continue
		}
		for i := 0; i < rho; i++ {
			sum[i] = lvcs.MulAddMod64(sum[i], 1, decs.GetOpeningPval(open, pos, i)%q, q)
		}
	}
	for i := 0; i < rho; i++ {
		if sum[i]%q != 0 {
			return false, i, sum[i] % q
		}
	}
	return true, -1, 0
}

func kMatrixEqual(a, b [][]KScalar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if len(a[i][j]) != len(b[i][j]) {
				return false
			}
			for t := range a[i][j] {
				if a[i][j][t] != b[i][j][t] {
					return false
				}
			}
		}
	}
	return true
}

func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateDistinctIndicesInRange(indices []int, start, end int) error {
	if end < start {
		return fmt.Errorf("invalid range [%d,%d)", start, end)
	}
	seen := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		if idx < start || idx >= end {
			return fmt.Errorf("index %d outside [%d,%d)", idx, start, end)
		}
		if _, ok := seen[idx]; ok {
			return fmt.Errorf("duplicate index %d", idx)
		}
		seen[idx] = struct{}{}
	}
	return nil
}

// checkEq4OnEvalOpen replays Eq.(4) on provided evaluation rows (theta==1).
func checkEq4OnEvalOpen(
	ringQ *ring.Ring,
	indices []int,
	Mvals [][]uint64,
	points []uint64,
	Q []*ring.Poly,
	Fpar []*ring.Poly,
	Fagg []*ring.Poly,
	gammaF [][]*ring.Poly,
	gammaAgg [][]uint64,
) bool {
	if ringQ == nil {
		return false
	}
	q := ringQ.Modulus[0]
	if len(indices) == 0 {
		return false
	}
	if len(points) == 0 {
		return false
	}
	rho := len(Q)
	if rho == 0 {
		return false
	}

	var (
		QCoeffs     [][]uint64
		FparCoeffs  [][]uint64
		FaggCoeffs  [][]uint64
		GammaCoeffs [][][]uint64
	)
	tmp := ringQ.NewPoly()
	QCoeffs = make([][]uint64, len(Q))
	for i := range Q {
		if Q[i] == nil {
			return false
		}
		ringQ.InvNTT(Q[i], tmp)
		QCoeffs[i] = append([]uint64(nil), tmp.Coeffs[0]...)
	}
	FparCoeffs = make([][]uint64, len(Fpar))
	for i := range Fpar {
		if Fpar[i] == nil {
			continue
		}
		ringQ.InvNTT(Fpar[i], tmp)
		FparCoeffs[i] = append([]uint64(nil), tmp.Coeffs[0]...)
	}
	FaggCoeffs = make([][]uint64, len(Fagg))
	for i := range Fagg {
		if Fagg[i] == nil {
			continue
		}
		ringQ.InvNTT(Fagg[i], tmp)
		FaggCoeffs[i] = append([]uint64(nil), tmp.Coeffs[0]...)
	}
	GammaCoeffs = make([][][]uint64, len(gammaF))
	for i := range gammaF {
		GammaCoeffs[i] = make([][]uint64, len(gammaF[i]))
		for j := range gammaF[i] {
			if gammaF[i][j] == nil {
				continue
			}
			ringQ.InvNTT(gammaF[i][j], tmp)
			GammaCoeffs[i][j] = append([]uint64(nil), tmp.Coeffs[0]...)
		}
	}

	for col, idx := range indices {
		if idx < 0 || idx >= len(points) {
			return false
		}
		x := points[idx] % q
		for i := 0; i < rho; i++ {
			lhs := EvalPoly(QCoeffs[i], x, q) % q
			var rhs uint64
			if i < len(Mvals) && col < len(Mvals[i]) {
				rhs = Mvals[i][col] % q
			}
			if i < len(gammaF) {
				rowGamma := gammaF[i]
				for j := range Fpar {
					var g uint64
					if j < len(rowGamma) && rowGamma[j] != nil {
						if GammaCoeffs != nil && GammaCoeffs[i][j] != nil {
							g = EvalPoly(GammaCoeffs[i][j], x, q) % q
						}
					}
					var fval uint64
					if FparCoeffs[j] != nil {
						fval = EvalPoly(FparCoeffs[j], x, q) % q
					}
					rhs = lvcs.MulAddMod64(rhs, g, fval, q)
				}
			}
			if i < len(gammaAgg) {
				rowGamma := gammaAgg[i]
				for j := range Fagg {
					var g uint64
					if j < len(rowGamma) {
						g = rowGamma[j] % q
					}
					var fval uint64
					if FaggCoeffs[j] != nil {
						fval = EvalPoly(FaggCoeffs[j], x, q) % q
					}
					rhs = lvcs.MulAddMod64(rhs, g, fval, q)
				}
			}
			if lhs != rhs {
				fmt.Printf("[eq4-eval] idx=%d i=%d lhs=%d rhs=%d\n", idx, i, lhs, rhs)
				return false
			}
		}
	}
	return true
}

func verifyLVCSConstraints(
	ringQ *ring.Ring,
	params decs.Params,
	proof *Proof,
	Gamma [][]uint64,
	Rpolys []*ring.Poly,
	coeffMatrix [][]uint64,
	barSets [][]uint64,
	vTargets [][]uint64,
	maskIdx []int,
	tail []int,
	ncols int,
	domainPoints []uint64,
) (bool, error) {
	base := resolveProofPCSOpening(proof)
	if base == nil {
		return false, errors.New("VerifyNIZK: nil PCS opening")
	}
	if len(coeffMatrix) == 0 || len(coeffMatrix[0]) == 0 {
		return false, errors.New("VerifyNIZK: empty coefficient matrix")
	}
	rowCount := base.R
	if rowCount <= 0 {
		rowCount = len(coeffMatrix[0])
	}
	if len(coeffMatrix[0]) != rowCount {
		return false, errors.New("VerifyNIZK: coefficient matrix row length mismatch")
	}
	eta := base.Eta
	if eta <= 0 {
		eta = len(Gamma)
	}
	Qvals, err := interpolateReplayQRows(ringQ, vTargets, barSets, ncols)
	if err != nil {
		return false, fmt.Errorf("VerifyNIZK: replay Q rows: %w", err)
	}
	preparedBase, err := prepareRowOpeningForVerify(base, Gamma, Rpolys, coeffMatrix, Qvals, barSets, maskIdx, tail, ncols, domainPoints, ringQ)
	if err != nil {
		return false, fmt.Errorf("VerifyNIZK: prepare row opening: %w", err)
	}
	maskOpen, err := buildSubsetOpening(preparedBase, maskIdx, rowCount, eta)
	if err != nil {
		return false, fmt.Errorf("VerifyNIZK: mask opening: %w", err)
	}
	tailOpen, err := buildSubsetOpening(preparedBase, tail, rowCount, eta)
	if err != nil {
		return false, fmt.Errorf("VerifyNIZK: tail opening: %w", err)
	}
	for i := range maskOpen.Pvals {
		if len(maskOpen.Pvals[i]) != rowCount {
			return false, fmt.Errorf("VerifyNIZK: mask Pvals[%d] len=%d want=%d", i, len(maskOpen.Pvals[i]), rowCount)
		}
		if eta > 0 && len(maskOpen.Mvals[i]) != eta {
			return false, fmt.Errorf("VerifyNIZK: mask Mvals[%d] len=%d want=%d", i, len(maskOpen.Mvals[i]), eta)
		}
	}
	for i := range tailOpen.Pvals {
		if len(tailOpen.Pvals[i]) != rowCount {
			return false, fmt.Errorf("VerifyNIZK: tail Pvals[%d] len=%d want=%d", i, len(tailOpen.Pvals[i]), rowCount)
		}
		if eta > 0 && len(tailOpen.Mvals[i]) != eta {
			return false, fmt.Errorf("VerifyNIZK: tail Mvals[%d] len=%d want=%d", i, len(tailOpen.Mvals[i]), eta)
		}
	}
	subsetParams := decs.Params{Degree: params.Degree, Eta: eta, NonceBytes: params.NonceBytes}
	if err := verifyDECSSubset(ringQ, proof.Root, subsetParams, Gamma, Rpolys, maskOpen, maskIdx, domainPoints); err != nil {
		return false, fmt.Errorf("VerifyNIZK: mask subset: %w", err)
	}
	if err := verifyDECSSubset(ringQ, proof.Root, subsetParams, Gamma, Rpolys, tailOpen, tail, domainPoints); err != nil {
		return false, fmt.Errorf("VerifyNIZK: tail subset: %w", err)
	}
	if len(coeffMatrix) != len(barSets) || len(coeffMatrix) != len(vTargets) {
		return false, errors.New("VerifyNIZK: coefficient matrix dimension mismatch")
	}
	mod := ringQ.Modulus[0]
	for t, idx := range maskIdx {
		maskedPos := idx - ncols
		row := maskOpen.Pvals[t]
		for k := 0; k < len(barSets); k++ {
			if len(coeffMatrix[k]) != len(row) {
				return false, errors.New("VerifyNIZK: coeff row length mismatch")
			}
			sum := uint64(0)
			for j := 0; j < len(row); j++ {
				sum = lvcs.MulAddMod64(sum, coeffMatrix[k][j], row[j], mod)
			}
			if sum != barSets[k][maskedPos]%mod {
				return false, fmt.Errorf("VerifyNIZK: masked linear relation mismatch k=%d pos=%d sum=%d target=%d", k, maskedPos, sum, barSets[k][maskedPos]%mod)
			}
		}
	}
	for t, idx := range tail {
		row := tailOpen.Pvals[t]
		for k := 0; k < len(barSets); k++ {
			lhs := Qvals[k].Coeffs[0][idx] % mod
			sum := uint64(0)
			for j := 0; j < len(row); j++ {
				sum = lvcs.MulAddMod64(sum, coeffMatrix[k][j], row[j], mod)
			}
			if lhs != sum {
				return false, fmt.Errorf("VerifyNIZK: tail linear relation mismatch k=%d idx=%d lhs=%d rhs=%d", k, idx, lhs, sum)
			}
		}
	}
	return true, nil
}

func buildSubsetOpening(base *decs.DECSOpening, indices []int, rowCount, eta int) (*decs.DECSOpening, error) {
	if base == nil {
		return nil, errors.New("nil base opening")
	}
	if err := decs.EnsureMerkleDecoded(base); err != nil {
		return nil, err
	}
	posByIdx := make(map[int]int, base.EntryCount())
	for i := 0; i < base.EntryCount(); i++ {
		idx := base.IndexAt(i)
		posByIdx[idx] = i
	}
	maskCount := 0
	maskBase := 0
	if len(indices) > 0 {
		maskBase = indices[0]
		for maskCount < len(indices) && indices[maskCount] == maskBase+maskCount {
			maskCount++
		}
	}
	tailCount := len(indices) - maskCount
	nonceBytes := base.NonceBytes
	if nonceBytes <= 0 && len(base.Nonces) > 0 && len(base.Nonces[0]) > 0 {
		nonceBytes = len(base.Nonces[0])
	}
	sub := &decs.DECSOpening{
		MaskBase:   maskBase,
		MaskCount:  maskCount,
		Indices:    make([]int, tailCount),
		Pvals:      make([][]uint64, len(indices)),
		Nodes:      append([][]byte(nil), base.Nodes...),
		R:          rowCount,
		Eta:        eta,
		NonceSeed:  append([]byte(nil), base.NonceSeed...),
		NonceBytes: nonceBytes,
	}
	if len(base.Nonces) > 0 {
		sub.Nonces = make([][]byte, len(indices))
	}
	if len(base.PathIndex) > 0 {
		sub.PathIndex = make([][]int, len(indices))
	}
	if eta > 0 {
		sub.Mvals = make([][]uint64, len(indices))
	}
	for i, idx := range indices {
		pos, ok := posByIdx[idx]
		if !ok {
			return nil, fmt.Errorf("opening missing index %d", idx)
		}
		if i >= maskCount {
			sub.Indices[i-maskCount] = idx
		}
		if len(base.Pvals) > 0 {
			sub.Pvals[i] = append([]uint64(nil), base.Pvals[pos]...)
		} else {
			sub.Pvals[i] = make([]uint64, rowCount)
			for j := 0; j < rowCount; j++ {
				sub.Pvals[i][j] = decs.GetOpeningPval(base, pos, j)
			}
		}
		if eta > 0 {
			if len(base.Mvals) > 0 {
				sub.Mvals[i] = append([]uint64(nil), base.Mvals[pos]...)
			} else {
				sub.Mvals[i] = make([]uint64, eta)
				for j := 0; j < eta; j++ {
					sub.Mvals[i][j] = decs.GetOpeningMval(base, pos, j)
				}
			}
		}
		if len(base.PathIndex) > 0 {
			sub.PathIndex[i] = append([]int(nil), base.PathIndex[pos]...)
		}
		if len(base.Nonces) > pos && len(base.Nonces[pos]) > 0 {
			sub.Nonces[i] = append([]byte(nil), base.Nonces[pos]...)
		}
	}
	if len(sub.PathIndex) > 0 && len(sub.PathIndex[0]) > 0 {
		sub.PathDepth = len(sub.PathIndex[0])
	}
	return sub, nil
}

func interpolateRowLocal(ringQ *ring.Ring, row []uint64, mask []uint64, ncols, ell int) (*ring.Poly, error) {
	mod := ringQ.Modulus[0]
	N := ringQ.N
	m := ncols + ell
	if m > int(N) {
		return nil, errors.New("interpolateRow: degree exceed ring.N")
	}
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pvs := ringQ.NewPoly()
	ringQ.NTT(px, pvs)
	xs := append([]uint64(nil), pvs.Coeffs[0][:m]...)
	ys := make([]uint64, m)
	copy(ys[:ncols], row)
	copy(ys[ncols:], mask)
	T := make([]uint64, m+1)
	T[0] = 1
	for _, xj := range xs {
		for k := m; k >= 1; k-- {
			T[k] = (T[k-1] + mod - (xj * T[k] % mod)) % mod
		}
		T[0] = (mod - (xj * T[0] % mod)) % mod
	}
	Pcoefs := make([]uint64, m)
	tmp := make([]uint64, m)
	for i, xi := range xs {
		tmp[m-1] = T[m]
		for k := m - 2; k >= 0; k-- {
			tmp[k] = (T[k+1] + xi*tmp[k+1]) % mod
		}
		denom := uint64(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			diff := (xi + mod - xj) % mod
			denom = (denom * diff) % mod
		}
		inv := new(big.Int).ModInverse(new(big.Int).SetUint64(denom), new(big.Int).SetUint64(mod))
		if inv == nil {
			return nil, errors.New("interpolateRow: denom not invertible")
		}
		scale := (ys[i] * inv.Uint64()) % mod
		for k := 0; k < m; k++ {
			Pcoefs[k] = (Pcoefs[k] + tmp[k]*scale) % mod
		}
	}
	P := ringQ.NewPoly()
	copy(P.Coeffs[0][:m], Pcoefs)
	for k := m; k < int(N); k++ {
		P.Coeffs[0][k] = 0
	}
	return P, nil
}

func verifyDECSSubset(ringQ *ring.Ring, root [16]byte, params decs.Params, Gamma [][]uint64, R []*ring.Poly, open *decs.DECSOpening, indices []int, points []uint64) error {
	entryCount := open.EntryCount()
	if len(indices) != entryCount {
		return fmt.Errorf("DECS subset: index length mismatch")
	}
	rowCount := len(Gamma[0])
	if rowCount <= 0 {
		return fmt.Errorf("DECS subset: empty Gamma rows")
	}
	if len(R) != params.Eta {
		return fmt.Errorf("DECS subset: R count mismatch")
	}
	Rcoeffs := make([][]uint64, params.Eta)
	for k := 0; k < params.Eta; k++ {
		coeffs, err := coeffFromNTTPoly(ringQ, R[k])
		if err != nil {
			return fmt.Errorf("DECS subset: R[%d] coeffs: %w", k, err)
		}
		Rcoeffs[k] = coeffs
	}
	mod := ringQ.Modulus[0]
	for t, idx := range indices {
		if idx < 0 || idx >= int(ringQ.N) {
			return fmt.Errorf("DECS subset: index %d out of range", idx)
		}
		if idx >= len(points) {
			return fmt.Errorf("DECS subset: point index %d out of range (points=%d)", idx, len(points))
		}
		buf := make([]byte, 4*(rowCount+params.Eta)+2+params.NonceBytes)
		off := 0
		pvals := make([]uint64, rowCount)
		for j := 0; j < rowCount; j++ {
			pv := decs.GetOpeningPval(open, t, j) % mod
			pvals[j] = pv
			binary.LittleEndian.PutUint32(buf[off:], uint32(pv))
			off += 4
		}
		mvals := make([]uint64, params.Eta)
		for k := 0; k < params.Eta; k++ {
			mv := decs.GetOpeningMval(open, t, k) % mod
			mvals[k] = mv
			binary.LittleEndian.PutUint32(buf[off:], uint32(mv))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(idx))
		off += 2
		var nonce []byte
		if len(open.Nonces) > t && len(open.Nonces[t]) > 0 {
			nonce = open.Nonces[t]
		} else if len(open.NonceSeed) > 0 && open.NonceBytes > 0 {
			nonce = decs.DeriveNonce(open.NonceSeed, idx, open.NonceBytes)
		}
		if len(nonce) != params.NonceBytes {
			return fmt.Errorf("DECS subset: nonce length mismatch at t=%d", t)
		}
		copy(buf[off:], nonce[:params.NonceBytes])
		path, err := extractPathNodes(open, t)
		if err != nil {
			return fmt.Errorf("DECS subset: %w", err)
		}
		if !decs.VerifyPath(buf, path, root, idx) {
			return fmt.Errorf("DECS subset: Merkle verification failed at idx=%d", idx)
		}
		x := points[idx] % mod
		for k := 0; k < params.Eta; k++ {
			lhs := EvalPoly(Rcoeffs[k], x, mod)
			rhs := mvals[k]
			for j := 0; j < rowCount; j++ {
				rhs = lvcs.MulAddMod64(rhs, Gamma[k][j], pvals[j], mod)
			}
			if lhs != rhs%mod {
				return fmt.Errorf("DECS subset: relation mismatch k=%d idx=%d lhs=%d rhs=%d", k, idx, lhs, rhs%mod)
			}
		}
	}
	return nil
}

func extractPathNodes(open *decs.DECSOpening, t int) ([][]byte, error) {
	if err := decs.EnsureMerkleDecoded(open); err != nil {
		return nil, err
	}
	if len(open.PathIndex) == 0 || t < 0 || t >= len(open.PathIndex) {
		return nil, errors.New("missing path indices")
	}
	path := make([][]byte, len(open.PathIndex[t]))
	for lvl, id := range open.PathIndex[t] {
		if id < 0 || id >= len(open.Nodes) {
			return nil, fmt.Errorf("path node index out of range at t=%d lvl=%d", t, lvl)
		}
		path[lvl] = open.Nodes[id]
	}
	return path, nil
}

func expandPackedOpening(op *decs.DECSOpening) *decs.DECSOpening {
	if op == nil {
		return nil
	}
	clone := cloneDECSOpening(op)
	fullIndices := clone.AllIndices()
	if len(fullIndices) > 0 {
		clone.Indices = append([]int(nil), fullIndices...)
		clone.TailCount = len(fullIndices)
	} else {
		clone.Indices = nil
		clone.TailCount = 0
	}
	clone.MaskBase = 0
	clone.MaskCount = 0
	clone.IndexBits = nil
	clone.PathBits = nil
	clone.PathBitWidth = 0
	clone.PathDepth = 0
	pCols := clone.R
	if clone.FormatVersion == 1 && clone.PColsEncoded > 0 {
		pCols = clone.PColsEncoded
	}
	if len(clone.Pvals) == 0 && pCols > 0 {
		clone.Pvals = make([][]uint64, len(clone.Indices))
		for i := range clone.Indices {
			clone.Pvals[i] = make([]uint64, pCols)
			for j := 0; j < pCols; j++ {
				clone.Pvals[i][j] = decs.GetOpeningPval(op, i, j)
			}
		}
	}
	mCols := clone.Eta
	if clone.MFormatVersion == 1 {
		mCols = clone.MColsEncoded
	}
	if len(clone.Mvals) == 0 && mCols > 0 {
		clone.Mvals = make([][]uint64, len(clone.Indices))
		for i := range clone.Indices {
			clone.Mvals[i] = make([]uint64, mCols)
			for j := 0; j < mCols; j++ {
				clone.Mvals[i][j] = decs.GetOpeningMval(op, i, j)
			}
		}
	} else if len(clone.Mvals) == 0 && clone.MFormatVersion == 1 && mCols == 0 {
		clone.Mvals = make([][]uint64, len(clone.Indices))
	}
	_ = decs.EnsureMerkleDecoded(clone)
	return clone
}
