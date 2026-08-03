package PIOP

import (
	"bytes"
	"testing"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
)

func testFormalBackendProof(t *testing.T, witnessNCols, pcsNCols, ell, nLeaves, witnessDegree, maskDegree int) *Proof {
	t.Helper()
	opts := SimOpts{
		RingDegree: 512,
		NCols:      witnessNCols,
		LVCSNCols:  pcsNCols,
		NLeaves:    nLeaves,
		Ell:        ell,
		EllPrime:   2,
		Rho:        1,
		Eta:        2,
		Lambda:     128,
		Kappa:      [4]int{0, 0, 0, 0},
		DQOverride: func() int {
			if maskDegree > 0 {
				return maskDegree
			}
			return 8
		}(),
		DomainMode: DomainModeExplicit,
	}
	opts.applyDefaults()
	ringQ, err := loadParamsRingForOpts(opts)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	q := ringQ.Modulus[0]
	omega, domainPoints, err := deriveExplicitDomain(q, nLeaves, pcsNCols, ell)
	if err != nil {
		t.Fatalf("derive domain: %v", err)
	}
	omegaWitness := append([]uint64(nil), omega[:witnessNCols]...)

	witnessCoeffs := make([]uint64, witnessDegree+1)
	for i := range witnessCoeffs {
		witnessCoeffs[i] = uint64(3+17*i) % q
	}
	witnessCoeffs[witnessDegree] = 1
	witnessHead := make([]uint64, pcsNCols)
	for i, w := range omega {
		witnessHead[i] = EvalPoly(witnessCoeffs, w%q, q)
	}

	maskCoeffs := SampleIndependentMaskPolynomialCoeffs(q, 1, maskDegree, omegaWitness)
	maskHead := make([]uint64, pcsNCols)
	for i, w := range omega {
		maskHead[i] = EvalPoly(maskCoeffs[0], w%q, q)
	}

	rows := []lvcs.RowInput{
		{Head: witnessHead, PolyCoeffs: witnessCoeffs, TrustedHead: true},
		{Head: maskHead, PolyCoeffs: maskCoeffs[0], TrustedHead: true},
	}
	decsParams := applyDECSWidths(decs.Params{Degree: rowOracleDegreeFloor(ringQ, rows, ell), Eta: opts.Eta}, opts)
	salt := bytes.Repeat([]byte{0x42}, fsSaltBytesForOpts(opts))
	ctx, err := mainCommitmentContextV2(salt)
	if err != nil {
		t.Fatalf("commitment context: %v", err)
	}
	rootHash, pk, layout, err := commitRows(ringQ, rows, ell, decsParams, 1, 1, 1, domainPoints, ctx, nil)
	if err != nil {
		t.Fatalf("commit rows: %v", err)
	}
	proof, err := RunMaskingFS(MaskingFSInput{
		RingQ:            ringQ,
		Opts:             opts,
		Omega:            omega,
		OmegaWitness:     omegaWitness,
		DomainPoints:     domainPoints,
		RootHash:         rootHash,
		Salt:             salt,
		PK:               pk,
		OracleLayout:     layout,
		RowInputs:        rows,
		MaskPolyCoeffs:   maskCoeffs,
		FparIntCoeffs:    [][]uint64{{0}},
		MaskRowOffset:    1,
		MaskRowCount:     1,
		MaskDegreeBound:  maskDegree,
		MaskDegreeTarget: maskDegree,
		NCols:            witnessNCols,
		PCSNCols:         pcsNCols,
		LVCSNCols:        pcsNCols,
		DecsParams:       decsParams,
	})
	if err != nil {
		t.Fatalf("RunMaskingFS: %v", err)
	}
	if proof.SchemaVersion != ProofSchemaVersionV2 || proof.Root != ([16]byte{}) || !bytes.Equal(proof.RootHash, rootHash) || !bytes.Equal(proof.Salt, salt) {
		t.Fatalf("unexpected v2 proof envelope: schema=%d legacy_root=%x root_hash=%x salt=%x", proof.SchemaVersion, proof.Root, proof.RootHash, proof.Salt)
	}
	if err := validateOpeningRoleV2(resolveProofPCSOpening(proof), decs.CommitmentRoleMain); err != nil {
		t.Fatalf("main v2 opening: %v", err)
	}
	if proof.QOpening != nil {
		if err := validateOpeningRoleV2(proof.QOpening, decs.CommitmentRoleQPayload); err != nil {
			t.Fatalf("Q v2 opening: %v", err)
		}
		if len(proof.QRootHash) == 0 || proof.QRoot != ([16]byte{}) {
			t.Fatalf("unexpected Q root envelope: legacy=%x full=%x", proof.QRoot, proof.QRootHash)
		}
	}
	return proof
}

func TestFormalSmallWoodBackendVerifiesRowDegreeAboveRingDimension(t *testing.T) {
	proof := testFormalBackendProof(t, 8, 520, 4, 600, 523, 40)
	if proof.RowDegreeBound <= proof.RingDegree {
		t.Fatalf("row degree bound=%d should exceed ring degree=%d", proof.RowDegreeBound, proof.RingDegree)
	}
	okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, &ConstraintReplay{
		RowCount:   1,
		FparCoeffs: [][]uint64{{0}},
		Eval: func(evalIdx uint64, rowVals []uint64) ([]uint64, []uint64, error) {
			return []uint64{0}, nil, nil
		},
	})
	if err != nil || !(okLin && okEq4 && okSum) {
		t.Fatalf("VerifyNIZKWithReplay=(%v,%v,%v,%v)", okLin, okEq4, okSum, err)
	}
}

func TestFormalSmallWoodBackendVerifiesQDegreeAboveRingDimension(t *testing.T) {
	proof := testFormalBackendProof(t, 8, 32, 4, 600, 12, 540)
	if proof.QDegreeBound <= proof.RingDegree {
		t.Fatalf("Q degree bound=%d should exceed ring degree=%d", proof.QDegreeBound, proof.RingDegree)
	}
	okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, &ConstraintReplay{
		RowCount:   1,
		FparCoeffs: [][]uint64{{0}},
		Eval: func(evalIdx uint64, rowVals []uint64) ([]uint64, []uint64, error) {
			return []uint64{0}, nil, nil
		},
	})
	if err != nil || !(okLin && okEq4 && okSum) {
		t.Fatalf("VerifyNIZKWithReplay=(%v,%v,%v,%v)", okLin, okEq4, okSum, err)
	}
}

func TestFormalSmallWoodBackendRejectsUnderclaimedRowDegree(t *testing.T) {
	proof := testFormalBackendProof(t, 8, 520, 4, 600, 523, 40)
	proof.RowDegreeBound = proof.RingDegree
	okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, &ConstraintReplay{
		RowCount:   1,
		FparCoeffs: [][]uint64{{0}},
		Eval: func(evalIdx uint64, rowVals []uint64) ([]uint64, []uint64, error) {
			return []uint64{0}, nil, nil
		},
	})
	if err == nil || okEq4 || okSum {
		t.Fatalf("underclaimed row degree accepted: (%v,%v,%v,%v)", okLin, okEq4, okSum, err)
	}
}

func TestFormalSmallWoodBackendRejectsUnderclaimedQDegree(t *testing.T) {
	proof := testFormalBackendProof(t, 8, 32, 4, 600, 12, 540)
	proof.QDegreeBound = proof.RingDegree
	okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, &ConstraintReplay{
		RowCount:   1,
		FparCoeffs: [][]uint64{{0}},
		Eval: func(evalIdx uint64, rowVals []uint64) ([]uint64, []uint64, error) {
			return []uint64{0}, nil, nil
		},
	})
	if err == nil || okEq4 || okSum {
		t.Fatalf("underclaimed Q degree accepted: (%v,%v,%v,%v)", okLin, okEq4, okSum, err)
	}
}
