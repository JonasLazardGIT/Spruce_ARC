package ntru

import (
	"errors"
	"fmt"

	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/internal/hash"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// ComputeTargetFromSeeds rebuilds the configured hash target in coefficient
// domain from the provided seeds. It returns coefficients centered in
// [-Q/2, Q/2]. Empty relation defaults to the BBS path.
func ComputeTargetFromSeeds(pp *ntrurio.SystemParams, Bfile, relation string, mSeed, x0Seed, x1Seed []byte) ([]int64, error) {
	if pp == nil {
		return nil, errors.New("nil params")
	}
	ringQ, err := ring.NewRing(pp.N, []uint64{pp.Q})
	if err != nil {
		return nil, err
	}
	B, err := loadBMatrix(Bfile, ringQ)
	if err != nil {
		return nil, err
	}
	mkprng, _ := utils.NewKeyedPRNG(mSeed)
	x0prng, _ := utils.NewKeyedPRNG(x0Seed)
	x1prng, _ := utils.NewKeyedPRNG(x1Seed)
	m := ringQ.NewPoly()
	x0 := ringQ.NewPoly()
	x1 := ringQ.NewPoly()
	if err := FillPolyBoundedFromPRNG(ringQ, mkprng, m, CurrentSeedPolyBounds()); err != nil {
		return nil, fmt.Errorf("sample m from seed: %w", err)
	}
	if err := FillPolyBoundedFromPRNG(ringQ, x0prng, x0, CurrentSeedPolyBounds()); err != nil {
		return nil, fmt.Errorf("sample x0 from seed: %w", err)
	}
	if err := FillPolyBoundedFromPRNG(ringQ, x1prng, x1, CurrentSeedPolyBounds()); err != nil {
		return nil, fmt.Errorf("sample x1 from seed: %w", err)
	}
	relation = credential.NormalizeHashRelation(relation)
	if relation == "" {
		relation = credential.HashRelationBBS
	}
	var tNTT *ring.Poly
	switch relation {
	case credential.HashRelationBBS:
		tNTT, err = vsishash.ComputeBBSHash(ringQ, B, m, x0, x1)
	case credential.HashRelationBBTran:
		tNTT, err = vsishash.ComputeBBTranHash(ringQ, B, m, x0, x1)
	default:
		return nil, fmt.Errorf("invalid hash relation %q", relation)
	}
	if err != nil {
		return nil, err
	}
	ringQ.InvNTT(tNTT, tNTT)
	coeffs := make([]int64, pp.N)
	q := int64(pp.Q)
	half := q / 2
	for i, c := range tNTT.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		coeffs[i] = v
	}
	return coeffs, nil
}

// loadBMatrix uses the same strict v3 reader as setup, issuance, and showing.
// Diagnostic seed profiles must not regain the retired four-row B shape or a
// parent-directory fallback merely because they are not part of issuance.
func loadBMatrix(path string, ringQ *ring.Ring) ([]*ring.Poly, error) {
	meta, err := ntrurio.LoadBMatrixMetadata(path)
	if err != nil {
		return nil, err
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if meta.RingDegree != int(ringQ.N) {
		return nil, fmt.Errorf("b ring degree=%d want=%d", meta.RingDegree, ringQ.N)
	}
	if meta.X0Len != 1 {
		return nil, fmt.Errorf("seed-derived diagnostic target supports x0_len=1, got canonical issuance x0_len=%d", meta.X0Len)
	}
	B := make([]*ring.Poly, len(meta.B))
	for i := range meta.B {
		p := ringQ.NewPoly()
		for j, coeff := range meta.B[i] {
			if coeff >= ringQ.Modulus[0] {
				return nil, fmt.Errorf("b[%d][%d]=%d is not canonical modulo %d", i, j, coeff, ringQ.Modulus[0])
			}
		}
		copy(p.Coeffs[0], meta.B[i])
		ringQ.NTT(p, p)
		B[i] = p
	}
	return B, nil
}
