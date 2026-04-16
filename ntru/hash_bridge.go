package ntru

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"vSIS-Signature/credential"
	ntrurio "vSIS-Signature/ntru/io"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// ComputeTargetFromSeeds rebuilds the configured hash target in coefficient
// domain from the provided seeds. It returns coefficients centered in
// [-Q/2, Q/2]. Empty relation defaults to the legacy BBS path.
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

// loadBMatrix is a light copy of the helper used by signer/verifier.
func loadBMatrix(path string, ringQ *ring.Ring) ([]*ring.Poly, error) {
	type bjson struct {
		B [][]uint64 `json:"B"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		// Fallback one level up to support subdirectory test runs
		if !filepath.IsAbs(path) {
			raw, err = os.ReadFile(filepath.Join("..", path))
		}
		if err != nil {
			return nil, err
		}
	}
	var bj bjson
	if err = json.Unmarshal(raw, &bj); err != nil {
		return nil, err
	}
	if len(bj.B) != 4 {
		return nil, fmt.Errorf("expected 4 polys in B, got %d", len(bj.B))
	}
	B := make([]*ring.Poly, 4)
	for i := 0; i < 4; i++ {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], bj.B[i])
		ringQ.NTT(p, p)
		B[i] = p
	}
	return B, nil
}
