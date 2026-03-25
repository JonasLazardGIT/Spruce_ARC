package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildCredentialRows maps credential witnesses into the row order used by pre-sign and showing.
func buildCredentialRows(ringQ *ring.Ring, wit WitnessInputs, opts SimOpts) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, ncols int, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	opts.applyDefaults()
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols

	require := func(vec []*ring.Poly, name string) error {
		if len(vec) == 0 {
			return fmt.Errorf("missing witness row %s", name)
		}
		return nil
	}
	if err = require(wit.M1, "M1"); err != nil {
		return
	}
	if err = require(wit.M2, "M2"); err != nil {
		return
	}
	if err = require(wit.RU0, "RU0"); err != nil {
		return
	}
	if err = require(wit.RU1, "RU1"); err != nil {
		return
	}
	if err = require(wit.R, "R"); err != nil {
		return
	}
	if err = require(wit.R0, "R0"); err != nil {
		return
	}
	if err = require(wit.R1, "R1"); err != nil {
		return
	}
	if err = require(wit.K0, "K0"); err != nil {
		return
	}
	if err = require(wit.K1, "K1"); err != nil {
		return
	}

	rows = []*ring.Poly{
		wit.M1[0],
		wit.M2[0],
		wit.RU0[0],
		wit.RU1[0],
		wit.R[0],
		wit.R0[0],
		wit.R1[0],
		wit.K0[0],
		wit.K1[0],
	}
	// Some pre-sign callers still provide T as an internal witness row.
	if len(wit.T) > 0 {
		tPoly := ringQ.NewPoly()
		if len(wit.T) > len(tPoly.Coeffs[0]) {
			err = fmt.Errorf("t length %d exceeds ring dimension %d", len(wit.T), len(tPoly.Coeffs[0]))
			return
		}
		q := int64(ringQ.Modulus[0])
		for i := range wit.T {
			v := wit.T[i] % q
			if v < 0 {
				v += q
			}
			tPoly.Coeffs[0][i] = uint64(v)
		}
		rows = append(rows, tPoly)
	}

	if len(wit.U) > 0 {
		rows = append(rows, wit.U...)
	}

	// Default-safe non-signature coefficient-bound scaffolding for pre-sign:
	// append extra NTT blocks (b>=1) and coefficient rows (all b>=0) for
	// message/randomness/carry families, mirroring showing-mode discipline.
	//
	// Families over base row layout:
	//   - message:    rows 0,1
	//   - randomness: rows 2..6
	//   - carry:      rows 7,8
	nonSigBlocks := 0
	msgCompCount := 0
	msgExtraNTTBase := -1
	msgCoeffBase := -1
	rndCompCount := 0
	rndExtraNTTBase := -1
	rndCoeffBase := -1
	x1CompCount := 0
	x1ExtraNTTBase := -1
	x1CoeffBase := -1

	if len(rows) >= 9 && ncols > 0 && ringQ.N%ncols == 0 {
		blocks := ringQ.N / ncols
		if blocks > 0 {
			var explicitOmega []uint64
			if opts.DomainMode == DomainModeExplicit {
				nLeaves := opts.NLeaves
				if nLeaves <= 0 {
					nLeaves = int(ringQ.N)
				}
				derivedOmega, _, derr := deriveExplicitDomain(ringQ.Modulus[0], nLeaves, ncols, opts.Ell)
				if derr != nil {
					err = fmt.Errorf("pre-sign non-signature bounds explicit omega: %w", derr)
					return
				}
				explicitOmega = derivedOmega
			}
			polyFromHead := func(head []uint64) *ring.Poly {
				if opts.DomainMode == DomainModeExplicit {
					pNTT := BuildThetaPrime(ringQ, head, explicitOmega)
					coeff := ringQ.NewPoly()
					ringQ.InvNTT(pNTT, coeff)
					return coeff
				}
				pNTT := ringQ.NewPoly()
				q := ringQ.Modulus[0]
				for i := 0; i < ncols && i < len(head); i++ {
					pNTT.Coeffs[0][i] = head[i] % q
				}
				out := ringQ.NewPoly()
				ringQ.InvNTT(pNTT, out)
				return out
			}
			baseRowCount := len(rows)
			type familySpec struct {
				count        int
				block0Base   int
				extraNTTBase *int
				coeffBase    *int
				componentOut *int
			}
			families := []familySpec{
				{count: 2, block0Base: 0, extraNTTBase: &msgExtraNTTBase, coeffBase: &msgCoeffBase, componentOut: &msgCompCount},
				{count: 5, block0Base: 2, extraNTTBase: &rndExtraNTTBase, coeffBase: &rndCoeffBase, componentOut: &rndCompCount},
				{count: 2, block0Base: 7, extraNTTBase: &x1ExtraNTTBase, coeffBase: &x1CoeffBase, componentOut: &x1CompCount},
			}
			for _, fam := range families {
				if fam.block0Base < 0 || fam.block0Base+fam.count > baseRowCount {
					continue
				}
				*fam.componentOut = fam.count
				fullNTT := make([]*ring.Poly, fam.count)
				coeffSrc := make([][]uint64, fam.count)
				for j := 0; j < fam.count; j++ {
					src := rows[fam.block0Base+j]
					fullNTT[j] = ringQ.NewPoly()
					ring.Copy(src, fullNTT[j])
					ringQ.NTT(fullNTT[j], fullNTT[j])
					coeffSrc[j] = append([]uint64(nil), src.Coeffs[0]...)
				}

				// Normalize block-0 rows to the same head-as-Ω representation used
				// for extra NTT blocks, so replayed NTT↔coef bridge identities
				// reference a coherent row encoding in explicit-domain mode.
				for j := 0; j < fam.count; j++ {
					head0 := append([]uint64(nil), fullNTT[j].Coeffs[0][:ncols]...)
					rows[fam.block0Base+j] = polyFromHead(head0)
				}

				*fam.extraNTTBase = len(rows)
				for b := 1; b < blocks; b++ {
					start := b * ncols
					end := start + ncols
					for j := 0; j < fam.count; j++ {
						head := append([]uint64(nil), fullNTT[j].Coeffs[0][start:end]...)
						rows = append(rows, polyFromHead(head))
					}
				}

				*fam.coeffBase = len(rows)
				for b := 0; b < blocks; b++ {
					start := b * ncols
					end := start + ncols
					for j := 0; j < fam.count; j++ {
						head := append([]uint64(nil), coeffSrc[j][start:end]...)
						rows = append(rows, polyFromHead(head))
					}
				}
			}
			if msgCompCount+rndCompCount+x1CompCount > 0 {
				nonSigBlocks = blocks
			}
		}
	}

	// Build row inputs (heads) in evaluation domain (Ω).
	rowInputs = buildRowInputs(ringQ, rows, ncols)

	// Layout: we only set counts; range/chain bases unused for credential mode.
	witnessCount = len(rows)
	hasBaseIdx := len(rows) >= 9
	layout = RowLayout{
		SigCount:           witnessCount,
		MsgCount:           0,
		RndCount:           0,
		HasExplicitBaseIdx: hasBaseIdx,
		IdxM1:              0,
		IdxM2:              1,
		IdxRU0:             2,
		IdxRU1:             3,
		IdxR:               4,
		IdxR0:              5,
		IdxR1:              6,
		IdxK0:              7,
		IdxK1:              8,
		IdxT:               -1,
		IdxUBase:           -1,
		NonSigBlocks:       nonSigBlocks,
		MsgCompCount:       msgCompCount,
		MsgExtraNTTBase:    msgExtraNTTBase,
		MsgCoeffBase:       msgCoeffBase,
		RndCompCount:       rndCompCount,
		RndExtraNTTBase:    rndExtraNTTBase,
		RndCoeffBase:       rndCoeffBase,
		X1CompCount:        x1CompCount,
		X1ExtraNTTBase:     x1ExtraNTTBase,
		X1CoeffBase:        x1CoeffBase,
	}

	// Masks start after witness rows.
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount > 0 {
		zeroHead := make([]uint64, ncols)
		for i := 0; i < maskRowCount; i++ {
			rows = append(rows, ringQ.NewPoly())
			rowInputs = append(rowInputs, lvcs.RowInput{Head: zeroHead})
		}
	}

	// DECS params: degree bound must be explicit (paper Eq.(3)), but callers
	// may still rely on the ncols+ell-1 heuristic. Do not clip silently: if the
	// Degree bound exceeds the ring dimension.
	maxDegree := opts.DQOverride
	if maxDegree <= 0 {
		maxDegree = ncols + opts.Ell - 1
	}
	if maxDegree < 0 || maxDegree >= int(ringQ.N) {
		err = fmt.Errorf("invalid degree bound %d (ringN=%d)", maxDegree, ringQ.N)
		return
	}
	decsParams = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
	return
}
