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

	if opts.DomainMode == DomainModeExplicit {
		pcsNCols := resolvePCSNCols(opts, ncols)
		omegaWitness, omegaErr := deriveExplicitWitnessOmega(ringQ.Modulus[0], opts.NLeaves, ncols, pcsNCols, opts.Ell)
		if omegaErr != nil {
			err = fmt.Errorf("derive explicit witness omega: %w", omegaErr)
			return
		}
		normalized := make([]*ring.Poly, len(rows))
		for i, row := range rows {
			if row == nil {
				err = fmt.Errorf("nil credential row %d", i)
				return
			}
			rowNTT := ringQ.NewPoly()
			ring.Copy(row, rowNTT)
			ringQ.NTT(rowNTT, rowNTT)
			head := append([]uint64(nil), rowNTT.Coeffs[0][:len(omegaWitness)]...)
			thetaNTT := BuildThetaPrime(ringQ, head, omegaWitness)
			thetaCoeff := ringQ.NewPoly()
			ringQ.InvNTT(thetaNTT, thetaCoeff)
			normalized[i] = thetaCoeff
		}
		rows = normalized
	}

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
