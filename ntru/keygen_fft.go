package ntru

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
)

var keygenFloat64s = cryptoRandFloat64s

// KeygenFFT is the shipped key generation path.
func KeygenFFT(par Params, opts KeygenOpts) (f, g, F, G []int64, err error) {
	if opts.Prec == 0 {
		opts.Prec = 128
	}
	if opts.MaxTrials <= 0 {
		opts.MaxTrials = 10000
	}
	if opts.Alpha <= 0 {
		opts.Alpha = 1.20
	}
	if !opts.UseCRadius && opts.Alpha < 1.0 {
		return nil, nil, nil, nil, fmtError("KeygenFFT: alpha must be ≥ 1")
	}
	if opts.UseCRadius && opts.Radius < 0 {
		return nil, nil, nil, nil, fmtError("KeygenFFT: Radius must be > 0 when UseCRadius is set")
	}
	if par.N <= 0 || (par.N&(par.N-1)) != 0 {
		return nil, nil, nil, nil, fmtError("KeygenFFT: N must be a power of two")
	}

	epar := EmbedParams{Prec: opts.Prec}
	solve := SolveOpts{Prec: opts.Prec, UseCTower: true, Reduce: true}

	envDebug := os.Getenv("NTRU_DEBUG") == "1"
	verbose := opts.Verbose || envDebug
	var tried, failWindow, failInvert, failSolve, failIdent int
	if verbose {
		q := float64(par.Q.Uint64())
		var rad float64
		if opts.UseCRadius {
			rad = math.Sqrt(q) * opts.Radius
		} else {
			rad = math.Sqrt(q) * 0.5 * (opts.Alpha + 1.0/opts.Alpha)
		}
		fmt.Printf("KeygenFFT: start N=%d Q=%s alpha=%.4f useCRadius=%v radius=%.6g rad=%.6g Prec=%d MaxTrials=%d\n",
			par.N, par.Q.String(), opts.Alpha, opts.UseCRadius, opts.Radius, rad, opts.Prec, opts.MaxTrials)
	}

	for trial := 0; trial < opts.MaxTrials; trial++ {
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d sampling radial (useCRadius=%v)\n", trial+1, opts.UseCRadius)
		}
		fi, gi, err := sampleAnnulusCandidate(par, opts, epar)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d decode OK\n", trial+1)
		}

		S, _, _, err := SlotSumsSquared(fi, gi, par, epar)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		half := par.N / 2
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d computed slot sums\n", trial+1)
		}
		if !AlphaWindowOK(S[:half], par.Q.Uint64(), opts.Alpha) {
			failWindow++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=window counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}

		if !IsUnitModQ(Int64ToModQPoly(fi, par), par) {
			failInvert++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=invert counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}

		F, G, err = NTRUSolve(fi, gi, par, solve)
		if err != nil {
			failSolve++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=solve counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}
		if !CheckNTRUIdentity(fi, gi, F, G, par) {
			failIdent++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=ident counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}
		if verbose {
			fmt.Printf("KeygenFFT: success at trial=%d (window=%d invert=%d solve=%d ident=%d)\n", tried+1, failWindow, failInvert, failSolve, failIdent)
		}
		return fi, gi, F, G, nil
	}
	if verbose {
		fmt.Printf("KeygenFFT: FINAL trials=%d window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
	}
	return nil, nil, nil, nil, fmtError("KeygenFFT: no key within MaxTrials and alpha window")
}

func sampleAnnulusCandidate(par Params, opts KeygenOpts, epar EmbedParams) (fInt, gInt []int64, err error) {
	fEval, gEval, err := KeygenRadialFGOpts(par, opts.Alpha, opts.UseCRadius, opts.Radius)
	if err != nil {
		return nil, nil, err
	}
	fFloat, err := ToCoeffFloat(fEval, par, epar)
	if err != nil {
		return nil, nil, err
	}
	gFloat, err := ToCoeffFloat(gEval, par, epar)
	if err != nil {
		return nil, nil, err
	}
	fInt, err = DecodeOdd(fFloat)
	if err != nil {
		return nil, nil, err
	}
	gInt, err = DecodeOdd(gFloat)
	if err != nil {
		return nil, nil, err
	}
	return fInt, gInt, nil
}

// KeygenRadialFGOpts adds the fixed-radius variant used by key generation.
func KeygenRadialFGOpts(par Params, alpha float64, useCRadius bool, cRadius float64) (fEval, gEval EvalVec, err error) {
	if par.N%2 != 0 || par.N <= 0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: N must be positive even")
	}
	if !useCRadius && alpha < 1.0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: alpha must be ≥ 1 (when not using fixed C-radius)")
	}
	if useCRadius && cRadius < 0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: Radius must be >= 0 when UseCRadius is set")
	}

	N := par.N
	half := N / 2
	q := float64(par.Q.Uint64())
	var rad float64
	if useCRadius {
		rad = math.Sqrt(q) * cRadius
	} else {
		rad = math.Sqrt(q) * 0.5 * (alpha + 1.0/alpha)
	}

	// r array of length 3*N/2 with uniform [0,1) from crypto/rand
	r, err := keygenFloat64s(3 * half)
	if err != nil {
		return EvalVec{}, EvalVec{}, err
	}

	f := make([]complex128, N)
	g := make([]complex128, N)

	for i := 0; i < half; i++ {
		af := rad * math.Cos((math.Pi/2.0)*r[i])
		ag := rad * math.Sin((math.Pi/2.0)*r[i])

		thetaF := 2.0 * math.Pi * r[i+half]
		thetaG := 2.0 * math.Pi * r[i+2*half]

		fRe := af * math.Cos(thetaF)
		fIm := af * math.Sin(thetaF)
		gRe := ag * math.Cos(thetaG)
		gIm := ag * math.Sin(thetaG)

		zf := complex(fRe, fIm)
		zg := complex(gRe, gIm)
		f[i] = zf
		g[i] = zg
		j := N - 1 - i
		f[j] = complex(fRe, -fIm)
		g[j] = complex(gRe, -gIm)
	}

	return EvalVec{V: f}, EvalVec{V: g}, nil
}

// cryptoRandFloat64s returns n independent floats U in [0,1) using crypto/rand.
// Mirrors C's simple_frand: U = uint64 / 2^64.
func cryptoRandFloat64s(n int) ([]float64, error) {
	if n <= 0 {
		return nil, nil
	}
	out := make([]float64, n)
	buf := make([]byte, 8*n)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}
	const inv2p64 = 5.421010862427522e-20 // 2^-64
	for i := 0; i < n; i++ {
		u := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = float64(u) * inv2p64
	}
	return out, nil
}
