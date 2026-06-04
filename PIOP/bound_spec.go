package PIOP

import "fmt"

// LinfSpec holds parameters for the membership-chain ℓ∞ bound proof.
type LinfSpec struct {
	Q   uint64 // modulus q
	R   uint64 // radix R (must satisfy 1 < R < q)
	W   int    // metadata: ceil(log2(R)) for display
	L   int    // number of digits
	Ell int    // blinding points per row
	// UsesAbsRow controls the reconstruction form:
	//   - true:  |P| chain with M row and constraints {M^2-P^2, M-recon(D)}
	//   - false: signed chain without M row and constraint {P-recon(D)}
	UsesAbsRow bool
	LSDLo      int        // least-significant digit minimum (balanced)
	LSDHi      int        // least-significant digit maximum (balanced)
	DigitLo    []int      // per-digit lower bound
	DigitHi    []int      // per-digit upper bound
	DMax       []int      // per-digit bound (balanced for digit 0, unsigned otherwise)
	PDi        [][]uint64 // membership polynomial coefficients per digit
	RPows      []uint64   // R^i mod q for i∈[0,L)
	MaxAbs     uint64     // largest magnitude representable by the gadget
}

// buildBalancedMembershipPoly returns ∏_{u=lo}^{hi} (X - u) with roots lifted to F_q.
func buildBalancedMembershipPoly(q uint64, lo, hi int) []uint64 {
	if lo > hi {
		return []uint64{1}
	}
	P := []uint64{1}
	for u := lo; u <= hi; u++ {
		var root uint64
		if u >= 0 {
			root = uint64(u) % q
		} else {
			root = q - uint64(-u)%q
		}
		P = polyMul(P, []uint64{modSub(0, root, q), 1}, q)
	}
	return P
}

func buildMembershipPolyRange(q uint64, lo, hi int) []uint64 {
	if lo > hi {
		return []uint64{1}
	}
	P := []uint64{1}
	for u := lo; u <= hi; u++ {
		var root uint64
		if u >= 0 {
			root = uint64(u) % q
		} else {
			root = q - uint64(-u)%q
		}
		P = polyMul(P, []uint64{modSub(0, root, q), 1}, q)
	}
	return P
}

// NewSignedLinfChainSpecRadix builds a signed-digit decomposition gadget with no
// auxiliary |P| row: P = Σ_i R^i·D_i and D_i constrained by per-digit ranges.
//
// Default digit ranges are balanced and contain exactly R values:
//   - odd R:  [-(R-1)/2, +(R-1)/2]
//   - even R: [-R/2, R/2-1]
//
// Optional caps tighten |digit_i|: if caps[i] > 0 then digit i is constrained
// to [-caps[i], caps[i]].
func NewSignedLinfChainSpecRadix(q uint64, R uint64, L, ell int, beta uint64, caps []int) LinfSpec {
	if (q & 1) == 0 {
		panic("q must be odd")
	}
	if ell < 1 {
		panic("ell must be ≥ 1")
	}
	if L < 1 {
		panic("L must be ≥ 1")
	}
	if R <= 1 {
		panic("R must be ≥ 2")
	}
	if R >= q {
		panic("R >= q")
	}

	dMax := make([]int, L)
	digitLo := make([]int, L)
	digitHi := make([]int, L)
	pols := make([][]uint64, L)

	var defaultLo, defaultHi int
	if R%2 == 0 {
		defaultLo = -int(R / 2)
		defaultHi = int(R/2) - 1
	} else {
		half := int((R - 1) / 2)
		defaultLo = -half
		defaultHi = half
	}
	defaultCap := defaultHi
	if -defaultLo > defaultCap {
		defaultCap = -defaultLo
	}
	for i := 0; i < L; i++ {
		lo := defaultLo
		hi := defaultHi
		if i < len(caps) && caps[i] > 0 {
			cap := caps[i]
			if cap > defaultCap {
				panic(fmt.Sprintf("signed linf chain: cap for digit %d exceeds balanced digit bound (%d > %d)", i, cap, defaultCap))
			}
			lo = -cap
			hi = cap
		}
		if lo > hi {
			panic(fmt.Sprintf("signed linf chain: invalid digit range for %d: [%d,%d]", i, lo, hi))
		}
		digitLo[i] = lo
		digitHi[i] = hi
		absLo := lo
		if absLo < 0 {
			absLo = -absLo
		}
		absHi := hi
		if absHi < 0 {
			absHi = -absHi
		}
		dMax[i] = absLo
		if absHi > dMax[i] {
			dMax[i] = absHi
		}
		pols[i] = buildMembershipPolyRange(q, lo, hi)
	}

	maxAbs := uint64(0)
	weight := uint64(1)
	for i := 0; i < L; i++ {
		term := uint64(dMax[i]) * weight
		if dMax[i] > 0 && term/uint64(dMax[i]) != weight {
			panic("signed linf chain: overflow while computing digit capacity")
		}
		if maxAbs > ^uint64(0)-term {
			panic("signed linf chain: maxAbs overflow")
		}
		maxAbs += term
		if i+1 < L {
			if weight > ^uint64(0)/R {
				panic("signed linf chain: R^i exceeds uint64 range")
			}
			weight *= R
		}
	}
	if beta > maxAbs {
		panic(fmt.Sprintf("signed linf chain: beta=%d exceeds representable range %d for R=%d and L=%d", beta, maxAbs, R, L))
	}

	rPows := make([]uint64, L)
	rPows[0] = 1 % q
	for i := 1; i < L; i++ {
		rPows[i] = (rPows[i-1] * (R % q)) % q
	}
	w := bitsForRadix(R)
	return LinfSpec{
		Q: q, R: R, W: w, L: L, Ell: ell, UsesAbsRow: false,
		LSDLo: digitLo[0], LSDHi: digitHi[0],
		DigitLo: digitLo, DigitHi: digitHi,
		DMax: dMax, PDi: pols, RPows: rPows, MaxAbs: maxAbs,
	}
}

func bitsForRadix(R uint64) int {
	if R <= 1 {
		return 0
	}
	w := 0
	pow := uint64(1)
	for pow < R {
		pow <<= 1
		w++
	}
	return w
}

// RangeMembershipSpec holds the vanishing polynomial for [-B, +B].
type RangeMembershipSpec struct {
	B      int
	Coeffs []uint64 // coefficients of P_B(X) in F_q, low-to-high degree
}

// NewRangeMembershipSpec builds P_B(X) = ∏_{i=-B}^B (X - ⟨i⟩_q).
func NewRangeMembershipSpec(q uint64, B int) RangeMembershipSpec {
	if B < 0 {
		panic("B must be >= 0")
	}
	roots := make([]uint64, 0, 2*B+1)
	for i := -B; i <= B; i++ {
		var r uint64
		if i >= 0 {
			r = uint64(i) % q
		} else {
			neg := uint64(-i) % q
			r = (q - neg) % q
		}
		roots = append(roots, r)
	}
	coeffs := []uint64{1}
	for _, r := range roots {
		next := make([]uint64, len(coeffs)+1)
		for d := range coeffs {
			next[d+1] = (next[d+1] + coeffs[d]) % q
			next[d] = (next[d] + q - (coeffs[d]*r)%q) % q
		}
		coeffs = next
	}
	return RangeMembershipSpec{B: B, Coeffs: coeffs}
}
