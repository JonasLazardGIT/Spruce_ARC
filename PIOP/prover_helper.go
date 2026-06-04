package PIOP

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// -----------------------------------------------------------------------------
//  field helpers (mod q)
// -----------------------------------------------------------------------------

func randUint64Mod(q uint64) uint64 {
	var bound uint64 = ^uint64(0) - (^uint64(0) % q)
	for {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			panic("randUint64Mod: entropy read failed: " + err.Error())
		}
		v := binary.LittleEndian.Uint64(buf[:])
		if v < bound {
			return v % q
		}
	}
}

// modAddReduced returns (a+b) mod q for reduced inputs a,b < q.
func modAddReduced(a, b, q uint64) uint64 {
	s, c := bits.Add64(a, b, 0)
	if c == 1 || s >= q {
		s -= q
	}
	return s
}

// modSubReduced returns (a-b) mod q for reduced inputs a,b < q.
func modSubReduced(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + q - b
}

// modMulReduced returns (a*b) mod q for reduced inputs a,b < q.
func modMulReduced(a, b, q uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, q)
	return rem
}

// modAdd returns (a+b) mod q.
func modAdd(a, b, q uint64) uint64 {
	if a >= q {
		a %= q
	}
	if b >= q {
		b %= q
	}
	return modAddReduced(a, b, q)
}

// modSub returns (a-b) mod q.
func modSub(a, b, q uint64) uint64 {
	if a >= q {
		a %= q
	}
	if b >= q {
		b %= q
	}
	return modSubReduced(a, b, q)
}

// modMul returns (a*b) mod q.
func modMul(a, b, q uint64) uint64 {
	if a >= q {
		a %= q
	}
	if b >= q {
		b %= q
	}
	return modMulReduced(a, b, q)
}

// modInv returns a^{‑1} mod q (q must be prime).
func modInv(a, q uint64) uint64 {
	return ring.ModExp(a, q-2, q) // Fermat since q is prime in all params used.
}

// -----------------------------------------------------------------------------
// Fiat–Shamir: tiny deterministic PRF stream (SHA‑256(counter || seed))
// -----------------------------------------------------------------------------

type fsRNG struct {
	seed [32]byte
	ctr  uint64
}

// KScalar encodes an element of K ≅ F^θ in φ^{-1}-coordinates.
type KScalar []uint64

// KVec is a convenience alias for a slice of K-scalars.
type KVec []KScalar

// KMat models a matrix whose entries live in K.
type KMat [][]KScalar

// KPoly represents a polynomial in K[X] via limb-wise coefficient slices.
// Limbs[j][k] stores the j-th limb of the X^k coefficient. Degree tracks the
// highest non-zero coefficient index (bounded by the construction input).
type KPoly struct {
	Limbs  [][]uint64
	Degree int
}

// --- Helpers to assemble QK from MK and {Γ′_K, γ′_K} on top of F-polys ---
// addScaledFPolyToKPoly: dst += (Φ(gK) * F[X]) where F has coeffs in F_q.
// Multiplication by an F element scales every limb by that element.
func addScaledFPolyToKPoly(r *ring.Ring, K *kf.Field, dst *KPoly, gK KScalar, F *ring.Poly) {
	if dst == nil || F == nil || K == nil {
		return
	}
	coeff := r.NewPoly()
	r.InvNTT(F, coeff)
	q := r.Modulus[0]
	theta := K.Theta
	if len(dst.Limbs) < theta {
		theta = len(dst.Limbs)
	}
	if len(gK) < theta {
		theta = len(gK)
	}
	if theta == 0 {
		return
	}
	var gStack [16]uint64
	var gReduced []uint64
	if theta <= len(gStack) {
		gReduced = gStack[:theta]
	} else {
		gReduced = make([]uint64, theta)
	}
	for j := 0; j < theta; j++ {
		g := gK[j]
		if g >= q {
			g %= q
		}
		gReduced[j] = g
	}
	for k, a := range coeff.Coeffs[0] {
		if a >= q {
			a %= q
		}
		if a == 0 {
			continue
		}
		for j := 0; j < theta; j++ {
			dst.Limbs[j][k] = modAddReduced(dst.Limbs[j][k], modMulReduced(gReduced[j], a, q), q)
		}
		if k > dst.Degree {
			dst.Degree = k
		}
	}
}

func ensureKPolyCapacity(kp *KPoly, need int) {
	if kp == nil || need <= 0 {
		return
	}
	for j := range kp.Limbs {
		if len(kp.Limbs[j]) < need {
			ext := make([]uint64, need)
			copy(ext, kp.Limbs[j])
			kp.Limbs[j] = ext
		}
	}
}

func addShiftedScaledFCoeffsToKPoly(K *kf.Field, dst *KPoly, gK KScalar, shift int, coeffs []uint64) {
	if dst == nil || K == nil || shift < 0 || len(coeffs) == 0 {
		return
	}
	q := K.Q
	theta := K.Theta
	if len(dst.Limbs) < theta {
		theta = len(dst.Limbs)
	}
	if len(gK) < theta {
		theta = len(gK)
	}
	if theta == 0 {
		return
	}
	var gStack [16]uint64
	var gReduced []uint64
	if theta <= len(gStack) {
		gReduced = gStack[:theta]
	} else {
		gReduced = make([]uint64, theta)
	}
	for j := 0; j < theta; j++ {
		g := gK[j]
		if g >= q {
			g %= q
		}
		gReduced[j] = g
	}
	ensureKPolyCapacity(dst, shift+len(coeffs))
	for k, a := range coeffs {
		if a >= q {
			a %= q
		}
		if a == 0 {
			continue
		}
		pos := shift + k
		for j := 0; j < theta; j++ {
			dst.Limbs[j][pos] = modAddReduced(dst.Limbs[j][pos], modMulReduced(gReduced[j], a, q), q)
		}
		if pos > dst.Degree {
			dst.Degree = pos
		}
	}
}

func addScaledFCoeffsToKPoly(K *kf.Field, dst *KPoly, gK KScalar, coeffs []uint64) {
	addShiftedScaledFCoeffsToKPoly(K, dst, gK, 0, coeffs)
}

// addShiftedScaledFPolyToKPoly adds (Φ(gK) * X^shift * F[X]) into dst.
// This is the coefficient-domain analogue of multiplying F by a low-degree
// K[X] polynomial whose coefficient at X^shift is gK.
func addShiftedScaledFPolyToKPoly(r *ring.Ring, K *kf.Field, dst *KPoly, gK KScalar, shift int, F *ring.Poly, allowWrap bool) {
	if dst == nil || F == nil || K == nil {
		return
	}
	if shift < 0 {
		panic("negative shift")
	}
	coeff := r.NewPoly()
	r.InvNTT(F, coeff)
	q := r.Modulus[0]
	theta := K.Theta
	if len(dst.Limbs) < theta {
		theta = len(dst.Limbs)
	}
	if len(gK) < theta {
		theta = len(gK)
	}
	if theta == 0 {
		return
	}
	var gStack [16]uint64
	var gReduced []uint64
	if theta <= len(gStack) {
		gReduced = gStack[:theta]
	} else {
		gReduced = make([]uint64, theta)
	}
	for j := 0; j < theta; j++ {
		g := gK[j]
		if g >= q {
			g %= q
		}
		gReduced[j] = g
	}
	if !allowWrap {
		ensureKPolyCapacity(dst, shift+len(coeff.Coeffs[0]))
	}
	limit := len(dst.Limbs[0])
	for k, a := range coeff.Coeffs[0] {
		if a >= q {
			a %= q
		}
		if a == 0 {
			continue
		}
		pos := shift + k
		if pos >= limit {
			if !allowWrap {
				ensureKPolyCapacity(dst, pos+1)
				limit = len(dst.Limbs[0])
			}
			wraps := pos / limit
			pos = pos % limit
			neg := wraps%2 == 1
			for j := 0; j < theta; j++ {
				term := modMulReduced(gReduced[j], a, q)
				if neg {
					dst.Limbs[j][pos] = modSubReduced(dst.Limbs[j][pos], term, q)
				} else {
					dst.Limbs[j][pos] = modAddReduced(dst.Limbs[j][pos], term, q)
				}
			}
			if pos > dst.Degree {
				dst.Degree = pos
			}
			continue
		}
		for j := 0; j < theta; j++ {
			dst.Limbs[j][pos] = modAddReduced(dst.Limbs[j][pos], modMulReduced(gReduced[j], a, q), q)
		}
		if pos > dst.Degree {
			dst.Degree = pos
		}
	}
}

// deepCopyKPoly returns a copy of kp.
func deepCopyKPoly(kp *KPoly) *KPoly {
	if kp == nil {
		return nil
	}
	out := &KPoly{Degree: kp.Degree, Limbs: make([][]uint64, len(kp.Limbs))}
	for j := range kp.Limbs {
		out.Limbs[j] = append([]uint64(nil), kp.Limbs[j]...)
	}
	return out
}

// BuildQK: Q_i(X) = M_i(X) + Σ_t Γ′_{i,t}·Fpar_t(X) + Σ_u γ′_{i,u}·Fagg_u(X) in K[X].
func BuildQK(
	r *ring.Ring,
	domainMode DomainMode,
	K *kf.Field,
	MK []*KPoly, Fpar, Fagg []*ring.Poly,
	FparCoeffs, FaggCoeffs [][]uint64,
	GammaPrimeK [][][]KScalar, GammaAggK [][]KScalar,
) []*KPoly {
	if K == nil {
		return nil
	}
	rho := len(MK)
	out := make([]*KPoly, rho)
	for i := 0; i < rho; i++ {
		qi := deepCopyKPoly(MK[i])
		if qi == nil {
			qi = newZeroKPoly(K.Theta, int(r.N))
		}
		allowWrap := false
		for j := range Fpar {
			var coeffs []uint64
			if j < len(FparCoeffs) && len(FparCoeffs[j]) > 0 {
				coeffs = FparCoeffs[j]
			}
			if i < len(GammaPrimeK) && j < len(GammaPrimeK[i]) {
				poly := GammaPrimeK[i][j]
				for shift := range poly {
					switch {
					case len(coeffs) > 0:
						addShiftedScaledFCoeffsToKPoly(K, qi, poly[shift], shift, coeffs)
					case Fpar[j] != nil:
						addShiftedScaledFPolyToKPoly(r, K, qi, poly[shift], shift, Fpar[j], allowWrap)
					}
				}
			}
		}
		for j := range Fagg {
			var coeffs []uint64
			if j < len(FaggCoeffs) && len(FaggCoeffs[j]) > 0 {
				coeffs = FaggCoeffs[j]
			}
			if i < len(GammaAggK) && j < len(GammaAggK[i]) {
				switch {
				case len(coeffs) > 0:
					addScaledFCoeffsToKPoly(K, qi, GammaAggK[i][j], coeffs)
				case Fagg[j] != nil:
					addScaledFPolyToKPoly(r, K, qi, GammaAggK[i][j], Fagg[j])
				}
			}
		}
		out[i] = qi
	}
	return out
}

func firstLimbCoeffs(kp *KPoly, q uint64) []uint64 {
	if kp == nil || len(kp.Limbs) == 0 {
		return nil
	}
	limb := kp.Limbs[0]
	if len(limb) == 0 {
		return []uint64{0}
	}
	deg := kp.Degree
	if deg < 0 {
		return []uint64{0}
	}
	if deg >= len(limb) {
		deg = len(limb) - 1
	}
	out := make([]uint64, deg+1)
	for i := 0; i <= deg; i++ {
		out[i] = limb[i] % q
	}
	return trimPoly(out, q)
}

// newFSRNG derives a PRF seed from a label and arbitrary transcript material.
func newFSRNG(label string, material ...[]byte) *fsRNG {
	h := sha256.New()
	h.Write([]byte(label))
	for _, m := range material {
		h.Write(m)
	}
	var s [32]byte
	copy(s[:], h.Sum(nil))
	return &fsRNG{seed: s}
}

func (r *fsRNG) nextU64() uint64 {
	var in [40]byte
	copy(in[:32], r.seed[:])
	binary.LittleEndian.PutUint64(in[32:], r.ctr)
	sum := sha256.Sum256(in[:])
	r.ctr++
	return binary.LittleEndian.Uint64(sum[:])
}

// Helpers to serialize inputs for FS binding.
func bytesU64Vec(v []uint64) []byte {
	out := make([]byte, 8*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint64(out[8*i:], x)
	}
	return out
}

func bytesU64Mat(M [][]uint64) []byte {
	total := 0
	for i := range M {
		total += len(M[i])
	}
	out := make([]byte, 8*total)
	off := 0
	for i := range M {
		for j := range M[i] {
			binary.LittleEndian.PutUint64(out[off:], M[i][j])
			off += 8
		}
	}
	return out
}

func bytesFromKScalarMat(M [][]KScalar) []byte {
	total := 0
	for i := range M {
		for j := range M[i] {
			total += len(M[i][j])
		}
	}
	out := make([]byte, 8*total)
	off := 0
	for i := range M {
		for j := range M[i] {
			for k := range M[i][j] {
				binary.LittleEndian.PutUint64(out[off:], M[i][j][k])
				off += 8
			}
		}
	}
	return out
}

func bytesFromUint64Tensor3(tensor [][][]uint64) []byte {
	total := 0
	for i := range tensor {
		for j := range tensor[i] {
			total += len(tensor[i][j])
		}
	}
	out := make([]byte, 8*total)
	off := 0
	for i := range tensor {
		for j := range tensor[i] {
			for k := range tensor[i][j] {
				binary.LittleEndian.PutUint64(out[off:], tensor[i][j][k])
				off += 8
			}
		}
	}
	return out
}

func bytesFromKScalarTensor3(tensor [][][]KScalar) []byte {
	total := 0
	for i := range tensor {
		for j := range tensor[i] {
			for k := range tensor[i][j] {
				total += len(tensor[i][j][k])
			}
		}
	}
	out := make([]byte, 8*total)
	off := 0
	for i := range tensor {
		for j := range tensor[i] {
			for k := range tensor[i][j] {
				for t := range tensor[i][j][k] {
					binary.LittleEndian.PutUint64(out[off:], tensor[i][j][k][t])
					off += 8
				}
			}
		}
	}
	return out
}

// sampleFSMatrix(rows × cols) with entries in F_q.
func sampleFSMatrix(rows, cols int, q uint64, rng *fsRNG) [][]uint64 {
	M := make([][]uint64, rows)
	for i := 0; i < rows; i++ {
		M[i] = make([]uint64, cols)
		for j := 0; j < cols; j++ {
			M[i][j] = rng.nextU64() % q
		}
	}
	return M
}

// sampleFSPolyTensor samples a rows×cols tensor of polynomials in F[X] with
// coefficient support < nCoeffs. Each entry is a coefficient slice of length
// nCoeffs (degree ≤ nCoeffs-1).
func sampleFSPolyTensor(rows, cols, nCoeffs int, q uint64, rng *fsRNG) [][][]uint64 {
	if rows < 0 || cols < 0 || nCoeffs <= 0 {
		return nil
	}
	out := make([][][]uint64, rows)
	for i := 0; i < rows; i++ {
		row := make([][]uint64, cols)
		for j := 0; j < cols; j++ {
			coeffs := make([]uint64, nCoeffs)
			for k := 0; k < nCoeffs; k++ {
				coeffs[k] = rng.nextU64() % q
			}
			row[j] = coeffs
		}
		out[i] = row
	}
	return out
}

// sampleFSMatrixK draws a rows×cols matrix of K elements using θ limbs per entry.
func sampleFSMatrixK(rows, cols, theta int, q uint64, rng *fsRNG) [][]KScalar {
	if rows < 0 || cols < 0 || theta <= 0 {
		return nil
	}
	mat := make([][]KScalar, rows)
	for i := 0; i < rows; i++ {
		row := make([]KScalar, cols)
		for j := 0; j < cols; j++ {
			k := make(KScalar, theta)
			for t := 0; t < theta; t++ {
				k[t] = rng.nextU64() % q
			}
			row[j] = k
		}
		mat[i] = row
	}
	return mat
}

// sampleFSPolyTensorK samples a rows×cols tensor of polynomials in K[X] with
// coefficient support < nCoeffs. Each coefficient is represented as θ limbs.
func sampleFSPolyTensorK(rows, cols, nCoeffs, theta int, q uint64, rng *fsRNG) [][][]KScalar {
	if rows < 0 || cols < 0 || nCoeffs <= 0 || theta <= 0 {
		return nil
	}
	out := make([][][]KScalar, rows)
	for i := 0; i < rows; i++ {
		row := make([][]KScalar, cols)
		for j := 0; j < cols; j++ {
			poly := make([]KScalar, nCoeffs)
			for k := 0; k < nCoeffs; k++ {
				limbs := make(KScalar, theta)
				for t := 0; t < theta; t++ {
					limbs[t] = rng.nextU64() % q
				}
				poly[k] = limbs
			}
			row[j] = poly
		}
		out[i] = row
	}
	return out
}

func kPolyTensorFirstLimb(tensor [][][]KScalar) [][][]uint64 {
	if len(tensor) == 0 {
		return nil
	}
	out := make([][][]uint64, len(tensor))
	for i := range tensor {
		out[i] = make([][]uint64, len(tensor[i]))
		for j := range tensor[i] {
			poly := tensor[i][j]
			coeffs := make([]uint64, len(poly))
			for k := range poly {
				if len(poly[k]) > 0 {
					coeffs[k] = poly[k][0]
				}
			}
			out[i][j] = coeffs
		}
	}
	return out
}

func sampleFSVectorK(rows, cols, theta int, q uint64, rng *fsRNG) [][]KScalar {
	return sampleFSMatrixK(rows, cols, theta, q, rng)
}

func newZeroKPoly(theta int, coeffLen int) *KPoly {
	if coeffLen <= 0 {
		coeffLen = 1
	}
	limbs := make([][]uint64, theta)
	for j := range limbs {
		limbs[j] = make([]uint64, coeffLen)
	}
	return &KPoly{Limbs: limbs, Degree: -1}
}

func (kp *KPoly) setCoeffK(k int, aLimbs []uint64) {
	for j := range kp.Limbs {
		kp.Limbs[j][k] = aLimbs[j]
	}
	if k > kp.Degree {
		kp.Degree = k
	}
}

func splitKPolysToCoeffRows(polys []*KPoly, theta int, q uint64) [][]uint64 {
	if theta <= 0 || len(polys) == 0 {
		return nil
	}
	out := make([][]uint64, 0, len(polys)*theta)
	for _, kp := range polys {
		for coord := 0; coord < theta; coord++ {
			var row []uint64
			if kp != nil && coord < len(kp.Limbs) {
				row = trimCoeffsCopy(kp.Limbs[coord], q)
			}
			if len(row) == 0 {
				row = []uint64{0}
			}
			out = append(out, row)
		}
	}
	return out
}

func restoreKPolysFromSplitCoeffRows(rows [][]uint64, theta int, q uint64) []*KPoly {
	if theta <= 0 || len(rows) == 0 || len(rows)%theta != 0 {
		return nil
	}
	out := make([]*KPoly, len(rows)/theta)
	for i := range out {
		limbs := make([][]uint64, theta)
		maxDeg := -1
		for coord := 0; coord < theta; coord++ {
			src := rows[i*theta+coord]
			limbs[coord] = trimCoeffsCopy(src, q)
			if deg := maxDegreeFromCoeffs(limbs[coord]); deg > maxDeg {
				maxDeg = deg
			}
		}
		out[i] = &KPoly{Degree: maxDeg, Limbs: limbs}
	}
	return out
}

func equalKPolys(a, b []*KPoly, q uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != b[i] {
				return false
			}
			continue
		}
		theta := len(a[i].Limbs)
		if len(b[i].Limbs) != theta {
			return false
		}
		for coord := 0; coord < theta; coord++ {
			ac := trimCoeffsCopy(a[i].Limbs[coord], q)
			bc := trimCoeffsCopy(b[i].Limbs[coord], q)
			if len(ac) != len(bc) {
				return false
			}
			for j := range ac {
				if ac[j]%q != bc[j]%q {
					return false
				}
			}
		}
	}
	return true
}

func evalKPolyAtKInto(K *kf.Field, dst *kf.Elem, kp *KPoly, e kf.Elem) {
	ensureKElem(K, dst)
	clear(dst.Limb)
	if kp == nil {
		return
	}
	coeff := K.Zero()
	for k := kp.Degree; k >= 0; k-- {
		K.MulInto(dst, *dst, e)
		setKPolyCoeff(K, &coeff, kp, k)
		K.AddInto(dst, *dst, coeff)
		if k == 0 {
			break
		}
	}
}

func evalKScalarPolyAtKInto(K *kf.Field, dst *kf.Elem, coeffs []KScalar, e kf.Elem) {
	ensureKElem(K, dst)
	clear(dst.Limb)
	coeff := K.Zero()
	for i := len(coeffs) - 1; i >= 0; i-- {
		K.MulInto(dst, *dst, e)
		setKCoords(K, &coeff, coeffs[i])
		K.AddInto(dst, *dst, coeff)
		if i == 0 {
			break
		}
	}
}

func ensureKElem(K *kf.Field, dst *kf.Elem) {
	if len(dst.Limb) != K.Theta {
		dst.Limb = make([]uint64, K.Theta)
	}
}

func setKCoords(K *kf.Field, dst *kf.Elem, coords []uint64) {
	ensureKElem(K, dst)
	clear(dst.Limb)
	n := len(coords)
	if n > K.Theta {
		n = K.Theta
	}
	for i := 0; i < n; i++ {
		dst.Limb[i] = coords[i] % K.Q
	}
}

func setKPolyCoeff(K *kf.Field, dst *kf.Elem, kp *KPoly, degree int) {
	ensureKElem(K, dst)
	clear(dst.Limb)
	if kp == nil || degree < 0 {
		return
	}
	theta := K.Theta
	if theta > len(kp.Limbs) {
		theta = len(kp.Limbs)
	}
	for j := 0; j < theta; j++ {
		if degree < len(kp.Limbs[j]) {
			dst.Limb[j] = kp.Limbs[j][degree] % K.Q
		}
	}
}

// maskSamplerParams configures sampling of independent PACS masks M_i of degree
// ≤ maxDeg with the ΣΩ M_i(ω)=0 condition (in F or K depending on the caller).
type maskSamplerParams struct {
	omega  []uint64
	maxDeg int
}

func validateMaskSamplerParams(q uint64, params maskSamplerParams) {
	s := len(params.omega)
	if s == 0 {
		panic("mask sampler: Ω must be non-empty")
	}
	seen := make(map[uint64]struct{}, s)
	for _, w := range params.omega {
		wm := w % q
		if _, ok := seen[wm]; ok {
			panic(fmt.Sprintf("mask sampler: Ω contains duplicate element %d (mod q)", wm))
		}
		seen[wm] = struct{}{}
	}
	if uint64(s) >= q {
		panic(fmt.Sprintf("mask sampler: |Ω| (= %d) must be < q (= %d)", s, q))
	}
}

func maskSamplerS(omega []uint64, dQ int, q uint64) []uint64 {
	S := make([]uint64, dQ+1)
	S[0] = uint64(len(omega)) % q
	if dQ == 0 {
		return S
	}
	powers := make([]uint64, len(omega))
	for k := 1; k <= dQ; k++ {
		sum := uint64(0)
		for j, w := range omega {
			if k == 1 {
				powers[j] = w % q
			} else {
				powers[j] = (powers[j] * w) % q
			}
			sum = modAdd(sum, powers[j], q)
		}
		S[k] = sum
	}
	return S
}

func sampleMaskPolynomialsF(
	ringQ *ring.Ring,
	params maskSamplerParams,
	rho int,
	extra func(i int) uint64,
) []*ring.Poly {
	q := ringQ.Modulus[0]
	validateMaskSamplerParams(q, params)
	if params.maxDeg >= int(ringQ.N) {
		panic(fmt.Sprintf("mask sampler: degree bound %d exceeds ring dimension N=%d; cyclotomic wrap is not supported here", params.maxDeg, ringQ.N))
	}
	S := maskSamplerS(params.omega, params.maxDeg, q)
	invS0 := ring.ModExp(S[0], q-2, q)
	out := make([]*ring.Poly, rho)
	for i := 0; i < rho; i++ {
		sum := uint64(0)
		coeffs := make([]uint64, ringQ.N)
		for k := 1; k <= params.maxDeg; k++ {
			randomCoeff := randUint64Mod(q)
			if k < len(S) {
				sum = modAdd(sum, modMul(randomCoeff, S[k], q), q)
			}
			coeffs[k] = randomCoeff % q
		}
		if extra != nil {
			sum = modAdd(sum, extra(i)%q, q)
		}
		a0 := modMul(modSub(0, sum%q, q), invS0, q)
		coeffs[0] = a0 % q

		p := ringQ.NewPoly()
		copy(p.Coeffs[0], coeffs[:])
		ringQ.NTT(p, p)
		out[i] = p
	}
	return out
}

func sampleMaskPolynomialsFCoeffs(
	q uint64,
	params maskSamplerParams,
	rho int,
	extra func(i int) uint64,
) [][]uint64 {
	validateMaskSamplerParams(q, params)
	S := maskSamplerS(params.omega, params.maxDeg, q)
	invS0 := ring.ModExp(S[0], q-2, q)
	out := make([][]uint64, rho)
	for i := 0; i < rho; i++ {
		sum := uint64(0)
		coeffs := make([]uint64, params.maxDeg+1)
		for k := 1; k <= params.maxDeg; k++ {
			randomCoeff := randUint64Mod(q)
			if k < len(S) {
				sum = modAdd(sum, modMul(randomCoeff, S[k], q), q)
			}
			coeffs[k] = randomCoeff % q
		}
		if extra != nil {
			sum = modAdd(sum, extra(i)%q, q)
		}
		a0 := modMul(modSub(0, sum%q, q), invS0, q)
		coeffs[0] = a0 % q
		out[i] = trimPoly(coeffs, q)
	}
	return out
}

func sampleMaskPolynomialsK(
	ringQ *ring.Ring,
	K *kf.Field,
	params maskSamplerParams,
	rho int,
	extra func(i int) kf.Elem,
) []*KPoly {
	if K == nil {
		return nil
	}
	q := ringQ.Modulus[0]
	validateMaskSamplerParams(q, params)
	S := maskSamplerS(params.omega, params.maxDeg, q)
	invS0 := K.Inv(K.EmbedF(S[0] % q))
	out := make([]*KPoly, rho)
	for i := 0; i < rho; i++ {
		kp := newZeroKPoly(K.Theta, params.maxDeg+1)
		sum := K.Zero()
		for k := 1; k <= params.maxDeg; k++ {
			limbs := make([]uint64, K.Theta)
			for t := 0; t < K.Theta; t++ {
				limbs[t] = randUint64Mod(q)
			}
			coeff := K.Phi(limbs)
			kp.setCoeffK(k, limbs)
			if k < len(S) && S[k]%q != 0 {
				sum = K.Add(sum, K.Mul(coeff, K.EmbedF(S[k]%q)))
			}
		}
		if extra != nil {
			sum = K.Add(sum, extra(i))
		}
		a0 := K.Mul(K.Sub(K.Zero(), sum), invS0)
		kp.setCoeffK(0, K.PhiInv(a0))
		out[i] = kp
	}
	return out
}

// SampleIndependentMaskPolynomials returns rho random polynomials of degree ≤ dQ
// whose evaluations on Ω sum to zero. They are independent from any Fiat–Shamir
// challenges and are used by the LayoutV2 pipeline.
func SampleIndependentMaskPolynomials(
	ringQ *ring.Ring,
	rho, dQ int,
	omega []uint64,
) []*ring.Poly {
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	return sampleMaskPolynomialsF(ringQ, params, rho, nil)
}

// SampleIndependentMaskPolynomialCoeffs returns rho random formal polynomials
// (coeff slices) of degree ≤ dQ with Σ_{ω∈Ω} M_i(ω)=0.
func SampleIndependentMaskPolynomialCoeffs(
	q uint64,
	rho, dQ int,
	omega []uint64,
) [][]uint64 {
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	return sampleMaskPolynomialsFCoeffs(q, params, rho, nil)
}

// SampleIndependentMaskPolynomialsK is the extension-field analogue of
// SampleIndependentMaskPolynomials.
func SampleIndependentMaskPolynomialsK(
	ringQ *ring.Ring,
	K *kf.Field,
	rho, dQ int,
	omega []uint64,
) []*KPoly {
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	return sampleMaskPolynomialsK(ringQ, K, params, rho, nil)
}

// -----------------------------------------------------------------------------
//  polynomial helpers
// -----------------------------------------------------------------------------

// polyMul naive O(n²)  – sufficient for n ≤ 64.
func polyMul(a, b []uint64, q uint64) []uint64 {
	if len(a) == 0 || len(b) == 0 {
		return []uint64{0}
	}
	out := make([]uint64, len(a)+len(b)-1)
	for i, av := range a {
		if av >= q {
			av %= q
		}
		if av == 0 {
			continue
		}
		for j, bv := range b {
			if bv >= q {
				bv %= q
			}
			if bv == 0 {
				continue
			}
			out[i+j] = modAddReduced(out[i+j], modMulReduced(av, bv, q), q)
		}
	}
	return out
}

func polyAdd(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	if n == 0 {
		return []uint64{0}
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		av := uint64(0)
		if i < len(a) {
			av = a[i] % q
		}
		bv := uint64(0)
		if i < len(b) {
			bv = b[i] % q
		}
		out[i] = modAdd(av, bv, q)
	}
	return trimPoly(out, q)
}

func polySub(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	if n == 0 {
		return []uint64{0}
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		av := uint64(0)
		if i < len(a) {
			av = a[i] % q
		}
		bv := uint64(0)
		if i < len(b) {
			bv = b[i] % q
		}
		out[i] = modSub(av, bv, q)
	}
	return trimPoly(out, q)
}

// scalePoly returns c·p  (mod q).
func scalePoly(p []uint64, c, q uint64) []uint64 {
	if c >= q {
		c %= q
	}
	out := make([]uint64, len(p))
	if c == 0 {
		return out
	}
	for i, v := range p {
		if v >= q {
			v %= q
		}
		out[i] = modMulReduced(v, c, q)
	}
	return out
}

func mulModXN1(dst, a, b []uint64, q uint64) {
	for i := range dst {
		dst[i] = 0
	}
	addMulModXN1Into(dst, a, b, 1, q)
}

func intIsPowerOfTwo(v int) bool {
	return v > 0 && (v&(v-1)) == 0
}

func addMulModXN1Into(dst, a, b []uint64, scale, q uint64) {
	n := len(dst)
	if n == 0 || len(a) == 0 || len(b) == 0 {
		return
	}
	if scale >= q {
		scale %= q
	}
	if scale == 0 {
		return
	}
	if len(a) <= n && len(b) <= n && intIsPowerOfTwo(n) {
		addMulModXN1Power2Into(dst, a, b, scale, q)
		return
	}
	for i, av := range a {
		if av >= q {
			av %= q
		}
		if av == 0 {
			continue
		}
		av = modMulReduced(av, scale, q)
		for j, bv := range b {
			if bv >= q {
				bv %= q
			}
			if bv == 0 {
				continue
			}
			term := modMulReduced(av, bv, q)
			deg := i + j
			idx := deg % n
			if ((deg / n) % 2) == 1 {
				dst[idx] = modSubReduced(dst[idx], term, q)
			} else {
				dst[idx] = modAddReduced(dst[idx], term, q)
			}
		}
	}
}

func addMulModXN1Power2Into(dst, a, b []uint64, scale, q uint64) {
	n := len(dst)
	if scale >= q {
		scale %= q
	}
	if n == 0 || scale == 0 {
		return
	}
	for i, av := range a {
		if av >= q {
			av %= q
		}
		if av == 0 {
			continue
		}
		av = modMulReduced(av, scale, q)
		if av == 0 {
			continue
		}
		positive := n - i
		if positive > len(b) {
			positive = len(b)
		}
		for j := 0; j < positive; j++ {
			bv := b[j]
			if bv >= q {
				bv %= q
			}
			if bv == 0 {
				continue
			}
			dst[i+j] = modAddReduced(dst[i+j], modMulReduced(av, bv, q), q)
		}
		for j := positive; j < len(b); j++ {
			bv := b[j]
			if bv >= q {
				bv %= q
			}
			if bv == 0 {
				continue
			}
			dst[i+j-n] = modSubReduced(dst[i+j-n], modMulReduced(av, bv, q), q)
		}
	}
}

type negacyclicProductScratch struct {
	a   *ring.Poly
	b   *ring.Poly
	out *ring.Poly
	acc *ring.Poly
}

func newNegacyclicProductScratch(ringQ *ring.Ring) *negacyclicProductScratch {
	if ringQ == nil {
		return nil
	}
	return &negacyclicProductScratch{
		a:   ringQ.NewPoly(),
		b:   ringQ.NewPoly(),
		out: ringQ.NewPoly(),
		acc: ringQ.NewPoly(),
	}
}

func resetRingPolyCoeffs(p *ring.Poly) {
	if p == nil || len(p.Coeffs) == 0 {
		return
	}
	for level := range p.Coeffs {
		row := p.Coeffs[level]
		for i := range row {
			row[i] = 0
		}
	}
}

func nttPolyFromModXN1Coeffs(ringQ *ring.Ring, coeffs []uint64) (*ring.Poly, bool) {
	if ringQ == nil || len(coeffs) > int(ringQ.N) {
		return nil, false
	}
	q := ringQ.Modulus[0]
	out := ringQ.NewPoly()
	for i, v := range coeffs {
		if v >= q {
			v %= q
		}
		out.Coeffs[0][i] = v
	}
	ringQ.NTT(out, out)
	return out, true
}

func shouldUseNTTNegacyclicProduct(ringQ *ring.Ring, dst, a, b []uint64) bool {
	if ringQ == nil || len(dst) != int(ringQ.N) || len(a) == 0 || len(b) == 0 {
		return false
	}
	if len(a) > int(ringQ.N) || len(b) > int(ringQ.N) {
		return false
	}
	n := len(dst)
	return n >= 512 && len(a)*len(b) >= 32768
}

func addMulModXN1PrecomputedNTTInto(ringQ *ring.Ring, dst []uint64, aNTT *ring.Poly, b []uint64, scale uint64, scratch *negacyclicProductScratch) bool {
	if scratch == nil || aNTT == nil || !shouldUseNTTNegacyclicProduct(ringQ, dst, aNTT.Coeffs[0], b) {
		return false
	}
	q := ringQ.Modulus[0]
	if scale >= q {
		scale %= q
	}
	if scale == 0 {
		return true
	}
	resetRingPolyCoeffs(scratch.b)
	for i, v := range b {
		if v >= q {
			v %= q
		}
		scratch.b.Coeffs[0][i] = v
	}
	ringQ.NTT(scratch.b, scratch.b)
	ringQ.MulCoeffs(aNTT, scratch.b, scratch.out)
	ringQ.InvNTT(scratch.out, scratch.out)
	addScaledInto(dst, scratch.out.Coeffs[0], scale, q)
	return true
}

func addMulModXN1PrecomputedBothNTTInto(ringQ *ring.Ring, dst []uint64, aNTT, bNTT *ring.Poly, scale uint64, scratch *negacyclicProductScratch) bool {
	if ringQ == nil || scratch == nil || aNTT == nil || bNTT == nil || len(dst) != int(ringQ.N) {
		return false
	}
	if len(aNTT.Coeffs) == 0 || len(bNTT.Coeffs) == 0 || len(aNTT.Coeffs[0]) != int(ringQ.N) || len(bNTT.Coeffs[0]) != int(ringQ.N) {
		return false
	}
	q := ringQ.Modulus[0]
	if scale >= q {
		scale %= q
	}
	if scale == 0 {
		return true
	}
	ringQ.MulCoeffs(aNTT, bNTT, scratch.out)
	if scale != 1 {
		ringQ.MulScalar(scratch.out, scale, scratch.out)
	}
	ringQ.InvNTT(scratch.out, scratch.out)
	addScaledInto(dst, scratch.out.Coeffs[0], 1, q)
	return true
}

func coeffsToNTTPolyInto(ringQ *ring.Ring, dst *ring.Poly, coeffs []uint64) bool {
	if ringQ == nil || dst == nil || len(coeffs) > int(ringQ.N) {
		return false
	}
	q := ringQ.Modulus[0]
	resetRingPolyCoeffs(dst)
	for i, v := range coeffs {
		if v >= q {
			v %= q
		}
		dst.Coeffs[0][i] = v
	}
	ringQ.NTT(dst, dst)
	return true
}

func addMulNTTIntoAccumulator(ringQ *ring.Ring, acc, aNTT, bNTT *ring.Poly, scale uint64, scratch *negacyclicProductScratch) bool {
	if ringQ == nil || scratch == nil || acc == nil || aNTT == nil || bNTT == nil {
		return false
	}
	if len(acc.Coeffs) == 0 || len(aNTT.Coeffs) == 0 || len(bNTT.Coeffs) == 0 {
		return false
	}
	if len(acc.Coeffs[0]) != int(ringQ.N) || len(aNTT.Coeffs[0]) != int(ringQ.N) || len(bNTT.Coeffs[0]) != int(ringQ.N) {
		return false
	}
	q := ringQ.Modulus[0]
	if scale >= q {
		scale %= q
	}
	if scale == 0 {
		return true
	}
	ringQ.MulCoeffs(aNTT, bNTT, scratch.out)
	if scale != 1 {
		ringQ.MulScalar(scratch.out, scale, scratch.out)
	}
	ringQ.Add(acc, scratch.out, acc)
	return true
}

func flushNTTAccumulatorInto(ringQ *ring.Ring, dst []uint64, acc *ring.Poly, scratch *negacyclicProductScratch) bool {
	if ringQ == nil || scratch == nil || acc == nil || len(dst) != int(ringQ.N) {
		return false
	}
	ringQ.InvNTT(acc, scratch.out)
	addScaledInto(dst, scratch.out.Coeffs[0], 1, ringQ.Modulus[0])
	return true
}

func addScaledInto(dst, src []uint64, scale, q uint64) {
	if scale >= q {
		scale %= q
	}
	if scale == 0 {
		return
	}
	limit := len(src)
	if len(dst) < limit {
		limit = len(dst)
	}
	for i := 0; i < limit; i++ {
		v := src[i]
		if v >= q {
			v %= q
		}
		if v == 0 {
			continue
		}
		dst[i] = modAddReduced(dst[i], modMulReduced(v, scale, q), q)
	}
}

func subInto(dst, src []uint64, q uint64) {
	limit := len(src)
	if len(dst) < limit {
		limit = len(dst)
	}
	for i := 0; i < limit; i++ {
		v := src[i]
		if v >= q {
			v %= q
		}
		if v == 0 {
			continue
		}
		dst[i] = modSubReduced(dst[i], v, q)
	}
}

// trimPoly removes trailing zero coefficients (mod q) while keeping at least one term.
func trimPoly(coeffs []uint64, q uint64) []uint64 {
	n := len(coeffs)
	for n > 1 {
		if coeffs[n-1]%q != 0 {
			break
		}
		n--
	}
	return coeffs[:n]
}

// checkOmega ensures Ω has distinct elements and q ∤ |Ω|.
func checkOmega(omega []uint64, q uint64) error {
	seen := make(map[uint64]struct{}, len(omega))
	for _, w := range omega {
		if _, ok := seen[w]; ok {
			return fmt.Errorf("omega has duplicate element %d", w)
		}
		seen[w] = struct{}{}
	}
	if len(omega) == 0 {
		return fmt.Errorf("|Ω| must be > 0")
	}
	if uint64(len(omega)) >= q {
		return fmt.Errorf("|Ω| (= %d) must be < q (= %d) so S0 is invertible", len(omega), q)
	}
	return nil
}

// lagrangeBasisNumerator returns Π_{j≠i} (X - x_j) as a coefficient slice.
func lagrangeBasisNumerator(xs []uint64, i int, q uint64) []uint64 {
	if i < 0 || i >= len(xs) {
		return []uint64{0}
	}
	num := []uint64{1}
	for j, xj := range xs {
		if j == i {
			continue
		}
		if xj >= q {
			xj %= q
		}
		oldLen := len(num)
		num = append(num, 0)
		for k := oldLen; k >= 1; k-- {
			num[k] = modSubReduced(num[k-1], modMulReduced(xj, num[k], q), q)
		}
		num[0] = modSubReduced(0, modMulReduced(xj, num[0], q), q)
	}
	return num
}

type interpolationPlan struct {
	q     uint64
	basis [][]uint64
}

func buildInterpolationPlan(xs []uint64, q uint64) (*interpolationPlan, error) {
	if err := checkOmega(xs, q); err != nil {
		return nil, err
	}
	n := len(xs)
	T := make([]uint64, n+1)
	T[0] = 1
	for idx := 0; idx < n; idx++ {
		x := xs[idx]
		if x >= q {
			x %= q
		}
		for k := idx + 1; k >= 1; k-- {
			T[k] = modSubReduced(T[k-1], modMulReduced(x, T[k], q), q)
		}
		T[0] = modSubReduced(0, modMulReduced(x, T[0], q), q)
	}
	basis := make([][]uint64, n)
	qi := make([]uint64, n)
	for i := 0; i < n; i++ {
		xi := xs[i]
		if xi >= q {
			xi %= q
		}
		qi[n-1] = T[n]
		for k := n - 2; k >= 0; k-- {
			qi[k] = modAddReduced(T[k+1], modMulReduced(xi, qi[k+1], q), q)
		}
		denom := uint64(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			if xj >= q {
				xj %= q
			}
			denom = modMulReduced(denom, modSubReduced(xi, xj, q), q)
		}
		scale := modInv(denom, q)
		row := make([]uint64, n)
		for k := 0; k < n; k++ {
			if qi[k] == 0 {
				continue
			}
			row[k] = modMulReduced(qi[k], scale, q)
		}
		basis[i] = trimPoly(row, q)
	}
	return &interpolationPlan{q: q, basis: basis}, nil
}

// Interpolate returns the coefficients of the unique poly of degree <len(xs)
// that satisfies P(xs[k]) = ys[k].  xs must be distinct.
func Interpolate(xs, ys []uint64, q uint64) []uint64 {
	n := len(xs)
	if n == 0 {
		return []uint64{0}
	}
	// T(X) = prod_j (X - xs[j]).
	T := make([]uint64, n+1)
	T[0] = 1
	for idx := 0; idx < n; idx++ {
		x := xs[idx]
		if x >= q {
			x %= q
		}
		for k := idx + 1; k >= 1; k-- {
			T[k] = modSubReduced(T[k-1], modMulReduced(x, T[k], q), q)
		}
		T[0] = modSubReduced(0, modMulReduced(x, T[0], q), q)
	}

	res := make([]uint64, n)
	qi := make([]uint64, n)
	for i := 0; i < n; i++ {
		// qi = T / (X - xs[i]) via synthetic division.
		xi := xs[i]
		if xi >= q {
			xi %= q
		}
		qi[n-1] = T[n]
		for k := n - 2; k >= 0; k-- {
			qi[k] = modAddReduced(T[k+1], modMulReduced(xi, qi[k+1], q), q)
		}

		// denom = Π_{j≠i} (xs[i]-xs[j]).
		denom := uint64(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			if xj >= q {
				xj %= q
			}
			denom = modMulReduced(denom, modSubReduced(xi, xj, q), q)
		}
		yi := ys[i]
		if yi >= q {
			yi %= q
		}
		scale := modMulReduced(yi, modInv(denom, q), q)
		if scale == 0 {
			continue
		}
		for k := 0; k < n; k++ {
			if qi[k] == 0 {
				continue
			}
			res[k] = modAddReduced(res[k], modMulReduced(qi[k], scale, q), q)
		}
	}
	return trimPoly(res, q)
}

type omegaInterpolationPlan struct {
	q     uint64
	basis [][]uint64
}

func newOmegaInterpolationPlan(omega []uint64, q uint64) (*omegaInterpolationPlan, error) {
	plan, err := buildInterpolationPlan(omega, q)
	if err != nil {
		return nil, err
	}
	basis := make([][]uint64, len(plan.basis))
	for i := range plan.basis {
		basis[i] = append([]uint64(nil), plan.basis[i]...)
	}
	return &omegaInterpolationPlan{q: q, basis: basis}, nil
}

func (p *omegaInterpolationPlan) interpolateInto(dst, values []uint64) {
	if p == nil {
		panic("omegaInterpolationPlan: nil plan")
	}
	if len(values) != len(p.basis) {
		panic("omegaInterpolationPlan: value length mismatch")
	}
	if len(dst) < len(p.basis) {
		panic("omegaInterpolationPlan: destination too short")
	}
	for i := 0; i < len(p.basis); i++ {
		dst[i] = 0
	}
	q := p.q
	for i, v := range values {
		if v >= q {
			v %= q
		}
		if v == 0 {
			continue
		}
		basis := p.basis[i]
		for j, c := range basis {
			if c == 0 {
				continue
			}
			dst[j] = modAddReduced(dst[j], modMulReduced(c, v, q), q)
		}
	}
	for i := len(p.basis); i < len(dst); i++ {
		dst[i] = 0
	}
}

func (p *omegaInterpolationPlan) coeffPolyFromHead(ringQ *ring.Ring, head []uint64) *ring.Poly {
	out := ringQ.NewPoly()
	p.interpolateInto(out.Coeffs[0], head)
	return out
}

func scalePolyNTT(r *ring.Ring, a *ring.Poly, c uint64, out *ring.Poly) {
	if out != a {
		copy(out.Coeffs[0], a.Coeffs[0])
	}
	q := r.Modulus[0]
	c %= q
	for i := range out.Coeffs[0] {
		out.Coeffs[0][i] = modMulReduced(out.Coeffs[0][i], c, q)
	}
}
