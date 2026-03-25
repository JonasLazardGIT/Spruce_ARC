package PIOP

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	CoeffNativeSigModelLiteralPackedAggregatedV3         = "literal_packed_aggregated_v3"
	CoeffNativeSigModelLiteralPackedAggregatedV4SplitPRF = "literal_packed_aggregated_v4_split_prf"
)

// SimOpts carries the proving and reporting knobs used by the retained
// issuance and showing flows.
type SimOpts struct {
	Rho      int
	EllPrime int
	Ell      int
	Eta      int
	NLeaves  int
	Theta    int
	Kappa    [4]int
	// ROQueryCaps records the assumed Random Oracle query counts (Q0..Q4) used
	// for the theorem-level ROM soundness bound.
	ROQueryCaps       [5]int
	NCols             int
	PCSNCols          int
	LVCSNCols         int
	PostSignLVCSNCols int
	PostSignNLeaves   int
	PRFLVCSNCols      int
	PRFNLeaves        int
	DQOverride        int
	Lambda            int
	ChainW            int
	ChainL            int
	// SigShortnessL overrides the default signature shortness digit count.
	SigShortnessL int
	// SigShortnessRadix overrides the balanced signature shortness radix.
	SigShortnessRadix int
	// CoeffNativeSigModel selects the coeff-native post-sign model.
	CoeffNativeSigModel string
	CoeffPacking        bool
	// Only explicit public-domain mode is supported.
	DomainMode DomainMode
	// PRFGroupRounds controls grouped PRF checkpointing in showing mode.
	PRFGroupRounds int
	Mutate         func(r *ring.Ring, omega []uint64, ell int, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly) `json:"-"`
	Credential     bool
}

func defaultSimOpts() SimOpts {
	return SimOpts{
		Rho:               7,
		EllPrime:          10,
		Ell:               26,
		Eta:               7,
		NLeaves:           0,
		Theta:             1,
		Kappa:             [4]int{0, 0, 0, 0},
		ROQueryCaps:       [5]int{1, 1, 1, 1, 1},
		NCols:             8,
		PCSNCols:          0,
		LVCSNCols:         0,
		DQOverride:        0,
		Lambda:            256,
		ChainW:            4,
		ChainL:            0,
		SigShortnessL:     0,
		SigShortnessRadix: 0,
		CoeffPacking:      false,
		DomainMode:        DomainModeExplicit,
		PRFGroupRounds:    1,
	}
}

func (o *SimOpts) applyDefaults() {
	def := defaultSimOpts()
	if o.Rho <= 0 {
		o.Rho = def.Rho
	}
	if o.EllPrime <= 0 {
		o.EllPrime = def.EllPrime
	}
	if o.Ell <= 0 {
		o.Ell = def.Ell
	}
	if o.Eta <= 0 {
		o.Eta = def.Eta
	}
	if o.NLeaves < 0 {
		o.NLeaves = 0
	}
	if o.Theta <= 0 {
		o.Theta = def.Theta
	}
	for i := 0; i < len(o.Kappa); i++ {
		if o.Kappa[i] <= 0 {
			o.Kappa[i] = def.Kappa[i]
		}
	}
	for i := 0; i < len(o.ROQueryCaps); i++ {
		if o.ROQueryCaps[i] <= 0 {
			o.ROQueryCaps[i] = def.ROQueryCaps[i]
		}
	}
	if o.NCols <= 0 {
		o.NCols = def.NCols
	}
	if o.PCSNCols < 0 {
		o.PCSNCols = 0
	}
	if o.LVCSNCols < 0 {
		o.LVCSNCols = 0
	}
	if o.PostSignLVCSNCols < 0 {
		o.PostSignLVCSNCols = 0
	}
	if o.PostSignNLeaves < 0 {
		o.PostSignNLeaves = 0
	}
	if o.PRFLVCSNCols < 0 {
		o.PRFLVCSNCols = 0
	}
	if o.PRFNLeaves < 0 {
		o.PRFNLeaves = 0
	}
	if o.DQOverride < 0 {
		o.DQOverride = 0
	}
	if o.Lambda <= 0 {
		o.Lambda = def.Lambda
	}
	if o.ChainW <= 0 {
		o.ChainW = def.ChainW
	}
	if o.ChainL < 0 {
		o.ChainL = 0
	}
	if o.SigShortnessL < 0 {
		o.SigShortnessL = 0
	}
	if o.SigShortnessRadix < 0 {
		o.SigShortnessRadix = 0
	}
	if o.PRFGroupRounds <= 0 {
		o.PRFGroupRounds = def.PRFGroupRounds
	}
	if o.DomainMode != DomainModeExplicit {
		o.DomainMode = DomainModeExplicit
	}
}

// CoeffNativeSigLayout captures the coeff-native post-sign witness partition
// used by the retained showing layouts.
type CoeffNativeSigLayout struct {
	Enabled bool
	Model   string

	// Signature witness rows for the active coeff-native post-sign model.
	// On the live semantic rewrite path these are scalar coefficient rows in
	// component-major, coefficient-minor order.
	SigBase   int
	SigCount  int
	SigBlocks int
	SigUCount int
	// Literal packed metadata for packed-row coeff-native models.
	PackedSigBase       int
	PackedSigCount      int
	PackedSigBlocks     int
	PackedSigComponents int
	PackedSigBlockWidth int
	// ScalarBundle rows pack independent scalar witness values into the Ω slots
	// of one or more committed rows. V3 uses these slots for U/X0/X1.
	ScalarBundleBase  int
	ScalarBundleCount int
	USlots            []PRFSlot
	X0Slots           []PRFSlot
	X1Slot            PRFSlot
	// Replay-facing projection rows for the compressed v3 non-sign scalar path.
	PostSignMsgSumRow int
	PostSignRndSumRow int
	PostSignX1Row     int
	// Signed-digit certificate rows for the compressed v3 non-sign scalar path.
	UScalarCertBase         int
	UScalarCertCount        int
	X0ScalarCertBase        int
	X0ScalarCertCount       int
	X1ScalarCertBase        int
	X1ScalarCertCount       int
	NonSigCertRowsPerScalar int
	NonSigCertRadix         int
	NonSigCertDigits        int
	// Semantic rewrite metadata for scalar signature rows.
	SigComponentCount int
	SigCoeffCount     int
	OutputBlocks      int
	OutputBlockWidth  int

	// Paper-level message/randomness witness rows, column-constant on Ω.
	UBase   int
	UCount  int
	X0Base  int
	X0Count int
	X1Row   int

	// Retained row-count metadata used by the current witness geometry and
	// replay-accounting helpers.
	W1SigBase      int
	W1SigCount     int
	W1MsgBase      int
	W1MsgCount     int
	W1MsgRowsPer   int
	W1RndBase      int
	W1RndCount     int
	W1RndRowsPer   int
	W2Base         int
	W2Count        int
	W2RowsPerBlock int
	W3RowsPerBlock int
}

type RowLayout struct {
	SigCount int
	MsgCount int
	RndCount int
	// ShowingPRFOnly marks a split PRF slice that intentionally omits all
	// post-sign witness families.
	ShowingPRFOnly bool
	// Explicit base indices for semantic witness rows.
	// When false, the standard issuance row order is used.
	HasExplicitBaseIdx bool
	IdxM1              int
	IdxM2              int
	IdxRU0             int
	IdxRU1             int
	IdxR               int
	IdxR0              int
	IdxR1              int
	IdxK0              int
	IdxK1              int
	IdxT               int
	IdxUBase           int
	ChainBase          int
	ChainRowsPerSig    int
	PackedSigChainBase int
	// Packed signature shortness metadata for modes that use one shortness row
	// per digit lane and coefficient group instead of per coefficient.
	PackedSigChainGroupCount   int
	PackedSigChainGroupSize    int
	PackedSigChainRowsPerGroup int
	SigSignedChain             bool
	MsgChainBase               int
	RndChainBase               int
	X1ChainBase                int
	MsgRangeBase               int
	RndRangeBase               int
	X1RangeBase                int
	NonSigBoundRowsPer         int
	// Experimental v3 logical-slice accounting for the single-root coeff-native
	// showing path.
	SigPrimaryLimbRows            int
	ScalarBundleRows              int
	SigBoundSliceRows             int
	PostSignScalarProjectionRows  int
	PostSignScalarCertificateRows int
	PRFScalarBundleRows           int
	PRFGroupedNonlinearRows       int
	// Signature packing metadata for showing.
	SigBlocks     int
	SigUCount     int
	SigExtraUBase int
	SigExtraTBase int
	SigDerivedT   bool
	SigCoeffBase  int
	// Non-signature coefficient-bound metadata for showing.
	NonSigBlocks    int
	MsgCompCount    int
	MsgExtraNTTBase int
	MsgCoeffBase    int
	RndCompCount    int
	RndExtraNTTBase int
	RndCoeffBase    int
	X1CompCount     int
	X1ExtraNTTBase  int
	X1CoeffBase     int

	// Coeff-native showing signature path.
	CoeffNativeSig CoeffNativeSigLayout
}

// KPolySnapshot serialises a K[X] polynomial by degree and limb coefficients.
type KPolySnapshot struct {
	Degree int
	Limbs  [][]uint64
}

// Proof captures the transcript material emitted by the prover following the
// nine-round SmallWood–ARK flow.
type Proof struct {
	Root             [16]byte
	Salt             []byte
	Ctr              [4]uint64
	Digests          [4][]byte
	LabelsDigest     []byte
	Lambda           int
	Kappa            [4]int
	Theta            int
	Chi              []uint64
	Zeta             []uint64
	Tail             []int
	VTargets         [][]uint64
	VTargetsBits     []byte
	VTargetsRows     int
	VTargetsCols     int
	VTargetsBitWidth uint8
	BarSets          [][]uint64
	BarSetsBits      []byte
	BarSetsRows      int
	BarSetsCols      int
	BarSetsBitWidth  uint8
	CoeffMatrix      [][]uint64
	KPoint           [][]uint64
	GammaPrimeK      [][][]KScalar
	GammaAggK        [][]KScalar
	GammaPrime       [][][]uint64
	GammaAgg         [][]uint64
	R                [][]uint64
	// Q commitment (paper Fig. 6, Step 6): Merkle root, degree-check R polynomials,
	// and an opening that reveals Q on Ω and at queried tail points.
	QRoot         [16]byte
	QR            [][]uint64
	QRBits        []byte
	QRRows        int
	QRCols        int
	QRBitWidth    uint8
	QDegreeBound  int
	QOpening      *decs.DECSOpening
	MKData        []KPolySnapshot
	QKData        []KPolySnapshot
	RowLayout     RowLayout
	MaskRowOffset int
	MaskRowCount  int
	// RowDegreeBound records the DECS/LVCS degree used for the committed row
	// oracle. This can exceed the Q/mask degree bound when explicit-domain row
	// interpolation over LVCSNCols imposes a larger floor.
	RowDegreeBound  int
	MaskDegreeBound int
	TailTranscript  []byte
	Gamma           [][]uint64
	GammaK          [][]KScalar
	RoundCounters   [4]uint64

	PCSGeometry   PCSGeometry
	PCSOpening    *decs.DECSOpening
	RowOpening    *decs.DECSOpening
	NColsUsed     int
	PCSNColsUsed  int
	LVCSNColsUsed int
	DomainMode    DomainMode
	NLeavesUsed   int
	EvalPoints    []uint64 // |E'|
	PvalsEvalBits []byte   // packed field-width matrix: |E'| x RowCount
	MvalsEvalBits []byte   // packed field-width matrix: |E'| x Eta
	MaskEvalBits  []byte   // packed field-width matrix: |E'| x rho (PACS masks)
	PvalsEvalRows int
	PvalsEvalCols int
	MvalsEvalRows int
	MvalsEvalCols int
	MaskEvalRows  int
	MaskEvalCols  int
	// Optional PRF layout metadata for showing proofs.
	PRFLayout *PRFLayout
	// ShowingSplit carries the post-sign and PRF slices for the split v4 model.
	ShowingSplit *ShowingSplitProof
}

// ShowingProofSlice records one independently committed slice inside the split
// showing proof. The proof payload is reused directly so existing prove/verify
// machinery can operate on each slice without a parallel proof format.
type ShowingProofSlice struct {
	Name  string
	Proof *Proof
}

// ShowingSplitProof groups the post-sign and PRF slices of the versioned split
// showing model.
type ShowingSplitProof struct {
	PostSign *ShowingProofSlice
	PRF      *ShowingProofSlice
}

type fsRoundResult struct {
	Seed []byte
	RNG  *fsRNG
}

func fsRound(fs *FS, proof *Proof, round int, label string, material ...[]byte) fsRoundResult {
	if fs == nil {
		panic("fsRound: nil FS state")
	}
	if proof == nil {
		panic("fsRound: nil proof")
	}
	h, ctr, seed := fs.GrindAndDerive(round, material, func(h []byte) []byte { return h })
	proof.Ctr[round] = ctr
	proof.RoundCounters[round] = ctr
	proof.Digests[round] = append([]byte(nil), h...)
	return fsRoundResult{
		Seed: append([]byte(nil), seed...),
		RNG:  newFSRNG(label, seed),
	}
}

func (p *Proof) setVTargets(mat [][]uint64) {
	if len(mat) == 0 {
		p.VTargets = nil
		p.VTargetsBits = nil
		p.VTargetsRows = 0
		p.VTargetsCols = 0
		p.VTargetsBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.VTargetsBits = bits
	p.VTargetsRows = rows
	p.VTargetsCols = cols
	p.VTargetsBitWidth = uint8(width)
	p.VTargets = nil
}

func (p *Proof) ensureVTargetsPacked() {
	if len(p.VTargetsBits) == 0 && len(p.VTargets) > 0 {
		p.setVTargets(p.VTargets)
	}
}

func (p *Proof) VTargetsMatrix() [][]uint64 {
	if len(p.VTargets) > 0 {
		return p.VTargets
	}
	if len(p.VTargetsBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.VTargetsBits)
	if err != nil {
		return nil
	}
	p.VTargets = mat
	p.VTargetsRows = rows
	p.VTargetsCols = cols
	p.VTargetsBitWidth = uint8(width)
	return mat
}

func (p *Proof) setBarSets(mat [][]uint64) {
	if len(mat) == 0 {
		p.BarSets = nil
		p.BarSetsBits = nil
		p.BarSetsRows = 0
		p.BarSetsCols = 0
		p.BarSetsBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.BarSetsBits = bits
	p.BarSetsRows = rows
	p.BarSetsCols = cols
	p.BarSetsBitWidth = uint8(width)
	p.BarSets = nil
}

func (p *Proof) setQR(mat [][]uint64) {
	if len(mat) == 0 {
		p.QR = nil
		p.QRBits = nil
		p.QRRows = 0
		p.QRCols = 0
		p.QRBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.QRBits = bits
	p.QRRows = rows
	p.QRCols = cols
	p.QRBitWidth = uint8(width)
	p.QR = copyMatrix(mat)
}

func (p *Proof) ensureQRPacked() {
	if len(p.QRBits) == 0 && len(p.QR) > 0 {
		p.setQR(p.QR)
	}
}

func (p *Proof) QRMatrix() [][]uint64 {
	if len(p.QR) > 0 {
		return p.QR
	}
	if len(p.QRBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.QRBits)
	if err != nil {
		return nil
	}
	p.QR = mat
	p.QRRows = rows
	p.QRCols = cols
	p.QRBitWidth = uint8(width)
	return mat
}

func (p *Proof) QRBytes() []byte {
	p.ensureQRPacked()
	return p.QRBits
}

func (p *Proof) ensureBarSetsPacked() {
	if len(p.BarSetsBits) == 0 && len(p.BarSets) > 0 {
		p.setBarSets(p.BarSets)
	}
}

func (p *Proof) BarSetsMatrix() [][]uint64 {
	if len(p.BarSets) > 0 {
		return p.BarSets
	}
	if len(p.BarSetsBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.BarSetsBits)
	if err != nil {
		return nil
	}
	p.BarSets = mat
	p.BarSetsRows = rows
	p.BarSetsCols = cols
	p.BarSetsBitWidth = uint8(width)
	return mat
}

// SoundnessBudget captures the four Eq. (8) error components together with the
// theorem-level ROM aggregation from Theorem 9 and the Eq. (10) size counters.
type SoundnessBudget struct {
	Eps                [4]float64
	RawBits            [4]float64
	Bits               [4]float64
	Grinding           [4]float64
	GrindingBits       [4]float64
	TheoremTerms       [4]float64
	TheoremBits        [4]float64
	Eq8Total           float64
	Eq8TotalBits       float64
	Collision          float64
	CollisionBits      float64
	Total              float64
	TotalBits          float64
	DQ                 int
	DDECS              int
	WitnessSupportCols int
	CommittedCols      int
	CollisionSpaceBits int
	QueryCaps          [5]int
	NRows              int
	M                  int
}

func maxDegreeFromCoeffs(poly []uint64) int {
	for i := len(poly) - 1; i >= 0; i-- {
		if poly[i] != 0 {
			return i
		}
	}
	return -1
}

// computeDQFromConstraintDegrees implements paper Eq.(3):
//
//	dQ = max( d·(ℓ+s−1)+s−1, d′·(ℓ+s−1) )
//
// where d and d′ are algebraic degrees of the parallel/aggregated constraint
// polynomials in the witness variables, s=|Ω|, and ℓ is the number of blinding
// points per committed row polynomial (so deg(P_i) ≤ ℓ+s−1).
func computeDQFromConstraintDegrees(d, dPrime, s, ell int) int {
	if s <= 0 {
		s = 1
	}
	if ell <= 0 {
		ell = 1
	}
	span := ell + s - 1
	c1 := d*span + (s - 1)
	c2 := dPrime * span
	if c1 >= c2 {
		return c1
	}
	return c2
}

func computeVTargets(mod uint64, rows [][]uint64, C [][]uint64) [][]uint64 {
	if len(rows) == 0 {
		return nil
	}
	ncols := len(rows[0])
	m := len(C)
	res := make([][]uint64, m)
	for k := 0; k < m; k++ {
		res[k] = make([]uint64, ncols)
		for i := 0; i < ncols; i++ {
			sum := uint64(0)
			for j := 0; j < len(rows); j++ {
				sum = lvcs.MulAddMod64(sum, C[k][j], rows[j][i], mod)
			}
			res[k][i] = sum
		}
	}
	return res
}

func copyMatrix(src [][]uint64) [][]uint64 {
	if src == nil {
		return nil
	}
	out := make([][]uint64, len(src))
	for i := range src {
		out[i] = append([]uint64(nil), src[i]...)
	}
	return out
}

func copyTensor3(src [][][]uint64) [][][]uint64 {
	if src == nil {
		return nil
	}
	out := make([][][]uint64, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		out[i] = make([][]uint64, len(src[i]))
		for j := range src[i] {
			out[i][j] = append([]uint64(nil), src[i][j]...)
		}
	}
	return out
}

func clonePolys(src []*ring.Poly) []*ring.Poly {
	if src == nil {
		return nil
	}
	out := make([]*ring.Poly, len(src))
	for i := range src {
		if src[i] != nil {
			out[i] = src[i].CopyNew()
		}
	}
	return out
}

func matrixEqual(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func tensor3Equal(a, b [][][]uint64) bool {
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
			for k := range a[i][j] {
				if a[i][j][k] != b[i][j][k] {
					return false
				}
			}
		}
	}
	return true
}

func kTensor3Equal(a, b [][][]KScalar) bool {
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
			for k := range a[i][j] {
				if len(a[i][j][k]) != len(b[i][j][k]) {
					return false
				}
				for t := range a[i][j][k] {
					if a[i][j][k][t] != b[i][j][k][t] {
						return false
					}
				}
			}
		}
	}
	return true
}

func copyKMatrix(src [][]KScalar) [][]KScalar {
	if src == nil {
		return nil
	}
	out := make([][]KScalar, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		row := make([]KScalar, len(src[i]))
		for j := range src[i] {
			if src[i][j] == nil {
				continue
			}
			scalar := make(KScalar, len(src[i][j]))
			copy(scalar, src[i][j])
			row[j] = scalar
		}
		out[i] = row
	}
	return out
}

func copyKTensor3(src [][][]KScalar) [][][]KScalar {
	if src == nil {
		return nil
	}
	out := make([][][]KScalar, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		out[i] = make([][]KScalar, len(src[i]))
		for j := range src[i] {
			poly := src[i][j]
			if poly == nil {
				continue
			}
			coeffs := make([]KScalar, len(poly))
			for k := range poly {
				if poly[k] == nil {
					continue
				}
				limbs := make(KScalar, len(poly[k]))
				copy(limbs, poly[k])
				coeffs[k] = limbs
			}
			out[i][j] = coeffs
		}
	}
	return out
}

func snapshotKPolys(polys []*KPoly) []KPolySnapshot {
	if polys == nil {
		return nil
	}
	out := make([]KPolySnapshot, len(polys))
	for i, kp := range polys {
		if kp == nil {
			continue
		}
		limbs := make([][]uint64, len(kp.Limbs))
		for j := range kp.Limbs {
			limbs[j] = append([]uint64(nil), kp.Limbs[j]...)
		}
		out[i] = KPolySnapshot{Degree: kp.Degree, Limbs: limbs}
	}
	return out
}

func restoreKPolys(data []KPolySnapshot) []*KPoly {
	if data == nil {
		return nil
	}
	out := make([]*KPoly, len(data))
	for i := range data {
		kp := &KPoly{Degree: data[i].Degree}
		if len(data[i].Limbs) > 0 {
			kp.Limbs = make([][]uint64, len(data[i].Limbs))
			for j := range data[i].Limbs {
				kp.Limbs[j] = append([]uint64(nil), data[i].Limbs[j]...)
			}
		}
		out[i] = kp
	}
	return out
}

func kMatrixFirstLimb(mat [][]KScalar) [][]uint64 {
	if mat == nil {
		return nil
	}
	out := make([][]uint64, len(mat))
	for i := range mat {
		row := make([]uint64, len(mat[i]))
		for j := range mat[i] {
			scalar := mat[i][j]
			if len(scalar) > 0 {
				row[j] = scalar[0]
			}
		}
		out[i] = row
	}
	return out
}

func trimCoeffsCopy(src []uint64, q uint64) []uint64 {
	if len(src) == 0 {
		return []uint64{0}
	}
	out := make([]uint64, len(src))
	for i := range src {
		out[i] = src[i] % q
	}
	last := len(out) - 1
	for last > 0 && out[last] == 0 {
		last--
	}
	return out[:last+1]
}

func encodeUint64Slice(vals []uint64) []byte {
	if len(vals) == 0 {
		return nil
	}
	out := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(out[i*8:], v)
	}
	return out
}

func cloneDECSOpening(op *decs.DECSOpening) *decs.DECSOpening {
	if op == nil {
		return nil
	}
	clone := &decs.DECSOpening{
		FormatVersion:  op.FormatVersion,
		PColsEncoded:   op.PColsEncoded,
		POmitCols:      append([]int(nil), op.POmitCols...),
		MFormatVersion: op.MFormatVersion,
		MColsEncoded:   op.MColsEncoded,
		MOmitCols:      append([]int(nil), op.MOmitCols...),
		MaskBase:       op.MaskBase,
		MaskCount:      op.MaskCount,
		Indices:        append([]int(nil), op.Indices...),
	}
	clone.TailCount = op.TailCount
	if len(op.IndexBits) > 0 {
		clone.IndexBits = append([]byte(nil), op.IndexBits...)
	}
	// copy metadata and packed buffers if present
	clone.R = op.R
	clone.Eta = op.Eta
	clone.NonceBytes = op.NonceBytes
	if len(op.NonceSeed) > 0 {
		clone.NonceSeed = append([]byte(nil), op.NonceSeed...)
	}
	if op.PvalsBits != nil {
		clone.PvalsBits = append([]byte(nil), op.PvalsBits...)
	}
	clone.PvalsBitWidth = op.PvalsBitWidth
	if op.MvalsBits != nil {
		clone.MvalsBits = append([]byte(nil), op.MvalsBits...)
	}
	clone.MvalsBitWidth = op.MvalsBitWidth
	if len(op.Pvals) > 0 {
		clone.Pvals = make([][]uint64, len(op.Pvals))
		for i := range op.Pvals {
			clone.Pvals[i] = append([]uint64(nil), op.Pvals[i]...)
		}
	}
	if len(op.Mvals) > 0 {
		clone.Mvals = make([][]uint64, len(op.Mvals))
		for i := range op.Mvals {
			clone.Mvals[i] = append([]uint64(nil), op.Mvals[i]...)
		}
	}
	if len(op.Nodes) > 0 {
		clone.Nodes = make([][]byte, len(op.Nodes))
		for i := range op.Nodes {
			clone.Nodes[i] = append([]byte(nil), op.Nodes[i]...)
		}
	}
	if len(op.PathIndex) > 0 {
		clone.PathIndex = make([][]int, len(op.PathIndex))
		for i := range op.PathIndex {
			clone.PathIndex[i] = append([]int(nil), op.PathIndex[i]...)
		}
	}
	if len(op.PathBits) > 0 {
		clone.PathBits = append([]byte(nil), op.PathBits...)
	}
	clone.PathBitWidth = op.PathBitWidth
	clone.PathDepth = op.PathDepth
	if len(op.FrontierRefsBits) > 0 {
		clone.FrontierRefsBits = append([]byte(nil), op.FrontierRefsBits...)
	}
	clone.FrontierRefWidth = op.FrontierRefWidth
	if len(op.Nonces) > 0 {
		clone.Nonces = make([][]byte, len(op.Nonces))
		for i := range op.Nonces {
			clone.Nonces[i] = append([]byte(nil), op.Nonces[i]...)
		}
	}
	if len(op.FrontierNodes) > 0 {
		clone.FrontierNodes = make([][]byte, len(op.FrontierNodes))
		for i := range op.FrontierNodes {
			clone.FrontierNodes[i] = append([]byte(nil), op.FrontierNodes[i]...)
		}
	}
	if len(op.FrontierProof) > 0 {
		clone.FrontierProof = append([]byte(nil), op.FrontierProof...)
	}
	if len(op.FrontierLR) > 0 {
		clone.FrontierLR = append([]byte(nil), op.FrontierLR...)
	}
	clone.FrontierDepth = op.FrontierDepth
	clone.FrontierRefCount = op.FrontierRefCount
	return clone
}

func maybeCompressRowOpeningPvals(open *decs.DECSOpening, coeffMatrix [][]uint64, mod uint64) {
	if open == nil || open.R <= 0 || len(open.Pvals) == 0 || len(coeffMatrix) == 0 {
		return
	}
	omitCols, ok := compressionPivotCols(coeffMatrix, open.R, mod)
	if !ok || len(omitCols) == 0 || len(omitCols) >= open.R {
		return
	}
	keepCols := compressionKeepCols(open.R, omitCols)
	if len(keepCols) == 0 {
		return
	}
	compressed := make([][]uint64, len(open.Pvals))
	for i := range open.Pvals {
		if len(open.Pvals[i]) != open.R {
			return
		}
		row := make([]uint64, len(keepCols))
		for j, col := range keepCols {
			row[j] = open.Pvals[i][col] % mod
		}
		compressed[i] = row
	}
	open.FormatVersion = 1
	open.PColsEncoded = len(keepCols)
	open.POmitCols = append([]int(nil), omitCols...)
	open.Pvals = compressed
}

func maybeCompressQOpeningPvals(open *decs.DECSOpening, gammaQ [][]uint64, mod uint64) (eqRows []int, compressed bool) {
	if open == nil || open.R <= 1 || len(open.Pvals) == 0 || len(gammaQ) == 0 {
		return nil, false
	}
	omitCols, eqRows, ok := qCompressionPOmitPlan(gammaQ, open.R, mod)
	if !ok || len(omitCols) == 0 || len(omitCols) >= open.R {
		return nil, false
	}
	keepCols := compressionKeepCols(open.R, omitCols)
	if len(keepCols) == 0 {
		return nil, false
	}
	encodedRows := make([][]uint64, len(open.Pvals))
	for i := range open.Pvals {
		if len(open.Pvals[i]) != open.R {
			return nil, false
		}
		row := make([]uint64, len(keepCols))
		for j, col := range keepCols {
			row[j] = open.Pvals[i][col] % mod
		}
		encodedRows[i] = row
	}
	open.FormatVersion = 1
	open.PColsEncoded = len(keepCols)
	open.POmitCols = append([]int(nil), omitCols...)
	open.Pvals = encodedRows
	return append([]int(nil), eqRows...), true
}

func maybeCompressQOpeningMvals(open *decs.DECSOpening, keepCols []int) {
	if open == nil || open.Eta <= 0 || len(open.Mvals) == 0 {
		return
	}
	keepSet := make(map[int]struct{}, len(keepCols))
	for _, col := range keepCols {
		if col < 0 || col >= open.Eta {
			return
		}
		keepSet[col] = struct{}{}
	}
	keep := make([]int, 0, len(keepSet))
	for col := 0; col < open.Eta; col++ {
		if _, ok := keepSet[col]; ok {
			keep = append(keep, col)
		}
	}
	omit := make([]int, 0, open.Eta-len(keep))
	for col := 0; col < open.Eta; col++ {
		if _, ok := keepSet[col]; !ok {
			omit = append(omit, col)
		}
	}
	if len(omit) == 0 {
		return
	}
	encoded := make([][]uint64, len(open.Mvals))
	for i := range encoded {
		if len(open.Mvals[i]) != open.Eta {
			return
		}
		row := make([]uint64, len(keep))
		for j, col := range keep {
			row[j] = open.Mvals[i][col]
		}
		encoded[i] = row
	}
	open.MFormatVersion = 1
	open.MColsEncoded = len(keep)
	open.MOmitCols = append([]int(nil), omit...)
	open.Mvals = encoded
}

func maybeCompressQOpening(open *decs.DECSOpening, gammaQ [][]uint64, mod uint64, compressM bool) {
	eqRows, pCompressed := maybeCompressQOpeningPvals(open, gammaQ, mod)
	if compressM && pCompressed {
		var keepM []int
		keepM = eqRows
		maybeCompressQOpeningMvals(open, keepM)
	}
}

func qCompressionPOmitPlan(gammaQ [][]uint64, rho int, mod uint64) (omitCols []int, eqRows []int, ok bool) {
	if rho <= 1 || len(gammaQ) == 0 {
		return nil, nil, false
	}
	maxOmit := rho - 1 // keep at least one encoded P column
	if maxOmit > len(gammaQ) {
		maxOmit = len(gammaQ)
	}
	for target := maxOmit; target >= 1; target-- {
		sub := make([][]uint64, target)
		eq := make([]int, target)
		for i := 0; i < target; i++ {
			if len(gammaQ[i]) < rho {
				return nil, nil, false
			}
			sub[i] = append([]uint64(nil), gammaQ[i][:rho]...)
			eq[i] = i
		}
		pivots, fullRank := compressionPivotCols(sub, rho, mod)
		if !fullRank || len(pivots) != target {
			continue
		}
		return pivots, eq, true
	}
	return nil, nil, false
}

func compressionKeepCols(total int, omit []int) []int {
	if total <= 0 {
		return nil
	}
	omitSet := make(map[int]struct{}, len(omit))
	for _, col := range omit {
		if col >= 0 && col < total {
			omitSet[col] = struct{}{}
		}
	}
	out := make([]int, 0, total-len(omitSet))
	for col := 0; col < total; col++ {
		if _, drop := omitSet[col]; drop {
			continue
		}
		out = append(out, col)
	}
	return out
}

func compressionPivotCols(coeff [][]uint64, colCount int, mod uint64) ([]int, bool) {
	rows := len(coeff)
	if rows == 0 || colCount <= 0 {
		return nil, false
	}
	a := make([][]uint64, rows)
	for i := 0; i < rows; i++ {
		if len(coeff[i]) < colCount {
			return nil, false
		}
		a[i] = make([]uint64, colCount)
		for j := 0; j < colCount; j++ {
			a[i][j] = coeff[i][j] % mod
		}
	}
	pivots := make([]int, 0, rows)
	row := 0
	for col := 0; col < colCount && row < rows; col++ {
		pivot := -1
		for r := row; r < rows; r++ {
			if a[r][col]%mod != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			continue
		}
		if pivot != row {
			a[row], a[pivot] = a[pivot], a[row]
		}
		invPivot := ring.ModExp(a[row][col]%mod, mod-2, mod)
		for c := col; c < colCount; c++ {
			a[row][c] = lvcs.MulMod64(a[row][c], invPivot, mod)
		}
		for r := row + 1; r < rows; r++ {
			factor := a[r][col] % mod
			if factor == 0 {
				continue
			}
			for c := col; c < colCount; c++ {
				term := lvcs.MulMod64(factor, a[row][c], mod)
				a[r][c] = compressionSubMod(a[r][c], term, mod)
			}
		}
		pivots = append(pivots, col)
		row++
	}
	return pivots, row == rows
}

func compressionSubMod(a, b, mod uint64) uint64 {
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

func bytesFromUint64Matrix(mat [][]uint64) []byte {
	return bytesU64Mat(mat)
}

// unpackUint64Matrix reconstructs a matrix from a flat little-endian byte slice.
// rows/cols must be provided; returns nil if lengths are inconsistent.
func unpackUint64Matrix(data []byte, rows, cols int) [][]uint64 {
	if rows <= 0 || cols <= 0 {
		return nil
	}
	need := rows * cols * 8
	if len(data) != need {
		return nil
	}
	out := make([][]uint64, rows)
	for r := 0; r < rows; r++ {
		row := make([]uint64, cols)
		for c := 0; c < cols; c++ {
			row[c] = binary.LittleEndian.Uint64(data[(r*cols+c)*8:])
		}
		out[r] = row
	}
	return out
}

func sampleDistinctFieldElemsAvoid(count int, q uint64, rng *fsRNG, forbid []uint64) []uint64 {
	res := make([]uint64, 0, count)
	seen := make(map[uint64]struct{}, count+len(forbid))
	for _, w := range forbid {
		seen[w%q] = struct{}{}
	}
	for len(res) < count {
		candidate := rng.nextU64() % q
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func sampleDistinctIndices(start, length, count int, rng *fsRNG) []int {
	if count > length {
		panic("sampleDistinctIndices: count exceeds range")
	}
	res := make([]int, 0, count)
	seen := make(map[int]struct{}, count)
	for len(res) < count {
		candidate := int(rng.nextU64()%uint64(length)) + start
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func ceilDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}

func logComb2(n float64, k int) float64 {
	if k < 0 || n <= 0 {
		return math.Inf(-1)
	}
	if float64(k) > n {
		return math.Inf(-1)
	}
	if k == 0 || n == 0 {
		return 0
	}
	// symmetry: C(n,k) == C(n,n-k)
	if float64(k) > n/2 {
		k = int(n) - k
	}
	if k <= 32 {
		var sum float64
		nf := n
		for i := 0; i < k; i++ {
			sum += math.Log2(nf - float64(i))
			sum -= math.Log2(float64(i + 1))
		}
		return sum
	}
	nPlus, _ := math.Lgamma(n + 1)
	kPlus, _ := math.Lgamma(float64(k) + 1)
	nMinusKPlus, _ := math.Lgamma(n - float64(k) + 1)
	return (nPlus - kPlus - nMinusKPlus) / math.Ln2
}

func clampBitsToProbability(rawBits float64) (float64, float64) {
	bits := rawBits
	if math.IsInf(bits, -1) || bits < 0 {
		bits = 0
	}
	if math.IsInf(bits, 1) {
		return bits, 0
	}
	return bits, math.Pow(2, -bits)
}

func theoremTerm(queryCap int, eps float64, kappa int) (float64, float64) {
	if queryCap <= 0 || eps <= 0 {
		return 0, math.Inf(1)
	}
	term := float64(queryCap) * eps * math.Pow(2, -float64(kappa))
	if term <= 0 {
		return 0, math.Inf(1)
	}
	if term >= 1 {
		return 1, 0
	}
	return term, -math.Log2(term)
}

// ComputeSoundnessBudgetForParams evaluates the SmallWood-ARK Eq. (8) terms and
// the Theorem 9 ROM aggregation for a concrete parameter tuple.
func ComputeSoundnessBudgetForParams(
	o SimOpts,
	q uint64,
	dQ int,
	witnessSupportCols int,
	committedCols int,
	nLeaves int,
	witnessRows int,
) SoundnessBudget {
	o.applyDefaults()
	fieldSize := float64(q)
	if o.Theta > 1 {
		// Small-field PACS lifts from the base field F_q to K/F_q of degree θ, so
		// PACS sampling happens over |K| = q^θ while PCS/LVCS/DECS stay over F_q.
		fieldSize = math.Pow(float64(q), float64(o.Theta))
	}
	return computeSoundnessBudget(
		o,
		q,
		fieldSize,
		fsCollisionSpaceBits(o.Lambda, 0),
		dQ,
		witnessSupportCols,
		committedCols,
		o.Ell,
		o.EllPrime,
		o.Eta,
		nLeaves,
		witnessRows,
	)
}

func computeSoundnessBudget(
	o SimOpts,
	q uint64,
	fieldSize float64,
	collisionSpaceBits int,
	dQ int,
	sWitness int,
	ncolsLVCS int,
	ell int,
	ellPrime int,
	eta int,
	nLeaves int,
	witnessRows int,
) SoundnessBudget {
	o.applyDefaults()
	sb := SoundnessBudget{DQ: dQ}
	if sWitness <= 0 {
		sWitness = 1
	}
	if ncolsLVCS <= 0 {
		ncolsLVCS = sWitness
	}
	if nLeaves <= 0 {
		nLeaves = sWitness
	}
	if collisionSpaceBits <= 0 {
		collisionSpaceBits = fsCollisionSpaceBits(o.Lambda, 0)
	}
	qf := float64(q)
	ddecs := ncolsLVCS + ell - 1
	sb.DDECS = ddecs
	sb.WitnessSupportCols = sWitness
	sb.CommittedCols = ncolsLVCS
	sb.CollisionSpaceBits = collisionSpaceBits
	sb.QueryCaps = o.ROQueryCaps

	rawBits1 := float64(eta)*math.Log2(qf) - logComb2Stable(float64(nLeaves), ddecs+2)
	sb.RawBits[0] = rawBits1
	sb.Bits[0], sb.Eps[0] = clampBitsToProbability(rawBits1)

	rhoEff := o.Rho
	if rhoEff < 1 {
		rhoEff = 1
	}
	var rawBits2 float64
	if o.Theta > 1 {
		rawBits2 = float64(o.Theta*rhoEff) * math.Log2(qf)
	} else {
		rawBits2 = float64(rhoEff) * math.Log2(qf)
	}
	sb.RawBits[1] = rawBits2
	sb.Bits[1], sb.Eps[1] = clampBitsToProbability(rawBits2)

	if ellPrime < 1 {
		ellPrime = 1
	}
	if fieldSize <= 0 {
		fieldSize = qf
	}
	// The PACS opening term uses Theorem 7 over S = K \ Ω in the small-field
	// variant, so the denominator is |S| = q^θ - s with s = |Ω| = NCols on this
	// branch, not the ring degree.
	Ssize := fieldSize - float64(sWitness)
	if Ssize < 1 {
		Ssize = 1
	}
	var rawBits3 float64
	if dQ < ellPrime {
		rawBits3 = math.Inf(1)
	} else {
		rawBits3 = logComb2Stable(Ssize, ellPrime) - logComb2Stable(float64(dQ), ellPrime)
		if math.IsInf(rawBits3, -1) {
			rawBits3 = math.Inf(1)
		}
	}
	sb.RawBits[2] = rawBits3
	sb.Bits[2], sb.Eps[2] = clampBitsToProbability(rawBits3)

	logCombCols := logComb2Stable(float64(ncolsLVCS+ell-1), ell)
	logCombLeaves := logComb2Stable(float64(nLeaves), ell)
	rawBits4 := logCombLeaves - logCombCols
	sb.RawBits[3] = rawBits4
	sb.Bits[3], sb.Eps[3] = clampBitsToProbability(rawBits4)

	sb.Eq8Total = sb.Eps[0] + sb.Eps[1] + sb.Eps[2] + sb.Eps[3]
	if sb.Eq8Total <= 0 {
		sb.Eq8Total = math.SmallestNonzeroFloat64
	}
	if sb.Eq8Total > 1 {
		sb.Eq8Total = 1
	}
	sb.Eq8TotalBits = -math.Log2(sb.Eq8Total)

	for i := 0; i < 4; i++ {
		kappa := o.Kappa[i]
		sb.GrindingBits[i] = float64(kappa)
		sb.Grinding[i] = math.Pow(2, -float64(kappa))
		sb.TheoremTerms[i], sb.TheoremBits[i] = theoremTerm(o.ROQueryCaps[i+1], sb.Eps[i], kappa)
	}

	querySquares := 0.0
	for _, cap := range o.ROQueryCaps {
		if cap > 0 {
			querySquares += float64(cap) * float64(cap)
		}
	}
	if querySquares > 0 {
		sb.Collision = querySquares * math.Pow(2, -float64(collisionSpaceBits))
		if sb.Collision > 1 {
			sb.Collision = 1
		}
		sb.CollisionBits = -math.Log2(sb.Collision)
	} else {
		sb.CollisionBits = math.Inf(1)
	}

	sb.Total = sb.Collision
	for _, term := range sb.TheoremTerms {
		sb.Total += term
	}
	if sb.Total <= 0 {
		sb.Total = math.SmallestNonzeroFloat64
	}
	if sb.Total > 1 {
		sb.Total = 1
	}
	sb.TotalBits = -math.Log2(sb.Total)

	rowsBlock := ceilDiv(witnessRows, ncolsLVCS)
	sb.NRows = rowsBlock * (sWitness + o.Theta)
	if o.Theta > 1 {
		// smallfield_matrix_v1 commits:
		// - rowsBlock witness blocks of size (s + theta),
		// - rho masks, each chunked into floor(dQ/ncols)+1 coefficient blocks,
		// - ell' coefficient matrices of size rowsBlock*theta for K-point replay.
		maskChunks := dQ/ncolsLVCS + 1
		sb.NRows += maskChunks * o.Theta * rhoEff
		sb.M = rowsBlock * o.Theta * ellPrime
	} else {
		sb.M = rowsBlock * ellPrime
	}
	return sb
}

func logSoundnessBudget(o SimOpts, q uint64, fieldSize float64, dQ int, sWitness int, ncolsLVCS int, ell int, ellPrime int, eta int, nLeaves int, witnessRows int) SoundnessBudget {
	sb := computeSoundnessBudget(o, q, fieldSize, fsCollisionSpaceBits(o.Lambda, 0), dQ, sWitness, ncolsLVCS, ell, ellPrime, eta, nLeaves, witnessRows)
	fmt.Printf("[soundness] eq8={eps1≤2^{-%0.2f}, eps2≤2^{-%0.2f}, eps3≤2^{-%0.2f}, eps4≤2^{-%0.2f}} eq8_total≈2^{-%0.2f} theorem_total≈2^{-%0.2f}\n",
		sb.Bits[0], sb.Bits[1], sb.Bits[2], sb.Bits[3], sb.Eq8TotalBits, sb.TotalBits)
	fmt.Printf("[soundness] theorem_terms={collision≈2^{-%0.2f}, round1≈2^{-%0.2f}, round2≈2^{-%0.2f}, round3≈2^{-%0.2f}, round4≈2^{-%0.2f}} qcaps=%v\n",
		sb.CollisionBits, sb.TheoremBits[0], sb.TheoremBits[1], sb.TheoremBits[2], sb.TheoremBits[3], sb.QueryCaps)
	fmt.Printf("[size] nrows=%d, m=%d, dQ=%d\n", sb.NRows, sb.M, sb.DQ)
	return sb
}

func sizeUint64Matrix(mat [][]uint64) int {
	sum := 0
	for _, row := range mat {
		sum += len(row) * 8
	}
	return sum
}

func varintSize(x int) int {
	if x < 0 {
		x = -x
	}
	ux := uint64(x)
	size := 1
	for ux >= 0x80 {
		size++
		ux >>= 7
	}
	return size
}

func sizeDECSOpening(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	sum := 0
	if open.FormatVersion != 0 {
		sum += 1
	}
	if open.PColsEncoded > 0 {
		sum += varintSize(open.PColsEncoded)
	}
	for _, col := range open.POmitCols {
		sum += varintSize(col)
	}
	if open.MFormatVersion != 0 {
		sum += 1
	}
	if open.MColsEncoded > 0 {
		sum += varintSize(open.MColsEncoded)
	}
	for _, col := range open.MOmitCols {
		sum += varintSize(col)
	}
	if open.MaskCount > 0 {
		sum += varintSize(open.MaskBase)
		sum += varintSize(open.MaskCount)
	}
	if len(open.IndexBits) > 0 && open.TailCount > 0 && len(open.Indices) == 0 {
		sum += len(open.IndexBits)
		sum += varintSize(open.TailCount)
	} else {
		for _, idx := range open.Indices {
			sum += varintSize(idx)
		}
	}
	if open.PvalsBits != nil {
		if open.PvalsBitWidth != 0 {
			sum += 1
		}
		sum += len(open.PvalsBits)
	} else {
		sum += sizeUint64Matrix(open.Pvals)
	}
	if open.MvalsBits != nil {
		if open.MvalsBitWidth != 0 {
			sum += 1
		}
		sum += len(open.MvalsBits)
	} else {
		sum += sizeUint64Matrix(open.Mvals)
	}
	// Nodes bytes (unique siblings)
	for _, node := range open.Nodes {
		sum += len(node)
	}
	for _, node := range open.FrontierNodes {
		sum += len(node)
	}
	if len(open.FrontierRefsBits) > 0 && open.FrontierRefWidth > 0 && open.FrontierRefCount > 0 {
		sum += len(open.FrontierRefsBits)
		sum += 1 // width byte
		sum += varintSize(open.FrontierRefCount)
	}
	sum += len(open.FrontierProof)
	sum += len(open.FrontierLR)
	if open.FrontierDepth > 0 {
		sum += 4
	}
	// PathIndex encoding (either packed bits or explicit ints)
	if len(open.PathBits) > 0 && open.PathDepth > 0 && open.PathBitWidth > 0 && len(open.PathIndex) == 0 {
		sum += len(open.PathBits)
		sum += 1 // bit width
		sum += varintSize(open.PathDepth)
	} else {
		for _, pi := range open.PathIndex {
			sum += len(pi) * 4
		}
	}
	if len(open.Nonces) > 0 {
		for _, nonce := range open.Nonces {
			sum += len(nonce)
		}
	} else if len(open.NonceSeed) > 0 {
		sum += len(open.NonceSeed)
	}
	if open.NonceBytes > 0 {
		sum += varintSize(open.NonceBytes)
	}
	return sum
}

func estimateProofSize(proof *Proof) int {
	if proof == nil {
		return 0
	}
	if proof.ShowingSplit != nil {
		sum := 0
		if proof.ShowingSplit.PostSign != nil {
			sum += estimateProofSize(proof.ShowingSplit.PostSign.Proof)
		}
		if proof.ShowingSplit.PRF != nil {
			sum += estimateProofSize(proof.ShowingSplit.PRF.Proof)
		}
		return sum
	}
	proof.syncPCSCompat()
	proof.ensureQRPacked()
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	sum := 0
	sum += len(proof.Salt)
	sum += 16 // Merkle root
	sum += len(proof.Ctr) * 8
	for _, d := range proof.Digests {
		sum += len(d)
	}
	// EvalPoints and KPoint are re-derived on verifier
	sum += len(proof.Chi) * 8
	sum += len(proof.Zeta) * 8
	sum += len(proof.Tail) * 4
	sum += 16 // QRoot
	sum += len(proof.QRBits)
	// CoeffMatrix (C) re-derived on verifier
	sum += len(proof.VTargetsBits)
	sum += len(proof.BarSetsBits)
	sum += sizeDECSOpening(resolveProofPCSOpening(proof))
	sum += sizeDECSOpening(proof.QOpening)
	return sum
}

// proofSizeBreakdown computes a per-component size accounting matching estimateProofSize.
func proofSizeBreakdown(proof *Proof) (map[string]int, int) {
	if proof == nil {
		return map[string]int{}, 0
	}
	if proof.ShowingSplit != nil {
		sizes := make(map[string]int)
		total := 0
		if proof.ShowingSplit.PostSign != nil {
			childSizes, childTotal := proofSizeBreakdown(proof.ShowingSplit.PostSign.Proof)
			total += childTotal
			for k, v := range childSizes {
				sizes[k] += v
			}
		}
		if proof.ShowingSplit.PRF != nil {
			childSizes, childTotal := proofSizeBreakdown(proof.ShowingSplit.PRF.Proof)
			total += childTotal
			for k, v := range childSizes {
				sizes[k] += v
			}
		}
		return sizes, total
	}
	proof.syncPCSCompat()
	proof.ensureQRPacked()
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	sizes := make(map[string]int)
	sizes["Salt"] = len(proof.Salt)
	sizes["Root"] = 16
	sizes["Ctr"] = len(proof.Ctr) * 8
	digSum := 0
	for _, d := range proof.Digests {
		digSum += len(d)
	}
	sizes["Digests"] = digSum
	sizes["EvalPoints"] = len(proof.EvalPoints) * 8
	sizes["PvalsEvalBits"] = len(proof.PvalsEvalBits)
	sizes["MvalsEvalBits"] = len(proof.MvalsEvalBits)
	sizes["MaskEvalBits"] = len(proof.MaskEvalBits)
	sizes["Chi"] = len(proof.Chi) * 8
	sizes["Zeta"] = len(proof.Zeta) * 8
	sizes["TailIndices"] = len(proof.Tail) * 4
	sizes["QRoot"] = 16
	sizes["QR"] = len(proof.QRBits)
	// C re-derived on verifier
	sizes["VTargets"] = len(proof.VTargetsBits)
	sizes["BarSets"] = len(proof.BarSetsBits)
	sizes["RowOpening"] = sizeDECSOpening(resolveProofPCSOpening(proof))
	sizes["QOpening"] = sizeDECSOpening(proof.QOpening)
	total := 0
	for _, v := range sizes {
		total += v
	}
	return sizes, total
}

// ProofSizeReport summarises the byte footprint of a proof as consumed by the verifier.
type ProofSizeReport struct {
	Total int
	Parts map[string]int
}

// MeasureProofSize returns a copy of the breakdown used by VerifyNIZK to reconstruct the proof.
func MeasureProofSize(proof *Proof) ProofSizeReport {
	parts, total := proofSizeBreakdown(proof)
	copyParts := make(map[string]int, len(parts))
	for k, v := range parts {
		copyParts[k] = v
	}
	return ProofSizeReport{Total: total, Parts: copyParts}
}

func combineOpenings(mask, tail *decs.DECSOpening) *decs.DECSOpening {
	combined := &decs.DECSOpening{}
	nodeMap := make(map[string]int)
	addNode := func(b []byte) int {
		key := string(b)
		if id, ok := nodeMap[key]; ok {
			return id
		}
		id := len(combined.Nodes)
		combined.Nodes = append(combined.Nodes, append([]byte(nil), b...))
		nodeMap[key] = id
		return id
	}
	// helper to append per-entry data and remap path indices
	appendOpen := func(src *decs.DECSOpening, storeIndices bool) {
		if src == nil {
			return
		}
		if err := decs.EnsureMerkleDecoded(src); err != nil {
			panic(err)
		}
		for _, b := range src.Nodes {
			_ = addNode(b)
		}
		for _, row := range src.Pvals {
			combined.Pvals = append(combined.Pvals, append([]uint64(nil), row...))
		}
		for _, row := range src.Mvals {
			combined.Mvals = append(combined.Mvals, append([]uint64(nil), row...))
		}
		for _, pi := range src.PathIndex {
			mapped := make([]int, len(pi))
			for i, id := range pi {
				if id < 0 || id >= len(src.Nodes) {
					mapped[i] = -1
					continue
				}
				mapped[i] = addNode(src.Nodes[id])
			}
			combined.PathIndex = append(combined.PathIndex, mapped)
		}
		if storeIndices {
			combined.Indices = append(combined.Indices, src.AllIndices()...)
		}
	}

	if mask != nil {
		maskIndices := mask.AllIndices()
		if len(maskIndices) > 0 {
			base := maskIndices[0]
			for i := 1; i < len(maskIndices); i++ {
				if maskIndices[i] != base+i {
					panic("mask indices not contiguous")
				}
			}
			combined.MaskBase = base
			combined.MaskCount = len(maskIndices)
		}
		combined.R = mask.R
		combined.Eta = mask.Eta
		if len(combined.NonceSeed) == 0 && len(mask.NonceSeed) > 0 {
			combined.NonceSeed = append([]byte(nil), mask.NonceSeed...)
			combined.NonceBytes = mask.NonceBytes
		}
		appendOpen(mask, false)
	}
	if tail != nil {
		if combined.R == 0 {
			combined.R = tail.R
		}
		if combined.Eta == 0 {
			combined.Eta = tail.Eta
		}
		if len(tail.NonceSeed) > 0 {
			if len(combined.NonceSeed) == 0 {
				combined.NonceSeed = append([]byte(nil), tail.NonceSeed...)
				combined.NonceBytes = tail.NonceBytes
			} else if !bytes.Equal(combined.NonceSeed, tail.NonceSeed) {
				panic("tail opening nonce seed mismatch")
			}
		}
		appendOpen(tail, true)
	}
	if len(combined.PathIndex) > 0 && len(combined.PathIndex[0]) > 0 {
		combined.PathDepth = len(combined.PathIndex[0])
	}
	return combined
}

func columnsToRowsSmallField(r *ring.Ring,
	w1 []*ring.Poly, _ *ring.Poly, _ []*ring.Poly,
	_ int, omega []uint64, ncols int, K *kf.Field,
) (rows [][]uint64, omegaS1 kf.Elem, muDenomInv kf.Elem, err error) {
	if K == nil {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: nil extension field")
	}
	q := r.Modulus[0]
	s := len(omega)
	if s == 0 {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: empty omega")
	}
	if ncols != s {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: ncols=%d must equal |Ω|=%d", ncols, s)
	}
	theta := K.Theta
	blocks := ceilDiv(len(w1), ncols)
	if blocks == 0 {
		blocks = 1
	}
	rows = make([][]uint64, 0, blocks*(s+theta))

	coeffs := make([][]uint64, len(w1))
	tmp := r.NewPoly()
	for i := range w1 {
		r.InvNTT(w1[i], tmp)
		coeffs[i] = append([]uint64(nil), tmp.Coeffs[0]...)
	}

	const maxAttempts = 1 << 12
	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate, randErr := K.RandomElement(nil)
		if randErr != nil {
			return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: %v", randErr)
		}
		conflict := false
		for _, w := range omega {
			if elemEqual(K, candidate, K.EmbedF(w%q)) {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		denom := K.One()
		zeroDiff := false
		for _, w := range omega {
			diff := K.Sub(candidate, K.EmbedF(w%q))
			if K.IsZero(diff) {
				zeroDiff = true
				break
			}
			denom = K.Mul(denom, diff)
		}
		if zeroDiff || K.IsZero(denom) {
			continue
		}
		muDenomInv = K.Inv(denom)
		omegaS1 = candidate
		break
	}
	if len(muDenomInv.Limb) == 0 {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: failed to sample ω_{s+1}")
	}

	Yvals := make([]kf.Elem, len(w1))
	for idx := range w1 {
		Yvals[idx] = K.EvalFPolyAtK(coeffs[idx], omegaS1)
	}

	for block := 0; block < blocks; block++ {
		for j := 0; j < s; j++ {
			row := make([]uint64, ncols)
			for t := 0; t < ncols; t++ {
				col := block*ncols + t
				if col < len(w1) {
					row[t] = EvalPoly(coeffs[col], omega[j]%q, q)
				}
			}
			rows = append(rows, row)
		}
		for coord := 0; coord < theta; coord++ {
			row := make([]uint64, ncols)
			for t := 0; t < ncols; t++ {
				col := block*ncols + t
				if col < len(Yvals) {
					row[t] = Yvals[col].Limb[coord] % q
				}
			}
			rows = append(rows, row)
		}
	}

	return rows, omegaS1, muDenomInv, nil
}

func buildKPointCoeffMatrix(
	r *ring.Ring, K *kf.Field, omega []uint64, rows [][]uint64, e kf.Elem, omegaS1 kf.Elem, muDenomInv kf.Elem,
	maskRowOffset, maskRowCount int,
) [][]uint64 {
	if K == nil {
		panic("buildKPointCoeffMatrix: nil field")
	}
	q := r.Modulus[0]
	s := len(omega)
	theta := K.Theta
	layerSize := s + theta
	if layerSize == 0 {
		return nil
	}
	totalRows := len(rows)
	witnessRowCount := totalRows
	if maskRowCount > 0 {
		if maskRowOffset < 0 || maskRowOffset > totalRows {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: mask offset %d out of bounds (total=%d)", maskRowOffset, totalRows))
		}
		if maskRowOffset+maskRowCount != totalRows {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: mask segment [%d,%d) inconsistent with total rows %d", maskRowOffset, maskRowOffset+maskRowCount, totalRows))
		}
		witnessRowCount = maskRowOffset
	}
	if witnessRowCount%layerSize != 0 {
		panic(fmt.Sprintf("buildKPointCoeffMatrix: inconsistent row count %d (layer size %d)", witnessRowCount, layerSize))
	}
	layerCount := witnessRowCount / layerSize

	lagNum := make([][]uint64, s)
	lagDenInv := make([]uint64, s)
	for k := 0; k < s; k++ {
		lagNum[k] = lagrangeBasisNumerator(omega, k, q)
		den := uint64(1)
		for j := 0; j < s; j++ {
			if j == k {
				continue
			}
			den = modMul(den, modSub(omega[k]%q, omega[j]%q, q), q)
		}
		lagDenInv[k] = modInv(den, q)
	}

	lambdas := make([]kf.Elem, s)
	lambdaAtOmegaS1 := make([]kf.Elem, s)
	for k := 0; k < s; k++ {
		numK := K.EvalFPolyAtK(lagNum[k], e)
		lambdas[k] = K.Mul(numK, K.EmbedF(lagDenInv[k]))
		numOmegaS1 := K.EvalFPolyAtK(lagNum[k], omegaS1)
		lambdaAtOmegaS1[k] = K.Mul(numOmegaS1, K.EmbedF(lagDenInv[k]))
	}

	prod := K.One()
	for _, w := range omega {
		diff := K.Sub(e, K.EmbedF(w%q))
		prod = K.Mul(prod, diff)
	}
	mu := K.Mul(prod, muDenomInv)
	Mmu := K.MulMatrix(mu)

	coeffs := make([][]uint64, layerCount*theta)
	for layer := 0; layer < layerCount; layer++ {
		base := layer * layerSize
		for k := 0; k < s; k++ {
			coeffK := K.Sub(lambdas[k], K.Mul(mu, lambdaAtOmegaS1[k]))
			for coord := 0; coord < theta; coord++ {
				rowIdx := layer*theta + coord
				if coeffs[rowIdx] == nil {
					coeffs[rowIdx] = make([]uint64, totalRows)
				}
				coeffs[rowIdx][base+k] = coeffK.Limb[coord] % q
			}
		}
		for coord := 0; coord < theta; coord++ {
			for rowIdx := 0; rowIdx < theta; rowIdx++ {
				coeffs[layer*theta+coord][base+s+rowIdx] = Mmu[coord][rowIdx] % q
			}
		}
	}

	return coeffs
}

func elemEqual(f *kf.Field, a, b kf.Elem) bool {
	if len(a.Limb) != len(b.Limb) {
		return false
	}
	for i := range a.Limb {
		if a.Limb[i]%f.Q != b.Limb[i]%f.Q {
			return false
		}
	}
	return true
}

func columnsToRows(r *ring.Ring, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly, ell int, omega []uint64) [][]uint64 {
	s := len(w1)
	ncols := len(omega)
	rows := make([][]uint64, s+2)
	q := r.Modulus[0]

	// Row 0..s-1: for each witness column k, evaluate w1[k](ω_j) for all j.
	tmp := r.NewPoly()
	for k := 0; k < s; k++ {
		rows[k] = make([]uint64, ncols)
		r.InvNTT(w1[k], tmp) // coeff domain of w1[k]
		for j := 0; j < ncols; j++ {
			rows[k][j] = EvalPoly(tmp.Coeffs[0], omega[j]%q, q)
		}
	}

	// Row s: w2(ω_j)
	r.InvNTT(w2, tmp)
	rows[s] = make([]uint64, ncols)
	for j := 0; j < ncols; j++ {
		rows[s][j] = EvalPoly(tmp.Coeffs[0], omega[j]%q, q)
	}

	// Row s+1: per‑column product w3[col](ω_col) on the diagonal; 0 elsewhere.
	rows[s+1] = make([]uint64, ncols)
	for col := 0; col < ncols && col < len(w3); col++ {
		r.InvNTT(w3[col], tmp)
		rows[s+1][col] = EvalPoly(tmp.Coeffs[0], omega[col]%q, q)
	}

	return rows
}

func evalAt(r *ring.Ring, p *ring.Poly, x uint64) uint64 {
	coeff := r.NewPoly()
	r.InvNTT(p, coeff)
	return EvalPoly(coeff.Coeffs[0], x%r.Modulus[0], r.Modulus[0])
}

func evalPolySetAtIndices(r *ring.Ring, polys []*ring.Poly, indices []int, points []uint64) [][]uint64 {
	if len(polys) == 0 || len(indices) == 0 {
		return nil
	}
	if len(points) == 0 {
		panic("evalPolySetAtIndices: explicit domain points are required")
	}
	q := r.Modulus[0]
	out := make([][]uint64, len(polys))
	tmp := r.NewPoly()
	for i := range polys {
		row := make([]uint64, len(indices))
		r.InvNTT(polys[i], tmp)
		coeffs := tmp.Coeffs[0]
		for j, idx := range indices {
			if idx < 0 || idx >= len(points) {
				panic(fmt.Sprintf("evalPolySetAtIndices: index %d out of range (len(points)=%d)", idx, len(points)))
			}
			row[j] = EvalPoly(coeffs, points[idx]%q, q)
		}
		out[i] = row
	}
	return out
}

func logComb2Stable(n float64, k int) float64 {
	if k < 0 || float64(k) > n {
		return -1e18
	}
	if k == 0 || float64(k) == n {
		return 0
	}
	if k <= 64 {
		sum := 0.0
		for i := 0; i < k; i++ {
			sum += math.Log2(n-float64(i)) - math.Log2(float64(i+1))
		}
		return sum
	}
	return logComb2(n, k)
}

func flattenBytes(parts [][]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func equalByteSlices(a, b []byte) bool {
	return bytes.Equal(a, b)
}
