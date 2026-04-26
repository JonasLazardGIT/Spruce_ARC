package credential

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const StateVersion = 4

// State captures all holder-side data needed to persist a credential.
// All polys are stored in coefficient form (no seeds).
type State struct {
	Version            int       `json:"version"`
	Mu                 [][]int64 `json:"mu"`
	MuLayout           string    `json:"mu_layout,omitempty"`
	R0                 [][]int64 `json:"r0"`
	R1                 [][]int64 `json:"r1"`
	Z                  [][]int64 `json:"z"`
	X0Len              int       `json:"x0_len,omitempty"`
	X0CoeffBound       int64     `json:"x0_coeff_bound,omitempty"`
	TargetDim          int       `json:"target_dim,omitempty"`
	TargetHidingLambda int       `json:"target_hiding_lambda,omitempty"`
	RingDegree         int       `json:"ring_degree,omitempty"`
	// Showing-signature rows s1 and s2 are the bounded rows.
	SigS1 []int64 `json:"sig_s1,omitempty"`
	SigS2 []int64 `json:"sig_s2,omitempty"`
	// PackedNCols fixes the issuance/showing witness packing width.
	PackedNCols int       `json:"packed_ncols,omitempty"`
	Com         [][]int64 `json:"com"`
	RI0         [][]int64 `json:"ri0"`
	RI1         [][]int64 `json:"ri1"`
	// Stable credential public parameters used by issuance and showing.
	CredentialPublicPath string `json:"credential_public_path"`
	HashRelation         string `json:"hash_relation"`
	// Paths to public parameters.
	BPath string `json:"b_path"`
	// Embedded public B-matrix (coeff domain) for portability.
	B [][]int64 `json:"b,omitempty"`
	// PRF params path used when deriving tag in showing.
	PRFParamsPath string `json:"prf_params_path,omitempty"`
	// NTRU keys (coeff form).
	NTRUPublic [][]int64 `json:"ntru_public,omitempty"`
}

// polyToInt64 converts a ring.Poly to coeff slice in [-q/2, q/2].
func polyToInt64(p *ring.Poly, ringQ *ring.Ring) []int64 {
	out := make([]int64, ringQ.N)
	q := int64(ringQ.Modulus[0])
	half := q / 2
	for i, c := range p.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out
}

// polysToInt64 converts a slice of polys.
func polysToInt64(vec []*ring.Poly, ringQ *ring.Ring) [][]int64 {
	out := make([][]int64, len(vec))
	for i, p := range vec {
		out[i] = polyToInt64(p, ringQ)
	}
	return out
}

func maxAbsInt64Slice(vals []int64) int64 {
	var m int64
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	return m
}

// SignatureCoordLinf returns the separate and joint infinity norms of the
// top-level signed rows that issuance persists and showing later checks.
func (st State) SignatureCoordLinf() (maxS1 int64, maxS2 int64, maxSig int64) {
	maxS1 = maxAbsInt64Slice(st.SigS1)
	maxS2 = maxAbsInt64Slice(st.SigS2)
	maxSig = maxS1
	if maxS2 > maxSig {
		maxSig = maxS2
	}
	return maxS1, maxS2, maxSig
}

func (st State) InferRingDegree() int {
	if st.RingDegree > 0 {
		return st.RingDegree
	}
	for _, row := range st.Mu {
		if len(row) > 0 {
			return len(row)
		}
	}
	for _, row := range st.R0 {
		if len(row) > 0 {
			return len(row)
		}
	}
	for _, row := range st.R1 {
		if len(row) > 0 {
			return len(row)
		}
	}
	if len(st.SigS1) > 0 {
		return len(st.SigS1)
	}
	if len(st.SigS2) > 0 {
		return len(st.SigS2)
	}
	for _, row := range st.NTRUPublic {
		if len(row) > 0 {
			return len(row)
		}
	}
	return 0
}

// polyFromInt64 builds a coeff-domain poly from centered coeffs in [-q/2,q/2].
func polyFromInt64(coeffs []int64, ringQ *ring.Ring) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i, v := range coeffs {
		val := v
		if val < 0 {
			val += q
		}
		p.Coeffs[0][i] = uint64(val % q)
	}
	return p
}

// polysFromInt64 builds a slice of polys from coeff slices.
func polysFromInt64(vec [][]int64, ringQ *ring.Ring) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i, coeffs := range vec {
		out[i] = polyFromInt64(coeffs, ringQ)
	}
	return out
}

// ValidateFullMuPayload checks the canonical signed payload shape: one
// coefficient-domain ring element with every coefficient bounded by BoundB.
func ValidateFullMuPayload(mu [][]int64, ringN int, boundB int64) error {
	if len(mu) != 1 {
		return fmt.Errorf("mu row count=%d want 1", len(mu))
	}
	if boundB < 0 {
		return fmt.Errorf("invalid mu bound=%d", boundB)
	}
	if ringN > 0 {
		if len(mu[0]) != ringN {
			return fmt.Errorf("mu coefficient length=%d want ring dimension %d", len(mu[0]), ringN)
		}
	}
	for i := range mu[0] {
		if mu[0][i] < -boundB || mu[0][i] > boundB {
			return fmt.Errorf("mu coefficient %d=%d outside [%d,%d]", i, mu[0][i], -boundB, boundB)
		}
	}
	return nil
}

// matrixToInt64 converts a matrix of polys (NTT or coeff) to coeff slices.
func matrixToInt64(mat [][]*ring.Poly, ringQ *ring.Ring, ntt bool) [][][]int64 {
	if len(mat) == 0 {
		return nil
	}
	rows := len(mat)
	cols := len(mat[0])
	out := make([][][]int64, rows)
	for i := 0; i < rows; i++ {
		out[i] = make([][]int64, cols)
		for j := 0; j < cols; j++ {
			p := mat[i][j]
			if ntt {
				cp := ringQ.NewPoly()
				ring.Copy(p, cp)
				ringQ.InvNTT(cp, cp)
				p = cp
			}
			out[i][j] = polyToInt64(p, ringQ)
		}
	}
	return out
}

// SaveState writes the credential state to the given path.
func SaveState(path string, ringQ *ring.Ring, st State) error {
	if st.Version == 0 {
		st.Version = StateVersion
	}
	if st.RingDegree == 0 && ringQ != nil {
		st.RingDegree = int(ringQ.N)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

// LoadState reads a credential state from disk.
func LoadState(path string) (State, error) {
	var st State
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("unmarshal state: %w", err)
	}
	switch st.Version {
	case StateVersion:
		if st.MuLayout == "" {
			st.MuLayout = MuLayoutFullCapacityHalvesV1
		}
		if st.MuLayout != MuLayoutFullCapacityHalvesV1 {
			return st, fmt.Errorf("unsupported credential mu layout %q in %s", st.MuLayout, path)
		}
		if st.X0Len == 0 {
			st.X0Len = len(st.R0)
		}
		if st.TargetDim == 0 {
			st.TargetDim = DefaultTargetDim
		}
		if st.TargetHidingLambda == 0 {
			st.TargetHidingLambda = DefaultTargetHidingLambda
		}
		if st.RingDegree == 0 {
			st.RingDegree = st.InferRingDegree()
		}
	default:
		return st, fmt.Errorf("unsupported credential state version %d in %s; regenerate the credential with the mu-aligned issuance flow", st.Version, path)
	}
	if len(st.Mu) == 0 {
		return st, fmt.Errorf("credential state %s missing mu payload", path)
	}
	if st.RingDegree <= 0 {
		return st, fmt.Errorf("credential state %s has invalid ring_degree=%d", path, st.RingDegree)
	}
	return st, nil
}
