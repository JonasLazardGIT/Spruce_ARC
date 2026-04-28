package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vSIS-Signature/commitment"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const DefaultPublicParamsPath = "Parameters/credential_public.json"
const PublicParamsVersion = 5
const MuLayoutFullCapacityHalvesV1 = "full_capacity_halves_v1"

// PublicParams captures the stable credential-side public parameters used by
// issuance and showing.
type PublicParams struct {
	Version              int                    `json:"version,omitempty"`
	Profile              string                 `json:"profile,omitempty"`
	HashRelation         string                 `json:"hash_relation"`
	Ac                   commitment.CoeffMatrix `json:"Ac"`
	CM                   commitment.CoeffMatrix `json:"C_M,omitempty"`
	AS                   commitment.CoeffMatrix `json:"A_s,omitempty"`
	BPath                string                 `json:"BPath"`
	BoundB               int64                  `json:"BoundB"`
	CommitmentBound      int64                  `json:"B,omitempty"`
	EllM                 int                    `json:"ell_M,omitempty"`
	KS                   int                    `json:"k_s,omitempty"`
	NC                   int                    `json:"n_c,omitempty"`
	EllMuSig             int                    `json:"ell_mu_sig,omitempty"`
	EllX0                int                    `json:"ell_x0,omitempty"`
	EllX1                int                    `json:"ell_x1,omitempty"`
	SignaturePreimageLen int                    `json:"signature_preimage_len,omitempty"`
	MLWEHidingBits       float64                `json:"mlwe_hiding_bits,omitempty"`
	MSISBindingBits      float64                `json:"msis_binding_bits,omitempty"`
	X0Len                int                    `json:"X0Len,omitempty"`
	X0CoeffBound         int64                  `json:"X0CoeffBound,omitempty"`
	TargetDim            int                    `json:"TargetDim,omitempty"`
	TargetHidingLambda   int                    `json:"TargetHidingLambda,omitempty"`
	RingDegree           int                    `json:"ring_degree,omitempty"`
	X0Distribution       string                 `json:"X0Distribution,omitempty"`
	LenMu                int                    `json:"LenMu,omitempty"`
	MuLayout             string                 `json:"MuLayout,omitempty"`
	LenM                 int                    `json:"LenM,omitempty"`
	LenK                 int                    `json:"LenK,omitempty"`
	LenR0H               int                    `json:"LenR0H,omitempty"`
	LenR1H               int                    `json:"LenR1H,omitempty"`
	LenRBar              int                    `json:"LenRBar,omitempty"`

	LegacyLenM1  int `json:"LenM1,omitempty"`
	LegacyLenM2  int `json:"LenM2,omitempty"`
	LegacyLenRU0 int `json:"LenRU0,omitempty"`
	LegacyLenRU1 int `json:"LenRU1,omitempty"`
	LegacyLenR   int `json:"LenR,omitempty"`
}

func (pp *PublicParams) normalizeLegacy() {
	if pp.Version == 0 {
		pp.Version = 1
	}
	if pp.LenM == 0 {
		pp.LenM = pp.LegacyLenM1
	}
	if pp.LenK == 0 {
		pp.LenK = pp.LegacyLenM2
	}
	if pp.LenMu == 0 && (pp.LenM > 0 || pp.LenK > 0) {
		pp.LenMu = 1
	}
	if pp.LenR0H == 0 {
		pp.LenR0H = pp.LegacyLenRU0
	}
	if pp.LenR1H == 0 {
		pp.LenR1H = pp.LegacyLenRU1
	}
	if pp.LenRBar == 0 {
		pp.LenRBar = pp.LegacyLenR
	}
	if pp.X0Len == 0 {
		if pp.LenR0H > 0 {
			pp.X0Len = pp.LenR0H
		} else {
			pp.X0Len = 1
		}
	}
	if pp.X0CoeffBound == 0 {
		if pp.BoundB > 0 {
			pp.X0CoeffBound = pp.BoundB
		} else {
			pp.X0CoeffBound = 1
		}
	}
	if pp.TargetDim == 0 {
		pp.TargetDim = DefaultTargetDim
	}
	if pp.TargetHidingLambda == 0 {
		pp.TargetHidingLambda = DefaultTargetHidingLambda
	}
	if pp.X0Distribution == "" {
		pp.X0Distribution = X0DistributionUniformInterval
	}
	if pp.MuLayout == "" {
		pp.MuLayout = MuLayoutFullCapacityHalvesV1
	}
	if pp.Version < PublicParamsVersion {
		pp.Version = PublicParamsVersion
	}
	if pp.RingDegree == 0 {
		pp.RingDegree = pp.InferRingDegree()
	}
	if pp.Profile != "" {
		if profile, ok := LookupIntGenISISProfile(pp.Profile); ok {
			if pp.RingDegree == 0 {
				pp.RingDegree = profile.N
			}
			if pp.CommitmentBound == 0 {
				pp.CommitmentBound = profile.B
			}
			if pp.BoundB == 0 {
				pp.BoundB = profile.B
			}
			if pp.EllM == 0 {
				pp.EllM = profile.EllM
			}
			if pp.KS == 0 {
				pp.KS = profile.KS
			}
			if pp.NC == 0 {
				pp.NC = profile.NC
			}
			if pp.EllMuSig == 0 {
				pp.EllMuSig = profile.EllMuSig
			}
			if pp.EllX0 == 0 {
				pp.EllX0 = profile.EllX0
			}
			if pp.EllX1 == 0 {
				pp.EllX1 = profile.EllX1
			}
			if pp.SignaturePreimageLen == 0 {
				pp.SignaturePreimageLen = profile.SignaturePreimageLen
			}
			if pp.MLWEHidingBits == 0 {
				pp.MLWEHidingBits = profile.MLWEHidingBits
			}
			if pp.MSISBindingBits == 0 {
				pp.MSISBindingBits = profile.MSISBindingBits
			}
			if pp.TargetDim == 0 {
				pp.TargetDim = profile.NC
			}
			if pp.X0Len == 0 || pp.LenR0H == 0 {
				pp.X0Len = profile.EllX0
			}
		}
	}
}

func (pp PublicParams) InferRingDegree() int {
	if pp.RingDegree > 0 {
		return pp.RingDegree
	}
	for i := range pp.Ac {
		for j := range pp.Ac[i] {
			if len(pp.Ac[i][j]) > 0 {
				return len(pp.Ac[i][j])
			}
		}
	}
	for i := range pp.CM {
		for j := range pp.CM[i] {
			if len(pp.CM[i][j]) > 0 {
				return len(pp.CM[i][j])
			}
		}
	}
	for i := range pp.AS {
		for j := range pp.AS[i] {
			if len(pp.AS[i][j]) > 0 {
				return len(pp.AS[i][j])
			}
		}
	}
	return 0
}

func (pp PublicParams) UsesIntGenISIS() bool {
	return pp.Profile == ProfileIntGenISISB || pp.Profile == ProfileIntGenISISA || len(pp.CM) > 0 || len(pp.AS) > 0
}

func (pp *PublicParams) Validate() error {
	pp.normalizeLegacy()
	if err := ValidateHashRelation(pp.HashRelation); err != nil {
		return err
	}
	if pp.BPath == "" {
		return fmt.Errorf("missing BPath")
	}
	if pp.BoundB <= 0 {
		return fmt.Errorf("invalid BoundB=%d", pp.BoundB)
	}
	if pp.UsesIntGenISIS() {
		return pp.validateIntGenISIS()
	}
	if len(pp.Ac) == 0 {
		return fmt.Errorf("missing Ac")
	}
	if pp.X0CoeffBound <= 0 {
		return fmt.Errorf("invalid X0CoeffBound=%d", pp.X0CoeffBound)
	}
	if pp.X0Len <= 0 {
		return fmt.Errorf("invalid X0Len=%d", pp.X0Len)
	}
	if pp.TargetDim <= 0 {
		return fmt.Errorf("invalid TargetDim=%d", pp.TargetDim)
	}
	if pp.TargetHidingLambda <= 0 {
		return fmt.Errorf("invalid TargetHidingLambda=%d", pp.TargetHidingLambda)
	}
	if pp.X0Distribution != X0DistributionUniformInterval {
		return fmt.Errorf("unsupported X0Distribution=%q", pp.X0Distribution)
	}
	if pp.MuLayout != MuLayoutFullCapacityHalvesV1 {
		return fmt.Errorf("unsupported MuLayout=%q", pp.MuLayout)
	}
	if pp.LenMu <= 0 || pp.LenR0H <= 0 || pp.LenR1H <= 0 || pp.LenRBar <= 0 {
		return fmt.Errorf("invalid row lengths mu=%d r0h=%d r1h=%d rbar=%d", pp.LenMu, pp.LenR0H, pp.LenR1H, pp.LenRBar)
	}
	if pp.LenR0H != pp.X0Len {
		return fmt.Errorf("LenR0H=%d must match X0Len=%d", pp.LenR0H, pp.X0Len)
	}
	if pp.RingDegree <= 0 {
		return fmt.Errorf("invalid ring_degree=%d", pp.RingDegree)
	}
	for i := range pp.Ac {
		for j := range pp.Ac[i] {
			if len(pp.Ac[i][j]) != pp.RingDegree {
				return fmt.Errorf("Ac[%d][%d] coefficient length=%d want ring_degree=%d", i, j, len(pp.Ac[i][j]), pp.RingDegree)
			}
		}
	}
	return nil
}

func (pp *PublicParams) validateIntGenISIS() error {
	if _, ok := LookupIntGenISISProfile(pp.Profile); pp.Profile != "" && !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", pp.Profile)
	}
	if pp.CommitmentBound <= 0 {
		return fmt.Errorf("invalid commitment bound B=%d", pp.CommitmentBound)
	}
	if pp.EllM <= 0 || pp.KS <= 0 || pp.NC <= 0 {
		return fmt.Errorf("invalid commitment dimensions ell_M=%d k_s=%d n_c=%d", pp.EllM, pp.KS, pp.NC)
	}
	if pp.EllMuSig != 1 {
		return fmt.Errorf("ell_mu_sig=%d want 1", pp.EllMuSig)
	}
	if pp.EllX0 != 2 {
		return fmt.Errorf("ell_x0=%d want 2", pp.EllX0)
	}
	if pp.EllX1 != 1 {
		return fmt.Errorf("ell_x1=%d want 1", pp.EllX1)
	}
	if pp.SignaturePreimageLen != 2 {
		return fmt.Errorf("signature_preimage_len=%d want 2", pp.SignaturePreimageLen)
	}
	if pp.TargetDim != pp.NC {
		return fmt.Errorf("target_dim=%d must match n_c=%d", pp.TargetDim, pp.NC)
	}
	if pp.X0Len != 0 && pp.X0Len != pp.EllX0 {
		return fmt.Errorf("legacy X0Len=%d must match ell_x0=%d", pp.X0Len, pp.EllX0)
	}
	if err := validateCoeffMatrixDims("C_M", pp.CM, pp.NC, pp.EllM, pp.RingDegree); err != nil {
		return err
	}
	if err := validateCoeffMatrixDims("A_s", pp.AS, pp.NC, pp.KS, pp.RingDegree); err != nil {
		return err
	}
	return nil
}

func validateCoeffMatrixDims(name string, mat commitment.CoeffMatrix, rows, cols, degree int) error {
	if len(mat) != rows {
		return fmt.Errorf("%s rows=%d want %d", name, len(mat), rows)
	}
	for i := range mat {
		if len(mat[i]) != cols {
			return fmt.Errorf("%s row %d cols=%d want %d", name, i, len(mat[i]), cols)
		}
		for j := range mat[i] {
			if len(mat[i][j]) != degree {
				return fmt.Errorf("%s[%d][%d] coefficient length=%d want ring_degree=%d", name, i, j, len(mat[i][j]), degree)
			}
		}
	}
	return nil
}

func LoadPublicParams(path string) (PublicParams, error) {
	var out PublicParams
	data, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("read public params: %w", err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("unmarshal public params: %w", err)
	}
	if err := (&out).Validate(); err != nil {
		return out, fmt.Errorf("validate public params %s: %w", path, err)
	}
	return out, nil
}

func SavePublicParams(path string, params PublicParams) error {
	if params.Version == 0 {
		params.Version = PublicParamsVersion
	}
	if err := (&params).Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir public params dir: %w", err)
	}
	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal public params: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write public params: %w", err)
	}
	return nil
}

func (pp PublicParams) ToIssuanceParams(ringQ *ring.Ring) (*Params, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if err := (&pp).Validate(); err != nil {
		return nil, err
	}
	var ac commitment.Matrix
	var err error
	if len(pp.Ac) > 0 {
		ac, err = commitment.MatrixFromCoeff(ringQ, pp.Ac)
		if err != nil {
			return nil, fmt.Errorf("lift Ac to NTT: %w", err)
		}
	}
	var cm commitment.Matrix
	if len(pp.CM) > 0 {
		cm, err = commitment.MatrixFromCoeff(ringQ, pp.CM)
		if err != nil {
			return nil, fmt.Errorf("lift C_M to NTT: %w", err)
		}
	}
	var as commitment.Matrix
	if len(pp.AS) > 0 {
		as, err = commitment.MatrixFromCoeff(ringQ, pp.AS)
		if err != nil {
			return nil, fmt.Errorf("lift A_s to NTT: %w", err)
		}
	}
	return &Params{
		HashRelation:         pp.HashRelation,
		Ac:                   ac,
		CM:                   cm,
		AS:                   as,
		BPath:                pp.BPath,
		Profile:              pp.Profile,
		BoundB:               pp.BoundB,
		CommitmentBound:      pp.CommitmentBound,
		EllM:                 pp.EllM,
		KS:                   pp.KS,
		NC:                   pp.NC,
		EllMuSig:             pp.EllMuSig,
		EllX0:                pp.EllX0,
		EllX1:                pp.EllX1,
		SignaturePreimageLen: pp.SignaturePreimageLen,
		X0Len:                pp.X0Len,
		X0CoeffBound:         pp.X0CoeffBound,
		TargetDim:            pp.TargetDim,
		TargetHidingLambda:   pp.TargetHidingLambda,
		RingDegree:           pp.RingDegree,
		X0Distribution:       pp.X0Distribution,
		LenMu:                pp.LenMu,
		MuLayout:             pp.MuLayout,
		LenM:                 pp.LenM,
		LenK:                 pp.LenK,
		LenR0H:               pp.LenR0H,
		LenR1H:               pp.LenR1H,
		LenRBar:              pp.LenRBar,
		LenM1:                pp.LenM,
		LenM2:                pp.LenK,
		LenRU0:               pp.LenR0H,
		LenRU1:               pp.LenR1H,
		LenR:                 pp.LenRBar,
		RingQ:                ringQ,
	}, nil
}

func (pp PublicParams) ToCommitmentParams(ringQ *ring.Ring) (commitment.TargetParams, error) {
	params, err := pp.ToIssuanceParams(ringQ)
	if err != nil {
		return commitment.TargetParams{}, err
	}
	if len(params.CM) == 0 || len(params.AS) == 0 {
		return commitment.TargetParams{}, fmt.Errorf("public params do not contain IntGenISIS C_M/A_s matrices")
	}
	out := commitment.TargetParams{
		RingQ: ringQ,
		CM:    params.CM,
		AS:    params.AS,
		EllM:  params.EllM,
		KS:    params.KS,
		NC:    params.NC,
		Bound: params.CommitmentBound,
	}
	if err := out.Validate(); err != nil {
		return commitment.TargetParams{}, err
	}
	return out, nil
}
