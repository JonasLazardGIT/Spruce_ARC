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
const PublicParamsVersion = 4
const MuLayoutFullCapacityHalvesV1 = "full_capacity_halves_v1"

// PublicParams captures the stable credential-side public parameters used by
// issuance and showing.
type PublicParams struct {
	Version            int                    `json:"version,omitempty"`
	HashRelation       string                 `json:"hash_relation"`
	Ac                 commitment.CoeffMatrix `json:"Ac"`
	BPath              string                 `json:"BPath"`
	BoundB             int64                  `json:"BoundB"`
	X0Len              int                    `json:"X0Len,omitempty"`
	X0CoeffBound       int64                  `json:"X0CoeffBound,omitempty"`
	TargetDim          int                    `json:"TargetDim,omitempty"`
	TargetHidingLambda int                    `json:"TargetHidingLambda,omitempty"`
	RingDegree         int                    `json:"ring_degree,omitempty"`
	X0Distribution     string                 `json:"X0Distribution,omitempty"`
	LenMu              int                    `json:"LenMu,omitempty"`
	MuLayout           string                 `json:"MuLayout,omitempty"`
	LenM               int                    `json:"LenM,omitempty"`
	LenK               int                    `json:"LenK,omitempty"`
	LenR0H             int                    `json:"LenR0H,omitempty"`
	LenR1H             int                    `json:"LenR1H,omitempty"`
	LenRBar            int                    `json:"LenRBar,omitempty"`

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
	return 0
}

func (pp *PublicParams) Validate() error {
	pp.normalizeLegacy()
	if err := ValidateHashRelation(pp.HashRelation); err != nil {
		return err
	}
	if len(pp.Ac) == 0 {
		return fmt.Errorf("missing Ac")
	}
	if pp.BPath == "" {
		return fmt.Errorf("missing BPath")
	}
	if pp.BoundB <= 0 {
		return fmt.Errorf("invalid BoundB=%d", pp.BoundB)
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
	ac, err := commitment.MatrixFromCoeff(ringQ, pp.Ac)
	if err != nil {
		return nil, fmt.Errorf("lift Ac to NTT: %w", err)
	}
	return &Params{
		HashRelation:       pp.HashRelation,
		Ac:                 ac,
		BPath:              pp.BPath,
		BoundB:             pp.BoundB,
		X0Len:              pp.X0Len,
		X0CoeffBound:       pp.X0CoeffBound,
		TargetDim:          pp.TargetDim,
		TargetHidingLambda: pp.TargetHidingLambda,
		RingDegree:         pp.RingDegree,
		X0Distribution:     pp.X0Distribution,
		LenMu:              pp.LenMu,
		MuLayout:           pp.MuLayout,
		LenM:               pp.LenM,
		LenK:               pp.LenK,
		LenR0H:             pp.LenR0H,
		LenR1H:             pp.LenR1H,
		LenRBar:            pp.LenRBar,
		LenM1:              pp.LenM,
		LenM2:              pp.LenK,
		LenRU0:             pp.LenR0H,
		LenRU1:             pp.LenR1H,
		LenR:               pp.LenRBar,
		RingQ:              ringQ,
	}, nil
}
