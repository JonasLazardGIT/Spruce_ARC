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

// PublicParams captures the stable credential-side public parameters used by
// issuance and showing.
type PublicParams struct {
	HashRelation string                 `json:"hash_relation"`
	Ac     commitment.CoeffMatrix `json:"Ac"`
	BPath  string                 `json:"BPath"`
	BoundB int64                  `json:"BoundB"`
	LenM1  int                    `json:"LenM1"`
	LenM2  int                    `json:"LenM2"`
	LenRU0 int                    `json:"LenRU0"`
	LenRU1 int                    `json:"LenRU1"`
	LenR   int                    `json:"LenR"`
}

func (pp PublicParams) Validate() error {
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
	if pp.LenM1 <= 0 || pp.LenM2 <= 0 || pp.LenRU0 <= 0 || pp.LenRU1 <= 0 || pp.LenR <= 0 {
		return fmt.Errorf("invalid row lengths m1=%d m2=%d ru0=%d ru1=%d r=%d", pp.LenM1, pp.LenM2, pp.LenRU0, pp.LenRU1, pp.LenR)
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
	if err := out.Validate(); err != nil {
		return out, fmt.Errorf("validate public params %s: %w", path, err)
	}
	return out, nil
}

func SavePublicParams(path string, params PublicParams) error {
	if err := params.Validate(); err != nil {
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
	if err := pp.Validate(); err != nil {
		return nil, err
	}
	ac, err := commitment.MatrixFromCoeff(ringQ, pp.Ac)
	if err != nil {
		return nil, fmt.Errorf("lift Ac to NTT: %w", err)
	}
	return &Params{
		HashRelation: pp.HashRelation,
		Ac:     ac,
		BPath:  pp.BPath,
		BoundB: pp.BoundB,
		LenM1:  pp.LenM1,
		LenM2:  pp.LenM2,
		LenRU0: pp.LenRU0,
		LenRU1: pp.LenRU1,
		LenR:   pp.LenR,
		RingQ:  ringQ,
	}, nil
}
