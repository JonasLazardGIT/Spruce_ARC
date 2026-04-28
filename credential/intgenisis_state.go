package credential

import (
	"encoding/json"
	"fmt"
	"os"
)

const IntGenISISStateVersion = 5

// IntGenISISState is the live credential witness/state for the committed-message
// protocol. It intentionally does not include c, T, r0/r1, holder/issuer split
// randomness, or LHL metadata.
type IntGenISISState struct {
	Version              int       `json:"version"`
	Profile              string    `json:"profile"`
	M                    [][]int64 `json:"M"`
	MAttr                [][]int64 `json:"m,omitempty"`
	K                    [][]int64 `json:"k,omitempty"`
	S                    [][]int64 `json:"s"`
	E                    [][]int64 `json:"e"`
	MuSig                [][]int64 `json:"mu_sig"`
	X0                   [][]int64 `json:"x0"`
	X1                   [][]int64 `json:"x1"`
	SigS1                []int64   `json:"sig_s1,omitempty"`
	SigS2                []int64   `json:"sig_s2,omitempty"`
	RingDegree           int       `json:"ring_degree"`
	PackedNCols          int       `json:"packed_ncols,omitempty"`
	CredentialPublicPath string    `json:"credential_public_path"`
	HashRelation         string    `json:"hash_relation"`
	BPath                string    `json:"b_path"`
	PRFParamsPath        string    `json:"prf_params_path,omitempty"`
	NTRUPublic           [][]int64 `json:"ntru_public,omitempty"`
}

func SaveIntGenISISState(path string, st IntGenISISState) error {
	if st.Version == 0 {
		st.Version = IntGenISISStateVersion
	}
	if err := st.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write IntGenISIS state: %w", err)
	}
	return nil
}

func LoadIntGenISISState(path string) (IntGenISISState, error) {
	var st IntGenISISState
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read IntGenISIS state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("unmarshal IntGenISIS state: %w", err)
	}
	if err := st.Validate(); err != nil {
		return st, fmt.Errorf("validate IntGenISIS state %s: %w", path, err)
	}
	return st, nil
}

func (st IntGenISISState) Validate() error {
	if st.Version != IntGenISISStateVersion {
		return fmt.Errorf("unsupported IntGenISIS state version %d", st.Version)
	}
	profile, ok := LookupIntGenISISProfile(st.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", st.Profile)
	}
	if st.RingDegree != profile.N {
		return fmt.Errorf("ring_degree=%d want %d", st.RingDegree, profile.N)
	}
	if len(st.M) != profile.EllM {
		return fmt.Errorf("M rows=%d want ell_M=%d", len(st.M), profile.EllM)
	}
	if len(st.S) != profile.KS {
		return fmt.Errorf("s rows=%d want k_s=%d", len(st.S), profile.KS)
	}
	if len(st.E) != profile.NC {
		return fmt.Errorf("e rows=%d want n_c=%d", len(st.E), profile.NC)
	}
	if len(st.MuSig) != profile.EllMuSig {
		return fmt.Errorf("mu_sig rows=%d want %d", len(st.MuSig), profile.EllMuSig)
	}
	if len(st.X0) != profile.EllX0 {
		return fmt.Errorf("x0 rows=%d want %d", len(st.X0), profile.EllX0)
	}
	if len(st.X1) != profile.EllX1 {
		return fmt.Errorf("x1 rows=%d want %d", len(st.X1), profile.EllX1)
	}
	for name, rows := range map[string][][]int64{
		"M":      st.M,
		"s":      st.S,
		"e":      st.E,
		"mu_sig": st.MuSig,
		"x0":     st.X0,
		"x1":     st.X1,
	} {
		for i := range rows {
			if len(rows[i]) != profile.N {
				return fmt.Errorf("%s[%d] coefficient length=%d want %d", name, i, len(rows[i]), profile.N)
			}
		}
	}
	if len(st.SigS1) > 0 && len(st.SigS1) != profile.N {
		return fmt.Errorf("sig_s1 coefficient length=%d want %d", len(st.SigS1), profile.N)
	}
	if len(st.SigS2) > 0 && len(st.SigS2) != profile.N {
		return fmt.Errorf("sig_s2 coefficient length=%d want %d", len(st.SigS2), profile.N)
	}
	return nil
}
