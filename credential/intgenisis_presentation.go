package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	IntGenISISPresentationVersion  = 1
	IntGenISISVerifierStateVersion = 1
)

type IntGenISISPresentation struct {
	Version            int             `json:"version"`
	Profile            string          `json:"profile"`
	PublicParamsDigest string          `json:"public_params_digest"`
	Nonce              [][]int64       `json:"nonce"`
	Tag                [][]int64       `json:"tag"`
	Proof              json.RawMessage `json:"proof"`
}

type IntGenISISVerifierState struct {
	Version int               `json:"version"`
	Seen    map[string]string `json:"seen"`
}

func PublicParamsDigest(public PublicParams) (string, error) {
	if err := (&public).Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(public)
	if err != nil {
		return "", fmt.Errorf("marshal public params for digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func SaveIntGenISISPresentation(path string, pres IntGenISISPresentation) error {
	if pres.Version == 0 {
		pres.Version = IntGenISISPresentationVersion
	}
	if err := pres.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir presentation dir: %w", err)
	}
	data, err := json.MarshalIndent(pres, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS presentation: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS presentation: %w", err)
	}
	return nil
}

func LoadIntGenISISPresentation(path string) (IntGenISISPresentation, error) {
	var pres IntGenISISPresentation
	data, err := os.ReadFile(path)
	if err != nil {
		return pres, fmt.Errorf("read IntGenISIS presentation: %w", err)
	}
	if err := json.Unmarshal(data, &pres); err != nil {
		return pres, fmt.Errorf("unmarshal IntGenISIS presentation: %w", err)
	}
	if err := pres.Validate(); err != nil {
		return pres, fmt.Errorf("validate IntGenISIS presentation %s: %w", path, err)
	}
	return pres, nil
}

func (pres IntGenISISPresentation) Validate() error {
	if pres.Version != IntGenISISPresentationVersion {
		return fmt.Errorf("unsupported IntGenISIS presentation version %d", pres.Version)
	}
	if pres.Profile == "" {
		return fmt.Errorf("presentation missing profile")
	}
	if pres.PublicParamsDigest == "" {
		return fmt.Errorf("presentation missing public params digest")
	}
	if len(pres.Nonce) == 0 {
		return fmt.Errorf("presentation missing nonce")
	}
	if len(pres.Tag) == 0 {
		return fmt.Errorf("presentation missing tag")
	}
	if len(pres.Proof) == 0 {
		return fmt.Errorf("presentation missing proof")
	}
	return nil
}

func LoadIntGenISISVerifierState(path string) (IntGenISISVerifierState, error) {
	var st IntGenISISVerifierState
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewIntGenISISVerifierState(), nil
	}
	if err != nil {
		return st, fmt.Errorf("read IntGenISIS verifier state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("unmarshal IntGenISIS verifier state: %w", err)
	}
	if st.Version == 0 {
		st.Version = IntGenISISVerifierStateVersion
	}
	if st.Version != IntGenISISVerifierStateVersion {
		return st, fmt.Errorf("unsupported IntGenISIS verifier state version %d", st.Version)
	}
	if st.Seen == nil {
		st.Seen = make(map[string]string)
	}
	return st, nil
}

func SaveIntGenISISVerifierState(path string, st IntGenISISVerifierState) error {
	if st.Version == 0 {
		st.Version = IntGenISISVerifierStateVersion
	}
	if st.Seen == nil {
		st.Seen = make(map[string]string)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir verifier state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS verifier state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write IntGenISIS verifier state: %w", err)
	}
	return nil
}

func NewIntGenISISVerifierState() IntGenISISVerifierState {
	return IntGenISISVerifierState{
		Version: IntGenISISVerifierStateVersion,
		Seen:    make(map[string]string),
	}
}

func (st IntGenISISVerifierState) ReplayKey(pres IntGenISISPresentation) string {
	data, _ := json.Marshal(struct {
		Profile string    `json:"profile"`
		Digest  string    `json:"digest"`
		Nonce   [][]int64 `json:"nonce"`
		Tag     [][]int64 `json:"tag"`
	}{
		Profile: pres.Profile,
		Digest:  pres.PublicParamsDigest,
		Nonce:   pres.Nonce,
		Tag:     pres.Tag,
	})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (st *IntGenISISVerifierState) MarkPresentation(pres IntGenISISPresentation) error {
	if st.Seen == nil {
		st.Seen = make(map[string]string)
	}
	key := st.ReplayKey(pres)
	if _, ok := st.Seen[key]; ok {
		return fmt.Errorf("replayed IntGenISIS nonce/tag pair")
	}
	st.Seen[key] = pres.Profile
	return nil
}
