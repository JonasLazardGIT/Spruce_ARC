package keys

import (
	"encoding/base64"
	"fmt"
	"math"
	"path/filepath"
	"time"
)

// Signature holds the signature bundle persisted to JSON.
type Signature struct {
	Version     string `json:"version"`
	SignatureID string `json:"signature_id"`
	Timestamp   string `json:"timestamp"`
	Params      struct {
		N            int    `json:"N"`
		Q            string `json:"Q"`
		ParamsDigest string `json:"params_digest"`
	} `json:"params"`
	Hash struct {
		BFile        string  `json:"B_file"`
		HashRelation string  `json:"hash_relation,omitempty"`
		MSeed        string  `json:"mseed"`
		X0Seed       string  `json:"x0seed"`
		X1Seed       string  `json:"x1seed"`
		TCoeffs      []int64 `json:"t_coeffs"`
	} `json:"hash"`
	PublicKey struct {
		KeyID   string  `json:"key_id"`
		HCoeffs []int64 `json:"h_coeffs"`
	} `json:"public_key"`
	Signature struct {
		S0   []int64 `json:"s0"`
		S1   []int64 `json:"s1"`
		S2   []int64 `json:"s2"`
		Norm struct {
			Passed       bool    `json:"passed"`
			L2Est        float64 `json:"l2_est"`
			ResidualLinf int64   `json:"residual_linf,omitempty"`
		} `json:"norm"`
		TrialsUsed int  `json:"trials_used"`
		Rejected   bool `json:"rejected"`
		MaxTrials  int  `json:"max_trials"`
	} `json:"signature"`
}

// NewSignature creates a base signature with timestamp.
func NewSignature() *Signature {
	s := &Signature{Version: SignatureV2}
	s.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return s
}

// Save writes signature to ./ntru_keys/signature.json.
func Save(sig *Signature) error {
	return SaveSignatureFile(filepath.Join("ntru_keys", "signature.json"), sig)
}

func SaveSignatureFile(path string, sig *Signature) error {
	if sig == nil {
		return fmt.Errorf("nil NTRU signature")
	}
	if err := ValidateSignature(sig); err != nil {
		return err
	}
	return writeJSON(path, sig)
}

func LoadSignatureFile(path string) (*Signature, error) {
	var sig Signature
	if err := readJSON(path, &sig); err != nil {
		return nil, err
	}
	if err := ValidateSignature(&sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// BindSignature fills the canonical v2 signature-bundle identity. A
// conflicting non-empty identity is rejected rather than overwritten.
func BindSignature(sig *Signature) error {
	id, err := ComputeSignatureID(sig)
	if err != nil {
		return err
	}
	if sig.SignatureID != "" && sig.SignatureID != id {
		return fmt.Errorf("NTRU signature ID mismatch: got %q want %q", sig.SignatureID, id)
	}
	sig.SignatureID = id
	return nil
}

// ValidateSignature checks the exact v2 artifact identity and all structural
// bindings that do not require polynomial arithmetic.
func ValidateSignature(sig *Signature) error {
	if err := validateSignatureContent(sig); err != nil {
		return err
	}
	if _, err := validateDigest("NTRU signature ID", sig.SignatureID); err != nil {
		return err
	}
	id, err := ComputeSignatureID(sig)
	if err != nil {
		return err
	}
	if sig.SignatureID != id {
		return fmt.Errorf("NTRU signature ID mismatch: got %q want %q", sig.SignatureID, id)
	}
	return nil
}

func validateSignatureContent(sig *Signature) error {
	if sig == nil {
		return fmt.Errorf("nil NTRU signature")
	}
	if sig.Version != SignatureV2 {
		return fmt.Errorf("unsupported NTRU signature version %q (want %q)", sig.Version, SignatureV2)
	}
	if _, err := time.Parse(time.RFC3339, sig.Timestamp); err != nil {
		return fmt.Errorf("invalid NTRU signature timestamp: %w", err)
	}
	if sig.Params.N <= 0 {
		return fmt.Errorf("invalid NTRU signature degree %d", sig.Params.N)
	}
	q, err := parseCanonicalQ(sig.Params.Q)
	if err != nil {
		return err
	}
	if _, err := validateDigest("NTRU params digest", sig.Params.ParamsDigest); err != nil {
		return err
	}
	embeddedPK := &PublicKey{
		Version:      KeyV2,
		ParamsDigest: sig.Params.ParamsDigest,
		KeyID:        sig.PublicKey.KeyID,
		N:            sig.Params.N,
		Q:            sig.Params.Q,
		HCoeffs:      sig.PublicKey.HCoeffs,
	}
	if err := ValidatePublicKey(embeddedPK); err != nil {
		return fmt.Errorf("invalid embedded NTRU public key: %w", err)
	}
	for _, row := range []struct {
		name string
		v    []int64
	}{
		{"target", sig.Hash.TCoeffs},
		{"s0", sig.Signature.S0},
		{"s1", sig.Signature.S1},
		{"s2", sig.Signature.S2},
	} {
		if len(row.v) != sig.Params.N {
			return fmt.Errorf("NTRU signature %s coefficient length=%d want N=%d", row.name, len(row.v), sig.Params.N)
		}
		if err := validateCentered(row.name, row.v, q); err != nil {
			return err
		}
	}
	seedCount := 0
	for _, encoded := range []string{sig.Hash.MSeed, sig.Hash.X0Seed, sig.Hash.X1Seed} {
		if encoded == "" {
			continue
		}
		seedCount++
		decoded, err := DecodeSeed(encoded)
		if err != nil || EncodeSeed(decoded) != encoded {
			return fmt.Errorf("invalid non-canonical NTRU signature seed")
		}
	}
	if seedCount != 0 && seedCount != 3 {
		return fmt.Errorf("NTRU signature must carry either zero or all three target seeds")
	}
	if seedCount == 3 && (sig.Hash.BFile == "" || sig.Hash.HashRelation == "") {
		return fmt.Errorf("seed-derived NTRU signature target is missing B_file/hash_relation")
	}
	if seedCount == 0 && (sig.Hash.BFile != "" || sig.Hash.HashRelation != "") {
		return fmt.Errorf("direct-target NTRU signature carries unused B_file/hash_relation metadata")
	}
	if sig.Signature.TrialsUsed <= 0 || sig.Signature.MaxTrials <= 0 || sig.Signature.TrialsUsed > sig.Signature.MaxTrials {
		return fmt.Errorf("invalid NTRU signature trial counts used=%d max=%d", sig.Signature.TrialsUsed, sig.Signature.MaxTrials)
	}
	if sig.Signature.Rejected != (sig.Signature.TrialsUsed > 1) {
		return fmt.Errorf("inconsistent NTRU signature rejection flag")
	}
	if !sig.Signature.Norm.Passed || math.IsNaN(sig.Signature.Norm.L2Est) || math.IsInf(sig.Signature.Norm.L2Est, 0) || sig.Signature.Norm.L2Est < 0 || (sig.Signature.Norm.L2Est == 0 && math.Signbit(sig.Signature.Norm.L2Est)) || sig.Signature.Norm.ResidualLinf < 0 {
		return fmt.Errorf("invalid NTRU signature norm metadata")
	}
	return nil
}

// DecodeSeed converts base64 seed string to bytes.
func DecodeSeed(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeSeed returns base64 representation of seed bytes.
func EncodeSeed(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
