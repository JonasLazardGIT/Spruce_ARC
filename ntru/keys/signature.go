package keys

import (
	"encoding/base64"
	"path/filepath"
	"time"
)

// Signature holds the signature bundle persisted to JSON.
type Signature struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Params    struct {
		N int    `json:"N"`
		Q string `json:"Q"`
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
	s := &Signature{Version: "ntru-signature-v1"}
	s.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return s
}

// Save writes signature to ./ntru_keys/signature.json.
func Save(sig *Signature) error {
	return SaveSignatureFile(filepath.Join("ntru_keys", "signature.json"), sig)
}

func SaveSignatureFile(path string, sig *Signature) error {
	if sig == nil {
		return nil
	}
	return writeJSON(path, sig)
}

// DecodeSeed converts base64 seed string to bytes.
func DecodeSeed(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeSeed returns base64 representation of seed bytes.
func EncodeSeed(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
