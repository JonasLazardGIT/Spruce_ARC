package keys

import "fmt"

// PrivateKey represents an NTRU private key persisted to JSON.
type PrivateKey struct {
	Version      string  `json:"version"`
	ParamsDigest string  `json:"params_digest"`
	PublicKeyID  string  `json:"public_key_id"`
	N            int     `json:"N"`
	Q            string  `json:"Q"`
	F            []int64 `json:"F"`
	G            []int64 `json:"G"`
	Fsmall       []int64 `json:"f"`
	Gsmall       []int64 `json:"g"`
	Policy       *struct {
		FPlus      int    `json:"f_plus"`
		FMinus     int    `json:"f_minus"`
		GPlus      int    `json:"g_plus"`
		GMinus     int    `json:"g_minus"`
		SeedHex    string `json:"seed,omitempty"`
		TrialsUsed int    `json:"trials_used"`
	} `json:"policy,omitempty"`
}

func SavePrivateFile(path string, sk *PrivateKey) error {
	if sk == nil {
		return fmt.Errorf("nil NTRU private key")
	}
	if err := ValidatePrivateKey(sk); err != nil {
		return err
	}
	return writeJSON(path, sk)
}

func LoadPrivateFile(path string) (*PrivateKey, error) {
	var sk PrivateKey
	if err := readJSON(path, &sk); err != nil {
		return nil, err
	}
	if err := ValidatePrivateKey(&sk); err != nil {
		return nil, err
	}
	return &sk, nil
}
