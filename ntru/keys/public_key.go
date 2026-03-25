package keys

import (
	"path/filepath"
)

// PublicKey represents an NTRU public key persisted to JSON.
type PublicKey struct {
	Version string  `json:"version"`
	N       int     `json:"N"`
	Q       string  `json:"Q"`
	HCoeffs []int64 `json:"h_coeffs"`
}

// SavePublic writes the public key to ./ntru_keys/public.json.
func SavePublic(pk *PublicKey) error {
	return SavePublicFile(filepath.Join("ntru_keys", "public.json"), pk)
}

// LoadPublic reads the public key from ./ntru_keys/public.json.
func LoadPublic() (*PublicKey, error) {
	return LoadPublicFile(filepath.Join("ntru_keys", "public.json"))
}

func SavePublicFile(path string, pk *PublicKey) error {
	if pk == nil {
		return nil
	}
	return writeJSON(path, pk)
}

func LoadPublicFile(path string) (*PublicKey, error) {
	var pk PublicKey
	if err := readJSON(path, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}
