package keys

// PublicKey represents an NTRU public key persisted to JSON.
type PublicKey struct {
	Version string  `json:"version"`
	N       int     `json:"N"`
	Q       string  `json:"Q"`
	HCoeffs []int64 `json:"h_coeffs"`
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
