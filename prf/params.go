package prf

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Params holds all public parameters for the PRF permutation.
// Matrices and round constants are stored in coefficient form (mod q).
type Params struct {
	Q             uint64     // field modulus
	D             uint64     // S-box exponent
	LenKey        int        // key length (lenkey)
	LenNonce      int        // nonce length (lennonce)
	LenTag        int        // tag length (lentag)
	RF            int        // number of external rounds (must be even)
	RP            int        // number of internal rounds
	SecPermBits   float64    `json:"sec_perm_bits,omitempty"`
	SecTruncBound float64    `json:"sec_trunc_bound,omitempty"`
	ME            [][]uint64 // external round MDS matrix (t x t)
	MI            [][]uint64 // internal round MDS matrix (t x t)
	CExt          [][]uint64 // external round constants [RF][t]
	CInt          []uint64   // internal round constants [RP]
}

// T returns the state width (lenkey + lennonce).
func (p *Params) T() int {
	return p.LenKey + p.LenNonce
}

// Validate performs basic consistency checks on the parameter set.
func (p *Params) Validate() error {
	if p == nil {
		return fmt.Errorf("nil params")
	}
	if p.Q == 0 {
		return fmt.Errorf("q must be >0")
	}
	if p.D < 3 {
		return fmt.Errorf("d must be >=3")
	}
	if p.LenKey <= 0 || p.LenNonce <= 0 || p.LenTag <= 0 {
		return fmt.Errorf("lenkey/lennonce/lentag must be >0")
	}
	if p.LenTag > p.T() {
		return fmt.Errorf("lentag (%d) exceeds t (%d)", p.LenTag, p.T())
	}
	if p.RF <= 0 || p.RF%2 != 0 {
		return fmt.Errorf("RF must be even and >0")
	}
	if p.RP <= 0 {
		return fmt.Errorf("RP must be >0")
	}
	if err := checkMatrix(p.ME, p.T()); err != nil {
		return fmt.Errorf("ME: %w", err)
	}
	if err := checkMatrix(p.MI, p.T()); err != nil {
		return fmt.Errorf("MI: %w", err)
	}
	if len(p.CExt) != p.RF {
		return fmt.Errorf("CExt rows=%d want RF=%d", len(p.CExt), p.RF)
	}
	for i, row := range p.CExt {
		if len(row) != p.T() {
			return fmt.Errorf("CExt[%d] len=%d want %d", i, len(row), p.T())
		}
	}
	if len(p.CInt) != p.RP {
		return fmt.Errorf("CInt len=%d want RP=%d", len(p.CInt), p.RP)
	}
	return nil
}

func checkMatrix(m [][]uint64, t int) error {
	if len(m) != t {
		return fmt.Errorf("rows=%d want %d", len(m), t)
	}
	for i := range m {
		if len(m[i]) != t {
			return fmt.Errorf("row %d len=%d want %d", i, len(m[i]), t)
		}
	}
	return nil
}

// LoadParams decodes parameters from JSON (matching the prf_params.json schema)
// and validates them.
func LoadParams(r io.Reader) (*Params, error) {
	dec := json.NewDecoder(r)
	var p Params
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode params: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadParamsFromFile opens the given path, decodes JSON parameters, and validates them.
func LoadParamsFromFile(path string) (*Params, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open params file: %w", err)
	}
	defer f.Close()
	return LoadParams(f)
}

// LoadBundledParams loads a params file from the prf package directory.
func LoadBundledParams(name string) (*Params, error) {
	path, err := bundledParamsPath(name)
	if err != nil {
		return nil, err
	}
	return LoadParamsFromFile(path)
}

func bundledParamsPath(name string) (string, error) {
	if name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("bundled params name must be a filename")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	return filepath.Join(dir, name), nil
}

// LoadDefaultParams loads prf_params.json from the prf package directory.
func LoadDefaultParams() (*Params, error) {
	return LoadBundledParams("prf_params.json")
}

// LoadLocalOrDefaultParams prefers a caller-provided local params file and
// falls back to the package default if it does not exist or fails to load.
func LoadLocalOrDefaultParams(path string) (*Params, error) {
	if path != "" {
		if params, err := LoadParamsFromFile(path); err == nil {
			return params, nil
		}
	}
	return LoadDefaultParams()
}

// LoadLocalOrBundledParams prefers a caller-provided local params file and
// falls back only to a bundled file with the same basename.
func LoadLocalOrBundledParams(path string) (*Params, error) {
	params, _, err := LoadLocalOrBundledParamsWithDigest(path)
	return params, err
}

// LoadLocalOrBundledParamsWithDigest returns the SHA-256 digest of the exact
// parameter file that was decoded. The fallback is restricted to a bundled
// file with the same basename.
func LoadLocalOrBundledParamsWithDigest(path string) (*Params, string, error) {
	if path == "" {
		var err error
		path, err = bundledParamsPath("prf_params.json")
		if err != nil {
			return nil, "", err
		}
		return loadParamsFromFileWithDigest(path)
	}
	if params, digest, err := loadParamsFromFileWithDigest(path); err == nil {
		return params, digest, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("load params %q: %w", path, err)
	}
	bundledPath, err := bundledParamsPath(filepath.Base(path))
	if err != nil {
		return nil, "", fmt.Errorf("load params %q: %w", path, err)
	}
	params, digest, err := loadParamsFromFileWithDigest(bundledPath)
	if err != nil {
		return nil, "", fmt.Errorf("load params %q: %w", path, err)
	}
	return params, digest, nil
}

func loadParamsFromFileWithDigest(path string) (*Params, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read params file: %w", err)
	}
	params, err := LoadParams(bytes.NewReader(raw))
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(raw)
	return params, fmt.Sprintf("%x", digest[:]), nil
}
