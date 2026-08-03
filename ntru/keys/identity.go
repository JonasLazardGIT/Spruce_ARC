package keys

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"math/big"
)

const (
	KeyVersionV2       = "ntru-key-v2"
	SignatureVersionV2 = "ntru-signature-v2"
	KeyV2              = KeyVersionV2
	SignatureV2        = SignatureVersionV2
)

func validateDigest(name, digest string) ([]byte, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
		return nil, fmt.Errorf("invalid %s: expected %d lowercase hexadecimal bytes", name, sha256.Size)
	}
	return decoded, nil
}

func parseCanonicalQ(qText string) (*big.Int, error) {
	if qText == "" {
		return nil, fmt.Errorf("missing NTRU key modulus")
	}
	q := new(big.Int)
	if _, ok := q.SetString(qText, 16); !ok || q.Sign() <= 0 {
		return nil, fmt.Errorf("invalid NTRU key modulus %q", qText)
	}
	if q.Text(16) != qText {
		return nil, fmt.Errorf("non-canonical NTRU key modulus %q", qText)
	}
	if q.Bit(0) == 0 {
		return nil, fmt.Errorf("unsupported even NTRU key modulus %q", qText)
	}
	return q, nil
}

func validateCentered(name string, coeffs []int64, q *big.Int) error {
	if q == nil || q.Sign() <= 0 {
		return fmt.Errorf("invalid modulus while checking %s", name)
	}
	half := new(big.Int).Rsh(new(big.Int).Set(q), 1)
	for i, coeff := range coeffs {
		v := big.NewInt(coeff)
		if new(big.Int).Abs(v).Cmp(half) > 0 {
			return fmt.Errorf("non-canonical %s[%d]=%d outside centered modulus interval", name, i, coeff)
		}
	}
	return nil
}

// PublicKeyID returns the canonical SHA-256 identity of a v2 public key. The
// digest binds the parameter digest, N, Q, and every public-key coefficient.
func PublicKeyID(pk *PublicKey) (string, error) {
	if pk == nil {
		return "", fmt.Errorf("nil NTRU public key")
	}
	if pk.Version != KeyV2 {
		return "", fmt.Errorf("unsupported NTRU public key version %q (want %q)", pk.Version, KeyV2)
	}
	paramsDigest, err := validateDigest("NTRU params digest", pk.ParamsDigest)
	if err != nil {
		return "", err
	}
	q, err := parseCanonicalQ(pk.Q)
	if err != nil {
		return "", err
	}
	if pk.N <= 0 {
		return "", fmt.Errorf("invalid NTRU public key degree %d", pk.N)
	}
	if len(pk.HCoeffs) != pk.N {
		return "", fmt.Errorf("NTRU public h coefficient length=%d want N=%d", len(pk.HCoeffs), pk.N)
	}
	if err := validateCentered("public h", pk.HCoeffs, q); err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("SPRUCE/NTRU/public-key/v2\x00"))
	_, _ = h.Write(paramsDigest)
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], uint64(pk.N))
	_, _ = h.Write(word[:])
	qBytes := q.Bytes()
	binary.BigEndian.PutUint64(word[:], uint64(len(qBytes)))
	_, _ = h.Write(word[:])
	_, _ = h.Write(qBytes)
	for _, coeff := range pk.HCoeffs {
		binary.BigEndian.PutUint64(word[:], uint64(coeff))
		_, _ = h.Write(word[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BindPublicKey fills the canonical v2 key ID. A conflicting non-empty ID is
// rejected rather than overwritten.
func BindPublicKey(pk *PublicKey) error {
	id, err := PublicKeyID(pk)
	if err != nil {
		return err
	}
	if pk.KeyID != "" && pk.KeyID != id {
		return fmt.Errorf("NTRU public key ID mismatch: got %q want %q", pk.KeyID, id)
	}
	pk.KeyID = id
	return nil
}

func ValidatePublicKey(pk *PublicKey) error {
	if pk == nil {
		return fmt.Errorf("nil NTRU public key")
	}
	if _, err := validateDigest("NTRU public key ID", pk.KeyID); err != nil {
		return err
	}
	id, err := PublicKeyID(pk)
	if err != nil {
		return err
	}
	if pk.KeyID != id {
		return fmt.Errorf("NTRU public key ID mismatch: got %q want %q", pk.KeyID, id)
	}
	return nil
}

func ValidatePrivateKey(sk *PrivateKey) error {
	if sk == nil {
		return fmt.Errorf("nil NTRU private key")
	}
	if sk.Version != KeyV2 {
		return fmt.Errorf("unsupported NTRU private key version %q (want %q)", sk.Version, KeyV2)
	}
	if _, err := validateDigest("NTRU params digest", sk.ParamsDigest); err != nil {
		return err
	}
	if _, err := validateDigest("NTRU public key ID", sk.PublicKeyID); err != nil {
		return err
	}
	if _, err := parseCanonicalQ(sk.Q); err != nil {
		return err
	}
	if sk.N <= 0 {
		return fmt.Errorf("invalid NTRU private key degree %d", sk.N)
	}
	for _, row := range []struct {
		name string
		v    []int64
	}{
		{"F", sk.F},
		{"G", sk.G},
		{"f", sk.Fsmall},
		{"g", sk.Gsmall},
	} {
		if len(row.v) != sk.N {
			return fmt.Errorf("NTRU private %s coefficient length=%d want N=%d", row.name, len(row.v), sk.N)
		}
	}
	return nil
}

// ComputeSignatureID returns the canonical SHA-256 identity of the complete
// v2 signature bundle. SignatureID itself is deliberately excluded.
func ComputeSignatureID(sig *Signature) (string, error) {
	if err := validateSignatureContent(sig); err != nil {
		return "", err
	}
	paramsDigest, _ := validateDigest("NTRU params digest", sig.Params.ParamsDigest)
	publicKeyID, _ := validateDigest("NTRU public key ID", sig.PublicKey.KeyID)
	h := sha256.New()
	_, _ = h.Write([]byte("SPRUCE/NTRU/signature-bundle/v2\x00"))
	writeDigestPart(h, paramsDigest)
	writeDigestPart(h, publicKeyID)
	writeStringPart(h, sig.Timestamp)
	writeUint64Part(h, uint64(sig.Params.N))
	writeStringPart(h, sig.Params.Q)
	writeStringPart(h, sig.Hash.BFile)
	writeStringPart(h, sig.Hash.HashRelation)
	writeStringPart(h, sig.Hash.MSeed)
	writeStringPart(h, sig.Hash.X0Seed)
	writeStringPart(h, sig.Hash.X1Seed)
	writeInt64SlicePart(h, sig.Hash.TCoeffs)
	writeInt64SlicePart(h, sig.PublicKey.HCoeffs)
	writeInt64SlicePart(h, sig.Signature.S0)
	writeInt64SlicePart(h, sig.Signature.S1)
	writeInt64SlicePart(h, sig.Signature.S2)
	if sig.Signature.Norm.Passed {
		writeUint64Part(h, 1)
	} else {
		writeUint64Part(h, 0)
	}
	writeUint64Part(h, math.Float64bits(sig.Signature.Norm.L2Est))
	writeUint64Part(h, uint64(sig.Signature.Norm.ResidualLinf))
	writeUint64Part(h, uint64(sig.Signature.TrialsUsed))
	if sig.Signature.Rejected {
		writeUint64Part(h, 1)
	} else {
		writeUint64Part(h, 0)
	}
	writeUint64Part(h, uint64(sig.Signature.MaxTrials))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeDigestPart(h hash.Hash, digest []byte) {
	writeUint64Part(h, uint64(len(digest)))
	_, _ = h.Write(digest)
}

func writeStringPart(h hash.Hash, value string) {
	writeDigestPart(h, []byte(value))
}

func writeUint64Part(h hash.Hash, value uint64) {
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], value)
	_, _ = h.Write(word[:])
}

func writeInt64SlicePart(h hash.Hash, values []int64) {
	writeUint64Part(h, uint64(len(values)))
	for _, value := range values {
		writeUint64Part(h, uint64(value))
	}
}
