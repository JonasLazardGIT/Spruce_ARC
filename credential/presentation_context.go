package credential

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"
)

const (
	IntGenISISMaxContextBytes = 4096
	contextDigestDomainV2     = "ARC-SPRUCE/context-digest/v2"
	contextLanesDomainV2      = "ARC-SPRUCE/context-lanes/v2"
)

// PresentationContextBinding is the canonical public statement derived from
// service-controlled opaque context bytes. Raw context bytes are supplied to
// the verifier independently and are not copied into a presentation.
type PresentationContextBinding struct {
	Digest string  `json:"digest"`
	Lanes  []int64 `json:"lanes"`
}

func contextBindingInput(domain string, raw []byte, fieldModulus uint64, manifestDigest, publicParamsDigest, verifierKeyDigest string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > IntGenISISMaxContextBytes {
		return nil, fmt.Errorf("context length=%d outside [1,%d]", len(raw), IntGenISISMaxContextBytes)
	}
	if fieldModulus < 2 {
		return nil, fmt.Errorf("invalid context field modulus %d", fieldModulus)
	}
	digests := []string{manifestDigest, publicParamsDigest, verifierKeyDigest}
	decoded := make([][]byte, len(digests))
	for i, digest := range digests {
		b, err := hex.DecodeString(digest)
		if err != nil || len(b) != 32 || hex.EncodeToString(b) != digest {
			return nil, fmt.Errorf("context binding digest %d must be canonical lowercase 32-byte hex", i)
		}
		decoded[i] = b
	}
	buf := make([]byte, 0, len(domain)+1+3*36+24+len(raw))
	appendLP := func(v []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		buf = append(buf, n[:]...)
		buf = append(buf, v...)
	}
	appendLP([]byte(domain))
	appendLP(raw)
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], fieldModulus)
	buf = append(buf, scalar[:]...)
	binary.BigEndian.PutUint64(scalar[:], uint64(IntGenISISQuotaSlots))
	buf = append(buf, scalar[:]...)
	for _, digest := range decoded {
		appendLP(digest)
	}
	return buf, nil
}

// DerivePresentationContext maps an opaque service context to eleven field
// elements using SHAKE256 and unbiased 128-bit rejection sampling.
func DerivePresentationContext(raw []byte, fieldModulus uint64, manifestDigest, publicParamsDigest, verifierKeyDigest string) (PresentationContextBinding, error) {
	digestInput, err := contextBindingInput(contextDigestDomainV2, raw, fieldModulus, manifestDigest, publicParamsDigest, verifierKeyDigest)
	if err != nil {
		return PresentationContextBinding{}, err
	}
	digestXOF := sha3.NewShake256()
	_, _ = digestXOF.Write(digestInput)
	digest := make([]byte, 32)
	if _, err := io.ReadFull(digestXOF, digest); err != nil {
		return PresentationContextBinding{}, fmt.Errorf("derive context digest: %w", err)
	}

	laneInput, err := contextBindingInput(contextLanesDomainV2, raw, fieldModulus, manifestDigest, publicParamsDigest, verifierKeyDigest)
	if err != nil {
		return PresentationContextBinding{}, err
	}
	laneXOF := sha3.NewShake256()
	_, _ = laneXOF.Write(laneInput)
	q := new(big.Int).SetUint64(fieldModulus)
	space := new(big.Int).Lsh(big.NewInt(1), 128)
	limit := new(big.Int).Sub(space, new(big.Int).Mod(new(big.Int).Set(space), q))
	lanes := make([]int64, IntGenISISContextLaneCount)
	block := make([]byte, 16)
	for i := range lanes {
		for {
			if _, err := io.ReadFull(laneXOF, block); err != nil {
				return PresentationContextBinding{}, fmt.Errorf("derive context lane %d: %w", i, err)
			}
			candidate := new(big.Int).SetBytes(block)
			if candidate.Cmp(limit) >= 0 {
				continue
			}
			candidate.Mod(candidate, q)
			lanes[i] = int64(candidate.Uint64())
			break
		}
	}
	binding := PresentationContextBinding{Digest: hex.EncodeToString(digest), Lanes: lanes}
	if err := binding.Validate(fieldModulus); err != nil {
		return PresentationContextBinding{}, fmt.Errorf("validate derived context binding: %w", err)
	}
	return binding, nil
}

func (c PresentationContextBinding) Validate(fieldModulus uint64) error {
	digest, err := hex.DecodeString(c.Digest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != c.Digest {
		return fmt.Errorf("context digest must be canonical lowercase 32-byte hex")
	}
	if len(c.Lanes) != IntGenISISContextLaneCount {
		return fmt.Errorf("context lanes=%d want %d", len(c.Lanes), IntGenISISContextLaneCount)
	}
	for i, lane := range c.Lanes {
		if lane < 0 || uint64(lane) >= fieldModulus {
			return fmt.Errorf("context lane %d=%d is not canonical modulo %d", i, lane, fieldModulus)
		}
	}
	return nil
}
