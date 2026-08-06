package credential

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

const (
	IntGenISISPresentationFormatV3        = IntGenISISPresentationFormatVersionV3
	IntGenISISPresentationV3MaxProofBytes = 16 << 20
	intGenISISCanonicalFqBitWidth         = 20
)

var intGenISISPresentationV3Magic = [8]byte{'S', 'P', 'R', 'P', 'R', 'E', 'S', 3}

// Keep this tiny header check byte-for-byte aligned with PIOP's canonical
// proof codec without importing PIOP back into credential (which would create
// a package cycle): magic "SPRUCEP6", codec version 6, showing kind 2.
//
// The enclosing presentation remains format 3 and the decoded in-memory proof
// remains schema 3.  The independent inner-codec bump is mandatory because
// radix-q field packing and the sound pre-challenge Q-kernel reconstruction
// change the byte grammar. P3 and the retired post-challenge P4 grammar are
// both rejected rather than migrated.
var intGenISISCanonicalShowingProofV6Header = [10]byte{'S', 'P', 'R', 'U', 'C', 'E', 'P', '6', 6, 2}

// IntGenISISPresentationCodecContext is the complete trusted context for the
// binary presentation envelope.  Preset/public/key/context values are omitted
// from the wire because the canonical PIOP proof binds them directly.
type IntGenISISPresentationCodecContext struct {
	Public      PublicParams
	VerifierKey IntGenISISVerifierKey
	Context     []int64
}

// IntGenISISPresentationV3 contains exactly the independently necessary
// presentation messages. CanonicalProof is intentionally opaque here: PIOP
// imports credential, so callers must pass it to PIOP.UnmarshalCanonicalProof
// with the same trusted context before accepting a presentation.
type IntGenISISPresentationV3 struct {
	Tag            []int64
	CanonicalProof []byte
}

// MarshalIntGenISISPresentationV3 encodes format-v3 magic, the configured tag
// as canonical 20-bit Fq elements, then the canonical proof bytes verbatim.
func MarshalIntGenISISPresentationV3(pres IntGenISISPresentationV3, ctx IntGenISISPresentationCodecContext) ([]byte, error) {
	_, profile, _, err := validateIntGenISISPresentationV3Context(ctx)
	if err != nil {
		return nil, err
	}
	tagLen, ok := IntGenISISPRFProfileTagElements(ctx.Public.PRFProfile)
	if !ok {
		return nil, fmt.Errorf("unsupported v3 PRF profile %q", ctx.Public.PRFProfile)
	}
	if len(pres.Tag) != tagLen {
		return nil, fmt.Errorf("presentation-v3 tag lanes=%d want %d", len(pres.Tag), tagLen)
	}
	if len(pres.CanonicalProof) > IntGenISISPresentationV3MaxProofBytes {
		return nil, fmt.Errorf("presentation-v3 canonical proof length=%d exceeds %d", len(pres.CanonicalProof), IntGenISISPresentationV3MaxProofBytes)
	}
	if err := validateCanonicalShowingProofV3Header(pres.CanonicalProof); err != nil {
		return nil, err
	}
	packedTag, err := packCanonicalFq20(pres.Tag, profile.Q)
	if err != nil {
		return nil, fmt.Errorf("pack presentation-v3 tag: %w", err)
	}
	out := make([]byte, 0, len(intGenISISPresentationV3Magic)+len(packedTag)+len(pres.CanonicalProof))
	out = append(out, intGenISISPresentationV3Magic[:]...)
	out = append(out, packedTag...)
	out = append(out, pres.CanonicalProof...)
	return out, nil
}

// UnmarshalIntGenISISPresentationV3 performs strict envelope and tag decoding.
// The returned CanonicalProof must subsequently be decoded and validated by
// PIOP.UnmarshalCanonicalProof; this function never treats opaque proof bytes
// as verified merely because their envelope is canonical.
func UnmarshalIntGenISISPresentationV3(data []byte, ctx IntGenISISPresentationCodecContext) (IntGenISISPresentationV3, error) {
	var zero IntGenISISPresentationV3
	_, profile, _, err := validateIntGenISISPresentationV3Context(ctx)
	if err != nil {
		return zero, err
	}
	tagLen, ok := IntGenISISPRFProfileTagElements(ctx.Public.PRFProfile)
	if !ok {
		return zero, fmt.Errorf("unsupported v3 PRF profile %q", ctx.Public.PRFProfile)
	}
	packedTagLen := packedFq20Len(tagLen)
	minLen := len(intGenISISPresentationV3Magic) + packedTagLen + len(intGenISISCanonicalShowingProofV6Header)
	maxLen := len(intGenISISPresentationV3Magic) + packedTagLen + IntGenISISPresentationV3MaxProofBytes
	if len(data) < minLen || len(data) > maxLen {
		return zero, fmt.Errorf("presentation-v3 length=%d outside [%d,%d]", len(data), minLen, maxLen)
	}
	if !bytes.Equal(data[:len(intGenISISPresentationV3Magic)], intGenISISPresentationV3Magic[:]) {
		return zero, fmt.Errorf("invalid IntGenISIS presentation-v3 magic/version")
	}
	off := len(intGenISISPresentationV3Magic)
	tag, err := unpackCanonicalFq20(data[off:off+packedTagLen], tagLen, profile.Q)
	if err != nil {
		return zero, fmt.Errorf("decode presentation-v3 tag: %w", err)
	}
	off += packedTagLen
	proof := append([]byte(nil), data[off:]...)
	if err := validateCanonicalShowingProofV3Header(proof); err != nil {
		return zero, err
	}
	return IntGenISISPresentationV3{Tag: tag, CanonicalProof: proof}, nil
}

// SaveIntGenISISPresentationV3 writes a public binary presentation atomically.
func SaveIntGenISISPresentationV3(path string, pres IntGenISISPresentationV3, ctx IntGenISISPresentationCodecContext) error {
	data, err := MarshalIntGenISISPresentationV3(pres, ctx)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS presentation-v3: %w", err)
	}
	return nil
}

// LoadIntGenISISPresentationV3 bounds allocation before strict envelope
// decoding. Proof-level truncation/trailing/canonical checks are performed by
// the mandatory PIOP canonical-proof decoder called by the verifier.
func LoadIntGenISISPresentationV3(path string, ctx IntGenISISPresentationCodecContext) (IntGenISISPresentationV3, error) {
	var zero IntGenISISPresentationV3
	_, _, _, err := validateIntGenISISPresentationV3Context(ctx)
	if err != nil {
		return zero, err
	}
	tagLen, ok := IntGenISISPRFProfileTagElements(ctx.Public.PRFProfile)
	if !ok {
		return zero, fmt.Errorf("unsupported v3 PRF profile %q", ctx.Public.PRFProfile)
	}
	maxLen := int64(len(intGenISISPresentationV3Magic) + packedFq20Len(tagLen) + IntGenISISPresentationV3MaxProofBytes)
	f, err := os.Open(path)
	if err != nil {
		return zero, fmt.Errorf("read IntGenISIS presentation-v3: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return zero, fmt.Errorf("stat IntGenISIS presentation-v3: %w", err)
	}
	if info.Size() <= 0 || info.Size() > maxLen {
		return zero, fmt.Errorf("presentation-v3 file length=%d outside bounded range", info.Size())
	}
	data := make([]byte, int(info.Size()))
	if _, err := io.ReadFull(f, data); err != nil {
		return zero, fmt.Errorf("read IntGenISIS presentation-v3: %w", err)
	}
	var trailing [1]byte
	if n, readErr := f.Read(trailing[:]); n != 0 || (readErr != nil && readErr != io.EOF) {
		return zero, fmt.Errorf("presentation-v3 file changed while reading or contains trailing data")
	}
	pres, err := UnmarshalIntGenISISPresentationV3(data, ctx)
	if err != nil {
		return zero, fmt.Errorf("decode IntGenISIS presentation-v3 %s: %w", path, err)
	}
	return pres, nil
}

func validateIntGenISISPresentationV3Context(ctx IntGenISISPresentationCodecContext) (IntGenISISPreset, IntGenISISProfile, int, error) {
	preset, profile, bindingWidth, err := validateIntGenISISV3PublicKeyContext(ctx.Public, ctx.VerifierKey)
	if err != nil {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, err
	}
	if len(ctx.Context) != IntGenISISContextLaneCount {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("presentation-v3 context lanes=%d want %d", len(ctx.Context), IntGenISISContextLaneCount)
	}
	for i, value := range ctx.Context {
		if value < 0 || uint64(value) >= profile.Q {
			return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("presentation-v3 context[%d]=%d is not canonical modulo %d", i, value, profile.Q)
		}
	}
	return preset, profile, bindingWidth, nil
}

func validateCanonicalShowingProofV3Header(proof []byte) error {
	if len(proof) < len(intGenISISCanonicalShowingProofV6Header) {
		return fmt.Errorf("presentation-v3 canonical proof is truncated before its schema/kind header")
	}
	if !bytes.Equal(proof[:len(intGenISISCanonicalShowingProofV6Header)], intGenISISCanonicalShowingProofV6Header[:]) {
		return fmt.Errorf("presentation-v3 requires canonical SPRUCEP6 codec-v6 showing proof; legacy or presign proof rejected")
	}
	return nil
}

func packedFq20Len(count int) int {
	return (count*intGenISISCanonicalFqBitWidth + 7) / 8
}

func packCanonicalFq20(values []int64, modulus uint64) ([]byte, error) {
	if modulus < 2 || modulus > 1<<intGenISISCanonicalFqBitWidth {
		return nil, fmt.Errorf("modulus=%d does not fit canonical 20-bit profile", modulus)
	}
	out := make([]byte, packedFq20Len(len(values)))
	for i, signed := range values {
		if signed < 0 || uint64(signed) >= modulus {
			return nil, fmt.Errorf("Fq value[%d]=%d is not canonical modulo %d", i, signed, modulus)
		}
		value := uint64(signed)
		start := i * intGenISISCanonicalFqBitWidth
		for bit := 0; bit < intGenISISCanonicalFqBitWidth; bit++ {
			if value&(uint64(1)<<bit) != 0 {
				pos := start + bit
				out[pos/8] |= byte(1 << (pos % 8))
			}
		}
	}
	return out, nil
}

func unpackCanonicalFq20(data []byte, count int, modulus uint64) ([]int64, error) {
	if count < 0 || len(data) != packedFq20Len(count) {
		return nil, fmt.Errorf("packed Fq length=%d want %d", len(data), packedFq20Len(count))
	}
	if modulus < 2 || modulus > 1<<intGenISISCanonicalFqBitWidth {
		return nil, fmt.Errorf("modulus=%d does not fit canonical 20-bit profile", modulus)
	}
	out := make([]int64, count)
	for i := range out {
		start := i * intGenISISCanonicalFqBitWidth
		var value uint64
		for bit := 0; bit < intGenISISCanonicalFqBitWidth; bit++ {
			pos := start + bit
			if data[pos/8]&(byte(1)<<(pos%8)) != 0 {
				value |= uint64(1) << bit
			}
		}
		if value >= modulus {
			return nil, fmt.Errorf("Fq value[%d]=%d is not canonical modulo %d", i, value, modulus)
		}
		out[i] = int64(value)
	}
	usedBits := count * intGenISISCanonicalFqBitWidth
	for pos := usedBits; pos < len(data)*8; pos++ {
		if data[pos/8]&(byte(1)<<(pos%8)) != 0 {
			return nil, fmt.Errorf("packed Fq has nonzero spare bit %d", pos-usedBits)
		}
	}
	return out, nil
}
