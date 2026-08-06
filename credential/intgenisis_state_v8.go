package credential

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	// IntGenISISStateFormatV8 is the binary credential-state wire version.  It
	// is deliberately separate from IntGenISISStateVersion: the latter remains
	// the legacy JSON/in-memory schema version so historical v7 artifacts keep
	// their existing boundary.
	IntGenISISStateFormatV8 = IntGenISISStateFormatVersionV8

	stateV8PublicBindingDomain = "ARC-SPRUCE/intgenisis-state-v8/public-binding"
	stateV8KeyBindingDomain    = "ARC-SPRUCE/intgenisis-state-v8/verifier-key-binding"
	stateV8FingerprintDomain   = "ARC-SPRUCE/intgenisis-state-v8/fingerprint"
)

var intGenISISStateV8Magic = [8]byte{'S', 'P', 'R', 'S', 'T', 'A', 'T', 8}

// IntGenISISStateCodecContext supplies all public and reconstructible state.
// PublicParamsPath is routing metadata only; its contents are represented by
// Public and are cryptographically bound at the configured transcript width.
type IntGenISISStateCodecContext struct {
	Public           PublicParams
	VerifierKey      IntGenISISVerifierKey
	PublicParamsPath string
}

// MarshalIntGenISISStateV8 returns the canonical compact binary encoding.
// MAttr, K, the reserved semantic-message tail, paths, public NTRU data, and
// every preset/layout field are reconstructed from the trusted context.
func MarshalIntGenISISStateV8(st IntGenISISState, ctx IntGenISISStateCodecContext) ([]byte, error) {
	preset, profile, bindingWidth, err := validateIntGenISISStateV8Context(ctx)
	if err != nil {
		return nil, err
	}
	if err := st.ValidateAgainst(ctx.Public, ctx.VerifierKey); err != nil {
		return nil, fmt.Errorf("validate state-v8 source: %w", err)
	}
	if st.CredentialPublicPath != ctx.PublicParamsPath {
		return nil, fmt.Errorf("state credential_public_path=%q does not match codec context path %q", st.CredentialPublicPath, ctx.PublicParamsPath)
	}
	if st.PackedNCols != preset.Showing.NCols {
		return nil, fmt.Errorf("state packed_ncols=%d want trusted showing width %d", st.PackedNCols, preset.Showing.NCols)
	}

	publicBinding, keyBinding, err := intGenISISStateV8Bindings(ctx.Public, ctx.VerifierKey, bindingWidth)
	if err != nil {
		return nil, err
	}
	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive state-v8 semantic layout: %w", err)
	}

	attributes := make([]int64, len(layout.Attribute))
	for i, slot := range layout.Attribute {
		attributes[i] = st.M[slot.Poly][slot.Coeff]
	}
	packedAttributes, err := packCanonicalTernary243(attributes)
	if err != nil {
		return nil, fmt.Errorf("pack state-v8 message attributes: %w", err)
	}
	seed, err := PRFSeedFromSemanticMessage(layout, st.M)
	if err != nil {
		return nil, fmt.Errorf("extract state-v8 PRF seed: %w", err)
	}
	packedSeed, err := packCanonicalBase9Seed(seed)
	if err != nil {
		return nil, fmt.Errorf("pack state-v8 PRF seed: %w", err)
	}

	ternaryRows := make([]int64, 0, stateV8TernaryValueCount(profile))
	for _, rows := range [][][]int64{st.S, st.E, st.MuSig, st.X0, st.X1} {
		for _, row := range rows {
			ternaryRows = append(ternaryRows, row...)
		}
	}
	packedTernaryRows, err := packCanonicalTernary243(ternaryRows)
	if err != nil {
		return nil, fmt.Errorf("pack state-v8 ternary witnesses: %w", err)
	}

	signature := make([]int64, 0, len(st.SigS1)+len(st.SigS2))
	signature = append(signature, st.SigS1...)
	signature = append(signature, st.SigS2...)
	packedSignature, err := packCanonicalShiftedSignature(signature, ctx.VerifierKey.SignatureBound)
	if err != nil {
		return nil, fmt.Errorf("pack state-v8 signature: %w", err)
	}

	wantLen, err := intGenISISStateV8EncodedLen(profile, ctx.VerifierKey.SignatureBound, bindingWidth)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, wantLen)
	out = append(out, intGenISISStateV8Magic[:]...)
	out = append(out, publicBinding...)
	out = append(out, keyBinding...)
	out = append(out, packedAttributes...)
	out = append(out, packedSeed...)
	out = append(out, packedTernaryRows...)
	out = append(out, packedSignature...)
	if len(out) != wantLen {
		return nil, fmt.Errorf("internal state-v8 length=%d want %d", len(out), wantLen)
	}
	return out, nil
}

// UnmarshalIntGenISISStateV8 decodes only the canonical v8 form.  It never
// attempts JSON migration or a legacy-state fallback.
func UnmarshalIntGenISISStateV8(data []byte, ctx IntGenISISStateCodecContext) (IntGenISISState, error) {
	var zero IntGenISISState
	preset, profile, bindingWidth, err := validateIntGenISISStateV8Context(ctx)
	if err != nil {
		return zero, err
	}
	wantLen, err := intGenISISStateV8EncodedLen(profile, ctx.VerifierKey.SignatureBound, bindingWidth)
	if err != nil {
		return zero, err
	}
	if len(data) != wantLen {
		return zero, fmt.Errorf("state-v8 length=%d want exactly %d", len(data), wantLen)
	}
	off := 0
	if !bytes.Equal(data[:len(intGenISISStateV8Magic)], intGenISISStateV8Magic[:]) {
		return zero, fmt.Errorf("invalid IntGenISIS state-v8 magic/version")
	}
	off += len(intGenISISStateV8Magic)
	publicBinding, keyBinding, err := intGenISISStateV8Bindings(ctx.Public, ctx.VerifierKey, bindingWidth)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(data[off:off+bindingWidth], publicBinding) {
		return zero, fmt.Errorf("state-v8 public-parameter binding mismatch")
	}
	off += bindingWidth
	if !bytes.Equal(data[off:off+bindingWidth], keyBinding) {
		return zero, fmt.Errorf("state-v8 verifier-key binding mismatch")
	}
	off += bindingWidth

	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		return zero, fmt.Errorf("derive state-v8 semantic layout: %w", err)
	}
	attributeBytes := packedTernary243Len(len(layout.Attribute))
	attributes, err := unpackCanonicalTernary243(data[off:off+attributeBytes], len(layout.Attribute))
	if err != nil {
		return zero, fmt.Errorf("decode state-v8 message attributes: %w", err)
	}
	off += attributeBytes
	seedBytes := packedBase9SeedLen(len(layout.Key))
	seed, err := unpackCanonicalBase9Seed(data[off:off+seedBytes], len(layout.Key))
	if err != nil {
		return zero, fmt.Errorf("decode state-v8 PRF seed: %w", err)
	}
	off += seedBytes

	mAttr := zeroRows(profile.EllM, profile.N)
	for i, slot := range layout.Attribute {
		mAttr[slot.Poly][slot.Coeff] = attributes[i]
	}
	semantic, err := EncodeSemanticMessage(layout, mAttr, seed)
	if err != nil {
		return zero, fmt.Errorf("reconstruct state-v8 semantic message: %w", err)
	}

	ternaryCount := stateV8TernaryValueCount(profile)
	ternaryBytes := packedTernary243Len(ternaryCount)
	ternaryValues, err := unpackCanonicalTernary243(data[off:off+ternaryBytes], ternaryCount)
	if err != nil {
		return zero, fmt.Errorf("decode state-v8 ternary witnesses: %w", err)
	}
	off += ternaryBytes
	valueOff := 0
	takeRows := func(count int) [][]int64 {
		rows := zeroRows(count, profile.N)
		for i := range rows {
			copy(rows[i], ternaryValues[valueOff:valueOff+profile.N])
			valueOff += profile.N
		}
		return rows
	}
	sRows := takeRows(profile.KS)
	eRows := takeRows(profile.NC)
	muSigRows := takeRows(profile.EllMuSig)
	x0Rows := takeRows(profile.EllX0)
	x1Rows := takeRows(profile.EllX1)
	if valueOff != len(ternaryValues) {
		return zero, fmt.Errorf("internal state-v8 ternary geometry consumed %d of %d values", valueOff, len(ternaryValues))
	}

	signatureCount := 2 * profile.N
	signature, err := unpackCanonicalShiftedSignature(data[off:], signatureCount, ctx.VerifierKey.SignatureBound)
	if err != nil {
		return zero, fmt.Errorf("decode state-v8 signature: %w", err)
	}
	off = len(data)
	if off != wantLen {
		return zero, fmt.Errorf("internal state-v8 decoder stopped at %d of %d bytes", off, wantLen)
	}

	st := IntGenISISState{
		Version:              IntGenISISStateVersion,
		Profile:              ctx.Public.Profile,
		PresetID:             ctx.Public.PresetID,
		PresetVersion:        ctx.Public.PresetVersion,
		PrimitiveProfileID:   ctx.Public.PrimitiveProfileID,
		PRFProfile:           ctx.Public.PRFProfile,
		TranscriptMode:       ctx.Public.TranscriptMode,
		PresetManifestDigest: ctx.Public.PresetManifestDigest,
		M:                    semantic.M,
		MAttr:                semantic.MAttr,
		K:                    semantic.K,
		S:                    sRows,
		E:                    eRows,
		MuSig:                muSigRows,
		X0:                   x0Rows,
		X1:                   x1Rows,
		SigS1:                append([]int64(nil), signature[:profile.N]...),
		SigS2:                append([]int64(nil), signature[profile.N:]...),
		RingDegree:           profile.N,
		PackedNCols:          preset.Showing.NCols,
		CredentialPublicPath: ctx.PublicParamsPath,
		HashRelation:         ctx.Public.HashRelation,
		BPath:                ctx.Public.BPath,
		PRFParamsPath:        preset.PRFParamsPath,
		NTRUPublic:           cloneInt64Rows(ctx.VerifierKey.NTRUPublic),
		SignatureBound:       ctx.VerifierKey.SignatureBound,
	}
	if err := st.ValidateAgainst(ctx.Public, ctx.VerifierKey); err != nil {
		return zero, fmt.Errorf("validate decoded state-v8: %w", err)
	}
	return st, nil
}

// SaveIntGenISISStateV8 atomically writes a mode-0600 canonical state.
func SaveIntGenISISStateV8(path string, st IntGenISISState, ctx IntGenISISStateCodecContext) error {
	data, err := MarshalIntGenISISStateV8(st, ctx)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write IntGenISIS state-v8: %w", err)
	}
	return nil
}

// LoadIntGenISISStateV8 reads exactly the context-derived fixed state length,
// bounding allocation before parsing.
func LoadIntGenISISStateV8(path string, ctx IntGenISISStateCodecContext) (IntGenISISState, error) {
	var zero IntGenISISState
	_, profile, bindingWidth, err := validateIntGenISISStateV8Context(ctx)
	if err != nil {
		return zero, err
	}
	wantLen, err := intGenISISStateV8EncodedLen(profile, ctx.VerifierKey.SignatureBound, bindingWidth)
	if err != nil {
		return zero, err
	}
	data, err := readExactBoundedFile(path, wantLen)
	if err != nil {
		return zero, fmt.Errorf("read IntGenISIS state-v8: %w", err)
	}
	st, err := UnmarshalIntGenISISStateV8(data, ctx)
	if err != nil {
		return zero, fmt.Errorf("decode IntGenISIS state-v8 %s: %w", path, err)
	}
	return st, nil
}

// IntGenISISStateV8Fingerprint validates canonical bytes and returns a
// configured-width SHAKE-256 fingerprint.  The fingerprint is an identifier,
// not a MAC or an authenticity claim.
func IntGenISISStateV8Fingerprint(data []byte, ctx IntGenISISStateCodecContext) (string, error) {
	_, _, bindingWidth, err := validateIntGenISISStateV8Context(ctx)
	if err != nil {
		return "", err
	}
	if _, err := UnmarshalIntGenISISStateV8(data, ctx); err != nil {
		return "", err
	}
	publicBinding, keyBinding, err := intGenISISStateV8Bindings(ctx.Public, ctx.VerifierKey, bindingWidth)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, len(publicBinding)+len(keyBinding)+len(data))
	payload = append(payload, publicBinding...)
	payload = append(payload, keyBinding...)
	payload = append(payload, data...)
	fingerprint, err := shakeConfiguredBinding(stateV8FingerprintDomain, payload, bindingWidth)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(fingerprint), nil
}

func validateIntGenISISStateV8Context(ctx IntGenISISStateCodecContext) (IntGenISISPreset, IntGenISISProfile, int, error) {
	preset, profile, bindingWidth, err := validateIntGenISISV3PublicKeyContext(ctx.Public, ctx.VerifierKey)
	if err != nil {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, err
	}
	if strings.TrimSpace(ctx.PublicParamsPath) == "" {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("state-v8 codec context requires public-parameter path")
	}
	return preset, profile, bindingWidth, nil
}

func validateIntGenISISV3PublicKeyContext(public PublicParams, key IntGenISISVerifierKey) (IntGenISISPreset, IntGenISISProfile, int, error) {
	if err := key.ValidateAgainst(public); err != nil {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("validate v3 public/key context: %w", err)
	}
	preset, ok := LookupIntGenISISPreset(public.PresetID)
	if !ok {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("unknown v3 preset_id %q", public.PresetID)
	}
	profile, ok := LookupIntGenISISProfile(public.Profile)
	if !ok {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("unknown v3 profile %q", public.Profile)
	}
	// The compact codec is enabled through trusted manifest properties, not a
	// user-selected alias. Publication-v4 deliberately retains these structural
	// versions while changing only the transcript/security-policy epoch.
	strictManifest := preset.ProofSchemaVersion == IntGenISISProofSchemaVersionV3 &&
		preset.RelationVersion == 3 && preset.LayoutVersion == 3 &&
		preset.StateFormatVersion == IntGenISISStateFormatVersionV8 &&
		preset.PresentationVersion == IntGenISISPresentationFormatVersionV3 &&
		preset.IssuanceVersion == IntGenISISIssuanceArtifactFormatVersionV4 &&
		preset.HolderUsageVersion == IntGenISISHolderUsageFormatVersionV3 &&
		preset.FieldProfileID != "" && preset.FieldProfileDigest != "" &&
		preset.Issuance.RelationVersion == 3 && preset.Issuance.LayoutVersion == 3 &&
		preset.Showing.RelationVersion == 3 && preset.Showing.LayoutVersion == 3 &&
		preset.Issuance.TranscriptOmissionMode == IntGenISISTranscriptOmissionModeV3 &&
		preset.Showing.TranscriptOmissionMode == IntGenISISTranscriptOmissionModeV3
	v3Policy := public.PresetVersion == IntGenISISPresetManifestVersionV3 && preset.PresetVersion == IntGenISISPresetManifestVersionV3 &&
		public.TranscriptMode == IntGenISISTranscriptProtocolV3 && preset.Showing.TranscriptMode == IntGenISISTranscriptProtocolV3 && preset.Issuance.TranscriptMode == IntGenISISTranscriptProtocolV3 &&
		preset.Issuance.SoundnessGate == IntGenISISSecurityGateV3 && preset.Showing.SoundnessGate == IntGenISISSecurityGateV3
	v4Policy := public.PresetVersion == IntGenISISPresetManifestVersionV4 && preset.PresetVersion == IntGenISISPresetManifestVersionV4 &&
		public.TranscriptMode == IntGenISISTranscriptProtocolV4 && preset.Showing.TranscriptMode == IntGenISISTranscriptProtocolV4 && preset.Issuance.TranscriptMode == IntGenISISTranscriptProtocolV4 &&
		preset.Issuance.SoundnessGate == IntGenISISSecurityGateV4 && preset.Showing.SoundnessGate == IntGenISISSecurityGateV4 && isIntGenISISPublicationPresetV4ID(preset.CanonicalID)
	if public.Profile != ProfileIntGenISISC || profile.N != 1024 || preset.ClaimScope != ClaimProofOnly || !(v3Policy || v4Policy) || !strictManifest {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("canonical strict codec is unavailable for preset %q version=%d profile=%q transcript=%q", public.PresetID, public.PresetVersion, public.Profile, public.TranscriptMode)
	}
	bits := preset.Issuance.FSCollisionBits
	if v4Policy {
		bits = preset.Issuance.FSOutputBits
		if preset.Showing.FSOutputBits > bits {
			bits = preset.Showing.FSOutputBits
		}
	} else if preset.Showing.FSCollisionBits > bits {
		bits = preset.Showing.FSCollisionBits
	}
	if bits < 128 || bits > 512 || (v4Policy && bits%8 != 0) {
		return IntGenISISPreset{}, IntGenISISProfile{}, 0, fmt.Errorf("invalid configured strict binding width %d bits", bits)
	}
	return preset, profile, (bits + 7) / 8, nil
}

func intGenISISStateV8Bindings(public PublicParams, key IntGenISISVerifierKey, width int) ([]byte, []byte, error) {
	publicBytes, err := json.Marshal(public)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public parameters for state-v8 binding: %w", err)
	}
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal verifier key for state-v8 binding: %w", err)
	}
	publicBinding, err := shakeConfiguredBinding(stateV8PublicBindingDomain, publicBytes, width)
	if err != nil {
		return nil, nil, err
	}
	keyBinding, err := shakeConfiguredBinding(stateV8KeyBindingDomain, keyBytes, width)
	if err != nil {
		return nil, nil, err
	}
	return publicBinding, keyBinding, nil
}

func shakeConfiguredBinding(domain string, payload []byte, width int) ([]byte, error) {
	if width <= 0 || width > 64 {
		return nil, fmt.Errorf("configured binding width=%d outside [1,64] bytes", width)
	}
	xof := sha3.NewShake256()
	var frame [8]byte
	binary.LittleEndian.PutUint64(frame[:], uint64(len(domain)))
	_, _ = xof.Write(frame[:])
	_, _ = xof.Write([]byte(domain))
	binary.LittleEndian.PutUint64(frame[:], uint64(width))
	_, _ = xof.Write(frame[:])
	binary.LittleEndian.PutUint64(frame[:], uint64(len(payload)))
	_, _ = xof.Write(frame[:])
	_, _ = xof.Write(payload)
	out := make([]byte, width)
	if _, err := io.ReadFull(xof, out); err != nil {
		return nil, fmt.Errorf("expand configured binding: %w", err)
	}
	return out, nil
}

func intGenISISStateV8EncodedLen(profile IntGenISISProfile, signatureBound int64, bindingWidth int) (int, error) {
	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		return 0, err
	}
	signatureBytes, err := packedShiftedSignatureLen(2*profile.N, signatureBound)
	if err != nil {
		return 0, err
	}
	return len(intGenISISStateV8Magic) + 2*bindingWidth +
		packedTernary243Len(len(layout.Attribute)) + packedBase9SeedLen(len(layout.Key)) +
		packedTernary243Len(stateV8TernaryValueCount(profile)) + signatureBytes, nil
}

func stateV8TernaryValueCount(profile IntGenISISProfile) int {
	return profile.N * (profile.KS + profile.NC + profile.EllMuSig + profile.EllX0 + profile.EllX1)
}

func packedTernary243Len(count int) int {
	return (count + 4) / 5
}

func packCanonicalTernary243(values []int64) ([]byte, error) {
	out := make([]byte, packedTernary243Len(len(values)))
	for group := range out {
		acc := 0
		pow := 1
		for lane := 0; lane < 5; lane++ {
			idx := group*5 + lane
			if idx >= len(values) {
				break
			}
			v := values[idx]
			if v < -1 || v > 1 {
				return nil, fmt.Errorf("ternary value[%d]=%d outside {-1,0,1}", idx, v)
			}
			acc += int(v+1) * pow
			pow *= 3
		}
		out[group] = byte(acc)
	}
	return out, nil
}

func unpackCanonicalTernary243(data []byte, count int) ([]int64, error) {
	if count < 0 || len(data) != packedTernary243Len(count) {
		return nil, fmt.Errorf("ternary base-243 length=%d want %d", len(data), packedTernary243Len(count))
	}
	out := make([]int64, count)
	for group, encoded := range data {
		acc := int(encoded)
		if acc >= 243 {
			return nil, fmt.Errorf("ternary group %d=%d is not canonical base-243", group, encoded)
		}
		lanes := 5
		if remain := count - group*5; remain < lanes {
			lanes = remain
		}
		for lane := 0; lane < lanes; lane++ {
			out[group*5+lane] = int64(acc%3) - 1
			acc /= 3
		}
		if acc != 0 {
			return nil, fmt.Errorf("ternary group %d has nonzero spare digits", group)
		}
	}
	return out, nil
}

func packedBase9SeedLen(count int) int {
	return 2 * ((count + 4) / 5)
}

func packCanonicalBase9Seed(values []int64) ([]byte, error) {
	out := make([]byte, packedBase9SeedLen(len(values)))
	for group := 0; group < (len(values)+4)/5; group++ {
		acc := uint32(0)
		pow := uint32(1)
		for lane := 0; lane < 5; lane++ {
			idx := group*5 + lane
			if idx >= len(values) {
				break
			}
			v := values[idx]
			if v < -IntGenISISPRFSeedBound || v > IntGenISISPRFSeedBound {
				return nil, fmt.Errorf("base-9 seed[%d]=%d outside [-%d,%d]", idx, v, IntGenISISPRFSeedBound, IntGenISISPRFSeedBound)
			}
			acc += uint32(v+IntGenISISPRFSeedBound) * pow
			pow *= 9
		}
		if acc > 0xffff {
			return nil, fmt.Errorf("base-9 seed group %d overflow", group)
		}
		binary.LittleEndian.PutUint16(out[2*group:], uint16(acc))
	}
	return out, nil
}

func unpackCanonicalBase9Seed(data []byte, count int) ([]int64, error) {
	if count < 0 || len(data) != packedBase9SeedLen(count) {
		return nil, fmt.Errorf("base-9 seed length=%d want %d", len(data), packedBase9SeedLen(count))
	}
	out := make([]int64, count)
	for group := 0; group < len(data)/2; group++ {
		acc := uint32(binary.LittleEndian.Uint16(data[2*group:]))
		if acc >= 59049 { // 9^5
			return nil, fmt.Errorf("base-9 seed group %d=%d is not canonical", group, acc)
		}
		lanes := 5
		if remain := count - group*5; remain < lanes {
			lanes = remain
		}
		for lane := 0; lane < lanes; lane++ {
			out[group*5+lane] = int64(acc%9) - IntGenISISPRFSeedBound
			acc /= 9
		}
		if acc != 0 {
			return nil, fmt.Errorf("base-9 seed group %d has nonzero spare digits", group)
		}
	}
	return out, nil
}

func shiftedSignatureBitWidth(bound int64) (int, error) {
	if bound <= 0 || bound > (1<<30) {
		return 0, fmt.Errorf("signature bound=%d outside supported range", bound)
	}
	max := uint64(2 * bound)
	width := 0
	for max > 0 {
		width++
		max >>= 1
	}
	if width == 0 || 4*width > 64 {
		return 0, fmt.Errorf("unsupported signature bit width %d", width)
	}
	return width, nil
}

func packedShiftedSignatureLen(count int, bound int64) (int, error) {
	if count < 0 {
		return 0, fmt.Errorf("negative signature coefficient count")
	}
	width, err := shiftedSignatureBitWidth(bound)
	if err != nil {
		return 0, err
	}
	groupBytes := (4*width + 7) / 8
	return ((count + 3) / 4) * groupBytes, nil
}

func packCanonicalShiftedSignature(values []int64, bound int64) ([]byte, error) {
	width, err := shiftedSignatureBitWidth(bound)
	if err != nil {
		return nil, err
	}
	groupBytes := (4*width + 7) / 8
	out := make([]byte, ((len(values)+3)/4)*groupBytes)
	mask := uint64(1<<width) - 1
	for group := 0; group < (len(values)+3)/4; group++ {
		var acc uint64
		for lane := 0; lane < 4; lane++ {
			idx := 4*group + lane
			if idx >= len(values) {
				break
			}
			v := values[idx]
			if v < -bound || v > bound {
				return nil, fmt.Errorf("signature coefficient[%d]=%d outside [-%d,%d]", idx, v, bound, bound)
			}
			shifted := uint64(v + bound)
			if shifted > mask {
				return nil, fmt.Errorf("signature coefficient[%d] does not fit %d bits", idx, width)
			}
			acc |= shifted << (lane * width)
		}
		for i := 0; i < groupBytes; i++ {
			out[group*groupBytes+i] = byte(acc >> (8 * i))
		}
	}
	return out, nil
}

func unpackCanonicalShiftedSignature(data []byte, count int, bound int64) ([]int64, error) {
	width, err := shiftedSignatureBitWidth(bound)
	if err != nil {
		return nil, err
	}
	wantLen, err := packedShiftedSignatureLen(count, bound)
	if err != nil {
		return nil, err
	}
	if len(data) != wantLen {
		return nil, fmt.Errorf("packed signature length=%d want %d", len(data), wantLen)
	}
	groupBytes := (4*width + 7) / 8
	mask := uint64(1<<width) - 1
	usedBits := 4 * width
	out := make([]int64, count)
	for group := 0; group < (count+3)/4; group++ {
		var acc uint64
		for i := 0; i < groupBytes; i++ {
			acc |= uint64(data[group*groupBytes+i]) << (8 * i)
		}
		if usedBits%8 != 0 && acc>>usedBits != 0 {
			return nil, fmt.Errorf("signature group %d has nonzero spare bits", group)
		}
		lanes := 4
		if remain := count - 4*group; remain < lanes {
			lanes = remain
		}
		for lane := 0; lane < lanes; lane++ {
			shifted := (acc >> (lane * width)) & mask
			if shifted > uint64(2*bound) {
				return nil, fmt.Errorf("signature group %d lane %d encodes %d above 2*bound=%d", group, lane, shifted, 2*bound)
			}
			out[4*group+lane] = int64(shifted) - bound
		}
		if lanes < 4 && acc>>(lanes*width) != 0 {
			return nil, fmt.Errorf("signature group %d has nonzero spare lanes", group)
		}
	}
	return out, nil
}

func readExactBoundedFile(path string, wantLen int) ([]byte, error) {
	if wantLen < 0 {
		return nil, fmt.Errorf("invalid expected file length %d", wantLen)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != int64(wantLen) {
		return nil, fmt.Errorf("file length=%d want exactly %d", info.Size(), wantLen)
	}
	data := make([]byte, wantLen)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	var trailing [1]byte
	n, err := f.Read(trailing[:])
	if n != 0 || (err != nil && err != io.EOF) {
		return nil, fmt.Errorf("file changed while reading or contains trailing data")
	}
	return data, nil
}
