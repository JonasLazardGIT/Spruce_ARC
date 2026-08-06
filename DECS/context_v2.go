package decs

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	// TranscriptVersionV2 is the exact protocol identity bound into every v2
	// commitment hash.  It is intentionally a semantic identifier rather than
	// a small integer so that similarly numbered transcript families cannot be
	// confused.
	TranscriptVersionV2 = "smallwood_2025_1085_salted_decs_v2"
	// TranscriptVersionV3 is the strict proof-only transcript used by the two
	// size-optimised SmallWood instantiations.  The opening container remains
	// the independently-taped v2 container; the commitment codec and every
	// hash domain are nevertheless versioned separately below.
	TranscriptVersionV3 = "smallwood_2025_1085_salted_decs_v3"

	commitmentCodecVersionV2 uint16 = 2
	commitmentCodecVersionV3 uint16 = 3

	MinSaltBytes = 16
	MaxSaltBytes = 64

	leafDomainV2    = "SPRUCE/SmallWood/DECS/leaf/v2"
	nodeDomainV2    = "SPRUCE/SmallWood/DECS/node/v2"
	paddingDomainV2 = "SPRUCE/SmallWood/DECS/padding/v2"
	gammaDomainV2   = "SPRUCE/SmallWood/DECS/gamma/v2"

	leafDomainV3    = "SPRUCE/SmallWood/DECS/leaf/v3"
	nodeDomainV3    = "SPRUCE/SmallWood/DECS/node/v3"
	paddingDomainV3 = "SPRUCE/SmallWood/DECS/padding/v3"
	gammaDomainV3   = "SPRUCE/SmallWood/DECS/gamma/v3"
)

// CommitmentRole is a canonical, application-selected label distinguishing
// transcript-bound commitments such as the main rows and Q payload.
type CommitmentRole string

const (
	CommitmentRoleMain         CommitmentRole = "main"
	CommitmentRoleQPayload     CommitmentRole = "q-payload"
	CommitmentRoleCompanion    CommitmentRole = "companion"
	CommitmentRoleReplay       CommitmentRole = "replay"
	CommitmentRoleSigShortness CommitmentRole = "sig-shortness"
)

// CommitmentContext is public auxiliary input to every v2 DECS hash. Salt is
// the proof-global salt; callers must pass the same context to commitment and
// verification. The context is copied when retained by a prover or verifier.
type CommitmentContext struct {
	TranscriptVersion string
	Role              CommitmentRole
	Salt              []byte
}

// Validate checks the context-level canonicality enforced by DECS. A higher
// layer remains responsible for checking the exact salt width declared by its
// manifest; DECS accepts the maintained 16..64-byte range.
func (c CommitmentContext) Validate() error {
	if c.TranscriptVersion != TranscriptVersionV2 && c.TranscriptVersion != TranscriptVersionV3 {
		return fmt.Errorf("decs: unsupported transcript version=%q", c.TranscriptVersion)
	}
	if err := validateCommitmentRole(c.Role); err != nil {
		return err
	}
	if len(c.Salt) < MinSaltBytes || len(c.Salt) > MaxSaltBytes {
		return fmt.Errorf("decs: salt width=%d outside %d..%d", len(c.Salt), MinSaltBytes, MaxSaltBytes)
	}
	return nil
}

func commitmentCodecVersion(ctx CommitmentContext) uint16 {
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		return commitmentCodecVersionV3
	}
	return commitmentCodecVersionV2
}

func leafDomain(ctx CommitmentContext) string {
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		return leafDomainV3
	}
	return leafDomainV2
}

func nodeDomain(ctx CommitmentContext) string {
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		return nodeDomainV3
	}
	return nodeDomainV2
}

func paddingDomain(ctx CommitmentContext) string {
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		return paddingDomainV3
	}
	return paddingDomainV2
}

func gammaDomain(ctx CommitmentContext) string {
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		return gammaDomainV3
	}
	return gammaDomainV2
}

func validateCommitmentRole(role CommitmentRole) error {
	if len(role) == 0 || len(role) > 64 {
		return fmt.Errorf("decs: commitment role length=%d outside 1..64", len(role))
	}
	for i := 0; i < len(role); i++ {
		b := role[i]
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '/' {
			continue
		}
		return fmt.Errorf("decs: commitment role contains non-canonical byte %#x", b)
	}
	return nil
}

func cloneCommitmentContext(c CommitmentContext) CommitmentContext {
	c.Salt = append([]byte(nil), c.Salt...)
	return c
}

func writeUint16(h sha3.ShakeHash, v uint16) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	_, _ = h.Write(buf[:])
}

func writeUint32(h sha3.ShakeHash, v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	_, _ = h.Write(buf[:])
}

func writeUint64(h sha3.ShakeHash, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, _ = h.Write(buf[:])
}

func writeLengthPrefixed(h sha3.ShakeHash, value []byte) {
	writeUint32(h, uint32(len(value)))
	_, _ = h.Write(value)
}

func writeContextV2(h sha3.ShakeHash, domain string, ctx CommitmentContext) {
	writeLengthPrefixed(h, []byte(domain))
	writeUint16(h, commitmentCodecVersion(ctx))
	writeLengthPrefixed(h, []byte(ctx.TranscriptVersion))
	writeLengthPrefixed(h, []byte(ctx.Role))
	writeLengthPrefixed(h, ctx.Salt)
}

// The append helpers below encode exactly the same framing as the write
// helpers above, but let the hot commitment paths reuse one backing buffer per
// worker. Passing small stack arrays through the sha3.ShakeHash interface made
// every integer write escape to the heap; a single buffered write avoids those
// allocations without changing the transcript bytes.
func appendUint16(dst []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(dst, v)
}

func appendUint32(dst []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(dst, v)
}

func appendUint64(dst []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(dst, v)
}

func appendLengthPrefixed(dst, value []byte) []byte {
	dst = appendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

func appendContextV2(dst []byte, domain string, ctx CommitmentContext) []byte {
	dst = appendLengthPrefixed(dst, []byte(domain))
	dst = appendUint16(dst, commitmentCodecVersion(ctx))
	dst = appendLengthPrefixed(dst, []byte(ctx.TranscriptVersion))
	dst = appendLengthPrefixed(dst, []byte(ctx.Role))
	return appendLengthPrefixed(dst, ctx.Salt)
}

// HashLeafV2 returns the canonical v2 leaf hash. All indices, evaluation
// points, moduli, and residues use full-width uint64 encodings. Counts and
// byte strings are explicitly framed.
func HashLeafV2(
	ctx CommitmentContext,
	index, point, modulus uint64,
	pvals, mvals []uint64,
	tape []byte,
	hashBytes int,
) ([]byte, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if modulus < 2 {
		return nil, fmt.Errorf("decs: invalid leaf modulus %d", modulus)
	}
	if !IsSupportedHashBytes(hashBytes) {
		return nil, fmt.Errorf("decs: invalid leaf hash width %d", hashBytes)
	}
	if !IsSupportedTapeBytes(len(tape)) {
		return nil, fmt.Errorf("decs: invalid tape width %d", len(tape))
	}
	for i, value := range pvals {
		if value >= modulus {
			return nil, fmt.Errorf("decs: non-canonical P value at column %d", i)
		}
	}
	for i, value := range mvals {
		if value >= modulus {
			return nil, fmt.Errorf("decs: non-canonical M value at column %d", i)
		}
	}
	return hashLeafV2With(sha3.NewShake256(), ctx, index, point, modulus, pvals, mvals, tape, hashBytes), nil
}

func hashLeafV2With(
	h sha3.ShakeHash,
	ctx CommitmentContext,
	index, point, modulus uint64,
	pvals, mvals []uint64,
	tape []byte,
	hashBytes int,
) []byte {
	out := make([]byte, hashBytes)
	hashLeafV2Into(h, nil, out, ctx, index, point, modulus, pvals, mvals, tape)
	return out
}

// hashLeafV2Into writes a canonical leaf hash into out and returns scratch for
// reuse by the caller. out must have the configured hash width.
func hashLeafV2Into(
	h sha3.ShakeHash,
	scratch, out []byte,
	ctx CommitmentContext,
	index, point, modulus uint64,
	pvals, mvals []uint64,
	tape []byte,
) []byte {
	scratch = frameLeafV2Into(scratch, ctx, index, point, modulus, pvals, mvals, tape)
	shakeFrameV2Into(h, out, scratch)
	return scratch
}

func frameLeafV2Into(
	scratch []byte,
	ctx CommitmentContext,
	index, point, modulus uint64,
	pvals, mvals []uint64,
	tape []byte,
) []byte {
	scratch = scratch[:0]
	scratch = appendContextV2(scratch, leafDomain(ctx), ctx)
	scratch = appendUint64(scratch, index)
	scratch = appendUint64(scratch, point)
	scratch = appendUint64(scratch, modulus)
	scratch = appendUint32(scratch, uint32(len(pvals)))
	for _, value := range pvals {
		scratch = appendUint64(scratch, value)
	}
	scratch = appendUint32(scratch, uint32(len(mvals)))
	for _, value := range mvals {
		scratch = appendUint64(scratch, value)
	}
	scratch = appendLengthPrefixed(scratch, tape)
	return scratch
}

func shakeFrameV2Into(h sha3.ShakeHash, out, frame []byte) {
	h.Reset()
	_, _ = h.Write(frame)
	_, _ = h.Read(out)
}

func hashNodeV2With(h sha3.ShakeHash, ctx CommitmentContext, level, index uint64, left, right []byte, hashBytes int) []byte {
	out := make([]byte, hashBytes)
	hashNodeV2Into(h, nil, out, ctx, level, index, left, right)
	return out
}

// hashNodeV2Into writes a canonical internal-node hash into out and returns
// scratch for reuse by the caller.
func hashNodeV2Into(h sha3.ShakeHash, scratch, out []byte, ctx CommitmentContext, level, index uint64, left, right []byte) []byte {
	scratch = scratch[:0]
	scratch = appendContextV2(scratch, nodeDomain(ctx), ctx)
	scratch = appendUint64(scratch, level)
	scratch = appendUint64(scratch, index)
	scratch = appendUint32(scratch, uint32(len(out)))
	scratch = appendLengthPrefixed(scratch, left)
	scratch = appendLengthPrefixed(scratch, right)
	h.Reset()
	_, _ = h.Write(scratch)
	_, _ = h.Read(out)
	return scratch
}

func hashPaddingV2With(h sha3.ShakeHash, ctx CommitmentContext, index uint64, hashBytes int) []byte {
	out := make([]byte, hashBytes)
	hashPaddingV2Into(h, nil, out, ctx, index)
	return out
}

// hashPaddingV2Into writes a canonical padding hash into out and returns
// scratch for reuse by the caller.
func hashPaddingV2Into(h sha3.ShakeHash, scratch, out []byte, ctx CommitmentContext, index uint64) []byte {
	scratch = scratch[:0]
	scratch = appendContextV2(scratch, paddingDomain(ctx), ctx)
	scratch = appendUint64(scratch, index)
	scratch = appendUint32(scratch, uint32(len(out)))
	h.Reset()
	_, _ = h.Write(scratch)
	_, _ = h.Read(out)
	return scratch
}

func validateOpeningV2(ctx CommitmentContext, open *DECSOpening, tapeBytes int) error {
	if err := ctx.Validate(); err != nil {
		return err
	}
	if open == nil {
		return fmt.Errorf("decs: nil v2 opening")
	}
	if open.Version != OpeningVersionV2 {
		return fmt.Errorf("decs: opening version=%d want=%d", open.Version, OpeningVersionV2)
	}
	if open.Role != ctx.Role {
		return fmt.Errorf("decs: opening role=%q want=%q", open.Role, ctx.Role)
	}
	if open.TapeBytes != tapeBytes || !IsSupportedTapeBytes(open.TapeBytes) {
		return fmt.Errorf("decs: opening tape width=%d want=%d", open.TapeBytes, tapeBytes)
	}
	if err := validateOpeningIndexEncodingV2(open); err != nil {
		return err
	}
	if open.FormatVersion > OpeningFormatColumnWidths || open.MFormatVersion > OpeningFormatColumnWidths {
		return fmt.Errorf("decs: unsupported v2 residue encoding")
	}
	if open.AuthFormat != OpeningAuthPaths && open.AuthFormat != OpeningAuthPositionalFrontierV3 {
		return fmt.Errorf("decs: unsupported authentication encoding %d", open.AuthFormat)
	}
	if open.AuthFormat == OpeningAuthPositionalFrontierV3 && ctx.TranscriptVersion != TranscriptVersionV3 {
		return fmt.Errorf("decs: exact-N positional frontier requires transcript v3")
	}
	if open.AuthFormat == OpeningAuthPositionalFrontierV3 && (len(open.PathIndex) != 0 || len(open.PathBits) != 0 || open.PathDepth != 0 || open.PathBitWidth != 0) {
		return fmt.Errorf("decs: positional frontier opening carries legacy path metadata")
	}
	n := open.EntryCount()
	if len(open.Tapes) != n {
		return fmt.Errorf("decs: v2 opening tape count=%d want=%d", len(open.Tapes), n)
	}
	for i, tape := range open.Tapes {
		if len(tape) != tapeBytes {
			return fmt.Errorf("decs: v2 opening tape[%d] width=%d want=%d", i, len(tape), tapeBytes)
		}
	}
	return nil
}

func validateOpeningIndexEncodingV2(open *DECSOpening) error {
	maxInt := int(^uint(0) >> 1)
	if open.MaskCount < 0 || (open.MaskCount > 0 && open.MaskBase < 0) || open.TailCount < 0 {
		return fmt.Errorf("decs: negative v2 opening index metadata")
	}
	if open.MaskCount > 0 && open.MaskBase > maxInt-(open.MaskCount-1) {
		return fmt.Errorf("decs: v2 mask index range overflows int")
	}
	if len(open.Indices) > 0 {
		if len(open.IndexBits) != 0 || open.IndexBitWidth != 0 {
			return fmt.Errorf("decs: v2 opening mixes explicit and packed indices")
		}
		if open.TailCount != 0 && open.TailCount != len(open.Indices) {
			return fmt.Errorf("decs: explicit v2 tail count mismatch")
		}
		if open.MaskCount > maxInt-len(open.Indices) {
			return fmt.Errorf("decs: v2 opening entry count overflows int")
		}
		return validateStrictlyIncreasingOpeningIndicesV2(open)
	}
	if open.TailCount == 0 {
		if len(open.IndexBits) != 0 || open.IndexBitWidth != 0 {
			return fmt.Errorf("decs: v2 opening has index bits without tail indices")
		}
		return validateStrictlyIncreasingOpeningIndicesV2(open)
	}
	if len(open.IndexBits) == 0 {
		return fmt.Errorf("decs: v2 packed tail indices are missing")
	}
	width := open.tailIndexBitWidth()
	if width <= 0 || width > 63 {
		return fmt.Errorf("decs: invalid v2 packed index width %d", width)
	}
	if open.TailCount > int(^uint(0)>>1)/width {
		return fmt.Errorf("decs: v2 packed index size overflows")
	}
	totalBits := open.TailCount * width
	wantBytes := (totalBits + 7) / 8
	if len(open.IndexBits) != wantBytes {
		return fmt.Errorf("decs: v2 packed index bytes=%d want=%d", len(open.IndexBits), wantBytes)
	}
	if unused := wantBytes*8 - totalBits; unused > 0 {
		usedBits := 8 - unused
		if open.IndexBits[wantBytes-1]>>usedBits != 0 {
			return fmt.Errorf("decs: non-canonical v2 packed index padding")
		}
	}
	if open.MaskCount > maxInt-open.TailCount {
		return fmt.Errorf("decs: v2 opening entry count overflows int")
	}
	return validateStrictlyIncreasingOpeningIndicesV2(open)
}

func validateStrictlyIncreasingOpeningIndicesV2(open *DECSOpening) error {
	previous := -1
	for i := 0; i < open.EntryCount(); i++ {
		idx := open.IndexAt(i)
		if idx < 0 {
			return fmt.Errorf("decs: malformed v2 opening index at position %d", i)
		}
		if idx <= previous {
			return fmt.Errorf("decs: v2 opening indices are not strictly increasing at %d", idx)
		}
		previous = idx
	}
	return nil
}
