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

	commitmentCodecVersionV2 uint16 = 2

	MinSaltBytes = 16
	MaxSaltBytes = 64

	leafDomainV2    = "SPRUCE/SmallWood/DECS/leaf/v2"
	nodeDomainV2    = "SPRUCE/SmallWood/DECS/node/v2"
	paddingDomainV2 = "SPRUCE/SmallWood/DECS/padding/v2"
	gammaDomainV2   = "SPRUCE/SmallWood/DECS/gamma/v2"
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
	if c.TranscriptVersion != TranscriptVersionV2 {
		return fmt.Errorf("decs: transcript version=%q want=%q", c.TranscriptVersion, TranscriptVersionV2)
	}
	if err := validateCommitmentRole(c.Role); err != nil {
		return err
	}
	if len(c.Salt) < MinSaltBytes || len(c.Salt) > MaxSaltBytes {
		return fmt.Errorf("decs: salt width=%d outside %d..%d", len(c.Salt), MinSaltBytes, MaxSaltBytes)
	}
	return nil
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
	writeUint16(h, commitmentCodecVersionV2)
	writeLengthPrefixed(h, []byte(ctx.TranscriptVersion))
	writeLengthPrefixed(h, []byte(ctx.Role))
	writeLengthPrefixed(h, ctx.Salt)
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
	h.Reset()
	writeContextV2(h, leafDomainV2, ctx)
	writeUint64(h, index)
	writeUint64(h, point)
	writeUint64(h, modulus)
	writeUint32(h, uint32(len(pvals)))
	for _, value := range pvals {
		writeUint64(h, value)
	}
	writeUint32(h, uint32(len(mvals)))
	for _, value := range mvals {
		writeUint64(h, value)
	}
	writeLengthPrefixed(h, tape)
	out := make([]byte, hashBytes)
	_, _ = h.Read(out)
	return out
}

func hashNodeV2With(h sha3.ShakeHash, ctx CommitmentContext, level, index uint64, left, right []byte, hashBytes int) []byte {
	h.Reset()
	writeContextV2(h, nodeDomainV2, ctx)
	writeUint64(h, level)
	writeUint64(h, index)
	writeUint32(h, uint32(hashBytes))
	writeLengthPrefixed(h, left)
	writeLengthPrefixed(h, right)
	out := make([]byte, hashBytes)
	_, _ = h.Read(out)
	return out
}

func hashPaddingV2With(h sha3.ShakeHash, ctx CommitmentContext, index uint64, hashBytes int) []byte {
	h.Reset()
	writeContextV2(h, paddingDomainV2, ctx)
	writeUint64(h, index)
	writeUint32(h, uint32(hashBytes))
	out := make([]byte, hashBytes)
	_, _ = h.Read(out)
	return out
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
