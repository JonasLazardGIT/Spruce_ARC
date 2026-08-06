package PIOP

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

const fsDigestBytes = 64

const (
	fsInitializationDomainV2 = "SPRUCE/SmallWood/Fiat-Shamir/init/v2"
	fsInitializationDomainV3 = "SPRUCE/SmallWood/Fiat-Shamir/init/v3"
	fsInitializationDomainV4 = "SPRUCE/SmallWood/Fiat-Shamir/init/v4"
	fsRoundInputDomainV3     = "SPRUCE/SmallWood/Fiat-Shamir/round/v3"
	fsRoundInputDomainV4     = "SPRUCE/SmallWood/Fiat-Shamir/round/v4"
)

type FSTranscriptPhase string

const (
	FSTranscriptPhaseIssuance FSTranscriptPhase = "issuance"
	FSTranscriptPhaseShowing  FSTranscriptPhase = "showing"
)

// XOF models the extendable-output function used by the Fiat–Shamir layer.
type XOF interface {
	Expand(label string, parts ...[]byte) []byte
}

// Shake256XOF is a SHAKE-256 backed implementation of XOF with a fixed output length.
type Shake256XOF struct {
	outLen int
}

// fsV3CounterExpander is an optional, package-private fast path used by the
// strict-v3 Fiat--Shamir loop.  Keeping it separate from XOF preserves the
// public interface and, importantly, leaves custom XOF implementations on the
// historical Expand path.
type fsV3CounterExpander interface {
	expand(counter uint64) []byte
}

type shake256V3CounterExpander struct {
	prefix sha3.ShakeHash
	outLen int
}

func (s Shake256XOF) newV3CounterExpander(label string, prefix []byte) fsV3CounterExpander {
	h := sha3.NewShake256()
	if _, err := h.Write([]byte(label)); err != nil {
		panic(fmt.Errorf("Shake256XOF: write label: %w", err))
	}
	if _, err := h.Write(prefix); err != nil {
		panic(fmt.Errorf("Shake256XOF: write v3 round prefix: %w", err))
	}
	return shake256V3CounterExpander{prefix: h, outLen: s.outLen}
}

// newBuiltinV3CounterExpander deliberately recognizes only the concrete
// built-in SHAKE implementation. A custom XOF may embed Shake256XOF while
// overriding Expand; structural interface detection would then silently
// bypass that override and change the custom transcript.
func newBuiltinV3CounterExpander(xof XOF, label string, prefix []byte) (fsV3CounterExpander, bool) {
	switch builtin := xof.(type) {
	case Shake256XOF:
		return builtin.newV3CounterExpander(label, prefix), true
	case *Shake256XOF:
		if builtin != nil {
			return builtin.newV3CounterExpander(label, prefix), true
		}
	}
	return nil, false
}

func (s shake256V3CounterExpander) expand(counter uint64) []byte {
	h := s.prefix.Clone()
	var suffix [8]byte
	binary.BigEndian.PutUint64(suffix[:], counter)
	if _, err := h.Write(suffix[:]); err != nil {
		panic(fmt.Errorf("Shake256XOF: write v3 counter: %w", err))
	}
	out := make([]byte, s.outLen)
	if _, err := h.Read(out); err != nil {
		panic(fmt.Errorf("Shake256XOF: read v3 round output: %w", err))
	}
	return out
}

// NewShake256XOF returns a SHAKE-256 XOF that emits outLen bytes on every squeeze.
func NewShake256XOF(outLen int) Shake256XOF {
	if outLen <= 0 {
		panic("NewShake256XOF: outLen must be > 0")
	}
	return Shake256XOF{outLen: outLen}
}

func fsSaltBytes(lambda int) int {
	if lambda <= 0 {
		lambda = defaultSimOpts().Lambda
	}
	bits := 2 * lambda
	return (bits + 7) / 8
}

func fsSaltBytesForOpts(opts SimOpts) int {
	if opts.SaltBits > 0 {
		return (opts.SaltBits + 7) / 8
	}
	return fsSaltBytes(opts.Lambda)
}

func fsCollisionSpaceBits(lambda int, saltLen int) int {
	if lambda <= 0 {
		lambda = defaultSimOpts().Lambda
	}
	bits := 2 * lambda
	if saltLen > 0 && 8*saltLen < bits {
		bits = 8 * saltLen
	}
	digestBits := 8 * fsDigestBytes
	if digestBits < bits {
		bits = digestBits
	}
	return bits
}

// Expand realises the SHAKE-256 duplex keyed by `label` and concatenates `parts`.
func (s Shake256XOF) Expand(label string, parts ...[]byte) []byte {
	h := sha3.NewShake256()
	if _, err := h.Write([]byte(label)); err != nil {
		panic(fmt.Errorf("Shake256XOF: write label: %w", err))
	}
	for _, p := range parts {
		if _, err := h.Write(p); err != nil {
			panic(fmt.Errorf("Shake256XOF: write payload: %w", err))
		}
	}
	out := make([]byte, s.outLen)
	if _, err := h.Read(out); err != nil {
		panic(fmt.Errorf("Shake256XOF: read output: %w", err))
	}
	return out
}

// FSParams bundles the Fiat–Shamir security parameters.
type FSParams struct {
	Lambda             int // random oracle security parameter (bits)
	Kappa              [4]int
	TranscriptVersion  string
	TranscriptProtocol string
	OutputBits         int
	Phase              FSTranscriptPhase
	Relation           string
}

// FS tracks the four grinding rounds in the SmallWood–ARK transcript.
type FS struct {
	xof     XOF
	params  FSParams
	initial []byte
	ctr     [4]uint64
	h       [4][]byte
	labels  [4]string
	chained bool
	phase   *PhaseRecorder
	// phasePrefix is "issuance" or "showing" for benchmark builds. It is
	// deliberately absent from transcript state.
	phasePrefix string
}

// NewFSChecked prepares Fiat--Shamir state after validating all v4 policy
// fields. V4 never applies width, phase, or relation defaults.
func NewFSChecked(x XOF, salt []byte, params FSParams) (*FS, error) {
	if x == nil {
		return nil, errors.New("NewFS: nil XOF")
	}
	if params.Lambda <= 0 {
		params.Lambda = 256
	}
	version := normalizeTranscriptVersion(params.TranscriptVersion)
	if transcriptUsesPublicationV4(version) {
		if params.OutputBits <= 0 || params.OutputBits%8 != 0 {
			return nil, fmt.Errorf("NewFS: v4 output bits=%d must be positive and byte-aligned", params.OutputBits)
		}
		if !decsHashWidthSupportedForFS(params.OutputBits) {
			return nil, fmt.Errorf("NewFS: v4 output bits=%d are unsupported", params.OutputBits)
		}
		if params.Phase != FSTranscriptPhaseIssuance && params.Phase != FSTranscriptPhaseShowing {
			return nil, fmt.Errorf("NewFS: v4 phase=%q is not issuance or showing", params.Phase)
		}
		params.Relation = strings.TrimSpace(params.Relation)
		if params.Relation == "" {
			return nil, errors.New("NewFS: v4 relation identifier is empty")
		}
		if outLen, ok := builtinShakeOutputBytes(x); ok && outLen*8 != params.OutputBits {
			return nil, fmt.Errorf("NewFS: v4 built-in XOF output=%d bits want=%d", outLen*8, params.OutputBits)
		}
	} else {
		// Historical proof transcripts always squeeze 64 bytes. Keep the value
		// explicit in state so reporting and replay cannot confuse their actual
		// width with their (often narrower) collision-accounting width.
		params.OutputBits = fsDigestBytes * 8
		if version == TranscriptVersionSmallWood2025V2 || version == TranscriptVersionSmallWood2025V3 {
			if outLen, ok := builtinShakeOutputBytes(x); ok && outLen != fsDigestBytes {
				return nil, fmt.Errorf("NewFS: historical %s built-in XOF output=%d bytes want=%d", version, outLen, fsDigestBytes)
			}
		}
	}
	initial := fsInitializationInput(params.TranscriptVersion, params.TranscriptProtocol, salt)
	if version == TranscriptVersionSmallWood2025V3 {
		initial = fsInitializationInputV3(params.TranscriptVersion, params.TranscriptProtocol, salt)
	} else if version == TranscriptVersionSmallWood2025V4 {
		initial = fsInitializationInputV4(params, salt)
	}
	fs := &FS{
		xof:     x,
		params:  params,
		initial: initial,
		labels:  [4]string{"fs-gamma", "fs-gammap", "fs-eprime", "fs-tail"},
	}
	fs.chained = version == TranscriptVersionSmallWood2025V2 || version == TranscriptVersionSmallWood2025V3 || version == TranscriptVersionSmallWood2025V4
	return fs, nil
}

func builtinShakeOutputBytes(x XOF) (int, bool) {
	switch builtin := x.(type) {
	case Shake256XOF:
		return builtin.outLen, true
	case *Shake256XOF:
		if builtin != nil {
			return builtin.outLen, true
		}
	}
	return 0, false
}

// NewFS retains the low-level constructor signature used by historical tests.
// Invalid publication-v4 parameters fail closed by panicking before hashing;
// production prover/verifier paths use NewFSChecked and return the error.
func NewFS(x XOF, salt []byte, params FSParams) *FS {
	fs, err := NewFSChecked(x, salt, params)
	if err != nil {
		panic(err)
	}
	return fs
}

func decsHashWidthSupportedForFS(bits int) bool {
	return bits > 0 && bits%8 == 0 && bits/8 >= 16 && bits/8 <= 64
}

// ResolveFSOutputBits returns the actual SHAKE output width. Historical v2/v3
// remain fixed at 512 bits. Publication v4 is explicit and fail-closed.
func ResolveFSOutputBits(opts SimOpts) (int, error) {
	if !transcriptUsesPublicationV4(opts.TranscriptVersion) {
		return fsDigestBytes * 8, nil
	}
	if opts.FSOutputBits <= 0 || opts.FSOutputBits%8 != 0 {
		return 0, fmt.Errorf("publication-v4 FS output bits=%d must be positive and byte-aligned", opts.FSOutputBits)
	}
	if !decsHashWidthSupportedForFS(opts.FSOutputBits) {
		return 0, fmt.Errorf("publication-v4 FS output bits=%d are outside the supported 128..512-bit range", opts.FSOutputBits)
	}
	if opts.FSCollisionBits <= 0 || opts.DECSHashBits <= 0 ||
		opts.FSOutputBits != opts.FSCollisionBits || opts.FSOutputBits != opts.DECSHashBits {
		return 0, fmt.Errorf(
			"publication-v4 requires FSOutputBits == FSCollisionBits == DECSHashBits, got (%d,%d,%d)",
			opts.FSOutputBits, opts.FSCollisionBits, opts.DECSHashBits,
		)
	}
	return opts.FSOutputBits, nil
}

func fsOutputBytesForOpts(opts SimOpts) (int, error) {
	bits, err := ResolveFSOutputBits(opts)
	if err != nil {
		return 0, err
	}
	return bits / 8, nil
}

func fsTranscriptIdentityForLayout(layout RowLayout, hashRelation string) (FSTranscriptPhase, string, error) {
	relation := strings.TrimSpace(hashRelation)
	switch {
	case layout.IntGenISISPreSign != nil:
		if relation == "" {
			return "", "", errors.New("issuance Fiat-Shamir relation identifier is empty")
		}
		return FSTranscriptPhaseIssuance, "intgenisis/presign/" + relation, nil
	case layout.IntGenISISShowing != nil:
		if relation == "" {
			return "", "", errors.New("showing Fiat-Shamir relation identifier is empty")
		}
		return FSTranscriptPhaseShowing, "intgenisis/showing/" + relation, nil
	default:
		return "", "", errors.New("publication-v4 Fiat-Shamir requires an issuance or showing relation layout")
	}
}

func newFSForOpts(opts SimOpts, salt []byte, layout RowLayout, hashRelation string) (*FS, error) {
	outBytes, err := fsOutputBytesForOpts(opts)
	if err != nil {
		return nil, err
	}
	params := FSParams{
		Lambda:             opts.Lambda,
		Kappa:              opts.Kappa,
		TranscriptVersion:  opts.TranscriptVersion,
		TranscriptProtocol: opts.TranscriptProtocolMode,
		OutputBits:         outBytes * 8,
	}
	if transcriptUsesPublicationV4(opts.TranscriptVersion) {
		params.Phase, params.Relation, err = fsTranscriptIdentityForLayout(layout, hashRelation)
		if err != nil {
			return nil, err
		}
	}
	return NewFSChecked(NewShake256XOF(outBytes), salt, params)
}

func newFSForProof(proof *Proof) (*FS, error) {
	if proof == nil {
		return nil, errors.New("nil proof")
	}
	opts := SimOpts{
		Lambda:                 proof.Lambda,
		Kappa:                  proof.Kappa,
		TranscriptVersion:      proof.TranscriptVersion,
		TranscriptProtocolMode: proof.TranscriptProtocolMode,
		FSOutputBits:           proof.FSOutputBits,
		FSCollisionBits:        proof.FSOutputBits,
		DECSHashBits:           proof.FSOutputBits,
	}
	return newFSForOpts(opts, proof.Salt, proof.RowLayout, proof.HashRelation)
}

// setPhaseRecorder attaches opt-in benchmark instrumentation without changing
// NewFS or XOF's public APIs.  It is intentionally package-private because
// transcript consumers must not treat timings as protocol inputs.
func (fs *FS) setPhaseRecorder(recorder *PhaseRecorder, prefix string) {
	if fs == nil {
		return
	}
	fs.phase = recorder
	fs.phasePrefix = prefix
}

func phasePrefixForRowLayout(layout RowLayout) string {
	switch {
	case layout.IntGenISISPreSign != nil:
		return "issuance"
	case layout.IntGenISISShowing != nil:
		return "showing"
	default:
		return "proof"
	}
}

// GrindAndDerive performs the κ-bit grinding loop for the selected round and
// returns the accepted hash material along with the derived challenge bytes.
func (fs *FS) GrindAndDerive(round int, material [][]byte, derive func([]byte) []byte) (h []byte, ctr uint64, chal []byte) {
	if round < 0 || round >= len(fs.ctr) {
		panic("FS.GrindAndDerive: round out of range")
	}
	kappa := fs.params.Kappa[round]
	counter := fs.ctr[round]
	strictV3 := transcriptUsesSmallWood2025V3(fs.params.TranscriptVersion)
	var counterExpander fsV3CounterExpander
	if strictV3 {
		// Build and absorb the complete, canonically framed prefix once. The
		// only omitted bytes are the unchanged big-endian uint64 counter.
		var prefixStart time.Time
		if fs.phase != nil {
			prefixStart = time.Now()
		}
		prefix := fs.roundInputPrefixV3(round, material)
		if fast, ok := newBuiltinV3CounterExpander(fs.xof, fs.labels[round], prefix); ok {
			counterExpander = fast
		}
		if fs.phase != nil {
			fs.phase.RecordDuration(fs.phaseLabel(round, "prefix"), time.Since(prefixStart))
		}
	}
	var loopStart time.Time
	if fs.phase != nil {
		loopStart = time.Now()
	}
	for {
		var digest []byte
		if counterExpander != nil {
			digest = counterExpander.expand(counter)
		} else {
			var input []byte
			if strictV3 {
				// Custom XOFs deliberately retain the historical per-counter
				// framing and Expand call sequence.
				input = fs.roundInputV3(round, material, counter)
			} else {
				input = fs.roundInput(round)
				for _, m := range material {
					input = append(input, m...)
				}
				input = append(input, u64le(counter)...)
			}
			digest = fs.xof.Expand(fs.labels[round], input)
		}
		if transcriptUsesPublicationV4(fs.params.TranscriptVersion) && len(digest)*8 != fs.params.OutputBits {
			panic(fmt.Sprintf("FS.GrindAndDerive: v4 XOF emitted %d bits, want %d", len(digest)*8, fs.params.OutputBits))
		}
		if hasZeroPrefix(digest, kappa) {
			if fs.phase != nil {
				fs.phase.RecordDuration(fs.phaseLabel(round, "counter_loop"), time.Since(loopStart))
			}
			fs.h[round] = append([]byte(nil), digest...)
			fs.ctr[round] = counter
			chal = derive(digest)
			return fs.h[round], counter, chal
		}
		counter++
		if counter == 0 {
			panic("FS.GrindAndDerive: counter wrapped")
		}
	}
}

func (fs *FS) phaseLabel(round int, suffix string) string {
	if fs.phasePrefix == "" {
		return fmt.Sprintf("fs.round%d.%s", round+1, suffix)
	}
	return fmt.Sprintf("%s.fs.round%d.%s", fs.phasePrefix, round+1, suffix)
}

func (fs *FS) roundInputPrefixV3(round int, material [][]byte) []byte {
	domain := fsRoundInputDomainV3
	if transcriptUsesPublicationV4(fs.params.TranscriptVersion) {
		domain = fsRoundInputDomainV4
	}
	input := appendFSLengthPrefixed(nil, []byte(domain))
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], uint64(round))
	input = append(input, word[:]...)
	input = appendFSLengthPrefixed(input, fs.roundInput(round))
	binary.BigEndian.PutUint64(word[:], uint64(len(material)))
	input = append(input, word[:]...)
	for _, part := range material {
		input = appendFSLengthPrefixed(input, part)
	}
	return input
}

func (fs *FS) roundInputV3(round int, material [][]byte, counter uint64) []byte {
	input := fs.roundInputPrefixV3(round, material)
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], counter)
	return append(input, word[:]...)
}

// expandRoundV3At expands one strict-v3 round at an authoritative counter. It
// is shared by the verifier and canonical decoder so those paths cannot drift
// from the prover's prefix framing. It never searches for a different counter.
func (fs *FS) expandRoundV3At(round int, material [][]byte, counter uint64) []byte {
	if fs == nil || round < 0 || round >= len(fs.labels) {
		panic("FS.expandRoundV3At: invalid state or round")
	}
	prefix := fs.roundInputPrefixV3(round, material)
	if fast, ok := newBuiltinV3CounterExpander(fs.xof, fs.labels[round], prefix); ok {
		return fast.expand(counter)
	}
	return fs.xof.Expand(fs.labels[round], fs.roundInputV3(round, material, counter))
}

func (fs *FS) roundInput(round int) []byte {
	if fs.chained && round > 0 {
		if len(fs.h[round-1]) == 0 {
			panic("FS.roundInput: missing previous chained digest")
		}
		return append([]byte(nil), fs.h[round-1]...)
	}
	input := make([]byte, len(fs.initial))
	copy(input, fs.initial)
	return input
}

func fsInitializationInput(version, protocol string, salt []byte) []byte {
	input := make([]byte, 0, len(fsInitializationDomainV2)+len(version)+len(protocol)+len(salt)+32)
	input = appendFSLengthPrefixed(input, []byte(fsInitializationDomainV2))
	input = appendFSLengthPrefixed(input, []byte(version))
	input = appendFSLengthPrefixed(input, []byte(protocol))
	input = appendFSLengthPrefixed(input, salt)
	return input
}

func fsInitializationInputV3(version, protocol string, salt []byte) []byte {
	input := make([]byte, 0, len(fsInitializationDomainV3)+len(version)+len(protocol)+len(salt)+32)
	input = appendFSLengthPrefixed(input, []byte(fsInitializationDomainV3))
	input = appendFSLengthPrefixed(input, []byte(version))
	input = appendFSLengthPrefixed(input, []byte(protocol))
	input = appendFSLengthPrefixed(input, salt)
	return input
}

func fsInitializationInputV4(params FSParams, salt []byte) []byte {
	input := make([]byte, 0, len(fsInitializationDomainV4)+len(params.TranscriptVersion)+len(params.TranscriptProtocol)+len(params.Relation)+len(salt)+80)
	input = appendFSLengthPrefixed(input, []byte(fsInitializationDomainV4))
	input = appendFSLengthPrefixed(input, []byte(params.TranscriptVersion))
	input = appendFSLengthPrefixed(input, []byte(params.TranscriptProtocol))
	input = appendFSLengthPrefixed(input, []byte(params.Phase))
	input = appendFSLengthPrefixed(input, []byte(params.Relation))
	var width [8]byte
	binary.BigEndian.PutUint64(width[:], uint64(params.OutputBits))
	input = appendFSLengthPrefixed(input, width[:])
	input = appendFSLengthPrefixed(input, salt)
	return input
}

func appendFSLengthPrefixed(dst, value []byte) []byte {
	var width [8]byte
	binary.BigEndian.PutUint64(width[:], uint64(len(value)))
	dst = append(dst, width[:]...)
	return append(dst, value...)
}

// hasZeroPrefix checks whether the first kappa bits of buf are zero.
func hasZeroPrefix(buf []byte, kappa int) bool {
	if kappa <= 0 {
		return true
	}
	needed := (kappa + 7) / 8
	if len(buf) < needed {
		return false
	}
	full := kappa / 8
	for i := 0; i < full; i++ {
		if buf[i] != 0 {
			return false
		}
	}
	rem := kappa % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xFF << (8 - rem))
	return buf[full]&mask == 0
}

func u64le(v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return buf[:]
}
