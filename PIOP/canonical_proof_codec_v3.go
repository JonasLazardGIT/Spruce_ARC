package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// CanonicalProofKind identifies the statement-specific relation whose layout
// is reconstructed from trusted verifier inputs. It is not a free-form wire
// dimension.
type CanonicalProofKind uint8

const (
	CanonicalProofPreSign CanonicalProofKind = 1
	CanonicalProofShowing CanonicalProofKind = 2

	// PreSign and Showing are concise aliases for callers constructing a
	// CanonicalProofContext.
	PreSign = CanonicalProofPreSign
	Showing = CanonicalProofShowing
)

// CanonicalProofContext supplies every public value which is deliberately not
// represented in the schema-3 proof wire.
type CanonicalProofContext struct {
	Kind    CanonicalProofKind
	Public  PublicInputs
	Options SimOpts
}

// PreparedExecutionContext is an immutable, public-only compilation of one
// canonical proof relation. It owns all backing data and is bound to the full
// public statement, preset manifest, phase, layout, field, domain, and codec
// geometry. It contains no witness, tape, salt, mask, or proof randomness.
type PreparedExecutionContext struct {
	geometry *canonicalProofGeometryV3
	digest   [sha256.Size]byte
}

// PrepareExecutionContext compiles the deterministic codec/replay geometry
// once. Local scheduling and recorders are deliberately excluded from the
// binding and can vary between uses without changing proof identity.
func PrepareExecutionContext(ctx CanonicalProofContext) (*PreparedExecutionContext, error) {
	owned, err := clonePublicInputsOwned(ctx.Public)
	if err != nil {
		return nil, fmt.Errorf("PIOP: prepare execution context public inputs: %w", err)
	}
	ctx.Public = owned
	ctx.Options.PhaseRecorder = nil
	ctx.Options.ExecutionPolicy = ExecutionPolicy{}
	ctx.Options.Mutate = nil
	geometry, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		return nil, err
	}
	material := make([]byte, 0, len(geometry.publicStatement)+16+8*len(geometry.domainPoints))
	material = append(material, byte(geometry.ctx.Kind), canonicalProofWireVersionV6)
	material = binary.LittleEndian.AppendUint64(material, geometry.q)
	material = binary.LittleEndian.AppendUint64(material, uint64(geometry.opts.NLeaves))
	material = append(material, geometry.publicStatement...)
	for _, point := range geometry.domainPoints {
		material = binary.LittleEndian.AppendUint64(material, point)
	}
	return &PreparedExecutionContext{geometry: geometry, digest: sha256.Sum256(material)}, nil
}

func (p *PreparedExecutionContext) BindingDigest() string {
	if p == nil {
		return ""
	}
	return hex.EncodeToString(p.digest[:])
}

func (p *PreparedExecutionContext) Kind() CanonicalProofKind {
	if p == nil || p.geometry == nil {
		return 0
	}
	return p.geometry.ctx.Kind
}

var canonicalProofMagicV6 = [8]byte{'S', 'P', 'R', 'U', 'C', 'E', 'P', '6'}

const (
	canonicalProofWireVersionV6 = byte(CanonicalProofCodecVersionV6)
	canonicalFqBitWidth         = 20
	// The strict target wires are well below 128 KiB. A one-MiB hard ceiling
	// leaves generous headroom while keeping arbitrary-input decoder and fuzz
	// allocations predictably bounded.
	canonicalProofMaxBytes    = 1 << 20
	canonicalProofMaxElements = 64 << 20
)

type canonicalProofGeometryV3 struct {
	ctx             CanonicalProofContext
	opts            SimOpts
	pub             PublicInputs
	ringQ           *ring.Ring
	q               uint64
	layout          RowLayout
	companion       *PRFCompanionLayout
	omegaWitness    []uint64
	domainPoints    []uint64
	K               *kf.Field
	omegaExtra      kf.Elem
	muInv           kf.Elem
	logicalRows     int
	witnessLayers   int
	replayRows      int
	maskRows        int
	totalRows       int
	queryCount      int
	rowDegree       int
	dQ              int
	rRows           int
	rCols           int
	qRows           int
	qCols           int
	qWireCols       int
	vRows           int
	vCols           int
	vRowWidths      []int
	vWireElements   int
	barRows         int
	barCols         int
	openingEntries  int
	openingPCols    int
	hashBytes       int
	tapeBytes       int
	saltBytes       int
	merkleDepth     int
	worstAuthNodes  int
	publicStatement []byte
}

type canonicalProofMatricesV3 struct {
	r        [][]uint64
	qPayload [][]uint64
	qCompact [][]uint64
	vTargets [][]uint64
	barSets  [][]uint64
}

// MarshalCanonicalProof serializes a strict schema-3 BQ128/WF128 proof with
// canonical codec v6. The
// encoding intentionally has no legacy migration path and no representation
// for verifier-debug coefficient snapshots, public extension-field profiles,
// challenge matrices, or challenge indices.
func MarshalCanonicalProof(proof *Proof, ctx CanonicalProofContext) ([]byte, error) {
	var started time.Time
	if ctx.Options.PhaseRecorder != nil {
		started = time.Now()
		defer func() {
			ctx.Options.PhaseRecorder.RecordDuration(canonicalProofPhasePrefix(ctx.Kind)+".canonical_encode", time.Since(started))
		}()
	}
	if proof == nil {
		return nil, errors.New("PIOP: canonical proof: nil proof")
	}
	geometry, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		return nil, err
	}
	return marshalCanonicalProofWithGeometryV3(proof, geometry)
}

// MarshalCanonicalProofPrepared preserves the exact canonical wire while
// reusing validated geometry. The optional recorder is operational only.
func MarshalCanonicalProofPrepared(proof *Proof, prepared *PreparedExecutionContext, recorder *PhaseRecorder) ([]byte, error) {
	if prepared == nil || prepared.geometry == nil {
		return nil, errors.New("PIOP: canonical proof: nil prepared execution context")
	}
	started := phaseTimingStart(recorder)
	out, err := marshalCanonicalProofWithGeometryV3(proof, prepared.geometry)
	if recorder != nil {
		recorder.RecordDuration(canonicalProofPhasePrefix(prepared.geometry.ctx.Kind)+".canonical_encode", time.Since(started))
	}
	return out, err
}

func marshalCanonicalProofWithGeometryV3(proof *Proof, geometry *canonicalProofGeometryV3) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("PIOP: canonical proof: nil proof")
	}
	if geometry == nil {
		return nil, errors.New("PIOP: canonical proof: nil trusted geometry")
	}
	if err := rejectCanonicalProofForbiddenV3(proof); err != nil {
		return nil, err
	}
	matrices := canonicalProofMatricesV3{
		r:        copyMatrix(proof.R),
		qPayload: copyMatrix(proof.QPayloadMatrix()),
		vTargets: copyMatrix(proof.VTargetsMatrix()),
		barSets:  copyMatrix(proof.BarSetsMatrix()),
	}
	if err := validateCanonicalProofMatricesV3(geometry, matrices); err != nil {
		return nil, err
	}
	expected, err := reconstructCanonicalProofV3(geometry, proofRootBytes(proof), proof.Salt, proof.Ctr, matrices)
	if err != nil {
		return nil, err
	}
	if err := validateCanonicalProofEnvelopeV3(proof, expected, geometry); err != nil {
		return nil, err
	}

	opening := resolveProofPCSOpening(proof)
	openingWire, err := marshalCanonicalOpeningV6(opening, expected.Tail, geometry)
	if err != nil {
		return nil, err
	}

	root := proofRootBytes(proof)
	out := make([]byte, 0, len(canonicalProofMagicV6)+2+len(root)+len(proof.Salt)+len(openingWire))
	out = append(out, canonicalProofMagicV6[:]...)
	out = append(out, canonicalProofWireVersionV6, byte(geometry.ctx.Kind))
	out = append(out, root...)
	out = append(out, proof.Salt...)
	for _, counter := range proof.Ctr {
		out = appendCanonicalUvarint(out, counter)
	}
	packedR, err := packCanonicalFqMatrixRadixQV5(matrices.r, geometry.q)
	if err != nil {
		return nil, err
	}
	out = append(out, packedR...)
	packedQ, err := marshalCanonicalQPayloadV3(matrices.qPayload, geometry)
	if err != nil {
		return nil, err
	}
	out = append(out, packedQ...)
	packedV, err := marshalCanonicalVTargetsV3(matrices.vTargets, geometry)
	if err != nil {
		return nil, err
	}
	out = append(out, packedV...)
	packedBar, err := packCanonicalFqMatrixRadixQV5(matrices.barSets, geometry.q)
	if err != nil {
		return nil, err
	}
	out = append(out, packedBar...)
	out = append(out, openingWire...)
	if len(out) > canonicalProofMaxBytes {
		return nil, fmt.Errorf("PIOP: canonical proof: output size %d exceeds codec limit", len(out))
	}
	return out, nil
}

// UnmarshalCanonicalProof parses only the strict schema-3 wire selected by
// ctx. All omitted dimensions and transcript-derived values are reconstructed
// before an authoritative DECS opening is installed on the returned proof.
func UnmarshalCanonicalProof(data []byte, ctx CanonicalProofContext) (*Proof, error) {
	var started time.Time
	if ctx.Options.PhaseRecorder != nil {
		started = time.Now()
		defer func() {
			ctx.Options.PhaseRecorder.RecordDuration(canonicalProofPhasePrefix(ctx.Kind)+".canonical_decode", time.Since(started))
		}()
	}
	if len(data) > canonicalProofMaxBytes {
		return nil, fmt.Errorf("PIOP: canonical proof: input size %d exceeds codec limit", len(data))
	}
	reader, err := newCanonicalProofReaderV3(data, ctx.Kind)
	if err != nil {
		return nil, err
	}
	// Reject malformed/legacy envelopes before compiling the trusted relation
	// geometry. Besides being cheaper, this keeps arbitrary-input decoder fuzzing
	// within a small allocation bound.
	geometry, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		return nil, err
	}
	return unmarshalCanonicalProofBodyV3(&reader, geometry)
}

// UnmarshalCanonicalProofPrepared parses with an immutable trusted geometry.
func UnmarshalCanonicalProofPrepared(data []byte, prepared *PreparedExecutionContext, recorder *PhaseRecorder) (*Proof, error) {
	if prepared == nil || prepared.geometry == nil {
		return nil, errors.New("PIOP: canonical proof: nil prepared execution context")
	}
	started := phaseTimingStart(recorder)
	proof, err := unmarshalCanonicalProofWithGeometryV3(data, prepared.geometry)
	if recorder != nil {
		recorder.RecordDuration(canonicalProofPhasePrefix(prepared.geometry.ctx.Kind)+".canonical_decode", time.Since(started))
	}
	return proof, err
}

func canonicalProofPhasePrefix(kind CanonicalProofKind) string {
	if kind == CanonicalProofPreSign {
		return "issuance"
	}
	if kind == CanonicalProofShowing {
		return "showing"
	}
	return "proof"
}

// unmarshalCanonicalProofWithGeometryV3 is the exact production decode path
// with trusted geometry supplied by the caller. It lets exhaustive boundary
// tests compile the relation once rather than once per truncated prefix.
func unmarshalCanonicalProofWithGeometryV3(data []byte, geometry *canonicalProofGeometryV3) (*Proof, error) {
	if geometry == nil {
		return nil, errors.New("PIOP: canonical proof: nil trusted geometry")
	}
	if len(data) > canonicalProofMaxBytes {
		return nil, fmt.Errorf("PIOP: canonical proof: input size %d exceeds codec limit", len(data))
	}
	reader, err := newCanonicalProofReaderV3(data, geometry.ctx.Kind)
	if err != nil {
		return nil, err
	}
	return unmarshalCanonicalProofBodyV3(&reader, geometry)
}

func newCanonicalProofReaderV3(data []byte, kind CanonicalProofKind) (canonicalProofReader, error) {
	reader := canonicalProofReader{data: data}
	magic, err := reader.take(len(canonicalProofMagicV6))
	if err != nil {
		return canonicalProofReader{}, err
	}
	if !bytes.Equal(magic, canonicalProofMagicV6[:]) {
		return canonicalProofReader{}, errors.New("PIOP: canonical proof: bad magic")
	}
	header, err := reader.take(2)
	if err != nil {
		return canonicalProofReader{}, err
	}
	if header[0] != canonicalProofWireVersionV6 {
		return canonicalProofReader{}, fmt.Errorf("PIOP: canonical proof: version=%d want=%d", header[0], canonicalProofWireVersionV6)
	}
	if CanonicalProofKind(header[1]) != kind {
		return canonicalProofReader{}, fmt.Errorf("PIOP: canonical proof: kind=%d does not match context kind=%d", header[1], kind)
	}
	return reader, nil
}

func unmarshalCanonicalProofBodyV3(reader *canonicalProofReader, geometry *canonicalProofGeometryV3) (*Proof, error) {
	root, err := reader.take(geometry.hashBytes)
	if err != nil {
		return nil, err
	}
	salt, err := reader.take(geometry.saltBytes)
	if err != nil {
		return nil, err
	}
	var counters [4]uint64
	for i := range counters {
		counters[i], err = reader.uvarint()
		if err != nil {
			return nil, fmt.Errorf("PIOP: canonical proof: counter %d: %w", i, err)
		}
	}
	fixedPayloadBytes, err := canonicalProofFixedPayloadBytesV3(geometry)
	if err != nil {
		return nil, err
	}
	expectedBytes := reader.off + fixedPayloadBytes
	if expectedBytes > canonicalProofMaxBytes {
		return nil, fmt.Errorf("PIOP: canonical proof: expected size %d exceeds codec limit", expectedBytes)
	}
	if len(reader.data) < expectedBytes {
		return nil, fmt.Errorf("PIOP: canonical proof: truncated input (got %d bytes, want %d)", len(reader.data), expectedBytes)
	}
	maxExpectedBytes := expectedBytes + geometry.worstAuthNodes*geometry.hashBytes
	if len(reader.data) > maxExpectedBytes {
		return nil, fmt.Errorf("PIOP: canonical proof: input exceeds exact-frontier bound by %d bytes", len(reader.data)-maxExpectedBytes)
	}
	r, err := takeCanonicalFqMatrixRadixQV5(reader, geometry.rRows, geometry.rCols, geometry.q, "R")
	if err != nil {
		return nil, err
	}
	qCompact, err := unmarshalCanonicalQPayloadV3(reader, geometry)
	if err != nil {
		return nil, err
	}
	vTargets, err := unmarshalCanonicalVTargetsV3(reader, geometry)
	if err != nil {
		return nil, err
	}
	barSets, err := takeCanonicalFqMatrixRadixQV5(reader, geometry.barRows, geometry.barCols, geometry.q, "BarSets")
	if err != nil {
		return nil, err
	}
	matrices := canonicalProofMatricesV3{r: r, qCompact: qCompact, vTargets: vTargets, barSets: barSets}
	proof, err := reconstructCanonicalProofV3(geometry, root, salt, counters, matrices)
	if err != nil {
		return nil, err
	}
	opening, err := unmarshalCanonicalOpeningV6(reader, proof.Tail, geometry)
	if err != nil {
		return nil, err
	}
	if reader.remaining() != 0 {
		return nil, fmt.Errorf("PIOP: canonical proof: trailing data (%d bytes)", reader.remaining())
	}
	proof.PCSOpening = opening
	proof.RowOpening = opening
	if err := ValidateSmallField2025Proof(proof); err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: reconstructed metadata: %w", err)
	}
	return proof, nil
}

// canonicalProofFixedPayloadBytesV3 returns the exact number of bytes after
// the four variable-width counters and before the transcript-derived Merkle
// frontier. The frontier length is exact but becomes known only after the
// fixed matrices reconstruct the Fiat--Shamir tail.
func canonicalProofFixedPayloadBytesV3(g *canonicalProofGeometryV3) (int, error) {
	if g == nil {
		return 0, errors.New("PIOP: canonical proof: nil trusted geometry")
	}
	total := 0
	addElements := func(count int) error {
		if count <= 0 || count > canonicalProofMaxElements {
			return fmt.Errorf("PIOP: canonical proof: invalid or excessive element count %d", count)
		}
		width, err := canonicalRadixQElementsByteLenV5(count, g.q)
		if err != nil {
			return err
		}
		if width < 0 || total > canonicalProofMaxBytes-width {
			return errors.New("PIOP: canonical proof: fixed payload size overflow")
		}
		total += width
		return nil
	}
	addPacked := func(rows, cols int) error {
		count, err := checkedCanonicalElementCount(rows, cols)
		if err != nil {
			return err
		}
		return addElements(count)
	}
	for _, shape := range [][2]int{
		{g.rRows, g.rCols},
		{g.barRows, g.barCols},
		{g.openingEntries, g.openingPCols},
	} {
		if err := addPacked(shape[0], shape[1]); err != nil {
			return 0, err
		}
	}
	if err := addElements(g.qRows * g.qWireCols); err != nil {
		return 0, err
	}
	if err := addElements(g.vWireElements); err != nil {
		return 0, err
	}
	for _, shape := range [][2]int{{g.openingEntries, g.tapeBytes}} {
		count, err := checkedCanonicalElementCount(shape[0], shape[1])
		if err != nil {
			return 0, err
		}
		if total > canonicalProofMaxBytes-count {
			return 0, errors.New("PIOP: canonical proof: fixed payload size overflow")
		}
		total += count
	}
	return total, nil
}

func deriveCanonicalProofGeometryV3(ctx CanonicalProofContext) (*canonicalProofGeometryV3, error) {
	if ctx.Kind != CanonicalProofPreSign && ctx.Kind != CanonicalProofShowing {
		return nil, fmt.Errorf("PIOP: canonical proof: unsupported kind %d", ctx.Kind)
	}
	opts := ctx.Options
	opts.applyDefaults()
	var err error
	opts, err = optsWithTrustedPresetID(opts, ctx.Public)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	version := normalizeTranscriptVersion(opts.TranscriptVersion)
	protocol := normalizeTranscriptProtocolMode(opts.TranscriptProtocolMode)
	if !((version == TranscriptVersionSmallWood2025V3 && protocol == TranscriptProtocolSmallField2025V3) ||
		(version == TranscriptVersionSmallWood2025V4 && protocol == TranscriptProtocolSmallField2025V4)) {
		return nil, fmt.Errorf("PIOP: canonical proof: context must select a strict v3 or publication-v4 transcript tuple")
	}
	if !opts.FixedTranscriptSize {
		return nil, errors.New("PIOP: canonical proof: v3 targets require fixed transcript size")
	}
	ctx.Options = opts
	if opts.RingDegree != 1024 || ctx.Public.RingDegree != 1024 || opts.NCols != 32 || opts.Rho != 1 || opts.EllPrime != 1 {
		return nil, fmt.Errorf("PIOP: canonical proof: context is not an N=1024, s=32, rho=ell_prime=1 target")
	}
	if opts.LVCSNCols < opts.NCols || opts.Ell <= 0 || opts.Eta <= 0 || opts.NLeaves <= opts.LVCSNCols+opts.Ell {
		return nil, errors.New("PIOP: canonical proof: invalid trusted geometry")
	}
	if _, err := ResolveFSOutputBits(opts); err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	if err := ValidateAggregateROQueryBudget(opts); err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	if err := ValidatePublicationV4Widths(opts); err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	hashBits, tapeBits := DECSHashBitsForOpts(opts), DECSTapeBitsForOpts(opts)
	if hashBits%8 != 0 || tapeBits%8 != 0 || opts.SaltBits%8 != 0 {
		return nil, errors.New("PIOP: canonical proof: byte-aligned root, tape, and salt widths are required")
	}
	hashBytes, tapeBytes, saltBytes := hashBits/8, tapeBits/8, fsSaltBytesForOpts(opts)
	if !decs.IsSupportedHashBytes(hashBytes) || !decs.IsSupportedTapeBytes(tapeBytes) || saltBytes < decs.MinSaltBytes || saltBytes > decs.MaxSaltBytes {
		return nil, errors.New("PIOP: canonical proof: configured cryptographic widths are unsupported")
	}

	pub := ctx.Public
	pub.IntGenISIS = true
	// Layout/policy descriptors are omitted from the wire and reconstructed
	// from trusted context. Bind them before validating the complete target
	// profile so fresh verifier contexts do not depend on prover-side map
	// mutations.
	pub, err = bindIntGenISISPublicExtrasWithOpts(pub, pub.RingDegree, opts)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: bind public inputs: %w", err)
	}
	if err := validateCanonicalTargetPublicBindingsV3(pub, opts, ctx.Kind); err != nil {
		return nil, err
	}
	ringQ, err := credential.LoadRingWithDegree(pub.RingDegree)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: load ring: %w", err)
	}
	if len(ringQ.Modulus) != 1 || ringQ.Modulus[0] >= 1<<canonicalFqBitWidth {
		return nil, fmt.Errorf("PIOP: canonical proof: modulus does not fit canonical 20-bit field encoding")
	}
	q := ringQ.Modulus[0]
	var layout RowLayout
	var companion *PRFCompanionLayout
	if ctx.Kind == CanonicalProofPreSign {
		layout, err = expectedIntGenISISPreSignLayoutV2(ringQ, pub, opts)
	} else {
		layout, companion, err = expectedIntGenISISShowingLayoutsV2(ringQ, pub, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: derive relation layout: %w", err)
	}
	degree, err := intGenISISDegreeMetadataForLayout(ringQ, pub, layout, opts)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: compile degree: %w", err)
	}
	dQ := degree.PaperConservativeDQ
	if dQ <= 0 || layout.SigCount <= 0 {
		return nil, fmt.Errorf("PIOP: canonical proof: compiled geometry is empty (dQ,rows)=(%d,%d)", dQ, layout.SigCount)
	}
	shape, err := deriveSmallFieldMaskShapeV3(dQ, opts.LVCSNCols, opts.Theta)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: mask geometry: %w", err)
	}
	logicalRows := layout.SigCount
	witnessLayers := ceilDiv(logicalRows, opts.LVCSNCols)
	if logicalRows <= 0 || witnessLayers <= 0 {
		return nil, errors.New("PIOP: canonical proof: empty relation layout")
	}
	replayRows := witnessLayers * (opts.NCols + opts.Theta)
	maskRows := shape.RowsPerMask
	totalRows := replayRows + maskRows
	queryCount := (witnessLayers + 1) * opts.Theta
	if queryCount <= 0 || queryCount >= totalRows {
		return nil, errors.New("PIOP: canonical proof: invalid query/opening geometry")
	}
	vRowWidths, vWireElements, err := deriveCanonicalVTargetRowWidthsV3(
		logicalRows, witnessLayers, opts.LVCSNCols, opts.Theta, shape.Nu,
	)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: VTargets wire geometry: %w", err)
	}
	if len(vRowWidths) != queryCount {
		return nil, errors.New("PIOP: canonical proof: VTargets/query geometry disagreement")
	}
	rowDegree := opts.LVCSNCols + opts.Ell - 1
	_, domainPoints, err := deriveExplicitDomainForRelation(q, opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: explicit domain: %w", err)
	}
	omegaWitness, err := deriveRelationWitnessOmega(q, opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: witness support: %w", err)
	}
	// The verifier's sum check evaluates Q on the first NCols domain points.
	// Pin that set to the relation's trusted Omega before using the same points
	// to reconstruct the omitted coefficient.
	if len(domainPoints) < len(omegaWitness) || !reflect.DeepEqual(domainPoints[:len(omegaWitness)], omegaWitness) {
		return nil, errors.New("PIOP: canonical proof: witness support is not the verifier's Q-sum domain")
	}
	field, err := deriveSmallFieldParamsNoRowsV3(ringQ, omegaWitness, opts.Theta)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: field profile: %w", err)
	}
	publicStatement, err := canonicalPublicStatementWithLayoutBytesV3(pub, layout)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: public statement: %w", err)
	}
	depth, err := canonicalMerkleDepth(opts.NLeaves)
	if err != nil {
		return nil, err
	}
	worstNodes, err := decs.MerkleFrontierWorstCaseNodesV3(opts.NLeaves, opts.Ell)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: derive Merkle frontier bound: %w", err)
	}
	geometry := &canonicalProofGeometryV3{
		ctx:             ctx,
		opts:            opts,
		pub:             pub,
		ringQ:           ringQ,
		q:               q,
		layout:          layout,
		companion:       companion,
		omegaWitness:    omegaWitness,
		domainPoints:    domainPoints,
		K:               field.K,
		omegaExtra:      field.OmegaS1,
		muInv:           field.MuInv,
		logicalRows:     logicalRows,
		witnessLayers:   witnessLayers,
		replayRows:      replayRows,
		maskRows:        maskRows,
		totalRows:       totalRows,
		queryCount:      queryCount,
		rowDegree:       rowDegree,
		dQ:              dQ,
		rRows:           opts.Eta,
		rCols:           rowDegree + 1,
		qRows:           opts.Theta,
		qCols:           dQ + 1,
		qWireCols:       dQ,
		vRows:           queryCount,
		vCols:           opts.LVCSNCols,
		vRowWidths:      vRowWidths,
		vWireElements:   vWireElements,
		barRows:         queryCount,
		barCols:         opts.Ell,
		openingEntries:  opts.Ell,
		openingPCols:    totalRows - queryCount,
		hashBytes:       hashBytes,
		tapeBytes:       tapeBytes,
		saltBytes:       saltBytes,
		merkleDepth:     depth,
		worstAuthNodes:  worstNodes,
		publicStatement: publicStatement,
	}
	for _, dims := range [][2]int{{geometry.rRows, geometry.rCols}, {geometry.qRows, geometry.qCols}, {geometry.vRows, geometry.vCols}, {geometry.barRows, geometry.barCols}, {geometry.openingEntries, geometry.openingPCols}, {geometry.worstAuthNodes, geometry.hashBytes}} {
		if _, err := checkedCanonicalElementCount(dims[0], dims[1]); err != nil {
			return nil, err
		}
	}
	if geometry.qWireCols <= 0 || geometry.vWireElements <= 0 {
		return nil, errors.New("PIOP: canonical proof: empty compressed matrix geometry")
	}
	return geometry, nil
}

// deriveCanonicalVTargetRowWidthsV3 returns the only widths omitted by the
// strict wire: the unused suffix of the final witness layer and the unused
// suffix of the Eq. (2) mask matrix. The order follows the trusted coefficient
// plan exactly: theta queries per witness layer, followed by theta mask queries.
func deriveCanonicalVTargetRowWidthsV3(logicalRows, witnessLayers, ncols, theta, maskNu int) ([]int, int, error) {
	if logicalRows <= 0 || witnessLayers <= 0 || ncols <= 0 || theta <= 1 || maskNu <= 0 || maskNu > ncols {
		return nil, 0, errors.New("invalid trusted ragged VTargets geometry")
	}
	finalWitnessWidth := logicalRows - (witnessLayers-1)*ncols
	if finalWitnessWidth <= 0 || finalWitnessWidth > ncols || logicalRows > witnessLayers*ncols {
		return nil, 0, errors.New("logical rows do not match the trusted witness-layer count")
	}
	rows := (witnessLayers + 1) * theta
	if rows <= 0 || rows > canonicalProofMaxElements {
		return nil, 0, errors.New("excessive trusted VTargets row count")
	}
	widths := make([]int, rows)
	for i := range widths {
		widths[i] = ncols
	}
	for i := (witnessLayers - 1) * theta; i < witnessLayers*theta; i++ {
		widths[i] = finalWitnessWidth
	}
	for i := witnessLayers * theta; i < rows; i++ {
		widths[i] = maskNu
	}
	elements := 0
	for _, width := range widths {
		if width <= 0 || width > ncols || elements > canonicalProofMaxElements-width {
			return nil, 0, errors.New("invalid trusted VTargets row width")
		}
		elements += width
	}
	return widths, elements, nil
}

func takeCanonicalFqMatrix20V3(reader *canonicalProofReader, rows, cols int, q uint64, name string) ([][]uint64, error) {
	count, err := checkedCanonicalElementCount(rows, cols)
	if err != nil {
		return nil, err
	}
	payload, err := reader.take(canonicalPackedByteLen(count, canonicalFqBitWidth))
	if err != nil {
		return nil, err
	}
	matrix, err := unpackCanonicalFqMatrix20(payload, rows, cols, q)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: %s: %w", name, err)
	}
	return matrix, nil
}

// canonicalQConstantFromTailV3 reconstructs q_0 from q_1,...,q_d using
// sum_{omega in Omega} Q(omega)=0. The identity holds coordinatewise in the
// public power basis of K, so each transmitted base-field row is independent.
func canonicalQConstantFromTailV3(tail, omega []uint64, q uint64) (uint64, error) {
	if len(tail) == 0 || len(omega) == 0 || q <= 2 || uint64(len(omega))%q == 0 {
		return 0, errors.New("PIOP: canonical proof: invalid Q reconstruction geometry")
	}
	for _, point := range omega {
		if point >= q {
			return 0, errors.New("PIOP: canonical proof: noncanonical witness-support point")
		}
	}
	powerSums := maskSamplerS(omega, len(tail), q)
	if len(powerSums) != len(tail)+1 || powerSums[0] == 0 {
		return 0, errors.New("PIOP: canonical proof: invalid Q power-sum plan")
	}
	var weighted uint64
	for coefficient, value := range tail {
		if value >= q {
			return 0, fmt.Errorf("PIOP: canonical proof: noncanonical Q tail coefficient %d", coefficient+1)
		}
		weighted = modAdd(weighted, modMul(value, powerSums[coefficient+1], q), q)
	}
	return modSub(0, modMul(weighted, modInv(powerSums[0], q), q), q), nil
}

func marshalCanonicalQPayloadV3(matrix [][]uint64, g *canonicalProofGeometryV3) ([]byte, error) {
	if g == nil || len(matrix) != g.qRows {
		return nil, errors.New("PIOP: canonical proof: invalid QPayload for compressed wire")
	}
	compact, err := canonicalQKernelCompactFromFullV5(matrix, g.omegaWitness, g.q)
	if err != nil {
		return nil, err
	}
	if len(compact) != g.qRows || len(compact[0]) != g.qWireCols {
		return nil, errors.New("PIOP: canonical proof: Q kernel compact geometry mismatch")
	}
	return packCanonicalFqMatrixRadixQV5(compact, g.q)
}

// unmarshalCanonicalQPayloadV3 reads every nonconstant Q coefficient. The sole
// omitted constant is fixed by the support-sum identity and is reconstructed
// before round 3 samples e.
func unmarshalCanonicalQPayloadV3(reader *canonicalProofReader, g *canonicalProofGeometryV3) ([][]uint64, error) {
	if g == nil || g.qWireCols != g.qCols-1 {
		return nil, errors.New("PIOP: canonical proof: invalid trusted QPayload wire geometry")
	}
	return takeCanonicalFqMatrixRadixQV5(reader, g.qRows, g.qWireCols, g.q, "QPayload")
}

func marshalCanonicalVTargetsV3(matrix [][]uint64, g *canonicalProofGeometryV3) ([]byte, error) {
	if g == nil || len(matrix) != g.vRows || len(g.vRowWidths) != g.vRows {
		return nil, errors.New("PIOP: canonical proof: invalid VTargets for compressed wire")
	}
	flat := make([]uint64, 0, g.vWireElements)
	for i, row := range matrix {
		if len(row) != g.vCols {
			return nil, fmt.Errorf("PIOP: canonical proof: VTargets row %d width=%d want=%d", i, len(row), g.vCols)
		}
		width := g.vRowWidths[i]
		for j := width; j < len(row); j++ {
			if row[j] != 0 {
				return nil, fmt.Errorf("PIOP: canonical proof: VTargets[%d][%d] is nonzero trusted padding", i, j)
			}
		}
		flat = append(flat, row[:width]...)
	}
	if len(flat) != g.vWireElements {
		return nil, errors.New("PIOP: canonical proof: VTargets compressed element-count mismatch")
	}
	return packCanonicalFqMatrixRadixQV5([][]uint64{flat}, g.q)
}

func unmarshalCanonicalVTargetsV3(reader *canonicalProofReader, g *canonicalProofGeometryV3) ([][]uint64, error) {
	if g == nil || len(g.vRowWidths) != g.vRows || g.vWireElements <= 0 {
		return nil, errors.New("PIOP: canonical proof: invalid trusted VTargets wire geometry")
	}
	packed, err := takeCanonicalFqMatrixRadixQV5(reader, 1, g.vWireElements, g.q, "VTargets")
	if err != nil {
		return nil, err
	}
	full := make([][]uint64, g.vRows)
	offset := 0
	for i, width := range g.vRowWidths {
		if width <= 0 || width > g.vCols || offset > len(packed[0])-width {
			return nil, errors.New("PIOP: canonical proof: invalid trusted VTargets row width")
		}
		full[i] = make([]uint64, g.vCols)
		copy(full[i], packed[0][offset:offset+width])
		offset += width
	}
	if offset != len(packed[0]) {
		return nil, errors.New("PIOP: canonical proof: VTargets trailing field elements")
	}
	return full, nil
}

func validateCanonicalTargetPublicBindingsV3(pub PublicInputs, opts SimOpts, kind CanonicalProofKind) error {
	opts, err := optsWithTrustedPresetID(opts, pub)
	if err != nil {
		return fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	preset, err := targetPresetForPRFOptsV3(opts)
	if err != nil {
		return fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	if err := credential.ValidateIntGenISISPresetManifest(preset); err != nil {
		return fmt.Errorf("PIOP: canonical proof: invalid target preset manifest: %w", err)
	}
	tuning := preset.Showing
	if kind == CanonicalProofPreSign {
		tuning = preset.Issuance
	}
	if opts.NCols != tuning.NCols || opts.LVCSNCols != tuning.LVCSNCols || opts.NLeaves != tuning.NLeaves ||
		opts.Eta != tuning.Eta || opts.Theta != tuning.Theta || opts.Rho != tuning.Rho || opts.Ell != tuning.Ell ||
		opts.EllPrime != tuning.EllPrime || opts.Kappa != tuning.Kappa || opts.DECSCollisionBits != tuning.DECSCollisionBits ||
		opts.DECSHashBits != tuning.DECSHashBits || opts.DECSTapeBits != tuning.DECSTapeBits ||
		opts.FSCollisionBits != tuning.FSCollisionBits || opts.FSOutputBits != tuning.FSOutputBits || opts.SaltBits != tuning.SaltBits ||
		opts.ROQueryCapsSet != tuning.ROQueryCapsSet || opts.ROQueryCapBitsSet != tuning.ROQueryCapBitsSet ||
		opts.AggregateROQueryCapLog2Set != tuning.AggregateROQueryCapLog2Set ||
		(opts.ROQueryCapsSet && opts.ROQueryCaps != tuning.ROQueryCaps) ||
		(opts.ROQueryCapBitsSet && opts.ROQueryCapBits != tuning.ROQueryCapBits) ||
		(opts.AggregateROQueryCapLog2Set && opts.AggregateROQueryCapLog2 != tuning.AggregateROQueryCapLog2) ||
		opts.TranscriptOmissionMode != tuning.TranscriptOmissionMode || opts.FixedTranscriptSize != tuning.FixedTranscriptSize ||
		opts.DQOverride != 0 {
		return fmt.Errorf("PIOP: canonical proof: verifier options do not match the manifest-bound %s tuning", map[CanonicalProofKind]string{CanonicalProofPreSign: "issuance", CanonicalProofShowing: "showing"}[kind])
	}
	_, canonicalPRF, err := loadTargetPRFParamsForPresetV3(preset, opts)
	if err != nil {
		return fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	semanticLayout, err := intGenISISSemanticLayout(pub.RingDegree, pub.BoundB)
	if err != nil {
		return fmt.Errorf("PIOP: canonical proof: derive semantic layout: %w", err)
	}
	profile, ok := kf.LookupSmallWoodFieldProfileV3(credential.IntGenISISSharedModulusQ, opts.Theta)
	if !ok {
		return fmt.Errorf("PIOP: canonical proof: missing theta=%d public field profile", opts.Theta)
	}
	profileDigest, err := profile.DigestHex(32)
	if err != nil {
		return fmt.Errorf("PIOP: canonical proof: digest public field profile: %w", err)
	}
	want := map[string][]byte{
		"IntGenISIS.preset_id":                        []byte(preset.CanonicalID),
		"IntGenISIS.preset_version":                   []byte(fmt.Sprintf("%d", preset.PresetVersion)),
		"IntGenISIS.proof_schema_version":             []byte(fmt.Sprintf("%d", preset.ProofSchemaVersion)),
		"IntGenISIS.relation_version":                 []byte(fmt.Sprintf("%d", preset.RelationVersion)),
		"IntGenISIS.layout_version":                   []byte(fmt.Sprintf("%d", preset.LayoutVersion)),
		"IntGenISIS.state_format_version":             []byte(fmt.Sprintf("%d", preset.StateFormatVersion)),
		"IntGenISIS.presentation_format_version":      []byte(fmt.Sprintf("%d", preset.PresentationVersion)),
		"IntGenISIS.issuance_artifact_format_version": []byte(fmt.Sprintf("%d", preset.IssuanceVersion)),
		"IntGenISIS.holder_usage_format_version":      []byte(fmt.Sprintf("%d", preset.HolderUsageVersion)),
		"IntGenISIS.primitive_profile_id":             []byte(preset.PrimitiveProfileID),
		"IntGenISIS.prf_profile":                      []byte(preset.PRFProfile),
		"IntGenISIS.prf_params":                       canonicalPRF,
		"IntGenISIS.semantic_message_layout":          semanticLayout.CanonicalBytesV3(),
		"IntGenISIS.transcript_mode":                  []byte(preset.Showing.TranscriptMode),
		"IntGenISIS.transcript_version":               []byte(opts.TranscriptVersion),
		"IntGenISIS.preset_manifest_digest":           []byte(credential.IntGenISISPresetManifestDigest(preset)),
		"IntGenISIS.preset_manifest":                  credential.IntGenISISPresetManifestCanonicalBytes(preset),
		"IntGenISIS.field_profile_id":                 []byte(profile.ID),
		"IntGenISIS.field_profile_digest":             []byte(profileDigest),
		"IntGenISIS.field_profile":                    profile.CanonicalBytes(),
	}
	for key, expected := range want {
		value, ok := pub.Extras[key].([]byte)
		if !ok || !bytes.Equal(value, expected) {
			return fmt.Errorf("PIOP: canonical proof: public binding %q does not match target manifest", key)
		}
	}
	return nil
}

func reconstructCanonicalProofV3(g *canonicalProofGeometryV3, root, salt []byte, counters [4]uint64, matrices canonicalProofMatricesV3) (*Proof, error) {
	return constructCanonicalProofV3(g, root, salt, &counters, matrices)
}

// grindCanonicalProofV3 is used by prover-side integration and focused codec
// tests to obtain the first accepted counter in each unchanged-kappa round.
// It is deliberately not used by decoding: a decoder authenticates the four
// counters supplied by the wire and never performs hidden extra grinding.
func grindCanonicalProofV3(g *canonicalProofGeometryV3, root, salt []byte, matrices canonicalProofMatricesV3) (*Proof, error) {
	return constructCanonicalProofV3(g, root, salt, nil, matrices)
}

func constructCanonicalProofV3(g *canonicalProofGeometryV3, root, salt []byte, counters *[4]uint64, matrices canonicalProofMatricesV3) (*Proof, error) {
	if g == nil {
		return nil, errors.New("PIOP: canonical proof: nil geometry")
	}
	if len(root) != g.hashBytes || len(salt) != g.saltBytes {
		return nil, errors.New("PIOP: canonical proof: root or salt width mismatch")
	}
	if err := validateCanonicalProofMatricesV3(g, matrices); err != nil {
		return nil, err
	}
	proofFSOutputBits := 0
	if transcriptUsesPublicationV4(g.opts.TranscriptVersion) {
		proofFSOutputBits = g.opts.FSOutputBits
	}
	proof := &Proof{
		SchemaVersion:          ProofSchemaVersionV3,
		RootHash:               append([]byte(nil), root...),
		RingDegree:             g.pub.RingDegree,
		HashRelation:           g.pub.HashRelation,
		TranscriptVersion:      g.opts.TranscriptVersion,
		TranscriptProtocolMode: g.opts.TranscriptProtocolMode,
		FSOutputBits:           proofFSOutputBits,
		FixedTranscriptSize:    true,
		Salt:                   append([]byte(nil), salt...),
		Lambda:                 g.opts.Lambda,
		Kappa:                  g.opts.Kappa,
		Theta:                  g.opts.Theta,
		R:                      copyMatrix(matrices.r),
		QDegreeBound:           g.dQ,
		RowLayout:              g.layout,
		MaskRowOffset:          g.replayRows,
		MaskRowCount:           g.maskRows,
		RowDegreeBound:         g.rowDegree,
		MaskDegreeBound:        g.dQ,
		NColsUsed:              g.opts.NCols,
		PCSNColsUsed:           g.opts.LVCSNCols,
		LVCSNColsUsed:          g.opts.LVCSNCols,
		DomainMode:             DomainModeExplicit,
		NLeavesUsed:            g.opts.NLeaves,
		PCSGeometry: PCSGeometry{
			Kind:                PCSGeometryKindSmallFieldMatrixV2,
			SmallFieldSource:    PCSGeometrySmallFieldSourceLiteralRowsV2,
			WitnessPackingCols:  g.opts.NCols,
			PCSNCols:            g.opts.LVCSNCols,
			Theta:               g.opts.Theta,
			Ell:                 g.opts.Ell,
			BlockCount:          g.witnessLayers,
			LogicalWitnessPolys: g.logicalRows,
			WitnessRows:         g.replayRows,
			ReplayWitnessRows:   g.replayRows,
			MaskRows:            g.maskRows,
		},
	}
	if counters != nil {
		proof.Ctr = *counters
		proof.RoundCounters = *counters
	}
	proof.PCSGeometry.OracleLayout.Witness.Offset = 0
	proof.PCSGeometry.OracleLayout.Witness.Count = g.replayRows
	proof.PCSGeometry.OracleLayout.Mask.Offset = g.replayRows
	proof.PCSGeometry.OracleLayout.Mask.Count = g.maskRows
	setCanonicalProofVTargets20(proof, matrices.vTargets)
	setCanonicalProofBarSets20(proof, matrices.barSets)

	var (
		qCompact [][]uint64
		err      error
	)
	if len(matrices.qPayload) > 0 {
		qCompact, err = canonicalQKernelCompactFromFullV5(matrices.qPayload, g.omegaWitness, g.q)
		if err != nil {
			return nil, fmt.Errorf("PIOP: canonical proof: compact QPayload: %w", err)
		}
	}
	if len(matrices.qCompact) > 0 {
		if len(qCompact) > 0 && !reflect.DeepEqual(qCompact, matrices.qCompact) {
			return nil, errors.New("PIOP: canonical proof: full and compact QPayload representations disagree")
		}
		qCompact = copyMatrix(matrices.qCompact)
	}
	if len(qCompact) != g.qRows || len(qCompact[0]) != g.qWireCols {
		return nil, errors.New("PIOP: canonical proof: missing or malformed compact QPayload")
	}
	// Restore the only omitted coordinate before h3 is derived.  This is a
	// deterministic function of the already-transmitted tail and Omega; it has
	// no access to the later evaluation challenge or Eq. (4) target.
	reconstructedQ, err := canonicalQKernelReconstructV5(qCompact, g.omegaWitness, g.dQ, g.q)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: reconstruct QPayload: %w", err)
	}
	if len(matrices.qPayload) > 0 && !reflect.DeepEqual(reconstructedQ, matrices.qPayload) {
		return nil, errors.New("PIOP: canonical proof: QPayload violates the pre-challenge support identity")
	}
	setCanonicalProofQPayload20(proof, reconstructedQ)

	fs, err := newFSForProof(proof)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: Fiat-Shamir policy: %w", err)
	}
	h1, err := deriveCanonicalProofRoundV3(fs, proof, 0, counters, [][]byte{proof.RootHash, g.publicStatement})
	if err != nil {
		return nil, err
	}
	proof.Gamma = sampleFSMatrix(g.opts.Eta, g.totalRows, g.q, newFSRNGForTranscript(proof.TranscriptVersion, "Gamma", h1))
	profileBytes, err := smallFieldProfileTranscriptBytesV3(g.q, g.opts.Theta)
	if err != nil {
		return nil, err
	}
	h2, err := deriveCanonicalProofRoundV3(fs, proof, 1, counters, [][]byte{bytesFromUint64Matrix(proof.R), profileBytes})
	if err != nil {
		return nil, err
	}
	fparCount, faggCount, err := canonicalConstraintFamilyCountsV3(g)
	if err != nil {
		return nil, err
	}
	proof.GammaPrimeK = sampleFSPolyTensorK(1, fparCount, g.opts.NCols, g.opts.Theta, g.q, newFSRNGForTranscript(proof.TranscriptVersion, "GammaPrime", h2))
	proof.GammaAggK = sampleFSVectorK(1, faggCount, g.opts.Theta, g.q, newFSRNGForTranscript(proof.TranscriptVersion, "GammaPrimeAgg", h2, []byte{1}))
	qTranscript, err := canonicalQKernelTranscriptBytesV6(qCompact, g.omegaWitness, g.q)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: frame compact QPayload: %w", err)
	}
	h3, err := deriveCanonicalProofRoundV3(fs, proof, 2, counters, [][]byte{qTranscript})
	if err != nil {
		return nil, err
	}
	kPointLimbs, kPoints, err := sampleSmallFieldKPoints(g.K, g.omegaWitness, 1, newFSRNGForTranscript(proof.TranscriptVersion, "EvalKPoint", h3))
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: derive K point: %w", err)
	}
	rows := make([][]uint64, g.totalRows)
	for i := range rows {
		rows[i] = make([]uint64, g.opts.LVCSNCols)
	}
	plan, err := buildSmallField2025CoeffPlanV3(
		g.ringQ, g.K, g.omegaWitness, rows, kPoints[0], g.omegaExtra, g.muInv,
		g.replayRows, g.replayRows, g.maskRows, g.dQ,
	)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: derive coefficient plan: %w", err)
	}
	if plan.QueryCount != g.queryCount || plan.WitnessLayers != g.witnessLayers {
		return nil, errors.New("PIOP: canonical proof: compiler/query geometry disagreement")
	}
	proof.KPoint = kPointLimbs
	proof.CoeffMatrix = plan.C
	if err := attachSmallField2025Proof(proof, plan, g.opts.Eta, g.opts.TranscriptOmissionMode); err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: rebuild small-field metadata: %w", err)
	}
	transcript4 := smallField2025Round4DirectPayloads(proof)
	transcript4 = append(transcript4, smallField2025TranscriptBytes(proof.SmallField2025))
	proof.TailTranscript = flattenBytes(transcript4)
	h4, err := deriveCanonicalProofRoundV3(fs, proof, 3, counters, transcript4)
	if err != nil {
		return nil, err
	}
	tailStart := g.opts.LVCSNCols + g.opts.Ell
	tailLen := len(g.domainPoints) - tailStart
	if tailLen < g.opts.Ell {
		return nil, errors.New("PIOP: canonical proof: insufficient tail domain")
	}
	proof.Tail = sampleDistinctIndices(tailStart, tailLen, g.opts.Ell, newFSRNGForTranscript(proof.TranscriptVersion, "TailPoints", h4))
	return proof, nil
}

func deriveCanonicalProofRoundV3(fs *FS, proof *Proof, round int, counters *[4]uint64, material [][]byte) ([]byte, error) {
	if counters != nil {
		return setCanonicalProofRoundV3(fs, proof, round, (*counters)[round], material)
	}
	digest, counter, _ := fs.GrindAndDerive(round, material, func(input []byte) []byte { return input })
	proof.Ctr[round] = counter
	proof.RoundCounters[round] = counter
	proof.Digests[round] = append([]byte(nil), digest...)
	return digest, nil
}

func canonicalConstraintFamilyCountsV3(g *canonicalProofGeometryV3) (int, int, error) {
	if g == nil || g.K == nil {
		return 0, 0, errors.New("PIOP: canonical proof: missing relation compiler context")
	}
	relation, err := canonicalConstraintRelationV3(g)
	if err != nil {
		return 0, 0, err
	}
	rowVals := make([]kf.Elem, g.logicalRows)
	for i := range rowVals {
		rowVals[i] = g.K.Zero()
	}
	if relation.EvalParallel != nil {
		fpar, err := relation.EvalParallel(g.K.Zero(), rowVals)
		if err != nil {
			return 0, 0, fmt.Errorf("PIOP: canonical proof: evaluate parallel relation shape: %w", err)
		}
		if relation.AggregateDot == nil || relation.AggregateCount <= 0 {
			return 0, 0, errors.New("PIOP: canonical proof: incomplete direct aggregate relation shape")
		}
		return len(fpar), relation.AggregateCount, nil
	}
	fpar, fagg, err := relation.Eval(g.K.Zero(), rowVals)
	if err != nil {
		return 0, 0, fmt.Errorf("PIOP: canonical proof: evaluate relation shape: %w", err)
	}
	return len(fpar), len(fagg), nil
}

func canonicalConstraintEvaluatorV3(g *canonicalProofGeometryV3) (KConstraintEvaluator, error) {
	relation, err := canonicalConstraintRelationV3(g)
	if err != nil {
		return nil, err
	}
	return relation.Eval, nil
}

func canonicalConstraintRelationV3(g *canonicalProofGeometryV3) (semanticKRelationV3, error) {
	if g == nil || g.K == nil {
		return semanticKRelationV3{}, errors.New("PIOP: canonical proof: missing relation compiler context")
	}
	var relation semanticKRelationV3
	if g.ctx.Kind == CanonicalProofPreSign {
		cfg, err := newIntGenISISPreSignReplayConfig(g.ringQ, g.pub, g.layout, g.omegaWitness, g.domainPoints)
		if err != nil {
			return semanticKRelationV3{}, fmt.Errorf("PIOP: canonical proof: pre-sign evaluator: %w", err)
		}
		relation, err = cfg.SemanticKRelationV3(g.K)
		if err != nil {
			return semanticKRelationV3{}, err
		}
	} else {
		cfg, err := newIntGenISISShowingReplayConfig(g.ringQ, g.pub, g.layout, g.omegaWitness, g.domainPoints, g.companion)
		if err != nil {
			return semanticKRelationV3{}, fmt.Errorf("PIOP: canonical proof: showing evaluator: %w", err)
		}
		relation.Eval, err = cfg.CoreKEvaluator(g.K)
		if err != nil {
			return semanticKRelationV3{}, err
		}
	}
	return relation, nil
}

func setCanonicalProofRoundV3(fs *FS, proof *Proof, round int, counter uint64, material [][]byte) ([]byte, error) {
	if fs == nil || proof == nil || round < 0 || round >= 4 {
		return nil, errors.New("PIOP: canonical proof: invalid Fiat-Shamir round")
	}
	digest := fs.expandRoundV3At(round, material, counter)
	if !hasZeroPrefix(digest, proof.Kappa[round]) {
		return nil, fmt.Errorf("PIOP: canonical proof: grinding predicate failed in round %d", round)
	}
	fs.h[round] = append([]byte(nil), digest...)
	fs.ctr[round] = counter
	proof.Digests[round] = append([]byte(nil), digest...)
	return digest, nil
}

func validateCanonicalProofMatricesV3(g *canonicalProofGeometryV3, m canonicalProofMatricesV3) error {
	checks := []struct {
		name       string
		matrix     [][]uint64
		rows, cols int
	}{
		{"R", m.r, g.rRows, g.rCols},
		{"VTargets", m.vTargets, g.vRows, g.vCols},
		{"BarSets", m.barSets, g.barRows, g.barCols},
	}
	for _, check := range checks {
		if len(check.matrix) != check.rows {
			return fmt.Errorf("PIOP: canonical proof: %s rows=%d want=%d", check.name, len(check.matrix), check.rows)
		}
		for i, row := range check.matrix {
			if len(row) != check.cols {
				return fmt.Errorf("PIOP: canonical proof: %s row %d width=%d want=%d", check.name, i, len(row), check.cols)
			}
			for j, value := range row {
				if value >= g.q {
					return fmt.Errorf("PIOP: canonical proof: %s[%d][%d]=%d is noncanonical", check.name, i, j, value)
				}
			}
		}
	}
	if len(m.qPayload) == 0 && len(m.qCompact) == 0 {
		return errors.New("PIOP: canonical proof: missing QPayload representation")
	}
	qChecks := []struct {
		name       string
		matrix     [][]uint64
		rows, cols int
	}{
		{"QPayload", m.qPayload, g.qRows, g.qCols},
		{"QCompact", m.qCompact, g.qRows, g.qWireCols},
	}
	for _, check := range qChecks {
		if len(check.matrix) == 0 {
			continue
		}
		if len(check.matrix) != check.rows {
			return fmt.Errorf("PIOP: canonical proof: %s rows=%d want=%d", check.name, len(check.matrix), check.rows)
		}
		for i, row := range check.matrix {
			if len(row) != check.cols {
				return fmt.Errorf("PIOP: canonical proof: %s row %d width=%d want=%d", check.name, i, len(row), check.cols)
			}
			for j, value := range row {
				if value >= g.q {
					return fmt.Errorf("PIOP: canonical proof: %s[%d][%d]=%d is noncanonical", check.name, i, j, value)
				}
			}
		}
	}
	return nil
}

func rejectCanonicalProofForbiddenV3(proof *Proof) error {
	version := normalizeTranscriptVersion(proof.TranscriptVersion)
	protocol := normalizeTranscriptProtocolMode(proof.TranscriptProtocolMode)
	if proof.SchemaVersion != ProofSchemaVersionV3 ||
		!((version == TranscriptVersionSmallWood2025V3 && protocol == TranscriptProtocolSmallField2025V3) ||
			(version == TranscriptVersionSmallWood2025V4 && protocol == TranscriptProtocolSmallField2025V4)) {
		return errors.New("PIOP: canonical proof: only strict schema v3/v4 transcripts are accepted")
	}
	if err := validateProofFSDigestWidths(proof); err != nil {
		return fmt.Errorf("PIOP: canonical proof: %w", err)
	}
	if proof.Root != [16]byte{} || proof.QRoot != [16]byte{} || len(proof.QRootHash) != 0 || proof.QOpening != nil ||
		len(proof.QR) != 0 || len(proof.QRBits) != 0 || proof.QRRows != 0 || proof.QRCols != 0 || proof.QRBitWidth != 0 {
		return errors.New("PIOP: canonical proof: retired root/Q commitment material is forbidden")
	}
	if len(proof.LabelsDigest) != 0 || len(proof.Chi) != 0 || len(proof.Zeta) != 0 {
		return errors.New("PIOP: canonical proof: labels digest and public field-profile payloads are forbidden")
	}
	if len(proof.MaskCoeffDebug) != 0 || len(proof.FparCoeffDebug) != 0 || len(proof.FaggCoeffDebug) != 0 || len(proof.QCoeffDebug) != 0 || len(proof.MKData) != 0 || len(proof.QKData) != 0 {
		return errors.New("PIOP: canonical proof: verifier-debug coefficient material is forbidden")
	}
	if len(proof.GammaPrime) != 0 {
		return errors.New("PIOP: canonical proof: retired base-field GammaPrime challenge is forbidden")
	}
	if len(proof.GammaAgg) != 0 {
		return errors.New("PIOP: canonical proof: retired base-field GammaAgg challenge is forbidden")
	}
	if len(proof.GammaK) != 0 {
		return errors.New("PIOP: canonical proof: retired GammaK challenge is forbidden")
	}
	if proof.PRFLayout != nil || proof.PRFCompanion != nil || proof.SourceProductBridge != nil {
		return errors.New("PIOP: canonical proof: retired PRF/source bridge metadata is forbidden")
	}
	if len(proof.EvalPoints) != 0 || len(proof.PvalsEvalBits) != 0 || len(proof.MvalsEvalBits) != 0 || len(proof.MaskEvalBits) != 0 ||
		proof.PvalsEvalRows != 0 || proof.PvalsEvalCols != 0 || proof.MvalsEvalRows != 0 || proof.MvalsEvalCols != 0 ||
		proof.MaskEvalRows != 0 || proof.MaskEvalCols != 0 {
		return errors.New("PIOP: canonical proof: retired evaluation/debug payload is forbidden")
	}
	if proof.SigShortness != nil {
		return errors.New("PIOP: canonical proof: independently serialized shortness metadata is not part of the v3 target wire")
	}
	return nil
}

func validateCanonicalProofEnvelopeV3(got, want *Proof, g *canonicalProofGeometryV3) error {
	if got == nil || want == nil {
		return errors.New("PIOP: canonical proof: nil envelope")
	}
	gotFSBits, wantFSBits := got.FSOutputBits, want.FSOutputBits
	if !transcriptUsesPublicationV4(got.TranscriptVersion) && gotFSBits == 0 {
		gotFSBits = fsDigestBytes * 8
	}
	if !transcriptUsesPublicationV4(want.TranscriptVersion) && wantFSBits == 0 {
		wantFSBits = fsDigestBytes * 8
	}
	if got.SchemaVersion != want.SchemaVersion || got.TranscriptVersion != want.TranscriptVersion || got.TranscriptProtocolMode != want.TranscriptProtocolMode || gotFSBits != wantFSBits ||
		got.RingDegree != want.RingDegree || got.HashRelation != want.HashRelation || got.FixedTranscriptSize != want.FixedTranscriptSize ||
		got.Lambda != want.Lambda || got.Kappa != want.Kappa || got.Theta != want.Theta || got.Ctr != want.Ctr || got.RoundCounters != want.RoundCounters ||
		got.NColsUsed != want.NColsUsed || got.PCSNColsUsed != want.PCSNColsUsed || got.LVCSNColsUsed != want.LVCSNColsUsed || got.NLeavesUsed != want.NLeavesUsed ||
		got.DomainMode != want.DomainMode || got.RowDegreeBound != want.RowDegreeBound || got.MaskDegreeBound != want.MaskDegreeBound || got.QDegreeBound != want.QDegreeBound ||
		got.MaskRowOffset != want.MaskRowOffset || got.MaskRowCount != want.MaskRowCount {
		return errors.New("PIOP: canonical proof: envelope metadata does not match trusted context")
	}
	if !bytes.Equal(proofRootBytes(got), want.RootHash) || !bytes.Equal(got.Salt, want.Salt) || !reflect.DeepEqual(got.RowLayout, want.RowLayout) || !reflect.DeepEqual(got.PCSGeometry, want.PCSGeometry) {
		return errors.New("PIOP: canonical proof: root, salt, relation layout, or PCS geometry mismatch")
	}
	for i := range got.Digests {
		if !bytes.Equal(got.Digests[i], want.Digests[i]) {
			return fmt.Errorf("PIOP: canonical proof: Fiat-Shamir digest %d is not context-derived", i)
		}
	}
	if !reflect.DeepEqual(got.Tail, want.Tail) || !reflect.DeepEqual(got.KPoint, want.KPoint) || !reflect.DeepEqual(got.CoeffMatrix, want.CoeffMatrix) {
		return errors.New("PIOP: canonical proof: challenge metadata is not canonical")
	}
	if len(got.Gamma) > 0 && !reflect.DeepEqual(got.Gamma, want.Gamma) {
		return errors.New("PIOP: canonical proof: reconstructed row-compression challenge mismatch")
	}
	if got.SmallField2025 == nil || !reflect.DeepEqual(got.SmallField2025, want.SmallField2025) {
		return errors.New("PIOP: canonical proof: SmallField metadata is not canonical")
	}
	if len(got.TailTranscript) > 0 && !bytes.Equal(got.TailTranscript, want.TailTranscript) {
		return errors.New("PIOP: canonical proof: tail transcript mismatch")
	}
	if !reflect.DeepEqual(got.GammaPrimeK, want.GammaPrimeK) || !reflect.DeepEqual(got.GammaAggK, want.GammaAggK) {
		return errors.New("PIOP: canonical proof: reconstructed constraint challenges mismatch")
	}
	if len(got.RootHash) != g.hashBytes || len(got.Salt) != g.saltBytes {
		return errors.New("PIOP: canonical proof: configured-width binding mismatch")
	}
	if got.PCSOpening == nil || got.RowOpening == nil || !reflect.DeepEqual(got.PCSOpening, got.RowOpening) {
		return errors.New("PIOP: canonical proof: authoritative opening aliases disagree")
	}
	return nil
}

func marshalCanonicalOpeningV6(open *decs.DECSOpening, tail []int, g *canonicalProofGeometryV3) ([]byte, error) {
	if open == nil {
		return nil, errors.New("PIOP: canonical proof: missing authoritative DECS opening")
	}
	if open.Version != decs.OpeningVersionV2 || open.Role != decs.CommitmentRoleMain || open.R != g.totalRows || open.Eta != g.opts.Eta || open.TapeBytes != g.tapeBytes {
		return nil, errors.New("PIOP: canonical proof: DECS opening header does not match trusted geometry")
	}
	if open.MaskCount != 0 || open.EntryCount() != g.openingEntries || !equalIntSlices(open.AllIndices(), tail) {
		return nil, errors.New("PIOP: canonical proof: DECS indices are not the Fiat-Shamir tail")
	}
	if open.FormatVersion != decs.OpeningFormatOmitCols && open.FormatVersion != decs.OpeningFormatColumnWidths {
		return nil, errors.New("PIOP: canonical proof: DECS P opening is not omission-compressed")
	}
	if open.PColsEncoded != g.openingPCols || len(open.POmitCols) != 0 || len(open.PvalsColumnWidths) != 0 {
		return nil, errors.New("PIOP: canonical proof: DECS P omission plan is noncanonical")
	}
	if open.MFormatVersion != decs.OpeningFormatOmitCols && open.MFormatVersion != decs.OpeningFormatColumnWidths {
		return nil, errors.New("PIOP: canonical proof: DECS M opening is not omission-compressed")
	}
	if open.MColsEncoded != 0 || len(open.Mvals) != 0 || len(open.MvalsBits) != 0 || len(open.MvalsColumnWidths) != 0 {
		return nil, errors.New("PIOP: canonical proof: DECS M values must be reconstructed")
	}
	if len(open.Tapes) != g.openingEntries {
		return nil, errors.New("PIOP: canonical proof: DECS tape count mismatch")
	}
	pvals := make([][]uint64, g.openingEntries)
	for i := range pvals {
		pvals[i] = make([]uint64, g.openingPCols)
		for j := range pvals[i] {
			pvals[i][j] = decs.GetOpeningPval(open, i, j)
			if pvals[i][j] >= g.q {
				return nil, fmt.Errorf("PIOP: canonical proof: noncanonical DECS P value at (%d,%d)", i, j)
			}
		}
	}
	packedP, err := packCanonicalFqMatrixRadixQV5(pvals, g.q)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(packedP)+g.openingEntries*g.tapeBytes+g.worstAuthNodes*g.hashBytes)
	out = append(out, packedP...)
	for i, tape := range open.Tapes {
		if len(tape) != g.tapeBytes {
			return nil, fmt.Errorf("PIOP: canonical proof: tape %d width=%d want=%d", i, len(tape), g.tapeBytes)
		}
		out = append(out, tape...)
	}
	nodes, err := canonicalOpeningPositionNodes(open, tail, g)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		out = append(out, node...)
	}
	if len(nodes) > g.worstAuthNodes {
		return nil, errors.New("PIOP: canonical proof: authentication multiproof exceeds public bound")
	}
	return out, nil
}

func unmarshalCanonicalOpeningV6(reader *canonicalProofReader, tail []int, g *canonicalProofGeometryV3) (*decs.DECSOpening, error) {
	if reader == nil {
		return nil, errors.New("PIOP: canonical proof: nil opening reader")
	}
	pCount, err := checkedCanonicalElementCount(g.openingEntries, g.openingPCols)
	if err != nil {
		return nil, err
	}
	pBytes, err := canonicalRadixQElementsByteLenV5(pCount, g.q)
	if err != nil {
		return nil, err
	}
	pPayload, err := reader.take(pBytes)
	if err != nil {
		return nil, err
	}
	pvals, err := unpackCanonicalFqMatrixRadixQV5(pPayload, g.openingEntries, g.openingPCols, g.q)
	if err != nil {
		return nil, fmt.Errorf("PIOP: canonical proof: DECS P values: %w", err)
	}
	tapePayload, err := reader.take(g.openingEntries * g.tapeBytes)
	if err != nil {
		return nil, err
	}
	keys := canonicalOpeningPositionKeys(tail, g.opts.NLeaves)
	if len(keys) > g.worstAuthNodes {
		return nil, errors.New("PIOP: canonical proof: authentication position count exceeds public bound")
	}
	authPayload, err := reader.take(len(keys) * g.hashBytes)
	if err != nil {
		return nil, err
	}
	opening := &decs.DECSOpening{
		Version:        decs.OpeningVersionV2,
		Role:           decs.CommitmentRoleMain,
		TapeBytes:      g.tapeBytes,
		FormatVersion:  decs.OpeningFormatOmitCols,
		PColsEncoded:   g.openingPCols,
		MFormatVersion: decs.OpeningFormatOmitCols,
		MColsEncoded:   0,
		Indices:        append([]int(nil), tail...),
		R:              g.totalRows,
		Eta:            g.opts.Eta,
		PvalsBitWidth:  canonicalFqBitWidth,
		AuthFormat:     decs.OpeningAuthPositionalFrontierV3,
	}
	opening.PvalsBits, err = packCanonicalFqMatrix20(pvals, g.q)
	if err != nil {
		return nil, err
	}
	opening.Tapes = make([][]byte, g.openingEntries)
	for i := range opening.Tapes {
		start := i * g.tapeBytes
		opening.Tapes[i] = append([]byte(nil), tapePayload[start:start+g.tapeBytes]...)
	}
	opening.Nodes = make([][]byte, len(keys))
	for i := range keys {
		start := i * g.hashBytes
		opening.Nodes[i] = append([]byte(nil), authPayload[start:start+g.hashBytes]...)
	}
	return opening, nil
}

type canonicalAuthPosition struct {
	start int
	end   int
}

func canonicalOpeningPositionKeys(tail []int, nLeaves int) []canonicalAuthPosition {
	if nLeaves <= 0 {
		return nil
	}
	positions, err := decs.MerkleFrontierPositionsV3(tail, nLeaves)
	if err != nil {
		return nil
	}
	keys := make([]canonicalAuthPosition, len(positions))
	for i, position := range positions {
		keys[i] = canonicalAuthPosition{start: position.Start, end: position.End}
	}
	return keys
}

func canonicalOpeningPositionNodes(open *decs.DECSOpening, tail []int, g *canonicalProofGeometryV3) ([][]byte, error) {
	keys := canonicalOpeningPositionKeys(tail, g.opts.NLeaves)
	if len(keys) == 0 {
		return nil, errors.New("PIOP: canonical proof: empty or invalid authentication frontier")
	}
	if open.AuthFormat == decs.OpeningAuthPositionalFrontierV3 {
		if len(open.PathIndex) != 0 || len(open.PathBits) != 0 || open.PathDepth != 0 || open.PathBitWidth != 0 {
			return nil, errors.New("PIOP: canonical proof: positional frontier carries legacy path metadata")
		}
		if len(open.Nodes) != len(keys) {
			return nil, fmt.Errorf("PIOP: canonical proof: authentication frontier nodes=%d want=%d", len(open.Nodes), len(keys))
		}
		nodes := make([][]byte, len(keys))
		for i, node := range open.Nodes {
			if len(node) != g.hashBytes {
				return nil, fmt.Errorf("PIOP: canonical proof: authentication node width=%d want=%d", len(node), g.hashBytes)
			}
			nodes[i] = append([]byte(nil), node...)
		}
		return nodes, nil
	}
	if open.AuthFormat != decs.OpeningAuthPaths {
		return nil, fmt.Errorf("PIOP: canonical proof: unsupported authentication encoding %d", open.AuthFormat)
	}
	required := make(map[canonicalAuthPosition]struct{}, len(keys))
	for _, key := range keys {
		required[key] = struct{}{}
	}
	values := make(map[canonicalAuthPosition][]byte, len(keys))
	for row, index := range tail {
		path, err := extractPathNodes(open, row)
		if err != nil {
			return nil, fmt.Errorf("PIOP: canonical proof: authentication path %d: %w", row, err)
		}
		pathPositions, err := decs.MerkleAuthenticationPathPositionsV3(index, g.opts.NLeaves)
		if err != nil {
			return nil, fmt.Errorf("PIOP: canonical proof: authentication path %d positions: %w", row, err)
		}
		if len(path) != len(pathPositions) {
			return nil, fmt.Errorf("PIOP: canonical proof: authentication depth=%d want=%d", len(path), len(pathPositions))
		}
		for level, node := range path {
			if len(node) != g.hashBytes {
				return nil, fmt.Errorf("PIOP: canonical proof: authentication node width=%d want=%d", len(node), g.hashBytes)
			}
			position := pathPositions[level]
			key := canonicalAuthPosition{start: position.Start, end: position.End}
			if _, needed := required[key]; !needed {
				continue
			}
			if previous, ok := values[key]; ok && !bytes.Equal(previous, node) {
				return nil, errors.New("PIOP: canonical proof: conflicting duplicate authentication position")
			}
			values[key] = append([]byte(nil), node...)
		}
	}
	nodes := make([][]byte, len(keys))
	for i, key := range keys {
		node, ok := values[key]
		if !ok {
			return nil, errors.New("PIOP: canonical proof: missing authentication position")
		}
		nodes[i] = node
	}
	return nodes, nil
}

func packCanonicalFqMatrix20(matrix [][]uint64, q uint64) ([]byte, error) {
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, errors.New("PIOP: canonical proof: cannot pack empty field matrix")
	}
	cols := len(matrix[0])
	count, err := checkedCanonicalElementCount(len(matrix), cols)
	if err != nil {
		return nil, err
	}
	out := make([]byte, canonicalPackedByteLen(count, canonicalFqBitWidth))
	bitPos := 0
	for i, row := range matrix {
		if len(row) != cols {
			return nil, fmt.Errorf("PIOP: canonical proof: ragged field matrix row %d", i)
		}
		for j, value := range row {
			if value >= q || value >= 1<<canonicalFqBitWidth {
				return nil, fmt.Errorf("PIOP: canonical proof: noncanonical field value at (%d,%d)", i, j)
			}
			canonicalPackUint(out, bitPos, canonicalFqBitWidth, value)
			bitPos += canonicalFqBitWidth
		}
	}
	return out, nil
}

func unpackCanonicalFqMatrix20(data []byte, rows, cols int, q uint64) ([][]uint64, error) {
	count, err := checkedCanonicalElementCount(rows, cols)
	if err != nil {
		return nil, err
	}
	want := canonicalPackedByteLen(count, canonicalFqBitWidth)
	if len(data) != want {
		return nil, fmt.Errorf("field payload bytes=%d want=%d", len(data), want)
	}
	usedBits := count * canonicalFqBitWidth
	if spare := want*8 - usedBits; spare > 0 && data[want-1]>>(8-spare) != 0 {
		return nil, errors.New("nonzero spare field bits")
	}
	out := make([][]uint64, rows)
	bitPos := 0
	for i := 0; i < rows; i++ {
		out[i] = make([]uint64, cols)
		for j := 0; j < cols; j++ {
			value := canonicalUnpackUint(data, bitPos, canonicalFqBitWidth)
			if value >= q {
				return nil, fmt.Errorf("field value at (%d,%d)=%d is >=q", i, j, value)
			}
			out[i][j] = value
			bitPos += canonicalFqBitWidth
		}
	}
	return out, nil
}

func setCanonicalProofQPayload20(proof *Proof, matrix [][]uint64) {
	targetCols := 0
	if proof != nil && proof.QDegreeBound >= 0 {
		targetCols = proof.QDegreeBound + 1
	}
	matrix = canonicalPadMatrixRows(matrix, targetCols)
	payload, _ := packCanonicalFqMatrix20(matrix, math.MaxUint64)
	proof.QPayloadBits = canonicalPackedMatrixFrame20(matrix, payload)
	proof.QPayloadRows = len(matrix)
	proof.QPayloadCols = len(matrix[0])
	proof.QPayloadBitWidth = canonicalFqBitWidth
	proof.QPayload = copyMatrix(matrix)
}

func canonicalPadMatrixRows(matrix [][]uint64, targetCols int) [][]uint64 {
	maxCols := 0
	for _, row := range matrix {
		if len(row) > maxCols {
			maxCols = len(row)
		}
	}
	if targetCols < maxCols {
		targetCols = maxCols
	}
	out := make([][]uint64, len(matrix))
	for i, row := range matrix {
		out[i] = make([]uint64, targetCols)
		copy(out[i], row)
	}
	return out
}

func setCanonicalProofVTargets20(proof *Proof, matrix [][]uint64) {
	payload, _ := packCanonicalFqMatrix20(matrix, math.MaxUint64)
	proof.VTargetsBits = canonicalPackedMatrixFrame20(matrix, payload)
	proof.VTargetsBits[9] = vTargetsFormatDense
	proof.VTargetsRows = len(matrix)
	proof.VTargetsCols = len(matrix[0])
	proof.VTargetsBitWidth = canonicalFqBitWidth
	proof.VTargetsWidthCodec = false
	proof.VTargets = copyMatrix(matrix)
}

func setCanonicalProofBarSets20(proof *Proof, matrix [][]uint64) {
	payload, _ := packCanonicalFqMatrix20(matrix, math.MaxUint64)
	proof.BarSetsBits = canonicalPackedMatrixFrame20(matrix, payload)
	proof.BarSetsRows = len(matrix)
	proof.BarSetsCols = len(matrix[0])
	proof.BarSetsBitWidth = canonicalFqBitWidth
	proof.BarSets = copyMatrix(matrix)
}

func canonicalPackedMatrixFrame20(matrix [][]uint64, payload []byte) []byte {
	out := make([]byte, 10+len(payload))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(matrix)))
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(matrix[0])))
	out[8] = canonicalFqBitWidth
	out[9] = 0
	copy(out[10:], payload)
	return out
}

func canonicalPackUint(out []byte, bitPos, width int, value uint64) {
	for bit := 0; bit < width; bit++ {
		if value&(uint64(1)<<bit) != 0 {
			pos := bitPos + bit
			out[pos>>3] |= 1 << uint(pos&7)
		}
	}
}

func canonicalUnpackUint(data []byte, bitPos, width int) uint64 {
	var value uint64
	for bit := 0; bit < width; bit++ {
		pos := bitPos + bit
		if data[pos>>3]&(1<<uint(pos&7)) != 0 {
			value |= uint64(1) << bit
		}
	}
	return value
}

func appendCanonicalUvarint(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

type canonicalProofReader struct {
	data []byte
	off  int
}

func (r *canonicalProofReader) remaining() int {
	if r == nil || r.off >= len(r.data) {
		return 0
	}
	return len(r.data) - r.off
}

func (r *canonicalProofReader) take(n int) ([]byte, error) {
	if r == nil || n < 0 || n > r.remaining() {
		return nil, errors.New("PIOP: canonical proof: truncated input")
	}
	out := r.data[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *canonicalProofReader) uvarint() (uint64, error) {
	start := r.off
	var value uint64
	for shift := uint(0); shift < 70; shift += 7 {
		b, err := r.take(1)
		if err != nil {
			return 0, err
		}
		if shift == 63 && b[0] > 1 {
			return 0, errors.New("unsigned LEB128 overflow")
		}
		value |= uint64(b[0]&0x7f) << shift
		if b[0]&0x80 == 0 {
			encoded := appendCanonicalUvarint(nil, value)
			if !bytes.Equal(encoded, r.data[start:r.off]) {
				return 0, errors.New("nonminimal unsigned LEB128")
			}
			return value, nil
		}
	}
	return 0, errors.New("unsigned LEB128 overflow")
}

func checkedCanonicalElementCount(rows, cols int) (int, error) {
	if rows <= 0 || cols <= 0 || rows > canonicalProofMaxElements/cols {
		return 0, fmt.Errorf("PIOP: canonical proof: invalid or excessive dimensions %dx%d", rows, cols)
	}
	count := rows * cols
	if count > canonicalProofMaxElements {
		return 0, fmt.Errorf("PIOP: canonical proof: element count %d exceeds limit", count)
	}
	return count, nil
}

func canonicalPackedByteLen(count, width int) int {
	return (count*width + 7) / 8
}

func canonicalMerkleDepth(nLeaves int) (int, error) {
	if nLeaves <= 0 {
		return 0, errors.New("PIOP: canonical proof: invalid Merkle leaf count")
	}
	depth := 0
	for size := uint64(1); size < uint64(nLeaves); size <<= 1 {
		depth++
		if depth > 63 {
			return 0, errors.New("PIOP: canonical proof: Merkle depth overflow")
		}
	}
	return depth, nil
}
