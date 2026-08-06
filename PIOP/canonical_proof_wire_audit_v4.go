package PIOP

import (
	"errors"
	"fmt"

	decs "vSIS-Signature/DECS"
)

// CanonicalProofWireAuditV6 is an exact decomposition of bytes emitted by
// MarshalCanonicalProof.  It deliberately uses physical-wire terminology;
// paper-accounted transcript sizes remain a separate ProofReport metric.
type CanonicalProofWireAuditV6 struct {
	CodecVersion          int    `json:"codec_version"`
	CodecProfile          string `json:"codec_profile"`
	ProofSchemaVersion    int    `json:"proof_schema_version"`
	FieldEncoding         string `json:"field_encoding"`
	QKernelEncoding       string `json:"q_kernel_encoding"`
	RadixQGroupElements   int    `json:"radix_q_group_elements"`
	MerkleTopology        string `json:"merkle_topology"`
	HeaderBytes           int    `json:"header_bytes"`
	RootBytes             int    `json:"root_bytes"`
	SaltBytes             int    `json:"salt_bytes"`
	CounterBytes          int    `json:"counter_bytes"`
	RBytes                int    `json:"r_bytes"`
	QBytes                int    `json:"q_bytes"`
	VTargetsBytes         int    `json:"vtargets_bytes"`
	BarSetsBytes          int    `json:"barsets_bytes"`
	OpeningPBytes         int    `json:"opening_p_bytes"`
	TapeBytes             int    `json:"tape_bytes"`
	AuthenticationBytes   int    `json:"authentication_bytes"`
	TotalBytes            int    `json:"total_bytes"`
	QFullFieldElements    int    `json:"q_full_field_elements"`
	QWireFieldElements    int    `json:"q_wire_field_elements"`
	QOmittedFieldElements int    `json:"q_omitted_field_elements"`
	MerkleNodesUsed       int    `json:"merkle_nodes_used"`
	MerkleNodesBound      int    `json:"merkle_nodes_bound"`
	MerklePaddingNodes    int    `json:"merkle_padding_nodes"`
}

// CanonicalProofWireAuditV5 is retained as a source-compatible name for
// readers of historical evidence structures. New evidence must identify the
// embedded CodecVersion and CodecProfile as v6.
type CanonicalProofWireAuditV5 = CanonicalProofWireAuditV6

// BuildCanonicalProofWireAuditV6 validates and serializes proof using the
// production codec, then derives every component length from trusted context.
// It never estimates a serialized size from an in-memory Go value.
func BuildCanonicalProofWireAuditV6(proof *Proof, ctx CanonicalProofContext) (CanonicalProofWireAuditV6, error) {
	var out CanonicalProofWireAuditV6
	if proof == nil {
		return out, errors.New("PIOP: canonical wire audit: nil proof")
	}
	wire, err := MarshalCanonicalProof(proof, ctx)
	if err != nil {
		return out, err
	}
	g, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		return out, err
	}
	bytesForElements := func(count int) (int, error) {
		return canonicalRadixQElementsByteLenV5(count, g.q)
	}
	rBytes, err := bytesForElements(g.rRows * g.rCols)
	if err != nil {
		return out, err
	}
	qBytes, err := bytesForElements(g.qRows * g.qWireCols)
	if err != nil {
		return out, err
	}
	vBytes, err := bytesForElements(g.vWireElements)
	if err != nil {
		return out, err
	}
	barBytes, err := bytesForElements(g.barRows * g.barCols)
	if err != nil {
		return out, err
	}
	pBytes, err := bytesForElements(g.openingEntries * g.openingPCols)
	if err != nil {
		return out, err
	}
	counterBytes := 0
	for _, counter := range proof.Ctr {
		counterBytes += len(appendCanonicalUvarint(nil, counter))
	}
	frontier, err := decs.MerkleFrontierPositionsV3(proof.Tail, g.opts.NLeaves)
	if err != nil {
		return out, fmt.Errorf("PIOP: canonical wire audit: Merkle frontier: %w", err)
	}
	out = CanonicalProofWireAuditV6{
		CodecVersion:          CanonicalProofCodecVersionV6,
		CodecProfile:          CanonicalProofCodecProfileV6,
		ProofSchemaVersion:    proof.SchemaVersion,
		FieldEncoding:         CanonicalProofFieldEncodingV6,
		QKernelEncoding:       CanonicalProofQKernelEncodingV6,
		RadixQGroupElements:   CanonicalProofRadixQGroupElementsV6,
		MerkleTopology:        decs.MerkleTopologyExactNV3,
		HeaderBytes:           len(canonicalProofMagicV6) + 2,
		RootBytes:             g.hashBytes,
		SaltBytes:             g.saltBytes,
		CounterBytes:          counterBytes,
		RBytes:                rBytes,
		QBytes:                qBytes,
		VTargetsBytes:         vBytes,
		BarSetsBytes:          barBytes,
		OpeningPBytes:         pBytes,
		TapeBytes:             g.openingEntries * g.tapeBytes,
		AuthenticationBytes:   len(frontier) * g.hashBytes,
		QFullFieldElements:    g.qRows * g.qCols,
		QWireFieldElements:    g.qRows * g.qWireCols,
		QOmittedFieldElements: g.qRows * (g.qCols - g.qWireCols),
		MerkleNodesUsed:       len(frontier),
		MerkleNodesBound:      g.worstAuthNodes,
		MerklePaddingNodes:    0,
	}
	out.TotalBytes = out.HeaderBytes + out.RootBytes + out.SaltBytes + out.CounterBytes +
		out.RBytes + out.QBytes + out.VTargetsBytes + out.BarSetsBytes +
		out.OpeningPBytes + out.TapeBytes + out.AuthenticationBytes
	if out.MerkleNodesUsed > out.MerkleNodesBound || out.TotalBytes != len(wire) {
		return CanonicalProofWireAuditV6{}, fmt.Errorf("PIOP: canonical wire audit: component total=%d wire=%d used_nodes=%d bound=%d", out.TotalBytes, len(wire), out.MerkleNodesUsed, out.MerkleNodesBound)
	}
	return out, nil
}

// BuildCanonicalProofWireAuditV5 is a deprecated compatibility wrapper. It
// audits the current v6 production wire and never emits or accepts v5 bytes.
func BuildCanonicalProofWireAuditV5(proof *Proof, ctx CanonicalProofContext) (CanonicalProofWireAuditV5, error) {
	return BuildCanonicalProofWireAuditV6(proof, ctx)
}
