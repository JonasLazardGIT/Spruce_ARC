package PIOP

import decs "vSIS-Signature/DECS"

// SourceProductBridge is retained only as a deprecated compatibility payload so
// proof/report schemas stay stable while maintained proofs keep it nil.
type SourceProductBridge struct {
	Version        int
	RowIndices     []int
	PhysicalRows   []int
	SupportSlots   []int
	RowsOpening    *decs.DECSOpening
	PackedDigest   []byte
	GeometryDigest []byte
	BridgeDigest   []byte
}

func sourceProductBridgeEnabledForProof(proof *Proof) bool {
	return proof != nil && proof.SourceProductBridge != nil
}
