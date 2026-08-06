package PIOP

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestCanonicalProofV3TargetGeometry(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	tests := []struct {
		name                                                            string
		theta, rows, dQ, replay, total, queries, mask, openingP, rowDeg int
		vWireElements, vWireBytes, qWireBytes                           int
	}{
		{"BQ128", 13, 49, 472, 90, 246, 39, 156, 207, 60, 1196, 2985, 15310},
		{"WF128", 7, 49, 391, 78, 155, 21, 77, 134, 50, 623, 1555, 6829},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := canonicalPreSignContextForTest(t, tc.theta)
			g, err := deriveCanonicalProofGeometryV3(ctx)
			if err != nil {
				t.Fatalf("derive geometry: %v", err)
			}
			if g.logicalRows != tc.rows || g.dQ != tc.dQ || g.replayRows != tc.replay || g.totalRows != tc.total || g.queryCount != tc.queries || g.maskRows != tc.mask || g.openingPCols != tc.openingP || g.rowDegree != tc.rowDeg {
				t.Fatalf("geometry=(rows=%d,dQ=%d,replay=%d,total=%d,queries=%d,mask=%d,P=%d,row_degree=%d), want (%d,%d,%d,%d,%d,%d,%d,%d)",
					g.logicalRows, g.dQ, g.replayRows, g.totalRows, g.queryCount, g.maskRows, g.openingPCols, g.rowDegree,
					tc.rows, tc.dQ, tc.replay, tc.total, tc.queries, tc.mask, tc.openingP, tc.rowDeg)
			}
			if g.openingPCols != g.totalRows-g.queryCount {
				t.Fatalf("opening P columns=%d want %d", g.openingPCols, g.totalRows-g.queryCount)
			}
			if g.qWireCols != g.dQ || g.vWireElements != tc.vWireElements {
				t.Fatalf("compressed geometry=(q_cols=%d,V_elements=%d), want (%d,%d)", g.qWireCols, g.vWireElements, g.dQ, tc.vWireElements)
			}
			fullV := canonicalPackedByteLen(g.vRows*g.vCols, canonicalFqBitWidth)
			wireV, err := canonicalRadixQElementsByteLenV5(g.vWireElements, g.q)
			if err != nil {
				t.Fatal(err)
			}
			fullQ := canonicalPackedByteLen(g.qRows*g.qCols, canonicalFqBitWidth)
			wireQ, err := canonicalRadixQElementsByteLenV5(g.qRows*g.qWireCols, g.q)
			if err != nil {
				t.Fatal(err)
			}
			if wireV != tc.vWireBytes || wireQ != tc.qWireBytes {
				t.Fatalf("codec-v6 bytes=(V=%d,Q=%d), want (%d,%d)", wireV, wireQ, tc.vWireBytes, tc.qWireBytes)
			}
			t.Logf("issuance canonical wire: QPayload=%d->%d B, VTargets=%d->%d B, saved=%d B", fullQ, wireQ, fullV, wireV, fullQ-wireQ+fullV-wireV)
		})
	}

	// Showing layout construction needs a complete trusted signature/PRF
	// statement. These compiler-independent identities pin the corrected v3
	// row geometry without inventing a synthetic showing statement.
	showing := []struct {
		name                                  string
		dQ, width, theta, logicalRows         int
		replay, mask, total, query, p         int
		vWireElements, vWireBytes, qWireBytes int
	}{
		{"BQ128", 570, 43, 13, 423, 450, 195, 645, 143, 502, 6032, 15051, 18489},
		{"WF128-L41", 471, 41, 7, 423, 429, 91, 520, 84, 436, 3241, 8087, 8227},
	}
	for _, tc := range showing {
		t.Run(tc.name+"-showing", func(t *testing.T) {
			shape, err := deriveSmallFieldMaskShapeV3(tc.dQ, tc.width, tc.theta)
			if err != nil {
				t.Fatal(err)
			}
			layers := ceilDiv(tc.logicalRows, tc.width)
			replay := layers * (32 + tc.theta)
			query := (layers + 1) * tc.theta
			total := replay + shape.RowsPerMask
			if replay != tc.replay || shape.RowsPerMask != tc.mask || total != tc.total || query != tc.query || total-query != tc.p {
				t.Fatalf("showing geometry=(replay=%d,mask=%d,total=%d,query=%d,P=%d), want (%d,%d,%d,%d,%d)", replay, shape.RowsPerMask, total, query, total-query, tc.replay, tc.mask, tc.total, tc.query, tc.p)
			}
			widths, elements, err := deriveCanonicalVTargetRowWidthsV3(tc.logicalRows, layers, tc.width, tc.theta, shape.Nu)
			if err != nil || len(widths) != query || elements != tc.vWireElements {
				t.Fatalf("derive compressed V geometry: widths=%d elements=%d err=%v", len(widths), elements, err)
			}
			fullV := canonicalPackedByteLen(query*tc.width, canonicalFqBitWidth)
			wireV, err := canonicalRadixQElementsByteLenV5(elements, credential.IntGenISISSharedModulusQ)
			if err != nil {
				t.Fatal(err)
			}
			fullQ := canonicalPackedByteLen(tc.theta*(tc.dQ+1), canonicalFqBitWidth)
			wireQ, err := canonicalRadixQElementsByteLenV5(tc.theta*tc.dQ, credential.IntGenISISSharedModulusQ)
			if err != nil {
				t.Fatal(err)
			}
			if wireV != tc.vWireBytes || wireQ != tc.qWireBytes {
				t.Fatalf("showing codec-v6 bytes=(V=%d,Q=%d), want (%d,%d)", wireV, wireQ, tc.vWireBytes, tc.qWireBytes)
			}
			t.Logf("showing canonical wire: QPayload=%d->%d B, VTargets=%d->%d B, saved=%d B", fullQ, wireQ, fullV, wireV, fullQ-wireQ+fullV-wireV)
		})
	}
}

func TestCanonicalProofV3StrictRoundTripAndRejections(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	ctx := canonicalPreSignContextForTest(t, 7)
	ctx.Options.PhaseRecorder = NewPhaseRecorder()
	g, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		t.Fatalf("derive geometry: %v", err)
	}
	proof := canonicalSyntheticProofV3(t, g)
	wire, err := MarshalCanonicalProof(proof, ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	audit, err := BuildCanonicalProofWireAuditV6(proof, ctx)
	if err != nil {
		t.Fatalf("audit canonical wire: %v", err)
	}
	if audit.TotalBytes != len(wire) || audit.CodecVersion != 6 || audit.ProofSchemaVersion != ProofSchemaVersionV3 ||
		audit.QWireFieldElements != g.qRows*g.qWireCols || audit.QOmittedFieldElements != g.qRows ||
		audit.MerkleNodesUsed > audit.MerkleNodesBound || audit.MerklePaddingNodes != 0 ||
		audit.AuthenticationBytes != audit.MerkleNodesUsed*g.hashBytes {
		t.Fatalf("canonical wire audit mismatch: %+v", audit)
	}
	decoded, err := UnmarshalCanonicalProof(wire, ctx)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	phaseLabels := make(map[string]bool)
	for _, timing := range ctx.Options.PhaseRecorder.Snapshot() {
		phaseLabels[timing.Label] = true
	}
	if !phaseLabels["issuance.canonical_encode"] || !phaseLabels["issuance.canonical_decode"] {
		t.Fatalf("canonical codec phase labels=%v", phaseLabels)
	}
	if decoded.SchemaVersion != ProofSchemaVersionV3 || decoded.TranscriptVersion != TranscriptVersionSmallWood2025V3 || decoded.TranscriptProtocolMode != TranscriptProtocolSmallField2025V3 {
		t.Fatalf("decoded v3 tuple=(%d,%q,%q)", decoded.SchemaVersion, decoded.TranscriptVersion, decoded.TranscriptProtocolMode)
	}
	if !reflect.DeepEqual(decoded.R, proof.R) || !reflect.DeepEqual(decoded.QPayloadMatrix(), proof.QPayloadMatrix()) ||
		!reflect.DeepEqual(decoded.VTargetsMatrix(), proof.VTargetsMatrix()) || !reflect.DeepEqual(decoded.BarSetsMatrix(), proof.BarSetsMatrix()) {
		t.Fatal("decoded independently necessary matrices differ")
	}
	if !reflect.DeepEqual(decoded.RowLayout, proof.RowLayout) || !reflect.DeepEqual(decoded.PCSGeometry, proof.PCSGeometry) ||
		!reflect.DeepEqual(decoded.CoeffMatrix, proof.CoeffMatrix) || !reflect.DeepEqual(decoded.KPoint, proof.KPoint) ||
		!reflect.DeepEqual(decoded.Gamma, proof.Gamma) || !reflect.DeepEqual(decoded.GammaPrimeK, proof.GammaPrimeK) ||
		!reflect.DeepEqual(decoded.GammaAggK, proof.GammaAggK) || !reflect.DeepEqual(decoded.Tail, proof.Tail) {
		t.Fatal("decoded proof was not fully hydrated from trusted context")
	}
	for i := range decoded.Digests {
		if !bytes.Equal(decoded.Digests[i], proof.Digests[i]) {
			t.Fatalf("digest %d differs", i)
		}
	}
	if decoded.PCSOpening == nil || decoded.RowOpening == nil || !reflect.DeepEqual(decoded.PCSOpening, decoded.RowOpening) {
		t.Fatal("decoded authoritative opening aliases differ")
	}
	if decoded.SmallField2025 == nil || !isExactSmallField2025TranscriptOmissionV3(decoded.SmallField2025.TranscriptOmission) {
		t.Fatal("decoded proof did not reconstruct the exact v3 omission descriptor")
	}
	if len(decoded.Chi) != 0 || len(decoded.Zeta) != 0 || len(decoded.LabelsDigest) != 0 || len(decoded.MKData) != 0 || len(decoded.QKData) != 0 {
		t.Fatal("decoded proof hydrated a forbidden wire/debug field")
	}
	wire2, err := MarshalCanonicalProof(decoded, ctx)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if !bytes.Equal(wire, wire2) {
		t.Fatal("canonical re-encoding changed bytes")
	}

	headerLen := len(canonicalProofMagicV6) + 2
	counterOffset := headerLen + g.hashBytes + g.saltBytes
	matrixOffset := counterOffset
	for _, counter := range proof.Ctr {
		matrixOffset += len(appendCanonicalUvarint(nil, counter))
	}
	keys := canonicalOpeningPositionKeys(proof.Tail, g.opts.NLeaves)

	t.Run("bad_version", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		bad[len(canonicalProofMagicV6)] = 3
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("legacy_p3_magic", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		copy(bad[:len(canonicalProofMagicV6)], []byte("SPRUCEP3"))
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("retired_unsound_p4_magic", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		copy(bad[:len(canonicalProofMagicV6)], []byte("SPRUCEP4"))
		bad[len(canonicalProofMagicV6)] = 4
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("retired_fixed-padding_p5_magic", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		copy(bad[:len(canonicalProofMagicV6)], []byte("SPRUCEP5"))
		bad[len(canonicalProofMagicV6)] = 5
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("bad_kind", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		bad[len(canonicalProofMagicV6)+1] = byte(CanonicalProofShowing)
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("nonminimal_counter", func(t *testing.T) {
		second := counterOffset + len(appendCanonicalUvarint(nil, proof.Ctr[0]))
		if proof.Ctr[1] != 0 || wire[second] != 0 {
			t.Fatalf("WF128 kappa[1]=0 counter encoding=%x want 00", wire[second])
		}
		bad := make([]byte, 0, len(wire)+1)
		bad = append(bad, wire[:second]...)
		bad = append(bad, 0x80, 0x00)
		bad = append(bad, wire[second+1:]...)
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("field_equal_q", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		group := g.rRows * g.rCols
		if group > canonicalRadixQGroupElementsV5 {
			group = canonicalRadixQGroupElementsV5
		}
		width, limit, err := canonicalRadixQGroupParamsV5(group, g.q)
		if err != nil {
			t.Fatal(err)
		}
		limit.FillBytes(bad[matrixOffset : matrixOffset+width])
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("nonzero_field_spare_bits", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		if bad[matrixOffset]&0x80 != 0 {
			t.Fatal("test geometry unexpectedly has no leading radix-q spare bit")
		}
		bad[matrixOffset] |= 0x80
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("retired_fixed_auth_padding", func(t *testing.T) {
		if len(keys) >= g.worstAuthNodes {
			t.Fatal("test tail unexpectedly has no authentication padding")
		}
		bad := append([]byte(nil), wire...)
		bad = append(bad, make([]byte, (g.worstAuthNodes-len(keys))*g.hashBytes)...)
		expectCanonicalProofDecodeError(t, bad, ctx)
	})
	t.Run("trailing", func(t *testing.T) {
		expectCanonicalProofDecodeError(t, append(append([]byte(nil), wire...), 0), ctx)
	})
	t.Run("every_truncation_boundary", func(t *testing.T) {
		fixedPayloadBytes, err := canonicalProofFixedPayloadBytesV3(g)
		if err != nil {
			t.Fatalf("derive fixed payload length: %v", err)
		}
		if want := matrixOffset + fixedPayloadBytes + len(keys)*g.hashBytes; want != len(wire) {
			t.Fatalf("preflight wire length=%d want marshaled length %d", want, len(wire))
		}
		for n := 0; n < len(wire); n++ {
			if _, err := unmarshalCanonicalProofWithGeometryV3(wire[:n:n], g); err == nil {
				t.Fatalf("accepted proof truncated at byte %d of %d", n, len(wire))
			}
		}
	})
	t.Run("wrong_public_statement", func(t *testing.T) {
		wrong := ctx
		wrong.Public = cloneCanonicalPublicInputsForTest(ctx.Public)
		wrong.Public.CM[0][0].Coeffs[0][0] = 1
		expectCanonicalProofDecodeError(t, wire, wrong)
	})
	t.Run("wrong_manifest", func(t *testing.T) {
		wrong := ctx
		wrong.Public = cloneCanonicalPublicInputsForTest(ctx.Public)
		wrong.Public.Extras["IntGenISIS.preset_manifest_digest"] = []byte("wrong")
		expectCanonicalProofDecodeError(t, wire, wrong)
	})
	t.Run("legacy_and_debug_source_rejected", func(t *testing.T) {
		legacy := *proof
		legacy.SchemaVersion = ProofSchemaVersionV2
		if _, err := MarshalCanonicalProof(&legacy, ctx); err == nil {
			t.Fatal("legacy source proof was accepted")
		}
		debug := *proof
		debug.MaskCoeffDebug = [][]uint64{{1}}
		if _, err := MarshalCanonicalProof(&debug, ctx); err == nil {
			t.Fatal("debug source proof was accepted")
		}
	})
	t.Run("conflicting_duplicate_auth_position", func(t *testing.T) {
		bad := *proof
		bad.PCSOpening = cloneCanonicalOpeningForTest(proof.PCSOpening)
		bad.RowOpening = bad.PCSOpening
		required := make(map[canonicalAuthPosition]bool)
		for _, key := range canonicalOpeningPositionKeys(proof.Tail, g.opts.NLeaves) {
			required[key] = true
		}
		seen := make(map[canonicalAuthPosition]struct{})
		changed := false
		for row, index := range proof.Tail {
			positions, err := decs.MerkleAuthenticationPathPositionsV3(index, g.opts.NLeaves)
			if err != nil {
				t.Fatalf("derive authentication path %d: %v", row, err)
			}
			for level, position := range positions {
				key := canonicalAuthPosition{start: position.Start, end: position.End}
				if !required[key] {
					continue
				}
				if _, ok := seen[key]; ok {
					originalID := bad.PCSOpening.PathIndex[row][level]
					conflict := append([]byte(nil), bad.PCSOpening.Nodes[originalID]...)
					conflict[0] ^= 1
					bad.PCSOpening.Nodes = append(bad.PCSOpening.Nodes, conflict)
					bad.PCSOpening.PathIndex[row][level] = len(bad.PCSOpening.Nodes) - 1
					changed = true
					break
				}
				seen[key] = struct{}{}
			}
			if changed {
				break
			}
		}
		if !changed {
			t.Fatal("test tail unexpectedly had no duplicate authentication position")
		}
		if _, err := canonicalOpeningPositionNodes(bad.PCSOpening, proof.Tail, g); err == nil {
			t.Fatal("positional multiproof canonicalizer accepted conflicting duplicate authentication node")
		}
		if _, err := MarshalCanonicalProof(&bad, ctx); err == nil {
			t.Fatal("conflicting duplicate authentication node was accepted")
		}
	})
}

func TestPreparedExecutionContextPreservesCanonicalWireAndOwnsInputs(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	ctx := canonicalPreSignContextForTest(t, 7)
	geometry, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof := canonicalSyntheticProofV3(t, geometry)
	want, err := MarshalCanonicalProof(proof, ctx)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareExecutionContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Kind() != CanonicalProofPreSign || len(prepared.BindingDigest()) != 64 {
		t.Fatalf("prepared identity kind=%d digest=%q", prepared.Kind(), prepared.BindingDigest())
	}
	got, err := MarshalCanonicalProofPrepared(proof, prepared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("prepared encoding changed canonical bytes")
	}
	decoded, err := UnmarshalCanonicalProofPrepared(got, prepared, nil)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := MarshalCanonicalProofPrepared(decoded, prepared, nil)
	if err != nil || !bytes.Equal(reencoded, want) {
		t.Fatalf("prepared round trip changed bytes: err=%v", err)
	}
	// The prepared object owns all public backing storage; later caller changes
	// cannot poison its trusted geometry or identity.
	ctx.Options.NLeaves++
	for key := range ctx.Public.Extras {
		ctx.Public.Extras[key] = []byte("mutated")
		break
	}
	afterMutation, err := MarshalCanonicalProofPrepared(proof, prepared, nil)
	if err != nil || !bytes.Equal(afterMutation, want) {
		t.Fatalf("caller mutation affected prepared context: err=%v", err)
	}
}

func TestCanonicalProofV3FreshPreSignVerifiesAfterRoundTrip(t *testing.T) {
	for _, theta := range []int{7, 13} {
		t.Run(map[int]string{7: "WF128", 13: "BQ128"}[theta], func(t *testing.T) {
			ctx := canonicalPreSignContextForTest(t, theta)
			geometry, err := deriveCanonicalProofGeometryV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ringQ, err := credential.LoadRingWithDegree(1024)
			if err != nil {
				t.Fatal(err)
			}
			profile := credential.Ternary1024IntGenISISProfile()
			layout, err := credential.DefaultSemanticMessageLayout(profile, intGenISISPRFKeyLen)
			if err != nil {
				t.Fatal(err)
			}
			message, err := credential.EncodeSemanticMessage(layout, credential.ZeroSemanticAttributes(layout), intGenISISTestPRFSeed())
			if err != nil {
				t.Fatal(err)
			}
			zero := func() *ring.Poly { return ringQ.NewPoly() }
			witness := WitnessInputs{
				M:     polysFromInt64ForIntGenISISTest(ringQ, message.M),
				MAttr: polysFromInt64ForIntGenISISTest(ringQ, message.MAttr),
				K:     polysFromInt64ForIntGenISISTest(ringQ, message.K),
				S:     []*ring.Poly{zero()},
				E:     []*ring.Poly{zero()},
			}
			proof, err := BuildIntGenISISPreSign(ringQ, ctx.Public, witness, ctx.Options)
			if err != nil {
				t.Fatalf("build fresh proof: %v", err)
			}
			if ok, verifyErr := VerifyIntGenISISPreSign(ctx.Public, proof, ctx.Options); verifyErr != nil || !ok {
				t.Fatalf("verify fresh source proof: ok=%v err=%v", ok, verifyErr)
			}
			report, err := BuildProofReport(proof, ctx.Options, ringQ)
			if err != nil {
				t.Fatalf("build strict-v3 proof report: %v", err)
			}
			type expectedPaper struct {
				total, fixed, r, q, p, auth, tapes, v, bar, maskRows int
			}
			wantPaper := map[int]expectedPaper{
				7:  {23790, 648, 5471, 6828, 3015, 5643, 144, 1558, 483, 77},
				13: {57271, 680, 8979, 15308, 9315, 17640, 594, 2990, 1765, 156},
			}[theta]
			got := report.PaperTranscript
			if got.OptimizedBytes != wantPaper.total || got.Audit.FixedV3.TotalBytes != wantPaper.fixed ||
				got.R.OptimizedBytes != wantPaper.r || got.Q.OptimizedBytes != wantPaper.q ||
				got.Pdecs.OptimizedBytes != wantPaper.p || got.Mdecs.OptimizedBytes != 0 ||
				got.Auth.OptimizedBytes != wantPaper.auth || got.Tapes.OptimizedBytes != wantPaper.tapes ||
				got.VTargets.OptimizedBytes != wantPaper.v || got.BarSets.OptimizedBytes != wantPaper.bar {
				t.Fatalf("strict-v3 issuance paper accounting mismatch: got=%+v want=%+v", got, wantPaper)
			}
			if report.Geometry.MaskRowsCommitted != wantPaper.maskRows {
				t.Fatalf("strict-v3 issuance mask rows=%d want %d", report.Geometry.MaskRowsCommitted, wantPaper.maskRows)
			}
			if report.TranscriptFocus.TranscriptSecurityStatus != SmallField2025StatusLiveV3 {
				t.Fatalf("strict-v3 issuance status=%q want %q", report.TranscriptFocus.TranscriptSecurityStatus, SmallField2025StatusLiveV3)
			}
			badOpts := ctx.Options
			badOpts.LVCSNCols++
			if _, buildErr := BuildIntGenISISPreSign(ringQ, ctx.Public, witness, badOpts); buildErr == nil || !strings.Contains(buildErr.Error(), "target binding") {
				t.Fatalf("strict-v3 builder accepted a non-manifest tuple: %v", buildErr)
			}
			if ok, verifyErr := VerifyIntGenISISPreSign(ctx.Public, proof, badOpts); verifyErr == nil || ok || !strings.Contains(verifyErr.Error(), "target binding") {
				t.Fatalf("strict-v3 verifier accepted a non-manifest tuple: ok=%v err=%v", ok, verifyErr)
			}
			wire, err := MarshalCanonicalProof(proof, ctx)
			if err != nil {
				t.Fatalf("marshal fresh proof: %v", err)
			}
			decoded, err := UnmarshalCanonicalProof(wire, ctx)
			if err != nil {
				t.Fatalf("unmarshal fresh proof: %v", err)
			}
			ok, err := VerifyIntGenISISPreSign(ctx.Public, decoded, ctx.Options)
			if err != nil || !ok {
				t.Fatalf("verify decoded fresh proof: ok=%v err=%v", ok, err)
			}

			// Regrind all permitted Fiat--Shamir counters after mutating an
			// independently transmitted message. The resulting algebraic
			// envelope is self-consistent, but the old committed DECS opening
			// cannot authenticate either a changed compact Q challenge path or
			// changed VTargets. This exercises the final root/opening boundary,
			// rather than relying on a stale-digest rejection.
			baseMatrices := canonicalProofMatricesV3{
				r:        copyMatrix(proof.R),
				vTargets: copyMatrix(proof.VTargetsMatrix()),
				barSets:  copyMatrix(proof.BarSetsMatrix()),
			}
			baseMatrices.qCompact, err = canonicalQKernelCompactFromFullV5(proof.QPayloadMatrix(), geometry.omegaWitness, geometry.q)
			if err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*canonicalProofMatricesV3){
				"compact_q": func(m *canonicalProofMatricesV3) {
					m.qCompact[0][0] = modAdd(m.qCompact[0][0], 1, geometry.q)
				},
				"vtargets": func(m *canonicalProofMatricesV3) {
					m.vTargets[0][0] = modAdd(m.vTargets[0][0], 1, geometry.q)
				},
			} {
				t.Run("authenticated_reject_"+name, func(t *testing.T) {
					mutated := canonicalProofMatricesV3{
						r:        copyMatrix(baseMatrices.r),
						qCompact: copyMatrix(baseMatrices.qCompact),
						vTargets: copyMatrix(baseMatrices.vTargets),
						barSets:  copyMatrix(baseMatrices.barSets),
					}
					mutate(&mutated)
					candidate, grindErr := grindCanonicalProofV3(geometry, proofRootBytes(proof), proof.Salt, mutated)
					if grindErr != nil {
						t.Fatalf("regrind mutated transcript: %v", grindErr)
					}
					candidate.PCSOpening = proof.PCSOpening
					candidate.RowOpening = proof.PCSOpening
					if accepted, verifyErr := VerifyIntGenISISPreSign(ctx.Public, candidate, ctx.Options); verifyErr == nil && accepted {
						t.Fatal("mutated transcript accepted with an opening for the original commitment messages")
					}
				})
			}
			decodedReport, err := BuildProofReport(decoded, ctx.Options, ringQ)
			if err != nil {
				t.Fatalf("build decoded strict-v3 proof report: %v", err)
			}
			if !decodedReport.ZeroKnowledgeEligible || decodedReport.TranscriptFocus.TranscriptSecurityStatus != SmallField2025StatusLiveV3 {
				t.Fatalf("decoded strict-v3 proof lost independent-tape ZK eligibility: eligible=%v status=%q", decodedReport.ZeroKnowledgeEligible, decodedReport.TranscriptFocus.TranscriptSecurityStatus)
			}
		})
	}
}

func TestCanonicalProofV5RadixQFieldPackingBoundaries(t *testing.T) {
	const q = credential.IntGenISISSharedModulusQ
	packed, err := packCanonicalFqMatrixRadixQV5([][]uint64{{0, q - 1}}, q)
	if err != nil {
		t.Fatalf("pack boundary values: %v", err)
	}
	got, err := unpackCanonicalFqMatrixRadixQV5(packed, 1, 2, q)
	if err != nil || !reflect.DeepEqual(got, [][]uint64{{0, q - 1}}) {
		t.Fatalf("unpack boundary values=%v err=%v", got, err)
	}
	if _, err := packCanonicalFqMatrixRadixQV5([][]uint64{{q}}, q); err == nil {
		t.Fatal("packed field value q")
	}
	width, limit, err := canonicalRadixQGroupParamsV5(2, q)
	if err != nil || width != len(packed) {
		t.Fatalf("derive group limit: width=%d bytes=%d err=%v", width, len(packed), err)
	}
	badRange := make([]byte, width)
	limit.FillBytes(badRange)
	if _, err := unpackCanonicalFqMatrixRadixQV5(badRange, 1, 2, q); err == nil {
		t.Fatal("unpacked radix-q integer q^r")
	}
	spare, err := packCanonicalFqMatrixRadixQV5([][]uint64{{1}}, q)
	if err != nil {
		t.Fatal(err)
	}
	if spare[0]&0x80 != 0 {
		t.Fatal("one-element group unexpectedly uses its top spare bit")
	}
	spare[0] |= 0x80
	if _, err := unpackCanonicalFqMatrixRadixQV5(spare, 1, 1, q); err == nil {
		t.Fatal("unpacked nonzero spare bits")
	}
	if _, err := unpackCanonicalFqMatrixRadixQV5(packed[:len(packed)-1], 1, 2, q); err == nil {
		t.Fatal("unpacked truncated radix-q group")
	}
	if _, err := unpackCanonicalFqMatrixRadixQV5(append(append([]byte(nil), packed...), 0), 1, 2, q); err == nil {
		t.Fatal("unpacked radix-q group with trailing byte")
	}

	// Exercise both a full bounded group and a partial final group.
	values := make([]uint64, canonicalRadixQGroupElementsV5+17)
	for i := range values {
		values[i] = uint64(i*7919) % q
	}
	multi, err := packCanonicalFqMatrixRadixQV5([][]uint64{values}, q)
	if err != nil {
		t.Fatal(err)
	}
	multiGot, err := unpackCanonicalFqMatrixRadixQV5(multi, 1, len(values), q)
	if err != nil || !reflect.DeepEqual(multiGot[0], values) {
		t.Fatalf("multi-group radix-q round trip failed: err=%v", err)
	}
}

func TestCanonicalProofV3StructuralWireOmissions(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	for _, theta := range []int{7, 13} {
		t.Run(map[int]string{7: "WF128", 13: "BQ128"}[theta], func(t *testing.T) {
			ctx := canonicalPreSignContextForTest(t, theta)
			g, err := deriveCanonicalProofGeometryV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			proof := canonicalSyntheticProofV3(t, g)
			qPayload := copyMatrix(proof.QPayloadMatrix())
			for rowIndex, row := range qPayload {
				var sum uint64
				for _, omega := range g.omegaWitness {
					sum = modAdd(sum, EvalPoly(row, omega, g.q), g.q)
				}
				if sum != 0 {
					t.Fatalf("QPayload row %d reconstruction identity sum=%d", rowIndex, sum)
				}
			}
			packedQ, err := marshalCanonicalQPayloadV3(qPayload, g)
			if err != nil {
				t.Fatalf("marshal compressed QPayload: %v", err)
			}
			wantQ, err := canonicalRadixQMatrixByteLenV5(g.qRows, g.qWireCols, g.q)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := len(packedQ), wantQ; got != want {
				t.Fatalf("compressed QPayload bytes=%d want=%d", got, want)
			}
			qReader := canonicalProofReader{data: packedQ}
			compactQ, err := unmarshalCanonicalQPayloadV3(&qReader, g)
			if err != nil || qReader.remaining() != 0 {
				t.Fatalf("decode compact QPayload: remaining=%d err=%v", qReader.remaining(), err)
			}
			decodedQ, err := canonicalQKernelReconstructV5(compactQ, g.omegaWitness, g.dQ, g.q)
			if err != nil || !reflect.DeepEqual(decodedQ, qPayload) {
				t.Fatalf("reconstruct QPayload: equal=%v err=%v", reflect.DeepEqual(decodedQ, qPayload), err)
			}
			badQ := copyMatrix(qPayload)
			badQ[0][0] = (badQ[0][0] + 1) % g.q
			if _, err := marshalCanonicalQPayloadV3(badQ, g); err == nil {
				t.Fatal("accepted a QPayload whose omitted coefficient was not derivable")
			}

			vTargets := copyMatrix(proof.VTargetsMatrix())
			packedV, err := marshalCanonicalVTargetsV3(vTargets, g)
			if err != nil {
				t.Fatalf("marshal compressed VTargets: %v", err)
			}
			wantV, err := canonicalRadixQElementsByteLenV5(g.vWireElements, g.q)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := len(packedV), wantV; got != want {
				t.Fatalf("compressed VTargets bytes=%d want=%d", got, want)
			}
			vReader := canonicalProofReader{data: packedV}
			decodedV, err := unmarshalCanonicalVTargetsV3(&vReader, g)
			if err != nil || vReader.remaining() != 0 || !reflect.DeepEqual(decodedV, vTargets) {
				t.Fatalf("reconstruct VTargets: remaining=%d equal=%v err=%v", vReader.remaining(), reflect.DeepEqual(decodedV, vTargets), err)
			}
			badV := copyMatrix(vTargets)
			changed := false
			for i, width := range g.vRowWidths {
				if width < g.vCols {
					badV[i][width] = 1
					changed = true
					break
				}
			}
			if !changed {
				t.Fatal("target geometry unexpectedly has no trusted VTargets suffix")
			}
			if _, err := marshalCanonicalVTargetsV3(badV, g); err == nil {
				t.Fatal("accepted a nonzero VTargets value in trusted omitted padding")
			}
		})
	}
}

func TestCanonicalQKernelV5PreChallengeConstantReconstruction(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	for _, theta := range []int{7, 13} {
		t.Run(map[int]string{7: "WF128", 13: "BQ128"}[theta], func(t *testing.T) {
			ctx := canonicalPreSignContextForTest(t, theta)
			g, err := deriveCanonicalProofGeometryV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			proof := canonicalSyntheticProofV3(t, g)
			full := proof.QPayloadMatrix()
			compact, err := canonicalQKernelCompactFromFullV5(full, g.omegaWitness, g.q)
			if err != nil {
				t.Fatal(err)
			}
			if len(compact) != theta || len(compact[0]) != g.dQ {
				t.Fatalf("compact Q shape=%dx%d want=%dx%d", len(compact), len(compact[0]), theta, g.dQ)
			}
			reconstructed, err := canonicalQKernelReconstructV5(compact, g.omegaWitness, g.dQ, g.q)
			if err != nil || !reflect.DeepEqual(reconstructed, full) {
				t.Fatalf("pre-challenge Q reconstruction equal=%v err=%v", reflect.DeepEqual(reconstructed, full), err)
			}
			for coord, row := range reconstructed {
				var supportSum uint64
				for _, omega := range g.omegaWitness {
					supportSum = modAdd(supportSum, EvalPoly(row, omega, g.q), g.q)
				}
				if supportSum != 0 {
					t.Fatalf("reconstructed Q row %d has support sum %d", coord, supportSum)
				}
			}

			// The reconstructed polynomial is fixed before h3/e. Changing a
			// later Eq. (4) target cannot repair any omitted direction: the
			// same Q(e) cannot equal both a target and target+1.
			e := g.K.Phi(proof.KPoint[0])
			polys := restoreKPolysFromSplitCoeffRows(reconstructed, theta, g.q)
			if len(polys) != 1 {
				t.Fatalf("reconstructed Q polys=%d want 1", len(polys))
			}
			got := g.K.Zero()
			evalKPolyAtKInto(g.K, &got, polys[0], e)
			changedTarget := g.K.Add(got, g.K.One())
			if elemEqual(g.K, got, changedTarget) {
				t.Fatal("changed post-challenge target was tautologically repaired")
			}
			first, err := canonicalQKernelTranscriptBytesV6(compact, g.omegaWitness, g.q)
			if err != nil {
				t.Fatal(err)
			}
			changed := copyMatrix(compact)
			changed[0][0] = modAdd(changed[0][0], 1, g.q)
			second, err := canonicalQKernelTranscriptBytesV6(changed, g.omegaWitness, g.q)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(first, second) {
				t.Fatal("compact Q mutation did not change its round-3 binding")
			}
		})
	}
}

func TestCanonicalProofV3SettersUseFixed20BitFramesAndPreserveV2(t *testing.T) {
	matrix := [][]uint64{{1, 2, 3}, {4, 5, 6}}
	v3 := &Proof{TranscriptVersion: TranscriptVersionSmallWood2025V3}
	v3.setQPayload(matrix)
	v3.setBarSets(matrix)
	v3.setVTargets(matrix)
	for name, bits := range map[string][]byte{"QPayload": v3.QPayloadBits, "BarSets": v3.BarSetsBits, "VTargets": v3.VTargetsBits} {
		if len(bits) < 10 || bits[8] != canonicalFqBitWidth {
			t.Fatalf("%s v3 frame width=%d want %d", name, bits[8], canonicalFqBitWidth)
		}
	}
	if v3.VTargetsBits[9] != vTargetsFormatDense {
		t.Fatalf("VTargets v3 format=%d want dense=%d", v3.VTargetsBits[9], vTargetsFormatDense)
	}
	v3.QPayload = nil
	v3.BarSets = nil
	v3.VTargets = nil
	if !reflect.DeepEqual(v3.QPayloadMatrix(), matrix) || !reflect.DeepEqual(v3.BarSetsMatrix(), matrix) || !reflect.DeepEqual(v3.VTargetsMatrix(), matrix) {
		t.Fatal("fixed-width v3 frames did not round trip through proof accessors")
	}

	v2 := &Proof{TranscriptVersion: TranscriptVersionSmallWood2025V2}
	wantQ, _, _, _ := decs.PackUintMatrix(matrix)
	wantBar := append([]byte(nil), wantQ...)
	wantV, _, _, _ := packProofVTargets(v2, matrix)
	v2.setQPayload(matrix)
	v2.setBarSets(matrix)
	v2.setVTargets(matrix)
	if !bytes.Equal(v2.QPayloadBits, wantQ) || !bytes.Equal(v2.BarSetsBits, wantBar) || !bytes.Equal(v2.VTargetsBits, wantV) {
		t.Fatal("v3 fixed-width branch changed a v2 setter encoding")
	}
}

func TestCanonicalProofV3MerklePositionsNonPowerOfTwo(t *testing.T) {
	depth, err := canonicalMerkleDepth(13)
	if err != nil || depth != 4 {
		t.Fatalf("depth=%d err=%v want 4", depth, err)
	}
	tail := []int{2, 3, 12}
	keys := canonicalOpeningPositionKeys(tail, 13)
	want := []canonicalAuthPosition{{start: 0, end: 2}, {start: 4, end: 8}, {start: 8, end: 12}}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("canonical keys=%+v want %+v", keys, want)
	}
	positions, err := decs.MerkleFrontierPositionsV3(tail, 13)
	if err != nil {
		t.Fatal(err)
	}
	if len(positions) != len(keys) {
		t.Fatalf("codec keys=%d DECS positions=%d", len(keys), len(positions))
	}
	for i, position := range positions {
		if keys[i] != (canonicalAuthPosition{start: position.Start, end: position.End}) {
			t.Fatalf("codec/DECS position %d differs: %+v vs %+v", i, keys[i], position)
		}
	}
}

func TestCanonicalProofV3CompletePublicStatement(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	ctx := canonicalPreSignContextForTest(t, 7)
	g, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base, err := canonicalPublicInputsBytesV3(g.pub)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := canonicalPublicStatementWithLayoutBytesV3(g.pub, g.layout)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bound, g.publicStatement) {
		t.Fatal("canonical proof geometry did not bind the reconstructed row layout")
	}
	mutations := []func(*PublicInputs){
		func(pub *PublicInputs) { pub.X0CoeffBound++ },
		func(pub *PublicInputs) { pub.TargetDim++ },
		func(pub *PublicInputs) { pub.TargetHidingLambda++ },
		func(pub *PublicInputs) { pub.ContextDigest = []byte{1} },
		func(pub *PublicInputs) { pub.T = []int64{-1} },
	}
	for i, mutate := range mutations {
		changed := g.pub
		mutate(&changed)
		encoded, err := canonicalPublicInputsBytesV3(changed)
		if err != nil {
			t.Fatalf("mutation %d: %v", i, err)
		}
		if bytes.Equal(base, encoded) {
			t.Fatalf("mutation %d did not change complete public statement", i)
		}
	}
	unsupported := g.pub
	unsupported.Extras = make(map[string]interface{}, len(g.pub.Extras)+1)
	for key, value := range g.pub.Extras {
		unsupported.Extras[key] = value
	}
	unsupported.Extras["unsupported"] = 7
	if _, err := canonicalPublicInputsBytesV3(unsupported); err == nil {
		t.Fatal("strict public statement accepted a non-byte Extra")
	}
}

func TestCanonicalProofV3BindsCompleteVersionTuple(t *testing.T) {
	for _, theta := range []int{7, 13} {
		ctx := canonicalPreSignContextForTest(t, theta)
		geometry, err := deriveCanonicalProofGeometryV3(ctx)
		if err != nil {
			t.Fatalf("theta=%d: derive target geometry: %v", theta, err)
		}
		presetID := credential.IntGenISISPresetSystemN1024WF128CROMV2
		if theta == 13 {
			presetID = credential.IntGenISISPresetPoCN1024BQ128R128V3
		}
		preset, err := credential.MustLookupIntGenISISPreset(presetID)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"IntGenISIS.preset_version":                   "3",
			"IntGenISIS.proof_schema_version":             "3",
			"IntGenISIS.relation_version":                 "3",
			"IntGenISIS.layout_version":                   "3",
			"IntGenISIS.state_format_version":             "8",
			"IntGenISIS.presentation_format_version":      "3",
			"IntGenISIS.issuance_artifact_format_version": "4",
			"IntGenISIS.holder_usage_format_version":      "3",
			"IntGenISIS.presentation_schema":              credential.IntGenISISPresentationSchemaV3,
		}
		for key, expected := range want {
			got, ok := geometry.pub.Extras[key].([]byte)
			if !ok || string(got) != expected {
				t.Fatalf("theta=%d: version binding %q=%q want %q", theta, key, got, expected)
			}
		}
		var manifest struct {
			PresetVersion       int `json:"preset_version"`
			ProofSchemaVersion  int `json:"proof_schema_version"`
			RelationVersion     int `json:"relation_version"`
			LayoutVersion       int `json:"layout_version"`
			StateFormatVersion  int `json:"state_format_version"`
			PresentationVersion int `json:"presentation_format_version"`
			IssuanceVersion     int `json:"issuance_artifact_format_version"`
			HolderUsageVersion  int `json:"holder_usage_format_version"`
		}
		manifestBytes := geometry.pub.Extras["IntGenISIS.preset_manifest"].([]byte)
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			t.Fatalf("theta=%d: decode bound canonical manifest: %v", theta, err)
		}
		if manifest.PresetVersion != preset.PresetVersion ||
			manifest.ProofSchemaVersion != preset.ProofSchemaVersion ||
			manifest.RelationVersion != preset.RelationVersion || manifest.LayoutVersion != preset.LayoutVersion ||
			manifest.StateFormatVersion != preset.StateFormatVersion || manifest.PresentationVersion != preset.PresentationVersion ||
			manifest.IssuanceVersion != preset.IssuanceVersion || manifest.HolderUsageVersion != preset.HolderUsageVersion {
			t.Fatalf("theta=%d: canonical manifest omitted or changed the v3 version tuple: %+v", theta, manifest)
		}
	}
}

func TestCanonicalProofV3BindsFixedPRFAndSemanticProfiles(t *testing.T) {
	for _, theta := range []int{7, 13} {
		t.Run(map[int]string{7: "WF128", 13: "BQ128"}[theta], func(t *testing.T) {
			ctx := canonicalPreSignContextForTest(t, theta)
			geometry, err := deriveCanonicalProofGeometryV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			preset, err := targetPresetForPRFOptsV3(ctx.Options)
			if err != nil {
				t.Fatal(err)
			}
			params, expectedPRF, err := prf.LoadEmbeddedTargetParamsV3(preset.PRFParamsPath)
			if err != nil {
				t.Fatal(err)
			}
			gotPRF, ok := geometry.pub.Extras["IntGenISIS.prf_params"].([]byte)
			if !ok || !bytes.Equal(gotPRF, expectedPRF) {
				t.Fatal("strict-v3 public statement omitted or changed complete PRF constants")
			}
			layout, err := intGenISISSemanticLayout(geometry.pub.RingDegree, geometry.pub.BoundB)
			if err != nil {
				t.Fatal(err)
			}
			gotLayout, ok := geometry.pub.Extras["IntGenISIS.semantic_message_layout"].([]byte)
			if !ok || !bytes.Equal(gotLayout, layout.CanonicalBytesV3()) || len(gotLayout) <= 32 {
				t.Fatal("strict-v3 public statement omitted complete semantic-layout bytes")
			}

			for _, key := range []string{"IntGenISIS.prf_params", "IntGenISIS.semantic_message_layout"} {
				mutated := cloneCanonicalPublicInputsForTest(geometry.pub)
				value := append([]byte(nil), mutated.Extras[key].([]byte)...)
				value[len(value)/2] ^= 1
				mutated.Extras[key] = value
				encoded, err := canonicalPublicStatementWithLayoutBytesV3(mutated, geometry.layout)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(encoded, geometry.publicStatement) {
					t.Fatalf("complete public statement did not bind %s", key)
				}
			}

			// A relocated, semantically identical JSON profile is accepted: the
			// path is operational metadata, not statement material.
			reencoded, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "relocated-prf.json")
			if err := os.WriteFile(path, reencoded, 0o600); err != nil {
				t.Fatal(err)
			}
			relocated := ctx
			relocated.Options.PRFParamsPath = path
			if _, err := deriveCanonicalProofGeometryV3(relocated); err != nil {
				t.Fatalf("semantically identical relocated PRF profile rejected: %v", err)
			}

			params.CInt[0] = (params.CInt[0] + 1) % params.Q
			altered, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, altered, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := deriveCanonicalProofGeometryV3(relocated); err == nil || !strings.Contains(err.Error(), "do not match fixed profile") {
				t.Fatalf("altered strict-v3 PRF relation accepted: %v", err)
			}

			missing := ctx
			missing.Options.PRFParamsPath = filepath.Join(t.TempDir(), "missing-custom-profile.json")
			if _, err := deriveCanonicalProofGeometryV3(missing); err == nil {
				t.Fatal("missing arbitrary strict-v3 PRF path received a fallback")
			}
		})
	}
}

func FuzzUnmarshalCanonicalProofV3(f *testing.F) {
	ctx := canonicalPreSignContextForTest(f, 7)
	geometry, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		f.Fatalf("derive synthetic WF128 geometry: %v", err)
	}
	proof := canonicalSyntheticProofV3(f, geometry)
	wire, err := MarshalCanonicalProof(proof, ctx)
	if err != nil {
		f.Fatalf("marshal synthetic WF128 seed: %v", err)
	}
	f.Add(wire)
	f.Add([]byte{})
	f.Add(append([]byte(nil), canonicalProofMagicV6[:]...))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, decodeErr := UnmarshalCanonicalProof(data, ctx)
		if decodeErr != nil {
			return
		}
		reencoded, encodeErr := MarshalCanonicalProof(decoded, ctx)
		if encodeErr != nil {
			t.Fatalf("successfully decoded proof does not re-encode: %v", encodeErr)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatal("successfully decoded proof has a noncanonical byte representation")
		}
	})
}

func canonicalPreSignContextForTest(t testing.TB, theta int) CanonicalProofContext {
	t.Helper()
	chdirForPIOPIntGenISISTest(t)
	presetID := credential.IntGenISISPresetSystemN1024WF128CROMV2
	if theta == 13 {
		presetID = credential.IntGenISISPresetPoCN1024BQ128R128V3
	}
	preset, err := credential.MustLookupIntGenISISPreset(presetID)
	if err != nil {
		t.Fatal(err)
	}
	tuning := preset.Issuance
	protocol, transcriptVersion, err := credential.ResolveIntGenISISTranscript(tuning.TranscriptMode)
	if err != nil {
		t.Fatal(err)
	}
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		t.Fatalf("missing profile %q", preset.Profile)
	}
	pp := credential.PublicParams{
		Profile:              preset.Profile,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PRFProfile:           preset.PRFProfile,
		TranscriptMode:       preset.Showing.TranscriptMode,
		PresetManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		RateLimitPolicy:      preset.RateLimitPolicy,
		Modulus:              ringQ.Modulus[0],
	}
	zero := func() *ring.Poly { return ringQ.NewPoly() }
	pub := PublicInputs{
		Com:            []*ring.Poly{zero()},
		CM:             [][]*ring.Poly{{zero()}},
		AS:             [][]*ring.Poly{{zero()}},
		BoundB:         credential.IntGenISISLiveBound,
		HashInputBound: credential.IntGenISISHashInputBound,
		X0Len:          profile.EllX0,
		RingDegree:     1024,
		HashRelation:   credential.HashRelationBBTran,
		IntGenISIS:     true,
		Extras:         pp.PresetTranscriptExtras(nil),
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:               true,
		RingDegree:               1024,
		NCols:                    tuning.NCols,
		LVCSNCols:                tuning.LVCSNCols,
		NLeaves:                  tuning.NLeaves,
		Ell:                      tuning.Ell,
		EllPrime:                 tuning.EllPrime,
		Eta:                      tuning.Eta,
		Rho:                      tuning.Rho,
		Theta:                    tuning.Theta,
		Kappa:                    tuning.Kappa,
		ROQueryCaps:              tuning.ROQueryCaps,
		ROQueryCapsSet:           tuning.ROQueryCapsSet,
		ROQueryCapBits:           tuning.ROQueryCapBits,
		ROQueryCapBitsSet:        tuning.ROQueryCapBitsSet,
		DECSCollisionBits:        tuning.DECSCollisionBits,
		DECSHashBits:             tuning.DECSHashBits,
		DECSTapeBits:             tuning.DECSTapeBits,
		FSCollisionBits:          tuning.FSCollisionBits,
		SaltBits:                 tuning.SaltBits,
		DomainMode:               DomainModeExplicit,
		TranscriptOmissionMode:   tuning.TranscriptOmissionMode,
		TranscriptProtocolMode:   protocol,
		TranscriptVersion:        transcriptVersion,
		FixedTranscriptSize:      tuning.FixedTranscriptSize,
		IntGenISISMSECompression: tuning.CompressedRows,
	})
	return CanonicalProofContext{Kind: CanonicalProofPreSign, Public: pub, Options: opts}
}

func canonicalSyntheticProofV3(t testing.TB, g *canonicalProofGeometryV3) *Proof {
	t.Helper()
	matrix := func(rows, cols int, domain uint64) [][]uint64 {
		out := make([][]uint64, rows)
		for i := range out {
			out[i] = make([]uint64, cols)
			for j := range out[i] {
				out[i][j] = (domain + uint64(i*cols+j)*17) % g.q
			}
		}
		return out
	}
	matrices := canonicalProofMatricesV3{
		r:        matrix(g.rRows, g.rCols, 1),
		qCompact: matrix(g.qRows, g.qWireCols, 2),
		vTargets: matrix(g.vRows, g.vCols, 3),
		barSets:  matrix(g.barRows, g.barCols, 4),
	}
	for i, width := range g.vRowWidths {
		for j := width; j < g.vCols; j++ {
			matrices.vTargets[i][j] = 0
		}
	}
	root := make([]byte, g.hashBytes)
	for i := range root {
		root[i] = byte(i + 1)
	}
	salt := make([]byte, g.saltBytes)
	for i := range salt {
		salt[i] = byte(0xa5 ^ i)
	}
	proof, err := grindCanonicalProofV3(g, root, salt, matrices)
	if err != nil {
		t.Fatalf("construct synthetic proof: %v", err)
	}
	open := &decs.DECSOpening{
		Version:        decs.OpeningVersionV2,
		Role:           decs.CommitmentRoleMain,
		TapeBytes:      g.tapeBytes,
		FormatVersion:  decs.OpeningFormatOmitCols,
		PColsEncoded:   g.openingPCols,
		MFormatVersion: decs.OpeningFormatOmitCols,
		MColsEncoded:   0,
		Indices:        append([]int(nil), proof.Tail...),
		R:              g.totalRows,
		Eta:            g.opts.Eta,
		PvalsBitWidth:  canonicalFqBitWidth,
	}
	open.Pvals = matrix(g.openingEntries, g.openingPCols, 5)
	open.Tapes = make([][]byte, g.openingEntries)
	for i := range open.Tapes {
		open.Tapes[i] = make([]byte, g.tapeBytes)
		for j := range open.Tapes[i] {
			open.Tapes[i][j] = byte(1 + (i*31+j)%251)
		}
	}
	open.PathIndex = make([][]int, len(proof.Tail))
	nodeByPosition := make(map[canonicalAuthPosition]int)
	for row, index := range proof.Tail {
		positions, err := decs.MerkleAuthenticationPathPositionsV3(index, g.opts.NLeaves)
		if err != nil {
			t.Fatalf("derive synthetic authentication path %d: %v", row, err)
		}
		open.PathIndex[row] = make([]int, len(positions))
		for level, position := range positions {
			key := canonicalAuthPosition{start: position.Start, end: position.End}
			nodeID, ok := nodeByPosition[key]
			if !ok {
				node := make([]byte, g.hashBytes)
				binary.LittleEndian.PutUint64(node, uint64(key.start))
				binary.LittleEndian.PutUint64(node[8:], uint64(key.end))
				for j := 16; j < len(node); j++ {
					node[j] = byte(1 + (key.start*13+key.end+j)%251)
				}
				nodeID = len(open.Nodes)
				nodeByPosition[key] = nodeID
				open.Nodes = append(open.Nodes, node)
			}
			open.PathIndex[row][level] = nodeID
		}
	}
	proof.PCSOpening = open
	proof.RowOpening = open
	return proof
}

func expectCanonicalProofDecodeError(t *testing.T, wire []byte, ctx CanonicalProofContext) {
	t.Helper()
	if _, err := UnmarshalCanonicalProof(wire, ctx); err == nil {
		t.Fatal("accepted noncanonical proof wire")
	}
}

func canonicalOverwriteUint(out []byte, bitPos, width int, value uint64) {
	for bit := 0; bit < width; bit++ {
		pos := bitPos + bit
		mask := byte(1 << uint(pos&7))
		out[pos>>3] &^= mask
		if value&(uint64(1)<<bit) != 0 {
			out[pos>>3] |= mask
		}
	}
}

func cloneCanonicalPublicInputsForTest(in PublicInputs) PublicInputs {
	out := in
	out.CM = make([][]*ring.Poly, len(in.CM))
	for i := range in.CM {
		out.CM[i] = make([]*ring.Poly, len(in.CM[i]))
		for j := range in.CM[i] {
			out.CM[i][j] = in.CM[i][j].CopyNew()
		}
	}
	out.Extras = make(map[string]interface{}, len(in.Extras))
	for key, value := range in.Extras {
		if raw, ok := value.([]byte); ok {
			out.Extras[key] = append([]byte(nil), raw...)
		} else {
			out.Extras[key] = value
		}
	}
	return out
}

func cloneCanonicalOpeningForTest(in *decs.DECSOpening) *decs.DECSOpening {
	out := *in
	out.Indices = append([]int(nil), in.Indices...)
	out.Pvals = copyMatrix(in.Pvals)
	out.Tapes = make([][]byte, len(in.Tapes))
	for i := range in.Tapes {
		out.Tapes[i] = append([]byte(nil), in.Tapes[i]...)
	}
	out.Nodes = make([][]byte, len(in.Nodes))
	for i := range in.Nodes {
		out.Nodes[i] = append([]byte(nil), in.Nodes[i]...)
	}
	out.PathIndex = make([][]int, len(in.PathIndex))
	for i := range in.PathIndex {
		out.PathIndex[i] = append([]int(nil), in.PathIndex[i]...)
	}
	return &out
}
