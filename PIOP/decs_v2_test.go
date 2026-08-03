package PIOP

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func validPIOPV2OpeningForTest(role decs.CommitmentRole) *decs.DECSOpening {
	return &decs.DECSOpening{
		Version:   decs.OpeningVersionV2,
		Role:      role,
		Indices:   []int{3},
		Tapes:     [][]byte{bytes.Repeat([]byte{0x5a}, 16)},
		TapeBytes: 16,
	}
}

func TestIntGenISISBuildersRejectMissingOrUnknownTranscriptTupleBeforeSetup(t *testing.T) {
	validPrepared := &IntGenISISShowingPreparedContext{opts: SimOpts{
		TranscriptVersion:      TranscriptVersionSmallWood2025V2,
		TranscriptProtocolMode: TranscriptProtocolSmallField2025V2,
		TranscriptOmissionMode: SmallField2025TranscriptOmissionModeDigestBoundV2,
	}}
	tests := []struct {
		name string
		run  func(SimOpts) error
	}{
		{
			name: "pre-sign",
			run: func(opts SimOpts) error {
				_, err := BuildIntGenISISPreSign(nil, PublicInputs{}, WitnessInputs{}, opts)
				return err
			},
		},
		{
			name: "prepare showing",
			run: func(opts SimOpts) error {
				_, err := PrepareIntGenISISShowingContext(PublicInputs{}, opts)
				return err
			},
		},
		{
			name: "prepared showing",
			run: func(opts SimOpts) error {
				_, err := BuildIntGenISISShowingCombinedPrepared(PublicInputs{}, WitnessInputs{}, opts, validPrepared)
				return err
			},
		},
	}
	badOpts := []SimOpts{
		{},
		{TranscriptVersion: "unknown", TranscriptProtocolMode: TranscriptProtocolSmallField2025V2},
		{TranscriptVersion: TranscriptVersionSmallWood2025V2, TranscriptProtocolMode: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, opts := range badOpts {
				err := test.run(opts)
				if err == nil || !strings.Contains(err.Error(), "requires transcript tuple") {
					t.Fatalf("opts=(%q,%q) error=%v; want transcript rejection", opts.TranscriptVersion, opts.TranscriptProtocolMode, err)
				}
			}
			unknownOmission := SimOpts{
				TranscriptVersion:      TranscriptVersionSmallWood2025V2,
				TranscriptProtocolMode: TranscriptProtocolSmallField2025V2,
				TranscriptOmissionMode: "unknown",
			}
			err := test.run(unknownOmission)
			if err == nil || !strings.Contains(err.Error(), "requires transcript omission mode") {
				t.Fatalf("unknown omission error=%v; want pre-setup transcript omission rejection", err)
			}
		})
	}
}

func v2AccountingProofForTest() *Proof {
	return &Proof{
		SchemaVersion:          ProofSchemaVersionV2,
		RootHash:               bytes.Repeat([]byte{0x31}, 21),
		Salt:                   bytes.Repeat([]byte{0x42}, 32),
		TranscriptVersion:      TranscriptVersionSmallWood2025V2,
		TranscriptProtocolMode: TranscriptProtocolSmallField2025V2,
		RingDegree:             16,
		QDegreeBound:           8,
		NColsUsed:              4,
		PCSNColsUsed:           4,
		NLeavesUsed:            16,
		SmallField2025: &SmallField2025LVCSProof{
			Version:          smallField2025LVCSProofVersionV2,
			Mode:             TranscriptProtocolSmallField2025V2,
			Status:           SmallField2025StatusLive,
			ReductionEnabled: true,
			HeadDomainMode:   SmallField2025HeadDomainV2,
			TranscriptOmission: &SmallField2025TranscriptOmission{
				Version:                      smallField2025TranscriptOmissionVersionV2,
				Mode:                         SmallField2025TranscriptOmissionModeDigestBoundV2,
				OmitPdecsReconstructibleCols: true,
			},
		},
		PCSOpening: &decs.DECSOpening{
			Version:   decs.OpeningVersionV2,
			Role:      decs.CommitmentRoleMain,
			Indices:   []int{3, 7},
			Tapes:     [][]byte{bytes.Repeat([]byte{0x51}, 16), bytes.Repeat([]byte{0x52}, 16)},
			TapeBytes: 16,
		},
	}
}

func TestValidateOpeningRoleV2RejectsLegacyAndMalformedTapes(t *testing.T) {
	if err := validateOpeningRoleV2(validPIOPV2OpeningForTest(decs.CommitmentRoleMain), decs.CommitmentRoleMain); err != nil {
		t.Fatalf("valid opening rejected: %v", err)
	}
	tests := map[string]func(*decs.DECSOpening){
		"legacy version": func(open *decs.DECSOpening) { open.Version = 0 },
		"wrong role":     func(open *decs.DECSOpening) { open.Role = decs.CommitmentRoleQPayload },
		"missing tape":   func(open *decs.DECSOpening) { open.Tapes = nil },
		"short tape":     func(open *decs.DECSOpening) { open.Tapes[0] = open.Tapes[0][:15] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			open := validPIOPV2OpeningForTest(decs.CommitmentRoleMain)
			mutate(open)
			if err := validateOpeningRoleV2(open, decs.CommitmentRoleMain); err == nil {
				t.Fatal("malformed or legacy opening accepted")
			}
		})
	}
}

func TestProofRootBytesV2NeverFallsBackToLegacyRoot(t *testing.T) {
	proof := &Proof{SchemaVersion: ProofSchemaVersionV2, Root: [16]byte{1}, QRoot: [16]byte{2}}
	if got := proofRootBytes(proof); len(got) != 0 {
		t.Fatalf("main v2 root fell back to legacy field: %x", got)
	}
	if got := proofQRootBytes(proof); len(got) != 0 {
		t.Fatalf("Q v2 root fell back to legacy field: %x", got)
	}
	proof.RootHash = bytes.Repeat([]byte{3}, 21)
	proof.QRootHash = bytes.Repeat([]byte{4}, 23)
	if got := proofRootBytes(proof); !bytes.Equal(got, proof.RootHash) {
		t.Fatalf("main full root mismatch: %x", got)
	}
	if got := proofQRootBytes(proof); !bytes.Equal(got, proof.QRootHash) {
		t.Fatalf("Q full root mismatch: %x", got)
	}
	if got := proofRootSerializedSize(proof); got != len(proof.RootHash) {
		t.Fatalf("main root serialized size=%d want=%d", got, len(proof.RootHash))
	}
	if got := proofQRootSerializedSize(proof); got != len(proof.QRootHash) {
		t.Fatalf("Q root serialized size=%d want=%d", got, len(proof.QRootHash))
	}
}

func TestProofJSONExcludesFixedWidthRootCompatibilityFields(t *testing.T) {
	proof := &Proof{
		SchemaVersion: ProofSchemaVersionV2,
		Root:          [16]byte{1},
		QRoot:         [16]byte{2},
		RootHash:      bytes.Repeat([]byte{3}, 21),
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["Root"]; exists {
		t.Fatalf("fixed-width Root serialized: %s", encoded)
	}
	if _, exists := fields["QRoot"]; exists {
		t.Fatalf("fixed-width QRoot serialized: %s", encoded)
	}
	if _, exists := fields["root_hash"]; !exists {
		t.Fatalf("full root hash missing: %s", encoded)
	}
}

func TestProofReportSerializesIndependentTapeAccounting(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	proof := v2AccountingProofForTest()
	report, err := BuildProofReport(proof, SimOpts{
		RingDegree: 16,
		NCols:      4,
		LVCSNCols:  4,
		Ell:        1,
		EllPrime:   1,
		Rho:        1,
		Theta:      1,
		Eta:        1,
		NLeaves:    16,
		Lambda:     128,
	}, ringQ)
	if err != nil {
		t.Fatalf("BuildProofReport: %v", err)
	}
	if report.TapeBytes != 32 || report.TapeCount != 2 || report.TapeWidthBytes != 16 ||
		report.TapeDisclosureMode != tapeDisclosureModeIndependentSelective ||
		report.LeafEncodingVersion != 2 || report.RootWidthBytes != 21 || !report.ZeroKnowledgeEligible {
		t.Fatalf("unexpected top-level disclosure accounting: %+v", report)
	}
	focus := report.TranscriptFocus
	if focus.TapeBytes != 32 || focus.TapeCount != 2 || focus.TapeWidthBytes != 16 ||
		focus.TapeDisclosureMode != tapeDisclosureModeIndependentSelective ||
		focus.LeafEncodingVersion != 2 || focus.RootWidthBytes != 21 || !focus.ZeroKnowledgeEligible ||
		focus.TranscriptSecurityStatus != SmallField2025StatusLive {
		t.Fatalf("unexpected transcript disclosure accounting: %+v", focus)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"tape_bytes":              float64(32),
		"tape_count":              float64(2),
		"tape_width_bytes":        float64(16),
		"tape_disclosure_mode":    tapeDisclosureModeIndependentSelective,
		"leaf_encoding_version":   float64(2),
		"root_width_bytes":        float64(21),
		"zero_knowledge_eligible": true,
	}
	for key, value := range want {
		if fields[key] != value {
			t.Fatalf("serialized %s=%v want=%v; json=%s", key, fields[key], value, encoded)
		}
	}
}

func TestV2DisclosureAccountingSumsAllRetainedSelectiveOpenings(t *testing.T) {
	proof := v2AccountingProofForTest()
	proof.SigShortness = &SigShortnessProof{
		Version: sigShortnessProofVersionV18,
		Opening: validPIOPV2OpeningForTest(decs.CommitmentRoleSigShortness),
	}
	proof.SigShortness.Opening.Indices = []int{11}
	proof.SourceProductBridge = &SourceProductBridge{
		RowsOpening: validPIOPV2OpeningForTest(decs.CommitmentRoleReplay),
	}
	proof.SourceProductBridge.RowsOpening.Indices = []int{12}
	proof.PRFCompanion = &PRFCompanionProof{
		Bridge: &PRFWitnessOmegaBridge{
			RowsOpening: validPIOPV2OpeningForTest(decs.CommitmentRoleCompanion),
		},
	}
	proof.PRFCompanion.Bridge.RowsOpening.Indices = []int{13}
	accounting := buildDECSV2DisclosureAccounting(proof)
	if accounting.TapeBytes != 80 || accounting.TapeCount != 5 || accounting.TapeWidthBytes != 16 || !accounting.ZeroKnowledgeEligible {
		t.Fatalf("unexpected aggregate selective-tape accounting: %+v", accounting)
	}
}

func TestV2DisclosureAccountingRequiresLocationSpecificOpeningRoles(t *testing.T) {
	proof := v2AccountingProofForTest()
	proof.SigShortness = &SigShortnessProof{Opening: validPIOPV2OpeningForTest(decs.CommitmentRoleSigShortness)}
	proof.SourceProductBridge = &SourceProductBridge{RowsOpening: validPIOPV2OpeningForTest(decs.CommitmentRoleReplay)}
	proof.PRFCompanion = &PRFCompanionProof{Bridge: &PRFWitnessOmegaBridge{RowsOpening: validPIOPV2OpeningForTest(decs.CommitmentRoleCompanion)}}
	if got := buildDECSV2DisclosureAccounting(proof); !got.ZeroKnowledgeEligible {
		t.Fatalf("exact role mapping rejected: %+v", got)
	}
	mutations := []struct {
		name string
		open *decs.DECSOpening
	}{
		{name: "signature shortness", open: proof.SigShortness.Opening},
		{name: "source replay", open: proof.SourceProductBridge.RowsOpening},
		{name: "PRF companion", open: proof.PRFCompanion.Bridge.RowsOpening},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			role := mutation.open.Role
			mutation.open.Role = decs.CommitmentRoleMain
			got := buildDECSV2DisclosureAccounting(proof)
			mutation.open.Role = role
			if got.ZeroKnowledgeEligible || got.TapeWidthBytes != 0 {
				t.Fatalf("wrong auxiliary role received live accounting: %+v", got)
			}
		})
	}
}

func TestProofReportCanonicalTapeAuditAggregatesAuxiliaryOpenings(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	proof := v2AccountingProofForTest()
	proof.SigShortness = &SigShortnessProof{
		Version: sigShortnessProofVersionV18,
		Opening: validPIOPV2OpeningForTest(decs.CommitmentRoleSigShortness),
	}
	report, err := BuildProofReport(proof, SimOpts{RingDegree: 16, NCols: 4, LVCSNCols: 4, Ell: 1, EllPrime: 1, Rho: 1, Theta: 1, Eta: 1, NLeaves: 16, Lambda: 128}, ringQ)
	if err != nil {
		t.Fatalf("BuildProofReport: %v", err)
	}
	if report.TapeBytes != 48 || report.TapeCount != 3 {
		t.Fatalf("proof-wide disclosure accounting mismatch: bytes=%d count=%d", report.TapeBytes, report.TapeCount)
	}
	audit := report.PaperTranscript.Audit.Tapes
	if audit.TapeBytes != report.TapeBytes || audit.TapeCount != report.TapeCount {
		t.Fatalf("canonical tape audit=%+v does not match report bytes=%d count=%d", audit, report.TapeBytes, report.TapeCount)
	}
	if report.PaperTranscript.Tapes.OptimizedBytes < report.TapeBytes {
		t.Fatalf("canonical tape bucket bytes=%d smaller than disclosed payload=%d", report.PaperTranscript.Tapes.OptimizedBytes, report.TapeBytes)
	}
}

func TestProofReportSecurityStatusFailsClosedWithoutIndependentV2Tapes(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Proof){
		func(proof *Proof) { proof.PCSOpening.Version = 1 },
		func(proof *Proof) { proof.PCSOpening.Tapes = proof.PCSOpening.Tapes[:1] },
		func(proof *Proof) { proof.PCSOpening.Tapes[0] = proof.PCSOpening.Tapes[0][:15] },
		func(proof *Proof) { proof.SmallField2025.TranscriptOmission = nil },
		func(proof *Proof) { proof.SmallField2025.TranscriptOmission.Mode = "unknown" },
	} {
		proof := v2AccountingProofForTest()
		mutate(proof)
		report, err := BuildProofReport(proof, SimOpts{RingDegree: 16, NCols: 4, LVCSNCols: 4, Ell: 1, EllPrime: 1, Rho: 1, Theta: 1, Eta: 1, NLeaves: 16, Lambda: 128}, ringQ)
		if err != nil {
			t.Fatalf("BuildProofReport: %v", err)
		}
		if report.ZeroKnowledgeEligible || report.TranscriptFocus.ZeroKnowledgeEligible ||
			report.TranscriptFocus.TranscriptSecurityStatus != SmallField2025StatusRejected ||
			report.TapeDisclosureMode != "" || report.LeafEncodingVersion != 0 {
			t.Fatalf("malformed opening received live accounting: %+v", report.TranscriptFocus)
		}
	}
}
