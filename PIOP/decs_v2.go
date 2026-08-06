package PIOP

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	decs "vSIS-Signature/DECS"
)

const tapeDisclosureModeIndependentSelective = "independent_selective"

type decsV2DisclosureAccounting struct {
	TapeBytes             int
	TapeCount             int
	TapeWidthBytes        int
	TapeDisclosureMode    string
	LeafEncodingVersion   int
	RootWidthBytes        int
	ZeroKnowledgeEligible bool
}

type retainedDECSOpeningKind uint8

const (
	retainedDECSOpeningMain retainedDECSOpeningKind = iota
	retainedDECSOpeningSigShortness
	retainedDECSOpeningSourceReplay
	retainedDECSOpeningPRFCompanion
)

type retainedDECSOpening struct {
	Kind         retainedDECSOpeningKind
	Opening      *decs.DECSOpening
	ExpectedRole decs.CommitmentRole
}

// retainedDECSOpenings enumerates every independently serialized selective
// opening in a proof. The role is part of each opening's commitment identity;
// auxiliary openings must therefore retain their protocol-specific role rather
// than being flattened into the main commitment role for accounting purposes.
func retainedDECSOpenings(proof *Proof) []retainedDECSOpening {
	if proof == nil {
		return nil
	}
	out := make([]retainedDECSOpening, 0, 4)
	if open := resolveProofPCSOpening(proof); open != nil {
		out = append(out, retainedDECSOpening{
			Kind:         retainedDECSOpeningMain,
			Opening:      open,
			ExpectedRole: decs.CommitmentRoleMain,
		})
	}
	if proof.SigShortness != nil && proof.SigShortness.Opening != nil {
		out = append(out, retainedDECSOpening{
			Kind:         retainedDECSOpeningSigShortness,
			Opening:      proof.SigShortness.Opening,
			ExpectedRole: decs.CommitmentRoleSigShortness,
		})
	}
	if proof.SourceProductBridge != nil && proof.SourceProductBridge.RowsOpening != nil {
		out = append(out, retainedDECSOpening{
			Kind:         retainedDECSOpeningSourceReplay,
			Opening:      proof.SourceProductBridge.RowsOpening,
			ExpectedRole: decs.CommitmentRoleReplay,
		})
	}
	if proof.PRFCompanion != nil && proof.PRFCompanion.Bridge != nil && proof.PRFCompanion.Bridge.RowsOpening != nil {
		out = append(out, retainedDECSOpening{
			Kind:         retainedDECSOpeningPRFCompanion,
			Opening:      proof.PRFCompanion.Bridge.RowsOpening,
			ExpectedRole: decs.CommitmentRoleCompanion,
		})
	}
	return out
}

func sampleProofSaltV2(opts SimOpts) ([]byte, error) {
	opts.applyDefaults()
	salt := make([]byte, fsSaltBytesForOpts(opts))
	if len(salt) < decs.MinSaltBytes || len(salt) > decs.MaxSaltBytes {
		return nil, fmt.Errorf("PIOP: v2 salt width=%d outside DECS range %d..%d", len(salt), decs.MinSaltBytes, decs.MaxSaltBytes)
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("PIOP: sample proof-global salt: %w", err)
	}
	return salt, nil
}

func commitmentContextV2(salt []byte, role decs.CommitmentRole) (decs.CommitmentContext, error) {
	return commitmentContextForTranscript(salt, role, TranscriptVersionSmallWood2025V2)
}

func commitmentContextForTranscript(salt []byte, role decs.CommitmentRole, transcriptVersion string) (decs.CommitmentContext, error) {
	version := normalizeTranscriptVersion(transcriptVersion)
	if version == "" {
		version = TranscriptVersionSmallWood2025V2
	}
	// Publication v4 retains the audited DECS-v3 commitment codec and domains;
	// the enclosing Fiat--Shamir initialization binds the v4 policy, phase,
	// relation, manifest statement, and actual output width.
	if version == TranscriptVersionSmallWood2025V4 {
		version = TranscriptVersionSmallWood2025V3
	}
	if version != TranscriptVersionSmallWood2025V2 && version != TranscriptVersionSmallWood2025V3 {
		return decs.CommitmentContext{}, fmt.Errorf("PIOP: unsupported DECS transcript version %q", version)
	}
	ctx := decs.CommitmentContext{
		TranscriptVersion: version,
		Role:              role,
		Salt:              append([]byte(nil), salt...),
	}
	if err := ctx.Validate(); err != nil {
		return decs.CommitmentContext{}, err
	}
	return ctx, nil
}

func mainCommitmentContextV2(salt []byte) (decs.CommitmentContext, error) {
	return commitmentContextV2(salt, decs.CommitmentRoleMain)
}

func mainCommitmentContextForTranscript(salt []byte, transcriptVersion string) (decs.CommitmentContext, error) {
	return commitmentContextForTranscript(salt, decs.CommitmentRoleMain, transcriptVersion)
}

func qCommitmentContextV2(salt []byte) (decs.CommitmentContext, error) {
	return commitmentContextV2(salt, decs.CommitmentRoleQPayload)
}

func qCommitmentContextForTranscript(salt []byte, transcriptVersion string) (decs.CommitmentContext, error) {
	return commitmentContextForTranscript(salt, decs.CommitmentRoleQPayload, transcriptVersion)
}

func validateIntGenISISV2TranscriptOpts(opts SimOpts) error {
	if err := opts.ExecutionPolicy.Validate(); err != nil {
		return err
	}
	version := normalizeTranscriptVersion(opts.TranscriptVersion)
	protocol := normalizeTranscriptProtocolMode(opts.TranscriptProtocolMode)
	wantOmission := ""
	switch {
	case version == TranscriptVersionSmallWood2025V2 && protocol == TranscriptProtocolSmallField2025V2:
		wantOmission = SmallField2025TranscriptOmissionModeDigestBoundV2
	case version == TranscriptVersionSmallWood2025V3 && protocol == TranscriptProtocolSmallField2025V3:
		wantOmission = SmallField2025TranscriptOmissionModeCanonicalV3
	case version == TranscriptVersionSmallWood2025V4 && protocol == TranscriptProtocolSmallField2025V4:
		wantOmission = SmallField2025TranscriptOmissionModeCanonicalV3
	default:
		return fmt.Errorf(
			"PIOP: IntGenISIS requires transcript tuple v2, v3, or v4 exactly; got (%q,%q) (v2=(%q,%q), v3=(%q,%q), v4=(%q,%q))",
			version,
			protocol,
			TranscriptVersionSmallWood2025V2,
			TranscriptProtocolSmallField2025V2,
			TranscriptVersionSmallWood2025V3,
			TranscriptProtocolSmallField2025V3,
			TranscriptVersionSmallWood2025V4,
			TranscriptProtocolSmallField2025V4,
		)
	}
	if opts.TranscriptOmissionMode != wantOmission {
		return fmt.Errorf(
			"PIOP: IntGenISIS transcript %q requires transcript omission mode %q, got %q",
			version,
			wantOmission,
			opts.TranscriptOmissionMode,
		)
	}
	return nil
}

func validateProverCommitmentContextV2(pkContext decs.CommitmentContext, expected decs.CommitmentContext) error {
	if err := pkContext.Validate(); err != nil {
		return err
	}
	if pkContext.TranscriptVersion != expected.TranscriptVersion || pkContext.Role != expected.Role || !bytes.Equal(pkContext.Salt, expected.Salt) {
		return fmt.Errorf("PIOP: prover commitment context does not match proof context")
	}
	return nil
}

func validateOpeningRoleV2(open *decs.DECSOpening, role decs.CommitmentRole) error {
	if open == nil {
		return fmt.Errorf("PIOP: missing v2 opening")
	}
	if open.Version != decs.OpeningVersionV2 {
		return fmt.Errorf("PIOP: opening version=%d want=%d", open.Version, decs.OpeningVersionV2)
	}
	if open.Role != role {
		return fmt.Errorf("PIOP: opening role=%q want=%q", open.Role, role)
	}
	if !decs.IsSupportedTapeBytes(open.TapeBytes) || len(open.Tapes) != open.EntryCount() {
		return fmt.Errorf("PIOP: malformed selective tape payload")
	}
	for i, tape := range open.Tapes {
		if len(tape) != open.TapeBytes {
			return fmt.Errorf("PIOP: tape %d width=%d want=%d", i, len(tape), open.TapeBytes)
		}
	}
	return nil
}

// buildDECSV2DisclosureAccounting reports the bytes actually disclosed by all
// retained selective openings. Eligibility is deliberately fail-closed: a
// report is live only for an exact supported strict transcript tuple and
// omission descriptor, a full declared-width root, and Version 2 DECS openings
// containing one uniform independent tape per selectively opened leaf under
// their exact protocol roles. Schema-3 proofs keep DECS opening version 2; only
// the surrounding proof/transcript schema changes.
func buildDECSV2DisclosureAccounting(proof *Proof) decsV2DisclosureAccounting {
	var out decsV2DisclosureAccounting
	if proof == nil {
		return out
	}
	out.RootWidthBytes = len(proof.RootHash)
	openings := retainedDECSOpenings(proof)
	if len(openings) == 0 || openings[0].Kind != retainedDECSOpeningMain {
		return out
	}
	mainOpening := openings[0].Opening
	out.TapeWidthBytes = mainOpening.TapeBytes
	openingsValid := true
	for _, retained := range openings {
		open := retained.Opening
		out.TapeCount += len(open.Tapes)
		for _, tape := range open.Tapes {
			out.TapeBytes += len(tape)
		}
		if open.TapeBytes != out.TapeWidthBytes || open.EntryCount() <= 0 || validateOpeningRoleV2(open, retained.ExpectedRole) != nil {
			openingsValid = false
		}
	}
	if !openingsValid {
		out.TapeWidthBytes = 0
		return out
	}
	version := normalizeTranscriptVersion(proof.TranscriptVersion)
	protocol := normalizeTranscriptProtocolMode(proof.TranscriptProtocolMode)
	strictTuple := (proof.SchemaVersion == ProofSchemaVersionV2 &&
		version == TranscriptVersionSmallWood2025V2 && protocol == TranscriptProtocolSmallField2025V2) ||
		(proof.SchemaVersion == ProofSchemaVersionV3 &&
			((version == TranscriptVersionSmallWood2025V3 && protocol == TranscriptProtocolSmallField2025V3) ||
				(version == TranscriptVersionSmallWood2025V4 && protocol == TranscriptProtocolSmallField2025V4)))
	if !strictTuple ||
		!decs.IsSupportedHashBytes(out.RootWidthBytes) ||
		proofHasLegacyQDECS(proof) ||
		!proofHasExactSmallField2025LiveMetadata(proof) {
		return out
	}
	if _, err := mainCommitmentContextForTranscript(proof.Salt, version); err != nil {
		return out
	}
	out.TapeDisclosureMode = tapeDisclosureModeIndependentSelective
	out.LeafEncodingVersion = int(decs.OpeningVersionV2)
	out.ZeroKnowledgeEligible = true
	return out
}
