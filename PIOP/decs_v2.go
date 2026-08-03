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
	ctx := decs.CommitmentContext{
		TranscriptVersion: TranscriptVersionSmallWood2025V2,
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

func qCommitmentContextV2(salt []byte) (decs.CommitmentContext, error) {
	return commitmentContextV2(salt, decs.CommitmentRoleQPayload)
}

func validateIntGenISISV2TranscriptOpts(opts SimOpts) error {
	version := normalizeTranscriptVersion(opts.TranscriptVersion)
	protocol := normalizeTranscriptProtocolMode(opts.TranscriptProtocolMode)
	if version != TranscriptVersionSmallWood2025V2 || protocol != TranscriptProtocolSmallField2025V2 {
		return fmt.Errorf(
			"PIOP: IntGenISIS requires transcript tuple (%q,%q), got (%q,%q)",
			TranscriptVersionSmallWood2025V2,
			TranscriptProtocolSmallField2025V2,
			version,
			protocol,
		)
	}
	if opts.TranscriptOmissionMode != SmallField2025TranscriptOmissionModeDigestBoundV2 {
		return fmt.Errorf(
			"PIOP: IntGenISIS v2 requires transcript omission mode %q, got %q",
			SmallField2025TranscriptOmissionModeDigestBoundV2,
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
// report is live only for the exact v2 transcript tuple and omission descriptor,
// a full declared-width root, and Version 2 openings containing one uniform
// independent tape per selectively opened leaf under their exact protocol roles.
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
	if proof.SchemaVersion != ProofSchemaVersionV2 ||
		normalizeTranscriptVersion(proof.TranscriptVersion) != TranscriptVersionSmallWood2025V2 ||
		normalizeTranscriptProtocolMode(proof.TranscriptProtocolMode) != TranscriptProtocolSmallField2025V2 ||
		!decs.IsSupportedHashBytes(out.RootWidthBytes) ||
		proofHasLegacyQDECS(proof) ||
		!proofHasExactSmallField2025LiveV2Metadata(proof) {
		return out
	}
	if _, err := mainCommitmentContextV2(proof.Salt); err != nil {
		return out
	}
	out.TapeDisclosureMode = tapeDisclosureModeIndependentSelective
	out.LeafEncodingVersion = int(decs.OpeningVersionV2)
	out.ZeroKnowledgeEligible = true
	return out
}
