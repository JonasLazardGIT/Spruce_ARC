package evidence

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func RenderGeneratedTeX(lock ArtifactLock) (macros, tables []byte, err error) {
	if lock.Schema != LockSchemaV2 || lock.Version != LockVersionV2 {
		return nil, nil, fmt.Errorf("cannot render non-v2 artifact lock")
	}
	var macro bytes.Buffer
	macro.WriteString("% Generated deterministically by spruce-evidence from the v2 artifact lock.\n")
	macro.WriteString("% The tracked copy lets the paper build without a SPRUCE checkout.\n")
	status := "validated proof-layer v2 evidence"
	if lock.Status == "pending" {
		status = "pending final v2 measurements"
	}
	writeTeXMacro(&macro, "SpruceEvidenceStatus", status, false)
	writeTeXMacro(&macro, "SpruceEvidenceLockSchema", lock.Schema, true)
	writeTeXMacro(&macro, "SpruceEvidenceSourceDigest", lock.SourceTree.Digest, true)
	gitRevision := "unavailable"
	if lock.Git != nil {
		gitRevision = lock.Git.Revision
	}
	writeTeXMacro(&macro, "SpruceEvidenceGitRevision", gitRevision, true)
	writeTeXMacro(&macro, "SpruceEvidenceSchema", lock.Schema, true)
	writeTeXMacro(&macro, "SpruceEvidenceDigest", lock.EvidenceDigest, true)
	writeTeXMacro(&macro, "SpruceSourceTreeDigest", lock.SourceTree.Digest, true)
	writeTeXMacro(&macro, "SpruceProtocolMode", lock.Identities.ProtocolMode, true)
	writeTeXMacro(&macro, "SpruceTranscriptVersion", lock.Identities.TranscriptVersion, true)
	writeTeXMacro(&macro, "SpruceSecurityStatus", lock.Identities.SecurityStatus, true)
	writeTeXMacro(&macro, "SpruceManifestSchema", lock.Identities.ManifestSchema, true)
	writeTeXMacro(&macro, "SprucePresentationSchema", lock.Identities.PresentationSchema, true)
	writeTeXMacro(&macro, "SprucePCSGeometry", lock.Identities.PCSGeometry, true)
	writeTeXMacro(&macro, "SpruceOmissionDescriptor", lock.Identities.OmissionDescriptor, true)
	writeTeXMacro(&macro, "SprucePresetCount", strconv.Itoa(lock.PresetCount), false)
	writeTeXMacro(&macro, "SpruceBaselineAggregation", lock.Aggregation, true)
	writeTeXMacro(&macro, "SpruceBaselineRunCount", strconv.Itoa(lock.RunCount), false)
	writeTeXMacro(&macro, "SpruceBaselineRunDigestCount", strconv.Itoa(lock.RunDigestCount), false)

	var table bytes.Buffer
	table.WriteString("% Generated deterministically by spruce-evidence from the v2 artifact lock.\n")
	table.WriteString("\\providecommand{\\SpruceGeneratedEvidenceSummary}{%\n")
	table.WriteString("\\begin{table*}[t]\n")
	table.WriteString("  \\centering\n")
	table.WriteString("  \\scriptsize\n")
	table.WriteString("  \\begin{tabular}{@{}lrrrrrrrr@{}}\n")
	table.WriteString("    \\toprule\n")
	table.WriteString("    Canonical preset & target & $r_{\\mathrm{iss}}$ & $d_{\\mathrm{iss}}$ & $r_{\\mathrm{show}}$ & $d_{\\mathrm{show}}$ & leaves & $\\eta$ & $\\theta$\\\\\n")
	table.WriteString("    \\midrule\n")
	for _, preset := range lock.Presets {
		table.WriteString("    " + teletype(preset.CanonicalID))
		if preset.Benchmark == nil || preset.Baseline == nil {
			table.WriteString(" & pending & pending & pending & pending & pending & pending & pending & pending\\\\\n")
			continue
		}
		bench := preset.Benchmark
		issuanceRows := formalRows(bench.Issuance)
		showingRows := formalRows(bench.Showing)
		issuanceDegree := formalDegree(bench.Issuance)
		showingDegree := formalDegree(bench.Showing)
		fmt.Fprintf(&table, " & %s & %d & %d & %d & %d & %d & %d & %d\\\\\n",
			formatFloat(bench.Security.TargetBits), issuanceRows, issuanceDegree,
			showingRows, showingDegree, bench.Showing.NLeaves, bench.Showing.Eta, bench.Showing.Theta)
	}
	table.WriteString("    \\bottomrule\n")
	table.WriteString("  \\end{tabular}\n")
	table.WriteString("  \\caption{Generated v2 relation geometry and SmallWood proof-layer targets. Rows and degrees come from the formal relation report; the tuning columns are the final retuned showing parameters.}\n")
	table.WriteString("  \\label{tab:generated-v2-relation}\n")
	table.WriteString("\\end{table*}%\n")
	table.WriteString("\n")
	table.WriteString("\\begin{table*}[t]\n")
	table.WriteString("  \\centering\n")
	table.WriteString("  \\scriptsize\n")
	table.WriteString("  \\begin{tabular}{@{}lrrrrrrr@{}}\n")
	table.WriteString("    \\toprule\n")
	table.WriteString("    Canonical preset & issuance B & showing B & combined B & issue prove ms & issue verify ms & show prove ms & show verify ms\\\\\n")
	table.WriteString("    \\midrule\n")
	for _, preset := range lock.Presets {
		table.WriteString("    " + teletype(preset.CanonicalID))
		if preset.Benchmark == nil || preset.Baseline == nil {
			table.WriteString(" & pending & pending & pending & pending & pending & pending & pending\\\\\n")
			continue
		}
		bench := preset.Benchmark
		median := preset.Baseline.MedianTimings
		issuanceBytes := bench.Issuance.WireSizes.PaperTranscript
		showingBytes := bench.Showing.WireSizes.PaperTranscript
		fmt.Fprintf(&table, " & %d & %d & %d & %s & %s & %s & %s\\\\\n",
			issuanceBytes, showingBytes, issuanceBytes+showingBytes,
			formatFloat(median.Issuance.ProvingMS), formatFloat(median.Issuance.VerificationMS),
			formatFloat(median.Showing.ProvingMS), formatFloat(median.Showing.VerificationMS))
	}
	table.WriteString("    \\bottomrule\n")
	table.WriteString("  \\end{tabular}\n")
	table.WriteString("  \\caption{Generated v2 wire sizes and independent scalar timing medians from three sequential runs per preset. Timings are observations, not security parameters.}\n")
	table.WriteString("  \\label{tab:generated-v2-evidence}\n")
	table.WriteString("\\end{table*}%\n")
	table.WriteString("}\n")
	return macro.Bytes(), table.Bytes(), nil
}

func formalRows(phase PhaseEvidence) int {
	if phase.Rows.Logical > 0 {
		return phase.Rows.Logical
	}
	return phase.Rows.Total
}

func formalDegree(phase PhaseEvidence) int {
	if phase.Degrees.ParallelAlgebraic > 0 {
		return phase.Degrees.ParallelAlgebraic
	}
	return phase.Degrees.Parallel
}

func WriteGeneratedTeX(dir string, lock ArtifactLock) error {
	macros, tables, err := RenderGeneratedTeX(lock)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, GeneratedMacrosFileName), macros, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, GeneratedTableFileName), tables, 0o644)
}

func ValidateGeneratedTeX(dir string, lock ArtifactLock) error {
	wantMacros, wantTables, err := RenderGeneratedTeX(lock)
	if err != nil {
		return err
	}
	checks := []struct {
		name string
		want []byte
	}{
		{GeneratedMacrosFileName, wantMacros},
		{GeneratedTableFileName, wantTables},
	}
	for _, check := range checks {
		path := filepath.Join(dir, check.name)
		have, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read generated TeX %s: %w", path, err)
		}
		if !bytes.Equal(have, check.want) {
			return fmt.Errorf("generated TeX %s differs from artifact lock; regenerate evidence", path)
		}
	}
	return nil
}

func writeTeXMacro(out *bytes.Buffer, name, value string, code bool) {
	fmt.Fprintf(out, "\\providecommand{\\%s}{", name)
	if code {
		out.WriteString(teletype(value))
	} else {
		out.WriteString(value)
	}
	out.WriteString("}\n")
}

func teletype(value string) string {
	return "\\texttt{\\detokenize{" + value + "}}"
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}
