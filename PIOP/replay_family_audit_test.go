package PIOP

import "testing"

func buildReplayFamilyAuditFixture(t *testing.T) *Proof {
	t.Helper()
	fx := buildPRFCompanionFixture(t)
	proof, err := BuildShowingCombined(fx.base.pub, fx.base.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing proof for replay audit: %v", err)
	}
	return proof
}

func replayAuditEntriesByFamily(entries []ReplayFamilyAuditEntry) map[ReplayFamilyKind]ReplayFamilyAuditEntry {
	out := make(map[ReplayFamilyKind]ReplayFamilyAuditEntry, len(entries))
	for _, entry := range entries {
		out[entry.Family] = entry
	}
	return out
}

func replaySubauditEntriesByKind(entries []ReplaySubfamilyAuditEntry) map[ReplaySubfamilyKind]ReplaySubfamilyAuditEntry {
	out := make(map[ReplaySubfamilyKind]ReplaySubfamilyAuditEntry, len(entries))
	for _, entry := range entries {
		out[entry.Kind] = entry
	}
	return out
}

func sortedUniqueRowsFromEntries(entries []ReplaySubfamilyAuditEntry, family ReplayFamilyKind) []int {
	var rows []int
	for _, entry := range entries {
		if entry.Family != family {
			continue
		}
		rows = append(rows, entry.SelectedRows...)
	}
	return sortedUniqueInts(rows)
}

func TestReplayFamilyAuditIncludesCanonicalFamilies(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	if len(audit.Families) != len(replayFamilyKinds) {
		t.Fatalf("family count=%d want %d", len(audit.Families), len(replayFamilyKinds))
	}
	got := replayAuditEntriesByFamily(audit.Families)
	for _, family := range replayFamilyKinds {
		if _, ok := got[family]; !ok {
			t.Fatalf("missing replay family %q", family)
		}
	}
}

func TestReplayFamilyAuditRowSetsAreSortedAndCoverSelector(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	selector := BuildShowingReplayActiveRowSelector(proof.RowLayout, replayCompanionLayoutFromProof(proof), proofPRFCompanionMode(proof))
	seen := make(map[int]struct{}, len(selector))
	for _, entry := range audit.Families {
		if !isStrictlyIncreasing(entry.LogicalRows) {
			t.Fatalf("%s logical rows not strictly increasing: %v", entry.Family, entry.LogicalRows)
		}
		if !isStrictlyIncreasing(entry.SelectedRows) {
			t.Fatalf("%s selected rows not strictly increasing: %v", entry.Family, entry.SelectedRows)
		}
		for _, idx := range entry.LogicalRows {
			if idx < 0 || idx >= proof.RowLayout.SigCount {
				t.Fatalf("%s logical row %d out of bounds for witness rows=%d", entry.Family, idx, proof.RowLayout.SigCount)
			}
		}
		for _, idx := range entry.SelectedRows {
			if idx < 0 || idx >= proof.RowLayout.SigCount {
				t.Fatalf("%s selected row %d out of bounds for witness rows=%d", entry.Family, idx, proof.RowLayout.SigCount)
			}
			if _, ok := seen[idx]; ok {
				t.Fatalf("selected row %d appears in multiple families", idx)
			}
			seen[idx] = struct{}{}
		}
	}
	if len(seen) != len(selector) {
		t.Fatalf("selected row union size=%d want selector size=%d", len(seen), len(selector))
	}
	for _, idx := range selector {
		if _, ok := seen[idx]; !ok {
			t.Fatalf("selector row %d missing from replay family audit", idx)
		}
	}
}

func TestReplayFamilyAuditDerivedFamiliesAreAlreadyExcluded(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	byFamily := replayAuditEntriesByFamily(audit.Families)
	for _, family := range []ReplayFamilyKind{ReplayFamilyTransformAlias, ReplayFamilyReplayImage} {
		entry, ok := byFamily[family]
		if !ok {
			t.Fatalf("missing replay family %q", family)
		}
		if entry.Derivability != ReplayFamilyAlreadyDerivedNow {
			t.Fatalf("%s derivability=%q want %q", family, entry.Derivability, ReplayFamilyAlreadyDerivedNow)
		}
		if entry.ReductionEffect != ReplayFamilyAlreadyExcludedFromSelector {
			t.Fatalf("%s reduction effect=%q want %q", family, entry.ReductionEffect, ReplayFamilyAlreadyExcludedFromSelector)
		}
	}
}

func TestReplayFamilyAuditRankingIsStable(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	if len(audit.Families) != len(replayFamilyKinds) {
		t.Fatalf("family count=%d want %d", len(audit.Families), len(replayFamilyKinds))
	}
	got := make([]ReplayFamilyKind, 0, len(audit.Families))
	for rank := 1; rank <= len(audit.Families); rank++ {
		found := false
		for _, entry := range audit.Families {
			if entry.PriorityRank != rank {
				continue
			}
			got = append(got, entry.Family)
			found = true
			break
		}
		if !found {
			t.Fatalf("missing family with priority rank=%d", rank)
		}
	}
	want := []ReplayFamilyKind{
		ReplayFamilySourceProduct,
		ReplayFamilyPRFCompanion,
		ReplayFamilyCarrier,
		ReplayFamilyTSource,
		ReplayFamilyReplayImage,
		ReplayFamilyTransformAlias,
	}
	if len(got) != len(want) {
		t.Fatalf("ranked family count=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ranked family[%d]=%q want %q (full order=%v)", i, got[i], want[i], got)
		}
	}
}

func TestReplaySubfamilyAuditIncludesCanonicalKinds(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	sub := audit.Subfamilies
	if len(sub.Entries) == 0 {
		t.Fatalf("missing replay subfamilies")
	}
	byKind := replaySubauditEntriesByKind(sub.Entries)
	for _, kind := range []ReplaySubfamilyKind{
		ReplaySubfamilySourceProductMSigmaR1,
		ReplaySubfamilySourceProductR0R1,
		ReplaySubfamilyPRFKeyRows,
		ReplaySubfamilyPRFCheckpointRows,
		ReplaySubfamilyPRFFinalTagRows,
		ReplaySubfamilyPRFHelperRows,
	} {
		if _, ok := byKind[kind]; !ok {
			t.Fatalf("missing replay subfamily %q", kind)
		}
	}
	for _, entry := range sub.Entries {
		if entry.Family == ReplayFamilySigPackedSource {
			t.Fatalf("unexpected signature replay-basis subfamily after packed-source removal: %+v", entry)
		}
	}
	if len(sub.SigBasisTargets) != 0 {
		t.Fatalf("unexpected sig basis targets=%v", sub.SigBasisTargets)
	}
}

func TestReplaySubfamilyAuditRowsAreSortedAndReconcileFamilies(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	byFamily := replayAuditEntriesByFamily(audit.Families)
	logicalWitnessRows := proof.PCSGeometry.LogicalWitnessPolys
	if logicalWitnessRows <= 0 {
		logicalWitnessRows = proof.RowLayout.SigCount
	}
	for _, entry := range audit.Subfamilies.Entries {
		if !isStrictlyIncreasing(entry.LogicalRows) {
			t.Fatalf("%s logical rows not strictly increasing: %v", entry.Kind, entry.LogicalRows)
		}
		if !isStrictlyIncreasing(entry.SelectedRows) {
			t.Fatalf("%s selected rows not strictly increasing: %v", entry.Kind, entry.SelectedRows)
		}
		for _, idx := range entry.LogicalRows {
			if idx < 0 || idx >= logicalWitnessRows {
				t.Fatalf("%s logical row %d out of bounds for logical witness rows=%d", entry.Kind, idx, logicalWitnessRows)
			}
		}
		for _, idx := range entry.SelectedRows {
			if idx < 0 || idx >= proof.RowLayout.SigCount {
				t.Fatalf("%s selected row %d out of bounds for witness rows=%d", entry.Kind, idx, proof.RowLayout.SigCount)
			}
		}
	}
	for _, family := range []ReplayFamilyKind{
		ReplayFamilySourceProduct,
		ReplayFamilyPRFCompanion,
	} {
		got := sortedUniqueRowsFromEntries(audit.Subfamilies.Entries, family)
		want := byFamily[family].SelectedRows
		if !equalIntSlices(got, want) {
			t.Fatalf("subfamily selected-row union for %q=%v want %v", family, got, want)
		}
	}
}

func TestReplaySubfamilyAuditPRFUsageAndRankingAreStable(t *testing.T) {
	proof := buildReplayFamilyAuditFixture(t)
	audit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		t.Fatalf("build replay family audit: %v", err)
	}
	byKind := replaySubauditEntriesByKind(audit.Subfamilies.Entries)
	if got := byKind[ReplaySubfamilyPRFKeyRows].Consumption; got != ReplaySubfamilyMixed {
		t.Fatalf("prf key rows consumption=%q want %q", got, ReplaySubfamilyMixed)
	}
	if got := byKind[ReplaySubfamilyPRFCheckpointRows].Consumption; got != ReplaySubfamilyMixed {
		t.Fatalf("prf checkpoint rows consumption=%q want %q", got, ReplaySubfamilyMixed)
	}
	if got := byKind[ReplaySubfamilyPRFFinalTagRows].Consumption; got != ReplaySubfamilyMixed {
		t.Fatalf("prf final-tag rows consumption=%q want %q", got, ReplaySubfamilyMixed)
	}
	if audit.Subfamilies.PRFBridgeBlocker == "" {
		t.Fatalf("missing prf bridge blocker summary")
	}
	if audit.Subfamilies.SigBasisBlocker != "" {
		t.Fatalf("unexpected sig basis blocker summary=%q", audit.Subfamilies.SigBasisBlocker)
	}
	wantPRF := []ReplaySubfamilyKind{
		ReplaySubfamilyPRFCheckpointRows,
		ReplaySubfamilyPRFFinalTagRows,
		ReplaySubfamilyPRFHelperRows,
	}
	if len(audit.Subfamilies.PRFBridgeTargets) < len(wantPRF) {
		t.Fatalf("prf bridge target count=%d want at least %d", len(audit.Subfamilies.PRFBridgeTargets), len(wantPRF))
	}
	for i := range wantPRF {
		if audit.Subfamilies.PRFBridgeTargets[i] != wantPRF[i] {
			t.Fatalf("prf bridge target[%d]=%q want %q (full order=%v)", i, audit.Subfamilies.PRFBridgeTargets[i], wantPRF[i], audit.Subfamilies.PRFBridgeTargets)
		}
	}
	if len(audit.Subfamilies.SigBasisTargets) != 0 {
		t.Fatalf("unexpected sig basis targets=%v", audit.Subfamilies.SigBasisTargets)
	}
	wantTop := []ReplaySubfamilyKind{
		ReplaySubfamilySourceProductMSigmaR1,
		ReplaySubfamilySourceProductR0R1,
		ReplaySubfamilyPRFCheckpointRows,
		ReplaySubfamilyPRFFinalTagRows,
	}
	if len(audit.Subfamilies.StageBTargets) < len(wantTop) {
		t.Fatalf("subfamily target count=%d want at least %d", len(audit.Subfamilies.StageBTargets), len(wantTop))
	}
	for i := range wantTop {
		if audit.Subfamilies.StageBTargets[i] != wantTop[i] {
			t.Fatalf("subfamily target[%d]=%q want %q (full order=%v)", i, audit.Subfamilies.StageBTargets[i], wantTop[i], audit.Subfamilies.StageBTargets)
		}
	}
}
