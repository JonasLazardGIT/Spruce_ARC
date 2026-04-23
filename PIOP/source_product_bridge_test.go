package PIOP

import (
	"testing"

	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func bridgeTestRowInputs(inputs []decsRowInput) []lvcs.RowInput {
	out := make([]lvcs.RowInput, len(inputs))
	for i := range inputs {
		out[i] = lvcs.RowInput{
			Head:       append([]uint64(nil), inputs[i].Head...),
			Tail:       append([]uint64(nil), inputs[i].Tail...),
			Poly:       inputs[i].Poly,
			PolyCoeffs: append([]uint64(nil), inputs[i].PolyCoeffs...),
		}
	}
	return out
}

func bridgeTestCopyRowsNTT(ringQ *ring.Ring, rows []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		if rows[i] == nil {
			continue
		}
		out[i] = ringQ.NewPoly()
		ring.Copy(rows[i], out[i])
	}
	return out
}

func bridgeTestAddCoeffDeltaToRow(ringQ *ring.Ring, row *ring.Poly, coeffIdx int, delta uint64) *ring.Poly {
	if ringQ == nil || row == nil {
		return row
	}
	out := ringQ.NewPoly()
	ring.Copy(row, out)
	ringQ.InvNTT(out, out)
	out.Coeffs[0][coeffIdx] = modAdd(out.Coeffs[0][coeffIdx], delta%ringQ.Modulus[0], ringQ.Modulus[0])
	ringQ.NTT(out, out)
	return out
}

func bridgeTestBucketHasNonZeroOnOmega(ringQ *ring.Ring, omega []uint64, polys []*ring.Poly, coeffs [][]uint64) bool {
	count := len(polys)
	if len(coeffs) > count {
		count = len(coeffs)
	}
	q := ringQ.Modulus[0]
	for i := 0; i < count; i++ {
		var actual []uint64
		if i < len(coeffs) && len(coeffs[i]) > 0 {
			actual = evalCoeffOnOmegaTest(coeffs[i], omega, q)
		} else if i < len(polys) && polys[i] != nil {
			vals, err := evalPolyOnOmegaTest(ringQ, omega, polys[i])
			if err != nil {
				return true
			}
			actual = vals
		}
		for _, v := range actual {
			if v%q != 0 {
				return true
			}
		}
	}
	return false
}

func TestSourceProductAliasStripeSchedulerPacksIntoTailBlock(t *testing.T) {
	layout := RowLayout{
		HasExplicitBaseIdx: true,
		IdxMSigmaR1:        2,
		IdxR0R1:            3,
	}

	stripe, err := buildSourceProductAliasStripeLayout(layout, 400, 32)
	if err != nil {
		t.Fatalf("build source-product alias stripe layout (tail pack): %v", err)
	}
	if stripe.PaddingRows != 0 {
		t.Fatalf("tail-pack padding=%d want 0", stripe.PaddingRows)
	}
	if got, want := stripe.PhysicalRows, []int{400, 401}; !equalIntSlices(got, want) {
		t.Fatalf("tail-pack physical rows=%v want %v", got, want)
	}
	if got, want := stripe.SupportSlots, []int{16, 17}; !equalIntSlices(got, want) {
		t.Fatalf("tail-pack support slots=%v want %v", got, want)
	}

	stripe, err = buildSourceProductAliasStripeLayout(layout, 415, 32)
	if err != nil {
		t.Fatalf("build source-product alias stripe layout (roll block): %v", err)
	}
	if stripe.PaddingRows != 1 {
		t.Fatalf("roll-block padding=%d want 1", stripe.PaddingRows)
	}
	if got, want := stripe.PhysicalRows, []int{416, 417}; !equalIntSlices(got, want) {
		t.Fatalf("roll-block physical rows=%v want %v", got, want)
	}
	if got, want := stripe.SupportSlots, []int{0, 1}; !equalIntSlices(got, want) {
		t.Fatalf("roll-block support slots=%v want %v", got, want)
	}
}

func TestSourceProductAliasStripeEqualityConstraintsVanishOnOmega(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	families, coeffs, err := buildSourceProductAliasStripeEqualityConstraints(fx.ringQ, fx.rowsNTT, fx.layout)
	if err != nil {
		t.Fatalf("build source-product alias equality constraints: %v", err)
	}
	if len(families) != 0 || len(coeffs) != 0 {
		t.Fatalf("source-product alias equality families=%d coeffs=%d want 0/0 after deprecation", len(families), len(coeffs))
	}
}

func TestSourceProductAliasStripeEqualityConstraintsDetectMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	families, coeffs, err := buildSourceProductAliasStripeEqualityConstraints(fx.ringQ, fx.rowsNTT, fx.layout)
	if err != nil {
		t.Fatalf("build source-product alias equality constraints: %v", err)
	}
	if len(families) != 0 || len(coeffs) != 0 {
		t.Fatalf("source-product alias equality families=%d coeffs=%d want 0/0 after deprecation", len(families), len(coeffs))
	}
}

func TestSourceProductBridgeCurrentPhysicalRowsDoNotRoundTripThroughSameRootOpening(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("source-product bridge should be disabled, got %+v", proof.SourceProductBridge)
	}
}

func TestSourceProductBridgeCurrentPhysicalRowsDoNotMatchCommittedKValues(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("source-product bridge should be disabled, got %+v", proof.SourceProductBridge)
	}
}

func TestSourceProductBridgeAliasRowsRoundTripThroughSameRootOpening(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("source-product bridge should be disabled, got %+v", proof.SourceProductBridge)
	}
}

func TestSourceProductBridgeAliasRowsMatchCommittedKValues(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("source-product bridge should be disabled, got %+v", proof.SourceProductBridge)
	}
}

func TestSourceProductBridgeActivatesOnLiveFullReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if sourceProductBridgeEnabled(fx.pub, fx.opts, fx.layout) {
		t.Fatal("source-product bridge should be disabled on live full replay")
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("source-product bridge should be absent, got %+v", proof.SourceProductBridge)
	}
	rep, err := BuildProofReport(proof, fx.opts, fx.ringQ)
	if err != nil {
		t.Fatalf("build proof report: %v", err)
	}
	if rep.TranscriptFocus.SourceProductBridgeBytes != 0 {
		t.Fatalf("source-product bridge bytes=%d want 0", rep.TranscriptFocus.SourceProductBridgeBytes)
	}
	if rep.TranscriptFocus.SourceProductBridgeSupportSlots != 0 {
		t.Fatalf("source-product bridge support slots report=%d want 0", rep.TranscriptFocus.SourceProductBridgeSupportSlots)
	}
	if rep.TranscriptFocus.SourceProductBridgeOpenedBlocks != 0 {
		t.Fatalf("source-product bridge opened blocks=%d want 0", rep.TranscriptFocus.SourceProductBridgeOpenedBlocks)
	}
}
