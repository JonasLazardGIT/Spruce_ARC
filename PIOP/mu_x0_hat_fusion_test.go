package PIOP

import (
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// TestMuX0AggregateFusionMatchesMaterializedHatOnOmega pins the local
// elimination lemma used by strict v3.  For every target NTT coordinate, the
// old L_lane*B_block*hat aggregate equals B_target times the H-weighted source
// aggregate.  The equality holds only after summing on Omega, which is why the
// production mode is deliberately not a generic same-point virtual-hat mode.
func TestMuX0AggregateFusionMatchesMaterializedHatOnOmega(t *testing.T) {
	const q = uint64(1017857)
	ringQ, err := ring.NewRing(16, []uint64{q})
	if err != nil {
		t.Fatal(err)
	}
	omega := []uint64{1, 2, 3, 4}
	interp, err := newOmegaInterpolationPlan(omega, q)
	if err != nil {
		t.Fatal(err)
	}
	source := ringQ.NewPoly()
	for i := range source.Coeffs[0] {
		source.Coeffs[0][i] = uint64(17*i*i+31*i+9) % q
	}
	views, err := intGenISISCoeffViewRowMaterials(ringQ, omega, []*ring.Poly{source}, len(omega), interp)
	if err != nil {
		t.Fatal(err)
	}
	rowsPerPoly := int(ringQ.N) / len(omega)
	makeRowFromHead := func(head []uint64) *ring.Poly { return interp.coeffPolyFromHead(ringQ, head) }
	hats, err := intGenISISHatRowMaterialsFromCoeffViews(ringQ, omega, views, rowsPerPoly, interp, makeRowFromHead, "fusion-test")
	if err != nil {
		t.Fatal(err)
	}
	basis, err := newTransformBridgeBasisCache(ringQ, omega, int(ringQ.N), rowsPerPoly)
	if err != nil {
		t.Fatal(err)
	}
	for block := 0; block < rowsPerPoly; block++ {
		for lane := range omega {
			target := block*len(omega) + lane
			bHead := make([]uint64, len(omega))
			for j := range bHead {
				bHead[j] = uint64(101+13*target+7*j) % q
			}
			bBlock := makeRowFromHead(bHead).Coeffs[0]
			oldAggregate := uint64(0)
			fusedAggregate := uint64(0)
			for _, x := range omega {
				lag := EvalPoly(basis.LagrangeBasis[lane], x, q)
				bAtX := EvalPoly(bBlock, x, q)
				hatAtX := EvalPoly(hats[block].Poly.Coeffs[0], x, q)
				oldAggregate = modAdd(oldAggregate, modMul(lag, modMul(bAtX, hatAtX, q), q), q)

				weightedSource := uint64(0)
				for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
					sourceAtX := EvalPoly(views[srcBlock].Poly.Coeffs[0], x, q)
					weightedSource = modAdd(weightedSource, modMul(basis.BlockFactors[target][srcBlock]%q, sourceAtX, q), q)
				}
				hAtX := EvalPoly(basis.TransformH[target], x, q)
				fusedAggregate = modAdd(fusedAggregate, modMul(bHead[lane], modMul(hAtX, weightedSource, q), q), q)
			}
			if oldAggregate != fusedAggregate {
				t.Fatalf("target %d old/fused aggregate=%d/%d", target, oldAggregate, fusedAggregate)
			}
		}
	}
}
