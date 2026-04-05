package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// rebuildPostSignConstraintSetWithBridges rebuilds the post-sign constraint set
// from committed witness rows in coeff form (used during replay).
func rebuildPostSignConstraintSetWithBridges(
	ringQ *ring.Ring,
	pub PublicInputs,
	layout RowLayout,
	rows []*ring.Poly,
	omega []uint64,
	opts SimOpts,
	root [16]byte,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(rows) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty witness rows")
	}
	opts.applyDefaults()
	// Convert rows to NTT form for the constraint builder.
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	_ = root
	return buildCredentialConstraintSetPostFromRows(ringQ, pub.BoundB, pub, layout, rowsNTT, omega, opts.DomainMode, opts, prfLayout, prfCompanionLayout)
}
