package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// rebuildPostSignConstraintSetWithBridges rebuilds the post-sign constraint set
// from committed witness rows already in NTT form. The active showing replay
// path rebuilds constraints from the same NTT-surface that the evaluator opens.
func rebuildPostSignConstraintSetWithBridges(
	ringQ *ring.Ring,
	pub PublicInputs,
	layout RowLayout,
	rowsNTT []*ring.Poly,
	omega []uint64,
	opts SimOpts,
	root [16]byte,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(rowsNTT) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty witness rows")
	}
	opts.applyDefaults()
	_ = root
	return buildCredentialConstraintSetPostFromRows(ringQ, pub.BoundB, pub, layout, rowsNTT, omega, opts.DomainMode, opts, prfLayout, prfCompanionLayout)
}
