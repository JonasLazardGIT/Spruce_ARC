package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildCredentialConstraintSetPostCoeffNative(
	ringQ *ring.Ring,
	bound int64,
	pub PublicInputs,
	layout RowLayout,
	rowsNTT []*ring.Poly,
	omega []uint64,
	domainMode DomainMode,
	opts SimOpts,
) (ConstraintSet, error) {
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return ConstraintSet{}, fmt.Errorf("unsupported coeff-native showing model %q; only the literal-packed protocol remains", layout.CoeffNativeSig.Model)
	}
	return buildCredentialConstraintSetPostCoeffNativeLiteralPacked(ringQ, bound, pub, layout, rowsNTT, omega, domainMode, opts)
}
