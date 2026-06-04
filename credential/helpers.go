package credential

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func SplitBBTranB(B []*ring.Poly, x0Len int, targetDim int) (*ring.Poly, *ring.Poly, []*ring.Poly, *ring.Poly, error) {
	if targetDim != 1 {
		return nil, nil, nil, nil, fmt.Errorf("unsupported TargetDim=%d", targetDim)
	}
	if x0Len <= 0 {
		return nil, nil, nil, nil, fmt.Errorf("invalid X0Len=%d", x0Len)
	}
	if want := 3 + x0Len; len(B) != want {
		return nil, nil, nil, nil, fmt.Errorf("b must contain %d polynomials for X0Len=%d, got %d", want, x0Len, len(B))
	}
	return B[0], B[1], B[2 : 2+x0Len], B[len(B)-1], nil
}
