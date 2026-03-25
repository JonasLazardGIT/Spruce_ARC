package credential

import (
	"vSIS-Signature/commitment"
	"vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Params captures the public inputs required during issuance.
type Params struct {
	Ac     commitment.Matrix
	BPath  string
	AcPath string
	BoundB int64
	LenM1  int
	LenM2  int
	LenRU0 int
	LenRU1 int
	LenR   int
	RingQ  *ring.Ring
}

// paramsFile mirrors the JSON schema stored on disk.
func LoadDefaultRing() (*ring.Ring, error) {
	par, err := io.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		return nil, err
	}
	return ring.NewRing(par.N, []uint64{par.Q})
}
