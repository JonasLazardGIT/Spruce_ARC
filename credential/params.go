package credential

import (
	"fmt"

	"vSIS-Signature/commitment"
	"vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Params captures the public inputs required during issuance.
type Params struct {
	HashRelation         string
	Ac                   commitment.Matrix
	CM                   commitment.Matrix
	AS                   commitment.Matrix
	BPath                string
	AcPath               string
	Profile              string
	BoundB               int64
	CommitmentBound      int64
	EllM                 int
	KS                   int
	NC                   int
	EllMuSig             int
	EllX0                int
	EllX1                int
	SignaturePreimageLen int
	X0Len                int
	X0CoeffBound         int64
	TargetDim            int
	TargetHidingLambda   int
	RingDegree           int
	X0Distribution       string
	LenMu                int
	MuLayout             string
	LenM                 int
	LenK                 int
	LenR0H               int
	LenR1H               int
	LenRBar              int
	// Deprecated aliases retained so older tests can still build while the
	// live runtime uses the semantic lengths above.
	LenM1  int
	LenM2  int
	LenRU0 int
	LenRU1 int
	LenR   int
	RingQ  *ring.Ring
}

const (
	DefaultTargetDim              = 1
	DefaultTargetHidingLambda     = 128
	X0DistributionUniformInterval = "uniform_interval"
)

// paramsFile mirrors the JSON schema stored on disk.
func LoadDefaultRing() (*ring.Ring, error) {
	return LoadRingWithDegree(0)
}

// LoadRingWithDegree loads the repository modulus and one of the maintained
// IntGenISIS ring degrees.
func LoadRingWithDegree(ringDegree int) (*ring.Ring, error) {
	par, err := io.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		return nil, err
	}
	n := par.N
	switch ringDegree {
	case 0, par.N:
	case 1024:
		n = 1024
	case 512:
		n = 512
	default:
		return nil, fmt.Errorf("unsupported ring degree %d (supported: %d, 1024, 512)", ringDegree, par.N)
	}
	return ring.NewRing(n, []uint64{par.Q})
}
