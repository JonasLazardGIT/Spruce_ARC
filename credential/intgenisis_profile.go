package credential

const (
	ProfileIntGenISISB = "intgenisis_profile_b"
	ProfileIntGenISISA = "intgenisis_profile_a"
)

// IntGenISISProfile records the committed-message / MLWE-hiding protocol
// dimensions. The old LHL/shared-randomness lengths are intentionally absent.
type IntGenISISProfile struct {
	Name                 string
	N                    int
	Q                    uint64
	EllM                 int
	KS                   int
	NC                   int
	B                    int64
	EllMuSig             int
	EllX0                int
	EllX1                int
	SignaturePreimageLen int
	MLWEHidingBits       float64
	MSISBindingBits      float64
}

func PrimaryIntGenISISProfile() IntGenISISProfile {
	return IntGenISISProfile{
		Name:                 ProfileIntGenISISB,
		N:                    512,
		Q:                    1054721,
		EllM:                 1,
		KS:                   2,
		NC:                   1,
		B:                    8,
		EllMuSig:             1,
		EllX0:                2,
		EllX1:                1,
		SignaturePreimageLen: 2,
		MLWEHidingBits:       194.408,
		MSISBindingBits:      427.780,
	}
}

func CompactIntGenISISProfile() IntGenISISProfile {
	return IntGenISISProfile{
		Name:                 ProfileIntGenISISA,
		N:                    256,
		Q:                    1054721,
		EllM:                 1,
		KS:                   4,
		NC:                   1,
		B:                    8,
		EllMuSig:             1,
		EllX0:                2,
		EllX1:                1,
		SignaturePreimageLen: 2,
		MLWEHidingBits:       194.4,
	}
}

func LookupIntGenISISProfile(name string) (IntGenISISProfile, bool) {
	switch name {
	case "", ProfileIntGenISISB:
		return PrimaryIntGenISISProfile(), true
	case ProfileIntGenISISA:
		return CompactIntGenISISProfile(), true
	default:
		return IntGenISISProfile{}, false
	}
}
