package credential

const (
	ProfileIntGenISISB = "intgenisis_profile_b"
	ProfileIntGenISISC = "intgenisis_profile_c"

	IntGenISISSharedModulusQ    = 1017857
	IntGenISISN512SignatureBeta = 6002
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
		Q:                    IntGenISISSharedModulusQ,
		EllM:                 1,
		KS:                   2,
		NC:                   1,
		B:                    4,
		EllMuSig:             1,
		EllX0:                2,
		EllX1:                1,
		SignaturePreimageLen: 2,
		MLWEHidingBits:       194.408,
		MSISBindingBits:      427.780,
	}
}

func Ternary1024IntGenISISProfile() IntGenISISProfile {
	return IntGenISISProfile{
		Name:                 ProfileIntGenISISC,
		N:                    1024,
		Q:                    IntGenISISSharedModulusQ,
		EllM:                 1,
		KS:                   1,
		NC:                   1,
		B:                    1,
		EllMuSig:             1,
		EllX0:                1,
		EllX1:                1,
		SignaturePreimageLen: 2,
		MLWEHidingBits:       194.408,
		MSISBindingBits:      427.780,
	}
}

func LookupIntGenISISProfile(name string) (IntGenISISProfile, bool) {
	switch name {
	case "", ProfileIntGenISISB:
		return PrimaryIntGenISISProfile(), true
	case ProfileIntGenISISC:
		return Ternary1024IntGenISISProfile(), true
	default:
		return IntGenISISProfile{}, false
	}
}

func LookupIntGenISISProfileByRingDegree(n int) (IntGenISISProfile, bool) {
	for _, profile := range []IntGenISISProfile{PrimaryIntGenISISProfile(), Ternary1024IntGenISISProfile()} {
		if profile.N == n {
			return profile, true
		}
	}
	return IntGenISISProfile{}, false
}
