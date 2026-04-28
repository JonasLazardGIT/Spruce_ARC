package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntGenISISStateRoundTripOmitsOldRandomness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential_state.intgenisis.json")
	profile := PrimaryIntGenISISProfile()
	row := func(v int64) []int64 {
		out := make([]int64, profile.N)
		out[0] = v
		return out
	}
	st := IntGenISISState{
		Version:              IntGenISISStateVersion,
		Profile:              profile.Name,
		M:                    [][]int64{row(1)},
		S:                    [][]int64{row(2), row(3)},
		E:                    [][]int64{row(4)},
		MuSig:                [][]int64{row(5)},
		X0:                   [][]int64{row(6), row(7)},
		X1:                   [][]int64{row(8)},
		SigS1:                row(9),
		SigS2:                row(10),
		RingDegree:           profile.N,
		CredentialPublicPath: "Parameters/credential_public.intgenisis_profile_b.json",
		HashRelation:         HashRelationBBTran,
		BPath:                "Parameters/Bmatrix.intgenisis_profile_b.json",
		PRFParamsPath:        "prf/prf_params.json",
	}
	if err := SaveIntGenISISState(path, st); err != nil {
		t.Fatalf("save state: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	text := string(raw)
	for _, stale := range []string{"r0h", "r1h", "ri0", "ri1", "rbar", "target_hiding_lambda", "\"com\"", "\"t\""} {
		if strings.Contains(text, stale) {
			t.Fatalf("IntGenISIS state leaked stale field %q: %s", stale, text)
		}
	}
	got, err := LoadIntGenISISState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if got.Profile != profile.Name || len(got.S) != profile.KS || len(got.X0) != profile.EllX0 {
		t.Fatalf("state mismatch: %+v", got)
	}
}
