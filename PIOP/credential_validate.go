package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// validatePublics checks public input shape in credential mode.
func validatePublics(pub PublicInputs) error {
	checkCount := func(name string, v []*ring.Poly, want int, allowZero bool) error {
		if len(v) == 0 {
			if allowZero {
				return nil
			}
			return fmt.Errorf("%s: missing polys", name)
		}
		if want > 0 && len(v) != want {
			return fmt.Errorf("%s: expected %d polys, got %d", name, want, len(v))
		}
		for i := range v {
			if v[i] == nil {
				return fmt.Errorf("%s: nil poly at index %d", name, i)
			}
		}
		return nil
	}
	if pub.X0Len <= 0 {
		pub.X0Len = 1
	}
	if pub.TargetDim <= 0 {
		pub.TargetDim = 1
	}
	if pub.X0CoeffBound <= 0 {
		pub.X0CoeffBound = pub.BoundB
	}
	if err := checkCount("RI0", pub.RI0, pub.X0Len, true); err != nil {
		return err
	}
	if err := checkCount("RI1", pub.RI1, 1, true); err != nil {
		return err
	}
	if len(pub.B) != 0 {
		wantB := 3 + pub.X0Len
		if len(pub.B) != wantB {
			return fmt.Errorf("b: expected %d polys, got %d", wantB, len(pub.B))
		}
	}
	if err := validateHashRelationPublicInputs(pub); err != nil {
		return err
	}
	if len(pub.Ac) > 0 {
		rowLen := len(pub.Ac[0])
		if rowLen == 0 {
			return fmt.Errorf("ac: empty first row")
		}
		for i, row := range pub.Ac {
			if len(row) != rowLen {
				return fmt.Errorf("ac: ragged row %d", i)
			}
		}
		if len(pub.Com) > 0 && len(pub.Com) != len(pub.Ac) {
			return fmt.Errorf("com length %d mismatches ac rows %d", len(pub.Com), len(pub.Ac))
		}
	}
	for name, mat := range map[string][][]*ring.Poly{"C_M": pub.CM, "A_s": pub.AS} {
		if len(mat) == 0 {
			continue
		}
		rowLen := len(mat[0])
		if rowLen == 0 {
			return fmt.Errorf("%s: empty first row", name)
		}
		for i, row := range mat {
			if len(row) != rowLen {
				return fmt.Errorf("%s: ragged row %d", name, i)
			}
			for j, poly := range row {
				if poly == nil {
					return fmt.Errorf("%s: nil poly at row %d col %d", name, i, j)
				}
			}
		}
		if name == "C_M" && len(pub.Com) > 0 && len(pub.Com) != len(mat) {
			return fmt.Errorf("com length %d mismatches C_M rows %d", len(pub.Com), len(mat))
		}
	}
	if len(pub.A) > 0 {
		rowLen := len(pub.A[0])
		if rowLen == 0 {
			return fmt.Errorf("a: empty first row")
		}
		for i, row := range pub.A {
			if len(row) != rowLen {
				return fmt.Errorf("a: ragged row %d", i)
			}
		}
	}
	return nil
}

// validateWitnesses checks witness shape in credential mode.
func validateWitnesses(wit WitnessInputs) error {
	checkAtLeastOne := func(name string, v []*ring.Poly) error {
		if len(v) == 0 {
			return fmt.Errorf("%s: missing poly", name)
		}
		for i := range v {
			if v[i] == nil {
				return fmt.Errorf("%s: nil poly at index %d", name, i)
			}
		}
		return nil
	}
	if len(wit.Mu) == 0 {
		if err := checkAtLeastOne("M1", wit.M1); err != nil {
			return err
		}
		if err := checkAtLeastOne("M2", wit.M2); err != nil {
			return err
		}
	} else if err := checkAtLeastOne("Mu", wit.Mu); err != nil {
		return err
	}
	if err := checkAtLeastOne("RU0", wit.RU0); err != nil {
		return err
	}
	if err := checkAtLeastOne("RU1", wit.RU1); err != nil {
		return err
	}
	if err := checkAtLeastOne("R", wit.R); err != nil {
		return err
	}
	if len(wit.R0) > 0 {
		if err := checkAtLeastOne("R0", wit.R0); err != nil {
			return err
		}
	}
	if len(wit.R1) > 0 {
		if err := checkAtLeastOne("R1", wit.R1); err != nil {
			return err
		}
	}
	if len(wit.Z) > 0 {
		if err := checkAtLeastOne("Z", wit.Z); err != nil {
			return err
		}
	}
	// Centered randomness rows require matching carry rows.
	if len(wit.R0) > 0 || len(wit.R1) > 0 {
		if err := checkAtLeastOne("K0", wit.K0); err != nil {
			return err
		}
		if err := checkAtLeastOne("K1", wit.K1); err != nil {
			return err
		}
	}
	if len(wit.RU0) != len(wit.R0) && len(wit.R0) > 0 {
		return fmt.Errorf("RU0 length=%d mismatches R0 length=%d", len(wit.RU0), len(wit.R0))
	}
	if len(wit.K0) != len(wit.R0) && len(wit.R0) > 0 {
		return fmt.Errorf("K0 length=%d mismatches R0 length=%d", len(wit.K0), len(wit.R0))
	}
	if len(wit.RU1) != 1 || len(wit.R1) > 1 || len(wit.K1) > 1 || len(wit.R) != 1 {
		return fmt.Errorf("RU1/R1/K1/R must remain scalar")
	}
	return nil
}
