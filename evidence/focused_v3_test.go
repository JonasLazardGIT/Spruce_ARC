package evidence

import (
	"path/filepath"
	"testing"
)

func TestFocusedV3SizeEvidence(t *testing.T) {
	e, err := ReadFocusedV3SizeEvidence(filepath.Join("focused-v3-size-optimization.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFocusedV3SizeEvidence(e); err != nil {
		t.Fatal(err)
	}
}
