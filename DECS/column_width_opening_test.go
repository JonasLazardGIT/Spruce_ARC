package decs

import "testing"

func TestPackOpeningColumnWidthPvalsRoundTrip(t *testing.T) {
	open := &DECSOpening{
		Pvals: [][]uint64{
			{0, 1, 17, 70000},
			{1, 0, 31, 80000},
			{0, 1, 3, 90000},
		},
		Mvals: [][]uint64{
			{1, 40000},
			{0, 50000},
			{1, 60000},
		},
		R:              4,
		Eta:            2,
		FormatVersion:  OpeningFormatColumnWidths,
		MFormatVersion: OpeningFormatColumnWidths,
	}
	PackOpening(open)
	if open.FormatVersion != OpeningFormatColumnWidths {
		t.Fatalf("P format=%d want column widths", open.FormatVersion)
	}
	if len(open.PvalsColumnWidths) != 4 {
		t.Fatalf("P column widths len=%d want 4", len(open.PvalsColumnWidths))
	}
	if open.MFormatVersion != OpeningFormatColumnWidths {
		t.Fatalf("M format=%d want column widths", open.MFormatVersion)
	}
	wantP := [][]uint64{{0, 1, 17, 70000}, {1, 0, 31, 80000}, {0, 1, 3, 90000}}
	for r := range wantP {
		for c, want := range wantP[r] {
			if got := GetOpeningPval(open, r, c); got != want {
				t.Fatalf("P[%d][%d]=%d want %d", r, c, got, want)
			}
		}
	}
	wantM := [][]uint64{{1, 40000}, {0, 50000}, {1, 60000}}
	for r := range wantM {
		for c, want := range wantM[r] {
			if got := GetOpeningMval(open, r, c); got != want {
				t.Fatalf("M[%d][%d]=%d want %d", r, c, got, want)
			}
		}
	}
}

func TestPackOpeningKeepsFlatWhenColumnWidthsAreLarger(t *testing.T) {
	open := &DECSOpening{
		Pvals: [][]uint64{
			{1000, 1001, 1002, 1003},
			{1004, 1005, 1006, 1007},
		},
		R: 4,
	}
	PackOpening(open)
	if open.FormatVersion != OpeningFormatPlain {
		t.Fatalf("P format=%d want plain flat packing", open.FormatVersion)
	}
	if len(open.PvalsColumnWidths) != 0 {
		t.Fatalf("unexpected column widths: %v", open.PvalsColumnWidths)
	}
	for r := 0; r < 2; r++ {
		for c := 0; c < 4; c++ {
			want := uint64(1000 + r*4 + c)
			if got := GetOpeningPval(open, r, c); got != want {
				t.Fatalf("P[%d][%d]=%d want %d", r, c, got, want)
			}
		}
	}
}
