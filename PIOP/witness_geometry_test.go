package PIOP

import "testing"

func TestReplayPRFRowCountUsesWitnessRowsForNonPackedLayout(t *testing.T) {
	layout := &PRFLayout{
		LenKey:      8,
		PackedRows:  false,
		WitnessRows: 166,
	}

	if got := replayPRFRowCount(layout); got != 166 {
		t.Fatalf("replayPRFRowCount() = %d, want 166", got)
	}
}

func TestReplayPRFRowCountPackedRowsStillCountsUniqueRows(t *testing.T) {
	layout := &PRFLayout{
		PackedRows: true,
		KeySlots: []PRFSlot{
			{Row: 3, Col: 0},
			{Row: 3, Col: 1},
			{Row: 4, Col: 0},
		},
		SBoxSlots: []PRFSlot{
			{Row: 4, Col: 1},
			{Row: 7, Col: 0},
		},
		WitnessRows: 99,
	}

	if got := replayPRFRowCount(layout); got != 3 {
		t.Fatalf("replayPRFRowCount() = %d, want 3 unique packed rows", got)
	}
}
