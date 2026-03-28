package PIOP

import "vSIS-Signature/prf"

func groupedPRFSBoxCount(lenKey, lenNonce, rf, rp, groupRounds int) int {
	inputLen := lenKey + lenNonce
	rounds := rf + rp
	if inputLen <= 0 || rounds <= 0 {
		return 0
	}
	if groupRounds <= 0 {
		groupRounds = 1
	}
	scheduleParams := &prf.Params{RF: rf, RP: rp}
	sboxCount := 0
	for round := 0; round < rounds; round++ {
		if !prf.ShouldCheckpointRound(scheduleParams, round, groupRounds) {
			continue
		}
		full := round < rf/2 || round >= rf/2+rp
		if full {
			sboxCount += inputLen
		} else {
			sboxCount++
		}
	}
	return sboxCount
}

func prfLogicalScalarCount(layout *PRFLayout) int {
	if layout == nil {
		return 0
	}
	if !layout.PackedRows && layout.WitnessRows > 0 {
		return layout.WitnessRows
	}
	sboxCount := len(layout.SBoxSlots)
	if sboxCount == 0 {
		sboxCount = groupedPRFSBoxCount(layout.LenKey, layout.LenNonce, layout.RF, layout.RP, layout.GroupRounds)
	}
	return layout.LenKey + sboxCount
}
