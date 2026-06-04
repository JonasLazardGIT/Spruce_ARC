package prf

import "fmt"

func isFullRound(params *Params, globalRound int) bool {
	if params == nil {
		return false
	}
	if globalRound < 0 {
		return false
	}
	if globalRound < params.RF/2 {
		return true
	}
	if globalRound < params.RF/2+params.RP {
		return false
	}
	return true
}

func fullRoundIndex(params *Params, globalRound int) (int, bool) {
	if params == nil {
		return 0, false
	}
	if globalRound < 0 || globalRound >= params.RF+params.RP {
		return 0, false
	}
	if globalRound < params.RF/2 {
		return globalRound, true
	}
	if globalRound < params.RF/2+params.RP {
		return 0, false
	}
	return globalRound - params.RP, true
}

// ShouldCheckpointRound reports whether the grouped PRF witness checkpoints a round.
func ShouldCheckpointRound(params *Params, globalRound, groupRounds int) bool {
	if params == nil {
		return false
	}
	if globalRound < 0 || globalRound >= params.RF+params.RP {
		return false
	}
	if groupRounds <= 1 {
		return true
	}
	fullIdx, ok := fullRoundIndex(params, globalRound)
	if !ok {
		return true
	}
	return fullIdx != params.RF-1
}

// SBoxOutputCountGrouped returns the grouped PRF witness size.
func SBoxOutputCountGrouped(params *Params, groupRounds int) (int, error) {
	if params == nil {
		return 0, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return 0, err
	}
	if groupRounds <= 0 {
		return 0, fmt.Errorf("invalid groupRounds=%d", groupRounds)
	}
	t := params.T()
	R := params.RF + params.RP
	count := 0
	for r := 0; r < R; r++ {
		if !ShouldCheckpointRound(params, r, groupRounds) {
			continue
		}
		if isFullRound(params, r) {
			count += t
		} else {
			count++
		}
	}
	return count, nil
}

// ConcatKeyNonce builds x^(0) = key || nonce with length checks.
func ConcatKeyNonce(key, nonce []Elem, params *Params) ([]Elem, error) {
	if params == nil {
		return nil, fmt.Errorf("nil params")
	}
	if len(key) != params.LenKey {
		return nil, fmt.Errorf("len(key)=%d want %d", len(key), params.LenKey)
	}
	if len(nonce) != params.LenNonce {
		return nil, fmt.Errorf("len(nonce)=%d want %d", len(nonce), params.LenNonce)
	}
	t := params.T()
	state := make([]Elem, t)
	copy(state, key)
	copy(state[params.LenKey:], nonce)
	return state, nil
}
