package prf

import "fmt"

// Trace returns the state after each round boundary, including the initial state.
func Trace(init []Elem, params *Params) ([][]Elem, error) {
	if params == nil {
		return nil, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(init) != params.T() {
		return nil, fmt.Errorf("len(init)=%d want %d", len(init), params.T())
	}
	f := NewField(params.Q)
	t := params.T()
	tmp := make([]Elem, t)
	out := make([]Elem, t)

	states := make([][]Elem, 0, params.RF+params.RP+1)
	state := make([]Elem, t)
	copy(state, init)
	states = append(states, append([]Elem(nil), state...))

	for r := 0; r < params.RF/2; r++ {
		externalRound(state, tmp, out, params.CExt[r], params.ME, f, params.D)
		states = append(states, append([]Elem(nil), state...))
	}
	for r := 0; r < params.RP; r++ {
		internalRound(state, tmp, out, params.CInt[r], params.MI, f, params.D)
		states = append(states, append([]Elem(nil), state...))
	}
	for r := params.RF / 2; r < params.RF; r++ {
		externalRound(state, tmp, out, params.CExt[r], params.ME, f, params.D)
		states = append(states, append([]Elem(nil), state...))
	}
	return states, nil
}

// SBoxOutputCount returns RF*t + RP.
func SBoxOutputCount(params *Params) (int, error) {
	if params == nil {
		return 0, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return 0, err
	}
	t := params.T()
	return params.RF*t + params.RP, nil
}

// TraceSBoxOutputs returns the S-box outputs in execution order and the final state.
func TraceSBoxOutputs(init []Elem, params *Params) ([]Elem, []Elem, error) {
	if params == nil {
		return nil, nil, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	if len(init) != params.T() {
		return nil, nil, fmt.Errorf("len(init)=%d want %d", len(init), params.T())
	}

	f := NewField(params.Q)
	t := params.T()
	tmp := make([]Elem, t)
	out := make([]Elem, t)

	state := make([]Elem, t)
	copy(state, init)

	want, err := SBoxOutputCount(params)
	if err != nil {
		return nil, nil, err
	}
	sboxes := make([]Elem, 0, want)

	for r := 0; r < params.RF/2; r++ {
		for i := 0; i < t; i++ {
			tmp[i] = f.powSmall(f.add(state[i], Elem(params.CExt[r][i]%f.q)), params.D)
			sboxes = append(sboxes, tmp[i])
		}
		matVec(out, params.ME, tmp, f)
		copy(state, out)
	}
	for r := 0; r < params.RP; r++ {
		tmp[0] = f.powSmall(f.add(state[0], Elem(params.CInt[r]%f.q)), params.D)
		sboxes = append(sboxes, tmp[0])
		for i := 1; i < t; i++ {
			tmp[i] = state[i]
		}
		matVec(out, params.MI, tmp, f)
		copy(state, out)
	}
	for r := params.RF / 2; r < params.RF; r++ {
		for i := 0; i < t; i++ {
			tmp[i] = f.powSmall(f.add(state[i], Elem(params.CExt[r][i]%f.q)), params.D)
			sboxes = append(sboxes, tmp[i])
		}
		matVec(out, params.ME, tmp, f)
		copy(state, out)
	}

	if len(sboxes) != want {
		return nil, nil, fmt.Errorf("sbox outputs=%d want %d", len(sboxes), want)
	}
	return sboxes, append([]Elem(nil), state...), nil
}

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

// MaxConstraintDegreeGrouped returns the maximum grouped PRF witness degree.
func MaxConstraintDegreeGrouped(params *Params, groupRounds int) (uint64, error) {
	if params == nil {
		return 0, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return 0, err
	}
	if groupRounds <= 0 {
		return 0, fmt.Errorf("invalid groupRounds=%d", groupRounds)
	}
	d := params.D
	if d == 0 {
		return 0, fmt.Errorf("invalid d=0")
	}
	stateDeg := uint64(1)
	maxDeg := uint64(1)
	R := params.RF + params.RP
	for round := 0; round < R; round++ {
		if stateDeg > ^uint64(0)/d {
			return 0, fmt.Errorf("degree overflow while evaluating grouped PRF depth at round %d", round)
		}
		nextDeg := stateDeg * d
		if ShouldCheckpointRound(params, round, groupRounds) {
			if nextDeg > maxDeg {
				maxDeg = nextDeg
			}
			stateDeg = 1
		} else {
			stateDeg = nextDeg
		}
	}
	// Final tag constraints are linear in the terminal state.
	if stateDeg > maxDeg {
		maxDeg = stateDeg
	}
	return maxDeg, nil
}

// TraceSBoxOutputsGrouped runs the permutation and returns:
//   - the list of checkpointed S-box outputs (in strict execution order),
//   - the final state y = P(init) (after the last linear layer, before feed-forward).
//
// This is the "g-round grouping" PRF witness: the prover commits only the S-box outputs
// for checkpoint rounds and recomputes intermediate rounds inside the constraint evaluator.
//
// Output ordering:
//   - rounds r=0..R-1 in execution order (external first half, internal, external second half)
//   - within a checkpointed full round: lanes 0..t-1
//   - within a checkpointed partial round: lane 0 only
func TraceSBoxOutputsGrouped(init []Elem, params *Params, groupRounds int) ([]Elem, []Elem, error) {
	if params == nil {
		return nil, nil, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	if groupRounds <= 0 {
		return nil, nil, fmt.Errorf("invalid groupRounds=%d", groupRounds)
	}
	if len(init) != params.T() {
		return nil, nil, fmt.Errorf("len(init)=%d want %d", len(init), params.T())
	}

	f := NewField(params.Q)
	t := params.T()
	tmp := make([]Elem, t)
	out := make([]Elem, t)
	state := make([]Elem, t)
	copy(state, init)

	want, err := SBoxOutputCountGrouped(params, groupRounds)
	if err != nil {
		return nil, nil, err
	}
	sboxes := make([]Elem, 0, want)

	// external rounds (first half): global rounds 0..RF/2-1
	for r := 0; r < params.RF/2; r++ {
		checkpoint := ShouldCheckpointRound(params, r, groupRounds)
		for i := 0; i < t; i++ {
			tmp[i] = f.powSmall(f.add(state[i], Elem(params.CExt[r][i]%f.q)), params.D)
			if checkpoint {
				sboxes = append(sboxes, tmp[i])
			}
		}
		matVec(out, params.ME, tmp, f)
		copy(state, out)
	}
	// internal rounds: global rounds RF/2..RF/2+RP-1
	for r := 0; r < params.RP; r++ {
		globalRound := params.RF/2 + r
		checkpoint := ShouldCheckpointRound(params, globalRound, groupRounds)
		tmp[0] = f.powSmall(f.add(state[0], Elem(params.CInt[r]%f.q)), params.D)
		if checkpoint {
			sboxes = append(sboxes, tmp[0])
		}
		for i := 1; i < t; i++ {
			tmp[i] = state[i]
		}
		matVec(out, params.MI, tmp, f)
		copy(state, out)
	}
	// external rounds (second half): global rounds RF/2+RP..RF+RP-1
	for r := params.RF / 2; r < params.RF; r++ {
		globalRound := r + params.RP
		checkpoint := ShouldCheckpointRound(params, globalRound, groupRounds)
		for i := 0; i < t; i++ {
			tmp[i] = f.powSmall(f.add(state[i], Elem(params.CExt[r][i]%f.q)), params.D)
			if checkpoint {
				sboxes = append(sboxes, tmp[i])
			}
		}
		matVec(out, params.ME, tmp, f)
		copy(state, out)
	}

	if len(sboxes) != want {
		return nil, nil, fmt.Errorf("grouped sbox outputs=%d want %d", len(sboxes), want)
	}
	return sboxes, append([]Elem(nil), state...), nil
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
