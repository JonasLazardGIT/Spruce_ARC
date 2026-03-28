package prf

import "fmt"

// LinearForm expresses one hidden scalar as a linear combination of the secret
// key lanes, prior grouped checkpoint outputs, and a public constant term.
type LinearForm struct {
	KeyCoeffs        []Elem
	CheckpointCoeffs []Elem
	Const            Elem
}

// GroupedCheckpoint records one grouped checkpoint relation.
type GroupedCheckpoint struct {
	Round  int
	Lane   int
	Input  Elem
	Output Elem
	Wire   LinearForm
}

// GroupedWitness is the canonical grouped PRF witness/metadata bundle used by
// the one-root companion path.
type GroupedWitness struct {
	Checkpoints       []GroupedCheckpoint
	CheckpointInputs  []Elem
	CheckpointOutputs []Elem
	FinalRoundInputs  []LinearForm
	FinalRoundOutputs []Elem
	FinalState        []Elem
	FinalTagState     []Elem
}

func cloneLinearForm(src LinearForm) LinearForm {
	out := src
	if len(src.KeyCoeffs) > 0 {
		out.KeyCoeffs = append([]Elem(nil), src.KeyCoeffs...)
	}
	if len(src.CheckpointCoeffs) > 0 {
		out.CheckpointCoeffs = append([]Elem(nil), src.CheckpointCoeffs...)
	}
	return out
}

func zeroLinearForm(lenKey, checkpointCap int) LinearForm {
	return LinearForm{
		KeyCoeffs:        make([]Elem, lenKey),
		CheckpointCoeffs: make([]Elem, checkpointCap),
	}
}

func basisKeyLinearForm(lenKey, checkpointCap, keyIdx int) LinearForm {
	out := zeroLinearForm(lenKey, checkpointCap)
	if keyIdx >= 0 && keyIdx < lenKey {
		out.KeyCoeffs[keyIdx] = 1
	}
	return out
}

func linearFormAdd(f Field, a, b LinearForm) LinearForm {
	out := zeroLinearForm(len(a.KeyCoeffs), len(a.CheckpointCoeffs))
	for i := range out.KeyCoeffs {
		out.KeyCoeffs[i] = f.add(a.KeyCoeffs[i], b.KeyCoeffs[i])
	}
	for i := range out.CheckpointCoeffs {
		out.CheckpointCoeffs[i] = f.add(a.CheckpointCoeffs[i], b.CheckpointCoeffs[i])
	}
	out.Const = f.add(a.Const, b.Const)
	return out
}

func linearFormAddConst(f Field, a LinearForm, c Elem) LinearForm {
	out := cloneLinearForm(a)
	out.Const = f.add(out.Const, c)
	return out
}

func linearFormScale(f Field, a LinearForm, scalar Elem) LinearForm {
	out := zeroLinearForm(len(a.KeyCoeffs), len(a.CheckpointCoeffs))
	for i := range out.KeyCoeffs {
		out.KeyCoeffs[i] = f.mul(a.KeyCoeffs[i], scalar)
	}
	for i := range out.CheckpointCoeffs {
		out.CheckpointCoeffs[i] = f.mul(a.CheckpointCoeffs[i], scalar)
	}
	out.Const = f.mul(a.Const, scalar)
	return out
}

func linearFormEval(f Field, form LinearForm, key []Elem, checkpoints []Elem) (Elem, error) {
	if len(form.KeyCoeffs) != len(key) {
		return 0, fmt.Errorf("linear form key coeffs=%d want %d", len(form.KeyCoeffs), len(key))
	}
	if len(form.CheckpointCoeffs) < len(checkpoints) {
		return 0, fmt.Errorf("linear form checkpoints=%d < witness checkpoints=%d", len(form.CheckpointCoeffs), len(checkpoints))
	}
	acc := form.Const
	for i := range key {
		acc = f.add(acc, f.mul(form.KeyCoeffs[i], key[i]))
	}
	for i := range checkpoints {
		acc = f.add(acc, f.mul(form.CheckpointCoeffs[i], checkpoints[i]))
	}
	return acc, nil
}

func applyLinearLayer(forms []LinearForm, mds [][]uint64, f Field) []LinearForm {
	out := make([]LinearForm, len(forms))
	for row := range forms {
		acc := zeroLinearForm(len(forms[0].KeyCoeffs), len(forms[0].CheckpointCoeffs))
		for col := range forms {
			scaled := linearFormScale(f, forms[col], Elem(mds[row][col]%f.q))
			acc = linearFormAdd(f, acc, scaled)
		}
		out[row] = acc
	}
	return out
}

// TraceGroupedWitness returns the canonical grouped checkpoint witness together
// with the public linear wiring metadata needed by the companion verifier.
func TraceGroupedWitness(key, nonce []Elem, params *Params, groupRounds int) (*GroupedWitness, error) {
	if params == nil {
		return nil, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(key) != params.LenKey {
		return nil, fmt.Errorf("len(key)=%d want %d", len(key), params.LenKey)
	}
	if len(nonce) != params.LenNonce {
		return nil, fmt.Errorf("len(nonce)=%d want %d", len(nonce), params.LenNonce)
	}
	if groupRounds <= 0 {
		return nil, fmt.Errorf("invalid groupRounds=%d", groupRounds)
	}
	init, err := ConcatKeyNonce(key, nonce, params)
	if err != nil {
		return nil, err
	}
	checkpointCount, err := SBoxOutputCountGrouped(params, groupRounds)
	if err != nil {
		return nil, err
	}
	f := NewField(params.Q)
	t := params.T()
	state := append([]Elem(nil), init...)
	symState := make([]LinearForm, t)
	for i := 0; i < t; i++ {
		if i < params.LenKey {
			symState[i] = basisKeyLinearForm(params.LenKey, checkpointCount, i)
			continue
		}
		form := zeroLinearForm(params.LenKey, checkpointCount)
		form.Const = nonce[i-params.LenKey]
		symState[i] = form
	}
	out := &GroupedWitness{
		Checkpoints:       make([]GroupedCheckpoint, 0, checkpointCount),
		CheckpointInputs:  make([]Elem, 0, checkpointCount),
		CheckpointOutputs: make([]Elem, 0, checkpointCount),
	}
	tmp := make([]Elem, t)
	nextZ := 0
	totalRounds := params.RF + params.RP
	for round := 0; round < totalRounds; round++ {
		fullRound := round < params.RF/2 || round >= params.RF/2+params.RP
		checkpoint := ShouldCheckpointRound(params, round, groupRounds)
		if !fullRound && !checkpoint {
			return nil, fmt.Errorf("grouped schedule left internal round %d unchecked", round)
		}
		if fullRound {
			extRound := round
			if round >= params.RF/2+params.RP {
				extRound = round - params.RP
			}
			if checkpoint {
				for lane := 0; lane < t; lane++ {
					in := f.add(state[lane], Elem(params.CExt[extRound][lane]%f.q))
					wire := linearFormAddConst(f, symState[lane], Elem(params.CExt[extRound][lane]%f.q))
					z := f.powSmall(in, params.D)
					out.Checkpoints = append(out.Checkpoints, GroupedCheckpoint{
						Round:  round,
						Lane:   lane,
						Input:  in,
						Output: z,
						Wire:   cloneLinearForm(wire),
					})
					out.CheckpointInputs = append(out.CheckpointInputs, in)
					out.CheckpointOutputs = append(out.CheckpointOutputs, z)
					state[lane] = z
					slot := zeroLinearForm(params.LenKey, checkpointCount)
					slot.CheckpointCoeffs[nextZ] = 1
					symState[lane] = slot
					nextZ++
				}
				nextState := make([]Elem, t)
				matVec(nextState, params.ME, state, f)
				state = nextState
				symState = applyLinearLayer(symState, params.ME, f)
				continue
			}
			if round != totalRounds-1 {
				return nil, fmt.Errorf("unexpected unchecked full round %d before terminal round", round)
			}
			out.FinalRoundInputs = make([]LinearForm, t)
			out.FinalRoundOutputs = make([]Elem, t)
			for lane := 0; lane < t; lane++ {
				in := f.add(state[lane], Elem(params.CExt[extRound][lane]%f.q))
				wire := linearFormAddConst(f, symState[lane], Elem(params.CExt[extRound][lane]%f.q))
				out.FinalRoundInputs[lane] = cloneLinearForm(wire)
				out.FinalRoundOutputs[lane] = f.powSmall(in, params.D)
				tmp[lane] = out.FinalRoundOutputs[lane]
			}
			finalState := make([]Elem, t)
			matVec(finalState, params.ME, tmp, f)
			out.FinalState = append([]Elem(nil), finalState...)
			out.FinalTagState = append([]Elem(nil), finalState[:params.LenTag]...)
			state = finalState
			break
		}
		internalRound := round - params.RF/2
		in := f.add(state[0], Elem(params.CInt[internalRound]%f.q))
		wire := linearFormAddConst(f, symState[0], Elem(params.CInt[internalRound]%f.q))
		z := f.powSmall(in, params.D)
		out.Checkpoints = append(out.Checkpoints, GroupedCheckpoint{
			Round:  round,
			Lane:   0,
			Input:  in,
			Output: z,
			Wire:   cloneLinearForm(wire),
		})
		out.CheckpointInputs = append(out.CheckpointInputs, in)
		out.CheckpointOutputs = append(out.CheckpointOutputs, z)
		state[0] = z
		slot := zeroLinearForm(params.LenKey, checkpointCount)
		slot.CheckpointCoeffs[nextZ] = 1
		symState[0] = slot
		nextZ++
		nextState := make([]Elem, t)
		matVec(nextState, params.MI, state, f)
		state = nextState
		symState = applyLinearLayer(symState, params.MI, f)
	}
	if nextZ != checkpointCount {
		return nil, fmt.Errorf("checkpoint count=%d want %d", nextZ, checkpointCount)
	}
	if len(out.FinalRoundInputs) == 0 || len(out.FinalRoundOutputs) == 0 || len(out.FinalState) == 0 {
		return nil, fmt.Errorf("missing terminal round witness")
	}
	if len(out.FinalTagState) != params.LenTag {
		return nil, fmt.Errorf("final tag state len=%d want %d", len(out.FinalTagState), params.LenTag)
	}
	return out, nil
}
