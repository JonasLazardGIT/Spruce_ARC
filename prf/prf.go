package prf

import "fmt"

const ContextLaneCountV2 = 11

// Tag computes F(key, nonce) as defined in §B.6:
// tag = Tr(P(key||nonce) + (key||nonce)), truncated to LenTag.
func Tag(key, nonce []Elem, params *Params) ([]Elem, error) {
	if err := params.Validate(); err != nil {
		return nil, err
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
	orig := make([]Elem, t)
	copy(orig, state)
	PermuteInPlace(state, params)
	f := NewField(params.Q)
	for i := 0; i < t; i++ {
		state[i] = f.add(state[i], orig[i])
	}
	return state[:params.LenTag], nil
}

// TagContextSlot computes the v2 presentation tag. The first eleven public
// input lanes are the context and the twelfth lane is the hidden quota slot.
func TagContextSlot(key, context []Elem, slot Elem, params *Params) ([]Elem, error) {
	if len(context) != ContextLaneCountV2 {
		return nil, fmt.Errorf("context lanes=%d want %d", len(context), ContextLaneCountV2)
	}
	if params == nil || params.LenNonce != ContextLaneCountV2+1 {
		return nil, fmt.Errorf("v2 PRF requires %d input lanes", ContextLaneCountV2+1)
	}
	if uint64(slot) >= params.Q {
		return nil, fmt.Errorf("hidden slot %d is not canonical modulo %d", slot, params.Q)
	}
	input := make([]Elem, 0, ContextLaneCountV2+1)
	input = append(input, context...)
	input = append(input, slot)
	return Tag(key, input, params)
}
