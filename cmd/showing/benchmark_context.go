package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type compactFullBenchmarkContext struct {
	ringQ        *ring.Ring
	state        credential.State
	publicParams credential.PublicParams
	prfParams    *prf.Params
	B            []*ring.Poly
	wit          PIOP.WitnessInputs
	A            [][]*ring.Poly
}

func loadShowingBenchmarkContextFromStatePath(statePath string) (*compactFullBenchmarkContext, error) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		return nil, fmt.Errorf("load ring: %w", err)
	}
	state, err := credential.LoadState(statePath)
	if err != nil {
		return nil, fmt.Errorf("load credential state: %w", err)
	}
	publicParams, err := loadCredentialPublicParamsFromState(state)
	if err != nil {
		return nil, fmt.Errorf("load credential public params: %w", err)
	}
	params, err := loadPRFParamsFromState(state)
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}
	B, err := loadBForShowing(ringQ, state, publicParams)
	if err != nil {
		return nil, fmt.Errorf("load B: %w", err)
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{})
	omega, err := deriveOmegaForOpts(ringQ, opts, publicParams.HashRelation)
	if err != nil {
		return nil, fmt.Errorf("derive omega: %w", err)
	}
	wit, err := buildWitnessFromState(ringQ, state, B, omega, publicParams.BoundB, publicParams.X0CoeffBound)
	if err != nil {
		return nil, fmt.Errorf("build witness: %w", err)
	}
	A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
	if err != nil {
		return nil, fmt.Errorf("build A: %w", err)
	}
	return &compactFullBenchmarkContext{
		ringQ:        ringQ,
		state:        state,
		publicParams: publicParams,
		prfParams:    params,
		B:            B,
		wit:          wit,
		A:            A,
	}, nil
}

func loadCompactFullBenchmarkContext() (*compactFullBenchmarkContext, error) {
	return loadShowingBenchmarkContextFromStatePath(filepath.Join("credential", "keys", "credential_state.json"))
}

func writeShowingJSONFile(path string, value interface{}, perm os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), perm)
}

func msString(ms float64) string {
	return time.Duration(ms * float64(time.Millisecond)).String()
}
