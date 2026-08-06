package PIOP

import (
	"fmt"
	"reflect"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type semanticKRelationV3 struct {
	Eval             KConstraintEvaluator
	EvalParallel     KParallelConstraintEvaluator
	AggregateDot     KAggregateDotFactory
	EvalInto         *semanticKConstraintIntoV3
	EvalParallelInto *semanticKConstraintIntoV3
	AggregateDotInto semanticKAggregateDotFactoryIntoV3
	AggregateCount   int
}

type semanticKRelationFactoryV3 func(*Proof, []byte) (semanticKRelationV3, error)

// intGenISISSemanticKFactoryV3 constructs the prover-side Eq. (4) evaluator
// from the same relation configurations consumed by VerifyWithConstraints.
// It intentionally has no formal-coefficient fallback.
func intGenISISSemanticKFactoryV3(
	ringQ *ring.Ring,
	K *kf.Field,
	pub PublicInputs,
	layout RowLayout,
	omegaWitness, domainPoints []uint64,
	set ConstraintSet,
	opts SimOpts,
	preparedShowing *intGenISISShowingReplayConfig,
) (semanticKRelationFactoryV3, error) {
	if ringQ == nil || K == nil || !pub.IntGenISIS {
		return nil, fmt.Errorf("strict v3 semantic factory requires IntGenISIS ring and field")
	}
	var relation semanticKRelationV3
	switch {
	case len(pub.A) > 0 && len(pub.B) > 0 && len(pub.CM) > 0 && len(pub.AS) > 0:
		cfg := preparedShowing
		if cfg == nil {
			var err error
			cfg, err = newIntGenISISShowingReplayConfig(ringQ, pub, layout, omegaWitness, domainPoints, set.PRFCompanionLayout)
			if err != nil {
				return nil, err
			}
		} else if layout.IntGenISISShowing == nil || cfg.Ring != ringQ || !reflect.DeepEqual(cfg.Layout, *layout.IntGenISISShowing) {
			return nil, fmt.Errorf("strict v3 prepared showing replay binding mismatch")
		}
		var err error
		relation.Eval, err = cfg.CoreKEvaluator(K)
		if err != nil {
			return nil, err
		}
		relation.EvalInto, err = cfg.CoreKIntoEvaluator(K)
		if err != nil {
			return nil, err
		}
	case set.PRFLayout == nil && len(pub.Com) > 0 && len(pub.CM) > 0 && len(pub.AS) > 0:
		cfg, err := newIntGenISISPreSignReplayConfig(ringQ, pub, layout, omegaWitness, domainPoints)
		if err != nil {
			return nil, err
		}
		relation, err = cfg.SemanticKRelationV3(K, opts.ExecutionPolicy)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported strict v3 IntGenISIS relation shape")
	}
	if relation.Eval == nil {
		return nil, fmt.Errorf("strict v3 semantic relation produced no K evaluator")
	}
	if set.PRFCompanionLayout != nil {
		return nil, fmt.Errorf("strict v3 relation must not carry a PRF companion layout")
	}
	return func(proof *Proof, _ []byte) (semanticKRelationV3, error) {
		if proof == nil || !transcriptUsesSmallWood2025V3(proof.TranscriptVersion) {
			return semanticKRelationV3{}, fmt.Errorf("semantic evaluator factory requires a v3 proof")
		}
		if proof.PRFCompanion != nil {
			return semanticKRelationV3{}, fmt.Errorf("strict v3 proof must not carry a PRF companion payload")
		}
		return relation, nil
	}, nil
}
