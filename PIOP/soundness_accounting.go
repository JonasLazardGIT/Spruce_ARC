package PIOP

import (
	"fmt"
	"math"

	decs "vSIS-Signature/DECS"
)

// FullGameSoundnessReport composes issuance/showing one-proof budgets under
// accepted-proof counts.
type FullGameSoundnessReport struct {
	AccountingMode                string     `json:"accounting_mode"`
	AggregateQueryCapLog2         float64    `json:"aggregate_query_cap_log2,omitempty"`
	MaxNativeAlgebraicError       float64    `json:"max_native_algebraic_error,omitempty"`
	MaxNativeAlgebraicBits        float64    `json:"max_native_algebraic_bits,omitempty"`
	WorkFactorBits                float64    `json:"work_factor_bits,omitempty"`
	IssuanceWorkFactorBits        float64    `json:"issuance_work_factor_bits,omitempty"`
	ShowingWorkFactorBits         float64    `json:"showing_work_factor_bits,omitempty"`
	AcceptedIssuance              int        `json:"accepted_issuance"`
	AcceptedShowing               int        `json:"accepted_showing"`
	IssuanceQueryCaps             [5]int     `json:"issuance_query_caps"`
	ShowingQueryCaps              [5]int     `json:"showing_query_caps"`
	GlobalQueryCaps               [5]int     `json:"global_query_caps"`
	IssuanceQueryCapBits          [5]float64 `json:"issuance_query_cap_bits,omitempty"`
	ShowingQueryCapBits           [5]float64 `json:"showing_query_cap_bits,omitempty"`
	GlobalQueryCapBits            [5]float64 `json:"global_query_cap_bits,omitempty"`
	CollisionSpaceBits            int        `json:"collision_space_bits"`
	ConservativeFullGameError     float64    `json:"full_game_conservative"`
	ConservativeFullGameBits      float64    `json:"full_game_conservative_bits"`
	GlobalCollisionFullGameError  float64    `json:"full_game_global_collision"`
	GlobalCollisionFullGameBits   float64    `json:"full_game_global_collision_bits"`
	GlobalCollisionError          float64    `json:"global_collision"`
	GlobalCollisionBits           float64    `json:"global_collision_bits"`
	IssuanceAlgebraicContribution float64    `json:"issuance_algebraic_contribution"`
	ShowingAlgebraicContribution  float64    `json:"showing_algebraic_contribution"`
}

const (
	FullGameAccountingLegacyPerDomain = "legacy_per_domain_phase_composition"
	FullGameAccountingAggregateV4     = "aggregate_q_whole_game_v4"
	FullGameAccountingWorkFactorV4    = "native_work_factor_curve_v4"
)

// ValidateAggregateROQueryBudget enforces v4's single whole-game Q. The five
// legacy per-domain slots are not part of the publication-v4 threat model:
// bounded-query presets use exactly one aggregate scalar, while WF128 uses no
// query-budget scalar at all.
func ValidateAggregateROQueryBudget(opts SimOpts) error {
	if !transcriptUsesPublicationV4(opts.TranscriptVersion) {
		return nil
	}
	if opts.ROQueryCapsSet || opts.ROQueryCapBitsSet || opts.ROQueryCaps != [5]int{} || opts.ROQueryCapBits != [5]float64{} {
		return fmt.Errorf("publication-v4 does not use legacy per-domain RO query caps")
	}
	if publicationV4UsesWorkFactor(opts) {
		if opts.AggregateROQueryCapLog2Set {
			return fmt.Errorf("WF128 uses native work-factor accounting and must not declare an aggregate-Q residual budget")
		}
		return nil
	}
	if !opts.AggregateROQueryCapLog2Set || math.IsNaN(opts.AggregateROQueryCapLog2) || math.IsInf(opts.AggregateROQueryCapLog2, 0) || opts.AggregateROQueryCapLog2 < 0 {
		return fmt.Errorf("publication-v4 requires a finite nonnegative aggregate RO query cap log2")
	}
	return nil
}

func ResolveDECSCollisionBits(bits int) int {
	if bits > 0 && bits%8 == 0 && decs.IsSupportedHashBytes(bits/8) {
		return bits
	}
	return decs.DefaultHashBytes * 8
}

func ResolveDECSTapeBits(bits int) int {
	if bits > 0 && bits%8 == 0 && decs.IsSupportedTapeBytes(bits/8) {
		return bits
	}
	return decs.DefaultHashBytes * 8
}

func DECSHashBitsForOpts(opts SimOpts) int {
	if opts.DECSHashBits > 0 {
		return ResolveDECSCollisionBits(opts.DECSHashBits)
	}
	return ResolveDECSCollisionBits(opts.DECSCollisionBits)
}

func DECSTapeBitsForOpts(opts SimOpts) int {
	if opts.DECSTapeBits > 0 {
		return ResolveDECSTapeBits(opts.DECSTapeBits)
	}
	if opts.DECSCollisionBits > 0 {
		return ResolveDECSTapeBits(opts.DECSCollisionBits)
	}
	return decs.DefaultHashBytes * 8
}

func FSCollisionBitsForOpts(opts SimOpts) int {
	if opts.FSCollisionBits > 0 {
		return opts.FSCollisionBits
	}
	return DECSHashBitsForOpts(opts)
}

func applyDECSWidths(params decs.Params, opts SimOpts) decs.Params {
	params.TapeBytes = DECSTapeBitsForOpts(opts) / 8
	params.HashBytes = DECSHashBitsForOpts(opts) / 8
	return params
}

func applyDECSCollisionWidth(params decs.Params, opts SimOpts) decs.Params {
	return applyDECSWidths(params, opts)
}

func proofRootBytes(proof *Proof) []byte {
	if proof == nil {
		return nil
	}
	if proof.SchemaVersion == ProofSchemaVersionV2 {
		return proof.RootHash
	}
	if len(proof.RootHash) > 0 {
		return proof.RootHash
	}
	return proof.Root[:]
}

func proofRootSerializedSize(proof *Proof) int {
	if proof == nil {
		return 0
	}
	if proof.SchemaVersion == ProofSchemaVersionV2 {
		return len(proof.RootHash)
	}
	size := len(proof.Root)
	if len(proof.RootHash) > 0 {
		size += len(proof.RootHash)
	}
	return size
}

func proofQRootBytes(proof *Proof) []byte {
	if proof == nil {
		return nil
	}
	if proof.SchemaVersion == ProofSchemaVersionV2 {
		return proof.QRootHash
	}
	if len(proof.QRootHash) > 0 {
		return proof.QRootHash
	}
	return proof.QRoot[:]
}

func proofQRootSerializedSize(proof *Proof) int {
	if proof == nil {
		return 0
	}
	if proof.SchemaVersion == ProofSchemaVersionV2 {
		return len(proof.QRootHash)
	}
	size := len(proof.QRoot)
	if len(proof.QRootHash) > 0 {
		size += len(proof.QRootHash)
	}
	return size
}

func proofDECSHashBits(proof *Proof) int {
	bytes := minPositiveInt(
		len(proofRootBytes(proof)),
		openingHashBytes(resolveProofPCSOpening(proof)),
	)
	if proof != nil && !proofUsesPaperQPayloadOnly(proof) {
		bytes = minPositiveInt(bytes, len(proofQRootBytes(proof)), openingHashBytes(proof.QOpening))
	}
	if bytes <= 0 {
		bytes = decs.DefaultHashBytes
	}
	return 8 * bytes
}

func proofDECSTapeBits(proof *Proof) int {
	bytes := openingTapeBytes(resolveProofPCSOpening(proof))
	if proof != nil && !proofUsesPaperQPayloadOnly(proof) {
		bytes = minPositiveInt(bytes, openingTapeBytes(proof.QOpening))
	}
	if bytes <= 0 {
		bytes = decs.DefaultHashBytes
	}
	return 8 * bytes
}

func openingHashBytes(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	min := 0
	for _, node := range open.Nodes {
		min = minPositiveInt(min, len(node))
	}
	return min
}

func openingTapeBytes(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.Version != decs.OpeningVersionV2 || !decs.IsSupportedTapeBytes(open.TapeBytes) || len(open.Tapes) != open.EntryCount() {
		return 0
	}
	for _, tape := range open.Tapes {
		if len(tape) != open.TapeBytes {
			return 0
		}
	}
	return open.TapeBytes
}

func minPositiveInt(vals ...int) int {
	min := 0
	for _, v := range vals {
		if v <= 0 {
			continue
		}
		if min == 0 || v < min {
			min = v
		}
	}
	return min
}

func ComposeFullGameSoundness(issuance, showing SoundnessBudget, acceptedIssuance, acceptedShowing int) FullGameSoundnessReport {
	if acceptedIssuance < 0 {
		acceptedIssuance = 0
	}
	if acceptedShowing < 0 {
		acceptedShowing = 0
	}
	collisionBits := issuance.CollisionSpaceBits
	if collisionBits <= 0 || (showing.CollisionSpaceBits > 0 && showing.CollisionSpaceBits < collisionBits) {
		collisionBits = showing.CollisionSpaceBits
	}
	if collisionBits <= 0 {
		collisionBits = decs.DefaultHashBytes * 8
	}
	if workFactorSoundnessInputsValid(issuance, showing, acceptedIssuance, acceptedShowing) {
		return composeWorkFactorFullGameSoundness(issuance, showing, acceptedIssuance, acceptedShowing, collisionBits)
	}
	if aggregateSoundnessInputsValid(issuance, showing, acceptedIssuance, acceptedShowing) {
		return composeAggregateFullGameSoundness(issuance, showing, acceptedIssuance, acceptedShowing, collisionBits)
	}
	var globalCaps [5]int
	issuanceCapBits := soundnessQueryCapBits(issuance)
	showingCapBits := soundnessQueryCapBits(showing)
	var globalCapBits [5]float64
	for i := range globalCaps {
		globalCaps[i] = acceptedIssuance*issuance.QueryCaps[i] + acceptedShowing*showing.QueryCaps[i]
		globalCapBits[i] = composeQueryCapLog2(issuanceCapBits[i], showingCapBits[i], acceptedIssuance, acceptedShowing)
	}
	globalCollision := collisionErrorLog(globalCapBits, collisionBits)
	issuanceAlgTotal := soundnessAlgebraicTotal(issuance)
	showingAlgTotal := soundnessAlgebraicTotal(showing)
	issuanceOneProof := soundnessOneProofTotal(issuance)
	showingOneProof := soundnessOneProofTotal(showing)
	issuanceAlg := float64(acceptedIssuance) * issuanceAlgTotal
	showingAlg := float64(acceptedShowing) * showingAlgTotal
	conservative := clampProbability(float64(acceptedIssuance)*issuanceOneProof + float64(acceptedShowing)*showingOneProof)
	global := clampProbability(globalCollision + issuanceAlg + showingAlg)
	return FullGameSoundnessReport{
		AccountingMode:                FullGameAccountingLegacyPerDomain,
		AcceptedIssuance:              acceptedIssuance,
		AcceptedShowing:               acceptedShowing,
		IssuanceQueryCaps:             issuance.QueryCaps,
		ShowingQueryCaps:              showing.QueryCaps,
		GlobalQueryCaps:               globalCaps,
		IssuanceQueryCapBits:          issuanceCapBits,
		ShowingQueryCapBits:           showingCapBits,
		GlobalQueryCapBits:            globalCapBits,
		CollisionSpaceBits:            collisionBits,
		ConservativeFullGameError:     conservative,
		ConservativeFullGameBits:      probabilityBits(conservative),
		GlobalCollisionFullGameError:  global,
		GlobalCollisionFullGameBits:   probabilityBits(global),
		GlobalCollisionError:          globalCollision,
		GlobalCollisionBits:           probabilityBits(globalCollision),
		IssuanceAlgebraicContribution: issuanceAlg,
		ShowingAlgebraicContribution:  showingAlg,
	}
}

func workFactorSoundnessInputsValid(issuance, showing SoundnessBudget, acceptedIssuance, acceptedShowing int) bool {
	return (acceptedIssuance == 0 || issuance.WorkFactorMode) &&
		(acceptedShowing == 0 || showing.WorkFactorMode) &&
		(acceptedIssuance > 0 || acceptedShowing > 0)
}

func composeWorkFactorFullGameSoundness(issuance, showing SoundnessBudget, acceptedIssuance, acceptedShowing, collisionBits int) FullGameSoundnessReport {
	bits := math.Inf(1)
	maxNativeBits := math.Inf(1)
	issuanceBits, showingBits := 0.0, 0.0
	includeNative := func(budget SoundnessBudget) {
		for _, branchBits := range budget.NativeAlgebraicBits {
			if branchBits >= 0 && !math.IsNaN(branchBits) && !math.IsInf(branchBits, 0) && branchBits < maxNativeBits {
				maxNativeBits = branchBits
			}
		}
	}
	if acceptedIssuance > 0 {
		issuanceBits = issuance.WorkFactorBits
		includeNative(issuance)
		if issuanceBits < bits {
			bits = issuanceBits
		}
	}
	if acceptedShowing > 0 {
		showingBits = showing.WorkFactorBits
		includeNative(showing)
		if showingBits < bits {
			bits = showingBits
		}
	}
	if math.IsInf(bits, 1) {
		bits = 0
	}
	maxNativeError := 0.0
	if math.IsInf(maxNativeBits, 1) {
		maxNativeBits = 0
	} else {
		maxNativeError = probabilityFromLog2(-maxNativeBits)
	}
	err := probabilityFromLog2(-bits)
	noQueryCap := [5]float64{math.Inf(-1), math.Inf(-1), math.Inf(-1), math.Inf(-1), math.Inf(-1)}
	return FullGameSoundnessReport{
		AccountingMode:               FullGameAccountingWorkFactorV4,
		MaxNativeAlgebraicError:      maxNativeError,
		MaxNativeAlgebraicBits:       maxNativeBits,
		WorkFactorBits:               bits,
		IssuanceWorkFactorBits:       issuanceBits,
		ShowingWorkFactorBits:        showingBits,
		AcceptedIssuance:             acceptedIssuance,
		AcceptedShowing:              acceptedShowing,
		IssuanceQueryCaps:            issuance.QueryCaps,
		ShowingQueryCaps:             showing.QueryCaps,
		IssuanceQueryCapBits:         soundnessQueryCapBits(issuance),
		ShowingQueryCapBits:          soundnessQueryCapBits(showing),
		GlobalQueryCapBits:           noQueryCap,
		CollisionSpaceBits:           collisionBits,
		ConservativeFullGameError:    err,
		ConservativeFullGameBits:     bits,
		GlobalCollisionFullGameError: err,
		GlobalCollisionFullGameBits:  bits,
		GlobalCollisionError:         probabilityFromLog2(-float64(collisionBits) / 2),
		GlobalCollisionBits:          float64(collisionBits) / 2,
	}
}

func aggregateSoundnessInputsValid(issuance, showing SoundnessBudget, acceptedIssuance, acceptedShowing int) bool {
	return (acceptedIssuance == 0 || issuance.AggregateQueryBudget) &&
		(acceptedShowing == 0 || showing.AggregateQueryBudget) &&
		(acceptedIssuance > 0 || acceptedShowing > 0)
}

func composeAggregateFullGameSoundness(issuance, showing SoundnessBudget, acceptedIssuance, acceptedShowing, collisionBits int) FullGameSoundnessReport {
	queryBits := math.Inf(-1)
	maxNative := 0.0
	maxPhase := ""
	include := func(name string, accepted int, budget SoundnessBudget) {
		if accepted <= 0 {
			return
		}
		if budget.AggregateQueryCapBits > queryBits {
			queryBits = budget.AggregateQueryCapBits
		}
		for _, term := range nativeAlgebraicTerms(budget) {
			if term > maxNative {
				maxNative = term
				maxPhase = name
			}
		}
	}
	include("issuance", acceptedIssuance, issuance)
	include("showing", acceptedShowing, showing)
	if math.IsInf(queryBits, -1) {
		queryBits = 0
	}
	collision := probabilityFromLog2(2*queryBits - float64(collisionBits))
	algebraic := 0.0
	if maxNative > 0 {
		algebraic = probabilityFromLog2(queryBits + math.Log2(maxNative))
	}
	full := clampProbability(collision + algebraic)
	var globalCapBits [5]float64
	for i := range globalCapBits {
		globalCapBits[i] = math.Inf(-1)
	}
	issuanceContribution, showingContribution := 0.0, 0.0
	if maxPhase == "issuance" {
		issuanceContribution = algebraic
	} else if maxPhase == "showing" {
		showingContribution = algebraic
	}
	return FullGameSoundnessReport{
		AccountingMode:                FullGameAccountingAggregateV4,
		AggregateQueryCapLog2:         queryBits,
		MaxNativeAlgebraicError:       maxNative,
		MaxNativeAlgebraicBits:        probabilityBits(maxNative),
		AcceptedIssuance:              acceptedIssuance,
		AcceptedShowing:               acceptedShowing,
		IssuanceQueryCaps:             issuance.QueryCaps,
		ShowingQueryCaps:              showing.QueryCaps,
		IssuanceQueryCapBits:          soundnessQueryCapBits(issuance),
		ShowingQueryCapBits:           soundnessQueryCapBits(showing),
		GlobalQueryCapBits:            globalCapBits,
		CollisionSpaceBits:            collisionBits,
		ConservativeFullGameError:     full,
		ConservativeFullGameBits:      probabilityBits(full),
		GlobalCollisionFullGameError:  full,
		GlobalCollisionFullGameBits:   probabilityBits(full),
		GlobalCollisionError:          collision,
		GlobalCollisionBits:           probabilityBits(collision),
		IssuanceAlgebraicContribution: issuanceContribution,
		ShowingAlgebraicContribution:  showingContribution,
	}
}

func nativeAlgebraicTerms(b SoundnessBudget) [4]float64 {
	for _, term := range b.NativeAlgebraicTerms {
		if term > 0 {
			return b.NativeAlgebraicTerms
		}
	}
	var out [4]float64
	for i := range out {
		out[i] = clampProbability(b.Eps[i] * b.Grinding[i])
	}
	return out
}

func probabilityFromLog2(logProb float64) float64 {
	if math.IsInf(logProb, -1) {
		return 0
	}
	if logProb >= 0 {
		return 1
	}
	return clampProbability(math.Exp2(logProb))
}

func soundnessAlgebraicTotal(b SoundnessBudget) float64 {
	if b.AlgebraicTotal > 0 {
		return b.AlgebraicTotal
	}
	sum := 0.0
	for _, term := range b.AlgebraicTerms {
		sum += term
	}
	if sum > 0 {
		return clampProbability(sum)
	}
	for _, term := range b.TheoremTerms {
		sum += term
	}
	return clampProbability(sum)
}

func soundnessOneProofTotal(b SoundnessBudget) float64 {
	if b.OneProofTotal > 0 {
		return b.OneProofTotal
	}
	if b.Total > 0 {
		return b.Total
	}
	return clampProbability(b.Collision + soundnessAlgebraicTotal(b))
}

func collisionErrorLog(capBits [5]float64, collisionSpaceBits int) float64 {
	if collisionSpaceBits <= 0 {
		return 0
	}
	logTerms := make([]float64, 0, len(capBits))
	for _, bits := range capBits {
		if !math.IsInf(bits, -1) && bits >= 0 {
			logTerms = append(logTerms, 2*bits-float64(collisionSpaceBits))
		}
	}
	if len(logTerms) == 0 {
		return 0
	}
	logProb := log2SumExp(logTerms)
	if logProb >= 0 {
		return 1
	}
	return clampProbability(math.Exp2(logProb))
}

func queryCapBitsFromCaps(caps [5]int) [5]float64 {
	var out [5]float64
	for i, cap := range caps {
		if cap > 0 {
			out[i] = math.Log2(float64(cap))
		} else {
			out[i] = -1
		}
	}
	return out
}

func soundnessQueryCapBits(b SoundnessBudget) [5]float64 {
	if b.AggregateQueryBudget || b.WorkFactorMode {
		return b.QueryCapBits
	}
	for _, bits := range b.QueryCapBits {
		if bits > 0 {
			return b.QueryCapBits
		}
	}
	return queryCapBitsFromCaps(b.QueryCaps)
}

func queryCapBitsForOpts(opts SimOpts) [5]float64 {
	if opts.ROQueryCapBitsSet {
		return opts.ROQueryCapBits
	}
	return queryCapBitsFromCaps(opts.ROQueryCaps)
}

func composeQueryCapLog2(aBits, bBits float64, aCount, bCount int) float64 {
	logTerms := make([]float64, 0, 2)
	if aCount > 0 && !math.IsInf(aBits, -1) && aBits >= 0 {
		logTerms = append(logTerms, math.Log2(float64(aCount))+aBits)
	}
	if bCount > 0 && !math.IsInf(bBits, -1) && bBits >= 0 {
		logTerms = append(logTerms, math.Log2(float64(bCount))+bBits)
	}
	if len(logTerms) == 0 {
		return -1
	}
	return log2SumExp(logTerms)
}

func log2SumExp(vals []float64) float64 {
	if len(vals) == 0 {
		return math.Inf(-1)
	}
	max := math.Inf(-1)
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	if math.IsInf(max, -1) {
		return max
	}
	sum := 0.0
	for _, v := range vals {
		sum += math.Exp2(v - max)
	}
	return max + math.Log2(sum)
}

func clampProbability(v float64) float64 {
	if v <= 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func probabilityBits(v float64) float64 {
	if v <= 0 {
		return math.Inf(1)
	}
	if v > 1 {
		v = 1
	}
	return -math.Log2(v)
}
