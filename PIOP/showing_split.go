package PIOP

import (
	"fmt"
	"path/filepath"

	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	defaultV4PostSignLVCSNCols = 32
	defaultV4PostSignNLeaves   = 1536
	defaultV4PRFLVCSNCols      = 28
	defaultV4PRFNLeaves        = 2048
)

type ShowingSplitGeometryDefaults struct {
	PostSignLVCSNCols int
	PostSignNLeaves   int
	PRFLVCSNCols      int
	PRFNLeaves        int
}

func DefaultShowingSplitGeometry() ShowingSplitGeometryDefaults {
	return ShowingSplitGeometryDefaults{
		PostSignLVCSNCols: defaultV4PostSignLVCSNCols,
		PostSignNLeaves:   defaultV4PostSignNLeaves,
		PRFLVCSNCols:      defaultV4PRFLVCSNCols,
		PRFNLeaves:        defaultV4PRFNLeaves,
	}
}

func resolveShowingSplitSliceOpts(opts SimOpts) (SimOpts, SimOpts) {
	opts.applyDefaults()
	post := opts
	prfOpts := opts

	post.CoeffNativeSigModel = CoeffNativeSigModelLiteralPackedAggregatedV3
	if post.LVCSNCols <= 0 {
		post.LVCSNCols = defaultV4PostSignLVCSNCols
	}
	if post.NLeaves <= 0 {
		post.NLeaves = defaultV4PostSignNLeaves
	}
	if post.PostSignLVCSNCols > 0 {
		post.LVCSNCols = post.PostSignLVCSNCols
	}
	if post.PostSignNLeaves > 0 {
		post.NLeaves = post.PostSignNLeaves
	}

	prfOpts.CoeffNativeSigModel = CoeffNativeSigModelLiteralPackedAggregatedV3
	prfOpts.LVCSNCols = defaultV4PRFLVCSNCols
	prfOpts.NLeaves = defaultV4PRFNLeaves
	if prfOpts.PRFLVCSNCols > 0 {
		prfOpts.LVCSNCols = prfOpts.PRFLVCSNCols
	}
	if prfOpts.PRFNLeaves > 0 {
		prfOpts.NLeaves = prfOpts.PRFNLeaves
	}
	return post, prfOpts
}

type showingRowMaterial struct {
	rows         []*ring.Poly
	layout       RowLayout
	prfLayout    *PRFLayout
	witnessCount int
	witnessNCols int
	omegaWitness []uint64
}

func buildShowingRowMaterial(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	params *prf.Params,
	opts SimOpts,
) (*showingRowMaterial, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	_, omega, _, err := loadParamsAndOmega(opts)
	if err != nil {
		return nil, err
	}
	rows, _, layout, prfLayout, _, _, _, witnessCount, _, witnessNCols, err := BuildCredentialRowsShowing(
		ringQ,
		pub,
		wit,
		params.LenKey,
		params.LenNonce,
		params.RF,
		params.RP,
		opts.PRFGroupRounds,
		opts,
	)
	if err != nil {
		return nil, err
	}
	if witnessNCols <= 0 {
		witnessNCols = opts.NCols
	}
	if len(omega) < witnessNCols {
		return nil, fmt.Errorf("omega len=%d < witness ncols=%d", len(omega), witnessNCols)
	}
	return &showingRowMaterial{
		rows:         rows[:witnessCount],
		layout:       layout,
		prfLayout:    prfLayout,
		witnessCount: witnessCount,
		witnessNCols: witnessNCols,
		omegaWitness: append([]uint64(nil), omega[:witnessNCols]...),
	}, nil
}

func rowsToNTT(ringQ *ring.Ring, rows []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		out[i] = ringQ.NewPoly()
		ring.Copy(rows[i], out[i])
		ringQ.NTT(out[i], out[i])
	}
	return out
}

func clonePostSignSliceLayout(layout RowLayout, witnessCount int) RowLayout {
	out := layout
	out.SigCount = witnessCount
	out.PRFScalarBundleRows = 0
	out.PRFGroupedNonlinearRows = 0
	return out
}

func buildShowingSplitCombined(pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	postOpts, prfOpts := resolveShowingSplitSliceOpts(opts)
	ringQ, _, _, err := loadParamsAndOmega(postOpts)
	if err != nil {
		return nil, err
	}
	params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}
	postMat, err := buildShowingRowMaterial(ringQ, pub, wit, params, postOpts)
	if err != nil {
		return nil, fmt.Errorf("build post-sign showing rows: %w", err)
	}
	prfMat, err := buildShowingRowMaterial(ringQ, pub, wit, params, prfOpts)
	if err != nil {
		return nil, fmt.Errorf("build prf showing rows: %w", err)
	}
	if postMat.prfLayout == nil || prfMat.prfLayout == nil {
		return nil, fmt.Errorf("missing prf layout for split showing build")
	}
	if postMat.prfLayout.StartIdx != prfMat.prfLayout.StartIdx {
		return nil, fmt.Errorf("split row partition mismatch: post prfStart=%d prf prfStart=%d", postMat.prfLayout.StartIdx, prfMat.prfLayout.StartIdx)
	}
	prfStart := postMat.prfLayout.StartIdx
	if prfStart < 0 || prfStart > postMat.witnessCount || prfStart > prfMat.witnessCount {
		return nil, fmt.Errorf("invalid split prf start=%d (post=%d prf=%d)", prfStart, postMat.witnessCount, prfMat.witnessCount)
	}
	postRows := append([]*ring.Poly(nil), postMat.rows[:prfStart]...)
	postLayout := clonePostSignSliceLayout(postMat.layout, prfStart)
	postSet, err := buildCredentialConstraintSetPostFromRows(
		ringQ,
		pub.BoundB,
		pub,
		postLayout,
		rowsToNTT(ringQ, postRows),
		postMat.omegaWitness,
		postOpts.DomainMode,
		postOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("build split post-sign constraints: %w", err)
	}
	postPrepared := &preparedCredentialBuild{
		rows:          postRows,
		rowInputs:     make([]lvcs.RowInput, len(postRows)),
		rowLayout:     postLayout,
		witnessCount:  len(postRows),
		witnessNCols:  postMat.witnessNCols,
		maskRowOffset: len(postRows),
		skipConstraintRebuild: true,
	}
	postProof, err := buildWithConstraintsPrepared(pub, wit, postSet, postOpts, FSModeCredential, postPrepared)
	if err != nil {
		return nil, fmt.Errorf("build split post-sign proof: %w", err)
	}

	prfRows := append([]*ring.Poly(nil), prfMat.rows[prfStart:prfMat.witnessCount]...)
	remap := make([]int, prfMat.witnessCount)
	for i := range remap {
		remap[i] = -1
	}
	for i := prfStart; i < prfMat.witnessCount; i++ {
		remap[i] = i - prfStart
	}
	prfLayoutLocal, err := remapPRFLayout(prfMat.prfLayout, remap)
	if err != nil {
		return nil, fmt.Errorf("rebase split prf layout: %w", err)
	}
	if prfLayoutLocal.StartIdx != 0 {
		return nil, fmt.Errorf("unexpected split prf local start=%d", prfLayoutLocal.StartIdx)
	}
	prfLayoutLocal.WitnessRows = len(prfRows)
	if err := ValidateRowDependencyClosure(RowLayout{ShowingPRFOnly: true}, prfLayoutLocal, len(prfRows)); err != nil {
		return nil, fmt.Errorf("split prf local dependency closure: %w", err)
	}
	prfSet, err := BuildPRFConstraintSetSBox(
		ringQ,
		params,
		rowsToNTT(ringQ, prfRows),
		prfLayoutLocal,
		pub.Tag,
		pub.Nonce,
		prfMat.omegaWitness,
	)
	if err != nil {
		return nil, fmt.Errorf("build split prf constraints: %w", err)
	}
	prfSet.PRFLayout = prfLayoutLocal
	prfPrepared := &preparedCredentialBuild{
		rows:          prfRows,
		rowInputs:     make([]lvcs.RowInput, len(prfRows)),
		rowLayout:     RowLayout{ShowingPRFOnly: true, SigCount: len(prfRows)},
		witnessCount:  len(prfRows),
		witnessNCols:  prfMat.witnessNCols,
		maskRowOffset: len(prfRows),
		skipConstraintRebuild: true,
	}
	prfProof, err := buildWithConstraintsPrepared(pub, wit, prfSet, prfOpts, FSModeCredential, prfPrepared)
	if err != nil {
		return nil, fmt.Errorf("build split prf proof: %w", err)
	}
	if prfProof.RowLayout.CoeffNativeSig.Enabled {
		return nil, fmt.Errorf("unexpected coeff-native row layout on split prf proof (model=%q)", prfProof.RowLayout.CoeffNativeSig.Model)
	}
	if !prfProof.RowLayout.ShowingPRFOnly {
		return nil, fmt.Errorf("missing prf-only row layout marker on split prf proof")
	}
	if prfProof.PRFLayout == nil {
		return nil, fmt.Errorf("missing prf layout on split prf proof")
	}
	if prfProof.PRFLayout.StartIdx != 0 {
		return nil, fmt.Errorf("unexpected split prf proof start=%d", prfProof.PRFLayout.StartIdx)
	}
	if prfProof.PRFLayout.WitnessRows != len(prfRows) {
		return nil, fmt.Errorf("unexpected split prf proof witness rows=%d want %d", prfProof.PRFLayout.WitnessRows, len(prfRows))
	}
	prfClosureRows := prfProof.RowLayout.SigCount
	if prfClosureRows <= 0 {
		prfClosureRows = prfProof.MaskRowOffset
	}
	if err := ValidateRowDependencyClosure(prfProof.RowLayout, prfProof.PRFLayout, prfClosureRows); err != nil {
		return nil, fmt.Errorf("split prf proof closure after build: %w deps=%v", err, BuildShowingRowDependencyMap(prfProof.RowLayout, prfProof.PRFLayout))
	}

	return &Proof{
		Lambda: opts.Lambda,
		Kappa:  opts.Kappa,
		Theta:  opts.Theta,
		ShowingSplit: &ShowingSplitProof{
			PostSign: &ShowingProofSlice{Name: "post_sign", Proof: postProof},
			PRF:      &ShowingProofSlice{Name: "prf", Proof: prfProof},
		},
	}, nil
}
