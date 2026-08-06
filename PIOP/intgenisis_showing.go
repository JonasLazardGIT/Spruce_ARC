package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"time"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	swDomain "vSIS-Signature/internal/domain"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	intGenISISShowingLayoutVersionYLinearBoundedV2                   = "intgenisis_showing_y_linear_bounded_sources_v2"
	intGenISISShowingLayoutVersionProjectionUDigitsYViewBoundedV4    = "intgenisis_showing_project_u_digits_y_view_bounded_sources_v4"
	intGenISISShowingLayoutVersionProjectionUDigitsYBoundedSourcesV6 = "intgenisis_showing_project_u_digits_y_bounded_sources_v6"
	intGenISISShowingLayoutVersionInputTraceCarrierV3                = "intgenisis_showing_input_trace_ternary_carrier_v3"
)

type intGenISISShortnessMembershipBackend string

const (
	intGenISISShortnessMembershipPolynomial         intGenISISShortnessMembershipBackend = "polynomial"
	intGenISISShortnessMembershipDegreeCappedLookup intGenISISShortnessMembershipBackend = "degree_capped_lookup"
)

const (
	intGenISISLinearHatSourceMaterialized = "materialized_hat"
	// intGenISISLinearHatSourceMuX0AggregateFused is deliberately narrower
	// than a generic virtual/source-view hat mode.  Only the public-linear
	// mu_sig and x0 terms are substituted into the projected signature
	// aggregate.  The nonlinear x1/Z inverse relation continues to consume
	// independently committed, materialized hats.
	intGenISISLinearHatSourceMuX0AggregateFused = "mu_x0_aggregate_fused"
)

// IntGenISISShowingPreparedContext stores public, transcript-independent
// state that can be reused across multiple showing proofs for the same public
// parameters and options. It is an optimization artifact only; verifiers never
// need it.
type IntGenISISShowingPreparedContext struct {
	mu sync.Mutex

	pub            PublicInputs
	opts           SimOpts
	ringQ          *ring.Ring
	omega          []uint64
	domainPoints   []uint64
	preparedDomain *swDomain.Prepared
	publicBinding  []byte
	pcsNCols       int
	prfParams      *prf.Params
	groupRounds    int

	yLinearKey   [32]byte
	yLinearCache *intGenISISYLinearMapCache

	projectedBasisOutputCount  int
	projectedBasisSourceBlocks int
	projectedBasis             *transformBridgeBasisCache

	// strictReplay is the witness-independent strict-v3 replay plan.  It owns
	// the input-trace IR and all public transform tables used by both semantic
	// metadata construction and semantic-Q evaluation.  The prepared context
	// is the lifetime/binding boundary, so repeated proofs never rebuild it.
	strictReplay *intGenISISShowingReplayConfig
}

func (ctx *IntGenISISShowingPreparedContext) loadOrBuildStrictReplay(
	ringQ *ring.Ring,
	pub PublicInputs,
	layout RowLayout,
	omegaWitness, domainPoints []uint64,
	prfCompanionLayout *PRFCompanionLayout,
) (*intGenISISShowingReplayConfig, error) {
	if ctx == nil {
		return newIntGenISISShowingReplayConfig(ringQ, pub, layout, omegaWitness, domainPoints, prfCompanionLayout)
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.strictReplay != nil {
		if layout.IntGenISISShowing == nil || !reflect.DeepEqual(ctx.strictReplay.Layout, *layout.IntGenISISShowing) {
			return nil, fmt.Errorf("prepared IntGenISIS showing replay layout mismatch")
		}
		return ctx.strictReplay, nil
	}
	cfg, err := newIntGenISISShowingReplayConfig(ringQ, pub, layout, omegaWitness, domainPoints, prfCompanionLayout)
	if err != nil {
		return nil, err
	}
	ctx.strictReplay = cfg
	return cfg, nil
}

func (ctx *IntGenISISShowingPreparedContext) strictReplayConfig() *intGenISISShowingReplayConfig {
	if ctx == nil {
		return nil
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.strictReplay
}

func (ctx *IntGenISISShowingPreparedContext) loadYLinearCache(key [32]byte) *intGenISISYLinearMapCache {
	if ctx == nil {
		return nil
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.yLinearCache != nil && ctx.yLinearKey == key {
		return ctx.yLinearCache
	}
	return nil
}

func (ctx *IntGenISISShowingPreparedContext) storeYLinearCache(key [32]byte, cache *intGenISISYLinearMapCache) {
	if ctx == nil || cache == nil {
		return
	}
	ctx.mu.Lock()
	ctx.yLinearKey = key
	ctx.yLinearCache = cache
	ctx.mu.Unlock()
}

func (ctx *IntGenISISShowingPreparedContext) loadProjectedBasis(outputCount, sourceBlocks int) *transformBridgeBasisCache {
	if ctx == nil {
		return nil
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.projectedBasis != nil && ctx.projectedBasisOutputCount == outputCount && ctx.projectedBasisSourceBlocks == sourceBlocks {
		return ctx.projectedBasis
	}
	return nil
}

func (ctx *IntGenISISShowingPreparedContext) storeProjectedBasis(outputCount, sourceBlocks int, basis *transformBridgeBasisCache) {
	if ctx == nil || basis == nil {
		return
	}
	ctx.mu.Lock()
	ctx.projectedBasisOutputCount = outputCount
	ctx.projectedBasisSourceBlocks = sourceBlocks
	ctx.projectedBasis = basis
	ctx.mu.Unlock()
}

func intGenISISShortnessMembershipBackendForOpts(_ SimOpts) intGenISISShortnessMembershipBackend {
	return intGenISISShortnessMembershipPolynomial
}

func intGenISISOptsUseStrictSmallField2025(opts SimOpts) bool {
	return transcriptUsesStrictSmallField2025(opts.TranscriptVersion, opts.TranscriptProtocolMode)
}

func intGenISISOptsUseStructuralV3(opts SimOpts) bool {
	version := normalizeTranscriptVersion(opts.TranscriptVersion)
	protocol := normalizeTranscriptProtocolMode(opts.TranscriptProtocolMode)
	return (version == TranscriptVersionSmallWood2025V3 && protocol == TranscriptProtocolSmallField2025V3) ||
		(version == TranscriptVersionSmallWood2025V4 && protocol == TranscriptProtocolSmallField2025V4)
}

func rejectIntGenISISUnsupportedDegreeCappedModes(opts SimOpts) error {
	if !intGenISISOptsUseStrictSmallField2025(opts) {
		return nil
	}
	if opts.IntGenISISMSECompression > 1 {
		return fmt.Errorf("%s strict IntGenISIS showing does not support raw M/s/e compression level %d without a degree-capped decode/membership backend", TranscriptProtocolSmallField2025V2, opts.IntGenISISMSECompression)
	}
	if opts.SigShortnessRadix == 25 && opts.SigShortnessL == 3 && intGenISISShortnessMembershipBackendForOpts(opts) == intGenISISShortnessMembershipPolynomial {
		return fmt.Errorf("%s strict IntGenISIS showing rejects raw R25/L3 polynomial shortness membership; degree-capped lookup backend is required", TranscriptProtocolSmallField2025V2)
	}
	return nil
}

func (wit *CoeffNativeShowingWitness) ValidateIntGenISIS(ringN int, pub PublicInputs) error {
	if wit == nil {
		return fmt.Errorf("nil IntGenISIS showing witness")
	}
	if len(wit.Sig) == 0 {
		return fmt.Errorf("missing signature preimage rows")
	}
	if wit.M == nil {
		return fmt.Errorf("missing semantic message M row")
	}
	if wit.MAttr == nil {
		return fmt.Errorf("missing semantic message m row")
	}
	if wit.K == nil {
		return fmt.Errorf("missing semantic message k row")
	}
	if len(wit.S) == 0 {
		return fmt.Errorf("missing commitment secret s rows")
	}
	if len(wit.E) == 0 {
		return fmt.Errorf("missing commitment error e rows")
	}
	if len(wit.MuSig) != 1 {
		return fmt.Errorf("mu_sig rows=%d want 1", len(wit.MuSig))
	}
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return err
	}
	if len(wit.X0) != x0Len {
		return fmt.Errorf("x0 rows=%d want %d", len(wit.X0), x0Len)
	}
	if wit.X1 == nil {
		return fmt.Errorf("missing x1 row")
	}
	if wit.Z == nil {
		return fmt.Errorf("missing Z row")
	}
	if wit.HiddenSlot >= 16 {
		return fmt.Errorf("hidden slot=%d outside [0,16)", wit.HiddenSlot)
	}
	recomposed := uint64(0)
	for i, bit := range wit.HiddenBits {
		if bit > 1 {
			return fmt.Errorf("hidden slot bit %d=%d is not Boolean", i, bit)
		}
		recomposed += bit << i
	}
	if recomposed != wit.HiddenSlot {
		return fmt.Errorf("hidden slot=%d does not match bit decomposition=%d", wit.HiddenSlot, recomposed)
	}
	if pub.HashInputBound != credential.IntGenISISHashInputBound {
		return fmt.Errorf("hash_input_bound=%d want %d", pub.HashInputBound, credential.IntGenISISHashInputBound)
	}
	if len(pub.A) > 0 && len(pub.A[0]) > 0 && len(wit.Sig) != len(pub.A[0]) {
		return fmt.Errorf("signature preimage rows=%d want %d", len(wit.Sig), len(pub.A[0]))
	}
	if len(pub.CM) > 0 && len(pub.CM[0]) > 0 && len(wit.S) > 0 && len(wit.MuSig) > 0 {
		if len(pub.CM[0]) != 1 {
			return fmt.Errorf("C_M cols=%d want ell_M=1", len(pub.CM[0]))
		}
	}
	check := func(name string, rows []*ring.Poly) error {
		for i, p := range rows {
			if p == nil || len(p.Coeffs) == 0 {
				return fmt.Errorf("nil %s row %d", name, i)
			}
			if ringN > 0 && len(p.Coeffs[0]) != ringN {
				return fmt.Errorf("%s row %d width=%d want ringN=%d", name, i, len(p.Coeffs[0]), ringN)
			}
		}
		return nil
	}
	if err := check("sig", wit.Sig); err != nil {
		return err
	}
	if err := check("M", []*ring.Poly{wit.M}); err != nil {
		return err
	}
	if err := check("m", []*ring.Poly{wit.MAttr}); err != nil {
		return err
	}
	if err := check("k", []*ring.Poly{wit.K}); err != nil {
		return err
	}
	if err := check("s", wit.S); err != nil {
		return err
	}
	if err := check("e", wit.E); err != nil {
		return err
	}
	if err := check("mu_sig", wit.MuSig); err != nil {
		return err
	}
	if err := check("x0", wit.X0); err != nil {
		return err
	}
	if err := check("x1", []*ring.Poly{wit.X1}); err != nil {
		return err
	}
	if err := check("Z", []*ring.Poly{wit.Z}); err != nil {
		return err
	}
	if wit.PackedNCols <= 0 {
		return fmt.Errorf("invalid packed ncols=%d", wit.PackedNCols)
	}
	return nil
}

func BuildCredentialRowsShowingIntGenISIS(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
) (
	rows []*ring.Poly,
	rowInputs []lvcs.RowInput,
	layout RowLayout,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
	decsParams decs.Params,
	maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int,
	err error,
) {
	return buildCredentialRowsShowingIntGenISIS(
		ringQ, pub, wit, prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds, opts, nil,
	)
}

func buildCredentialRowsShowingIntGenISIS(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
	preparedOmega []uint64,
) (
	rows []*ring.Poly,
	rowInputs []lvcs.RowInput,
	layout RowLayout,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
	decsParams decs.Params,
	maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int,
	err error,
) {
	if ringQ == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil ring")
	}
	recordRowPhase := func(label string, start time.Time) {
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration(label, time.Since(start))
		}
	}
	validateStart := phaseTimingStart(opts.PhaseRecorder)
	if !pub.IntGenISIS {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("IntGenISIS showing rows require IntGenISIS public inputs")
	}
	cn := wit.CoeffNativeShowing
	if err := cn.ValidateIntGenISIS(int(ringQ.N), pub); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := validateIntGenISISSemanticPolys(ringQ, pub.BoundB, []*ring.Poly{cn.M}, []*ring.Poly{cn.MAttr}, []*ring.Poly{cn.K}); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("semantic message: %w", err)
	}
	if err := validateIntGenISISLiveBoundPolys(ringQ, pub.BoundB, "s", cn.S); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := validateIntGenISISLiveBoundPolys(ringQ, pub.BoundB, "e", cn.E); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	for _, source := range []struct {
		name string
		rows []*ring.Poly
	}{
		{"mu_sig", cn.MuSig},
		{"x0", cn.X0},
		{"x1", []*ring.Poly{cn.X1}},
	} {
		if err := validateIntGenISISBoundedPolys(ringQ, pub.HashInputBound, source.name, source.rows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := validateIntGenISISBoundedPolys(ringQ, sigBound, "u", cn.Sig); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	opts.applyDefaults()
	if err := validateIntGenISISReplayProjection(opts.IntGenISISReplayProjection); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := rejectIntGenISISUnsafeSigLookup(opts); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := rejectIntGenISISUnsupportedDegreeCappedModes(opts); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	replayProjection := normalizeIntGenISISReplayProjection(opts.IntGenISISReplayProjection)
	structuralV3 := intGenISISOptsUseStructuralV3(opts)
	layoutVersion := intGenISISShowingLayoutVersionYLinearBoundedV2
	layoutReplayProjection := ""
	if replayProjection == IntGenISISReplayProjectionProjectUDigitsYViewV3 {
		layoutVersion = intGenISISShowingLayoutVersionProjectionUDigitsYViewBoundedV4
		layoutReplayProjection = replayProjection
	} else if replayProjection == IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
		layoutVersion = intGenISISShowingLayoutVersionProjectionUDigitsYBoundedSourcesV6
		layoutReplayProjection = replayProjection
	}
	if structuralV3 {
		if replayProjection != IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("strict v3 showing requires replay projection %q", IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6)
		}
		layoutVersion = intGenISISShowingLayoutVersionInputTraceCarrierV3
		layoutReplayProjection = replayProjection
	}
	ncols = opts.NCols
	if ncols <= 0 {
		ncols = cn.PackedNCols
	}
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	if ncols > int(ringQ.N) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("ncols=%d exceeds ringN=%d", ncols, ringQ.N)
	}
	if structuralV3 && ncols != prfInputTraceV3PackWidth {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("strict v3 showing requires ncols=%d, got %d", prfInputTraceV3PackWidth, ncols)
	}
	lvcsNCols := resolvePCSNCols(opts, ncols)
	if lvcsNCols < ncols {
		lvcsNCols = ncols
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	ell := opts.Ell
	if ell <= 0 {
		ell = 1
	}
	var omegaWitness []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(preparedOmega) > 0 {
			if len(preparedOmega) < ncols {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prepared witness omega len=%d want at least %d", len(preparedOmega), ncols)
			}
			omegaWitness = append([]uint64(nil), preparedOmega[:ncols]...)
		} else {
			omegaWitness, err = deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, lvcsNCols, ell, pub.HashRelation)
			if err != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("derive witness omega: %w", err)
			}
		}
	} else {
		omegaWitness, err = ringDomainSlots(ringQ)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		if len(omegaWitness) > ncols {
			omegaWitness = omegaWitness[:ncols]
		}
	}
	q := ringQ.Modulus[0]
	rowInterp, err := newOmegaInterpolationPlan(omegaWitness[:ncols], q)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("row omega interpolation plan: %w", err)
	}
	shortSpec, err := intGenISISUShortnessSpecForOpts(q, sigBound, opts)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	mseCompressionDesc, err := intGenISISMSECompressionDescriptorForBound(opts.IntGenISISMSECompression, pub.BoundB)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	recordRowPhase("showing.rows.validate", validateStart)
	makeRowInput := func(p *ring.Poly) (lvcs.RowInput, error) {
		head, herr := rowHeadOnOmega(ringQ, omegaWitness, p, ncols)
		if herr != nil {
			return lvcs.RowInput{}, herr
		}
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return lvcs.RowInput{Head: head, Poly: cp, TrustedHead: true}, nil
	}
	makeRowFromHead := func(head []uint64) *ring.Poly {
		return rowInterp.coeffPolyFromHead(ringQ, head)
	}

	viewRowsPerPoly := int(ringQ.N) / ncols
	coreRowCount := 0
	uStart := -1
	mStart := -1
	mAttrStart := -1
	kStart := -1
	sStart := -1
	eStart := -1
	muSigStart := -1
	x0Start := -1
	x1Start := -1
	zStart := -1
	rowInputs = make([]lvcs.RowInput, 0)
	appendRowMaterialsWithInputs := func(label string, materials []intGenISISRowMaterial) error {
		rowInputsStart := phaseTimingStart(opts.PhaseRecorder)
		for _, material := range materials {
			idx := len(rows)
			if material.Poly == nil {
				return fmt.Errorf("%s row %d has nil polynomial", label, idx)
			}
			rows = append(rows, material.Poly)
			if len(material.Head) == ncols {
				head := append([]uint64(nil), material.Head...)
				for i := range head {
					head[i] %= q
				}
				cp := ringQ.NewPoly()
				ring.Copy(material.Poly, cp)
				rowInputs = append(rowInputs, lvcs.RowInput{Head: head, Poly: cp, TrustedHead: true})
				continue
			}
			in, ierr := makeRowInput(material.Poly)
			if ierr != nil {
				return fmt.Errorf("%s row %d input: %w", label, idx, ierr)
			}
			rowInputs = append(rowInputs, in)
		}
		recordRowPhase("showing.rows.row_inputs", rowInputsStart)
		return nil
	}
	digitOnlyU := replayProjection == IntGenISISReplayProjectionProjectUDigitsYViewV3 || replayProjection == IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
	uViewStart := -1
	coeffViewsStart := phaseTimingStart(opts.PhaseRecorder)
	uViewRows := []intGenISISRowMaterial(nil)
	if !digitOnlyU {
		uViewStart = len(rows)
		uViewRows, err = intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, cn.Sig, ncols, rowInterp)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("u coefficient views: %w", err)
		}
		if err := appendRowMaterialsWithInputs("u coefficient view", uViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	recordRowPhase("showing.rows.coeff_views", coeffViewsStart)
	uShortnessSourceRows := len(cn.Sig) * viewRowsPerPoly
	if digitOnlyU {
		uShortnessSourceRows = 0
	}
	uShortnessStart := len(rows)
	shortnessStart := phaseTimingStart(opts.PhaseRecorder)
	uShortnessRows, err := intGenISISUShortnessDigitRowMaterials(ringQ, omegaWitness, cn.Sig, ncols, shortSpec, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("u shortness digit rows: %w", err)
	}
	if err := appendRowMaterialsWithInputs("u shortness digit", uShortnessRows); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	recordRowPhase("showing.rows.shortness_digits", shortnessStart)
	boundViewStart := len(rows)
	coeffViewsStart = phaseTimingStart(opts.PhaseRecorder)
	mViewRows, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, []*ring.Poly{cn.M}, ncols, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("m coefficient views: %w", err)
	}
	sViewRows, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, cn.S, ncols, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("s coefficient views: %w", err)
	}
	eViewRows, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, cn.E, ncols, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("e coefficient views: %w", err)
	}
	muSigViewRows, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, cn.MuSig, ncols, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("mu_sig coefficient views: %w", err)
	}
	x0ViewRows, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, cn.X0, ncols, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("x0 coefficient views: %w", err)
	}
	x1ViewRows, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, []*ring.Poly{cn.X1}, ncols, rowInterp)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("x1 coefficient views: %w", err)
	}
	recordRowPhase("showing.rows.coeff_views", coeffViewsStart)
	mViewStart := -1
	sViewStart := -1
	eViewStart := -1
	mCarrierStart := -1
	sCarrierStart := -1
	eCarrierStart := -1
	mCarrierCount := 0
	sCarrierCount := 0
	eCarrierCount := 0
	mCompressedSourceRows := 0
	mSeedViewStart := -1
	mSeedViewCount := 0
	if mseCompressionDesc.Level > 0 {
		carriersStart := phaseTimingStart(opts.PhaseRecorder)
		mOrdinaryViewRows, mSeedViewRows, serr := intGenISISSplitMViewRowsForPack9Tail(mViewRows, int(ringQ.N), ncols)
		if serr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, serr
		}
		mCarrierStart = len(rows)
		mCarrierRows, cerr := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omegaWitness, mOrdinaryViewRows, mseCompressionDesc.PackWidth, rowInterp, makeRowFromHead, "M")
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if err := appendRowMaterialsWithInputs("M compressed carrier", mCarrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		mCarrierCount = len(mCarrierRows)
		mCompressedSourceRows = len(mOrdinaryViewRows)
		mSeedViewStart = len(rows)
		if err := appendRowMaterialsWithInputs("M seed-tail coefficient view", mSeedViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		mSeedViewCount = len(mSeedViewRows)
		sCarrierStart = len(rows)
		sCarrierRows, cerr := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omegaWitness, sViewRows, mseCompressionDesc.PackWidth, rowInterp, makeRowFromHead, "s")
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if err := appendRowMaterialsWithInputs("s compressed carrier", sCarrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		sCarrierCount = len(sCarrierRows)
		eCarrierStart = len(rows)
		eCarrierRows, cerr := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omegaWitness, eViewRows, mseCompressionDesc.PackWidth, rowInterp, makeRowFromHead, "e")
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if err := appendRowMaterialsWithInputs("e compressed carrier", eCarrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		eCarrierCount = len(eCarrierRows)
		recordRowPhase("showing.rows.carriers", carriersStart)
	} else {
		mViewStart = len(rows)
		if err := appendRowMaterialsWithInputs("M coefficient view", mViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		sViewStart = len(rows)
		if err := appendRowMaterialsWithInputs("s coefficient view", sViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		eViewStart = len(rows)
		if err := appendRowMaterialsWithInputs("e coefficient view", eViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	muSigCarrierStart, muSigCarrierCount := -1, 0
	x0CarrierStart, x0CarrierCount := -1, 0
	x1CarrierStart, x1CarrierCount := -1, 0
	if structuralV3 {
		if len(muSigViewRows)%ternaryCarrierV3PackWidth != 0 || len(x0ViewRows)%ternaryCarrierV3PackWidth != 0 || len(x1ViewRows)%ternaryCarrierV3PackWidth != 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("strict v3 hash source row groups must be divisible by %d", ternaryCarrierV3PackWidth)
		}
		allHashSources := make([]intGenISISRowMaterial, 0, len(muSigViewRows)+len(x0ViewRows)+len(x1ViewRows))
		allHashSources = append(allHashSources, muSigViewRows...)
		allHashSources = append(allHashSources, x0ViewRows...)
		allHashSources = append(allHashSources, x1ViewRows...)
		carrierRows, carrierLayout, cerr := packTernarySourceRowsV3(ringQ, omegaWitness, allHashSources, rowInterp, makeRowFromHead)
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if carrierLayout.CarrierRows*carrierLayout.PackWidth != len(allHashSources) {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("strict v3 hash carrier geometry mismatch")
		}
		muSigCarrierStart = len(rows)
		muSigCarrierCount = len(muSigViewRows) / ternaryCarrierV3PackWidth
		x0CarrierStart = muSigCarrierStart + muSigCarrierCount
		x0CarrierCount = len(x0ViewRows) / ternaryCarrierV3PackWidth
		x1CarrierStart = x0CarrierStart + x0CarrierCount
		x1CarrierCount = len(x1ViewRows) / ternaryCarrierV3PackWidth
		if err := appendRowMaterialsWithInputs("mu_sig/x0/x1 v3 carriers", carrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		muSigStart, x0Start, x1Start = muSigCarrierStart, x0CarrierStart, x1CarrierStart
	} else {
		muSigStart = len(rows)
		if err := appendRowMaterialsWithInputs("mu_sig coefficient view", muSigViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		x0Start = len(rows)
		if err := appendRowMaterialsWithInputs("x0 coefficient view", x0ViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		x1Start = len(rows)
		if err := appendRowMaterialsWithInputs("x1 coefficient view", x1ViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	boundViewCount := len(rows) - boundViewStart
	yViewStart := -1
	yViewRows := []intGenISISRowMaterial(nil)
	if !digitOnlyU {
		yCoeff, yerr := intGenISISCommitmentLinearYCoeff(ringQ, pub, cn)
		if yerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("commitment-linear y: %w", yerr)
		}
		yViewStart = len(rows)
		coeffViewsStart = phaseTimingStart(opts.PhaseRecorder)
		yViewRows, err = intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, []*ring.Poly{yCoeff}, ncols, rowInterp)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("y coefficient views: %w", err)
		}
		recordRowPhase("showing.rows.coeff_views", coeffViewsStart)
		if err := appendRowMaterialsWithInputs("Y coefficient view", yViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	buildAndAppendHats := func(label string, coeffRows []intGenISISRowMaterial) (int, int, error) {
		start := len(rows)
		hatStart := phaseTimingStart(opts.PhaseRecorder)
		hatRows, herr := intGenISISHatRowMaterialsFromCoeffViews(ringQ, omegaWitness, coeffRows, viewRowsPerPoly, rowInterp, makeRowFromHead, label)
		if herr != nil {
			return 0, 0, herr
		}
		if err := appendRowMaterialsWithInputs(label+" hat", hatRows); err != nil {
			return 0, 0, err
		}
		recordRowPhase("showing.rows.hats", hatStart)
		recordRowPhase("showing.rows.hats."+label, hatStart)
		return start, len(hatRows), nil
	}
	buildAndAppendDirectHats := func(label string, polys []*ring.Poly) (int, int, error) {
		coeffViewsStart := phaseTimingStart(opts.PhaseRecorder)
		coeffRows, cerr := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, polys, ncols, rowInterp)
		if cerr != nil {
			return 0, 0, cerr
		}
		recordRowPhase("showing.rows.coeff_views", coeffViewsStart)
		return buildAndAppendHats(label, coeffRows)
	}
	uHatStart, uHatCount := -1, 0
	yHatStart, yHatCount := -1, 0
	if replayProjection == IntGenISISReplayProjectionNone {
		uHatStart, uHatCount, err = buildAndAppendHats("u", uViewRows)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("u hats: %w", err)
		}
		yHatStart, yHatCount, err = buildAndAppendHats("Y", yViewRows)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("y hats: %w", err)
		}
	}
	muSigHatStart, muSigHatCount := -1, 0
	x0HatStart, x0HatCount := -1, 0
	if !structuralV3 {
		muSigHatStart, muSigHatCount, err = buildAndAppendHats("mu_sig", muSigViewRows)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("mu_sig hats: %w", err)
		}
		x0HatStart, x0HatCount, err = buildAndAppendHats("x0", x0ViewRows)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("x0 hats: %w", err)
		}
	}
	x1HatStart, x1HatCount, err := buildAndAppendHats("x1", x1ViewRows)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("x1 hats: %w", err)
	}
	zHatStart, zHatCount, err := buildAndAppendDirectHats("Z", []*ring.Poly{cn.Z})
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("z hats: %w", err)
	}

	companionMode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	prfInputTraceV3Start, prfInputTraceV3Rows := -1, 0
	prfInputTraceV3Logical, prfInputTraceV3Padding, prfInputTraceV3TagCount := 0, 0, 0
	if structuralV3 {
		prfTraceStart := phaseTimingStart(opts.PhaseRecorder)
		key, kerr := extractIntGenISISPRFKeyElemsFromSemanticM(ringQ, pub.BoundB, []*ring.Poly{cn.M})
		if kerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("extract IntGenISIS PRF key from M: %w", kerr)
		}
		if len(key) != prfParamsLenKey {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("semantic key length=%d want %d", len(key), prfParamsLenKey)
		}
		params, perr := loadBoundPRFParamsForOpts(opts)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("load prf params: %w", perr)
		}
		contextElems, cerr := publicContextElems(pub.Context, params.Q)
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		trace, terr := prf.TraceInputWitnessContextSlotV3(key, contextElems, prf.Elem(cn.HiddenSlot), params)
		if terr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("trace PRF input witness v3: %w", terr)
		}
		hiddenBits := [4]prf.Elem{}
		for i, bit := range cn.HiddenBits {
			hiddenBits[i] = prf.Elem(bit)
		}
		prfInputTraceV3Start = len(rows)
		startIdx = prfInputTraceV3Start
		packed, perr := packCanonicalPRFInputTraceV3Rows(ringQ, prfInputTraceV3Start, trace, hiddenBits, makeRowFromHead)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack PRF input-trace v3 rows: %w", perr)
		}
		if err := appendRowMaterialsWithInputs("PRF input-trace v3", packed.Rows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		prfInputTraceV3Rows = packed.Layout.PackedRows
		prfInputTraceV3Logical = packed.Layout.LogicalScalars
		prfInputTraceV3Padding = packed.Layout.PaddingScalars
		prfInputTraceV3TagCount = len(pub.Tag)
		// Strict v3 authenticates this relation directly through Q.  It has no
		// companion bridge matrices and no PRFCompanion proof payload.
		prfCompanionLayout = nil
		recordRowPhase("showing.rows.prf_input_trace_v3", prfTraceStart)
	} else if companionMode != "" {
		prfCompanionStart := phaseTimingStart(opts.PhaseRecorder)
		if prfGroupRounds <= 0 {
			prfGroupRounds = 1
		}
		key, kerr := extractIntGenISISPRFKeyElemsFromSemanticM(ringQ, pub.BoundB, []*ring.Poly{cn.M})
		if kerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("extract IntGenISIS PRF key from M: %w", kerr)
		}
		if len(key) != prfParamsLenKey {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("semantic key length=%d want %d", len(key), prfParamsLenKey)
		}
		params, perr := loadBoundPRFParamsForOpts(opts)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("load prf params: %w", perr)
		}
		contextElems, cerr := publicContextElems(pub.Context, params.Q)
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if uint64(cn.HiddenSlot) >= params.Q {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("hidden slot=%d is not canonical modulo %d", cn.HiddenSlot, params.Q)
		}
		groupedWitness, gwerr := prf.TraceGroupedWitnessContextSlot(key, contextElems, prf.Elem(cn.HiddenSlot), params, prfGroupRounds)
		if gwerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("trace prf witness: %w", gwerr)
		}
		companionStart := len(rows)
		startIdx = companionStart
		hiddenBits := [4]prf.Elem{}
		for i, bit := range cn.HiddenBits {
			hiddenBits[i] = prf.Elem(bit)
		}
		packed, perr := packPRFCompanionWitnessRows(ringQ, ncols, companionStart, companionMode, true, key, prf.Elem(cn.HiddenSlot), hiddenBits, groupedWitness, makeRowFromHead)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack prf companion rows: %w", perr)
		}
		rows = append(rows, packed.Rows...)
		for i, p := range packed.Rows {
			in, ierr := makeRowInput(p)
			if ierr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf row %d input: %w", i, ierr)
			}
			rowInputs = append(rowInputs, in)
		}
		rowSemantics := make([]RowSemantics, len(packed.Rows))
		for i := range rowSemantics {
			rowSemantics[i] = CoeffPackedRow
		}
		dataSlots := append([]CoeffSlot(nil), packed.KeySlots...)
		dataSlots = append(dataSlots, packed.HiddenSlotSlot)
		dataSlots = append(dataSlots, packed.HiddenSlotBitSlots[:]...)
		dataSlots = append(dataSlots, packed.CheckpointSlots...)
		dataSlots = append(dataSlots, packed.FinalRoundOutputSlots...)
		dataRows := len(uniqueRowsFromCoeffSlots(dataSlots))
		helperRows := maxInt(len(packed.Rows)-dataRows, 0)
		keySourceSlots := []CoeffSlot(nil)
		keySourceDecodeLanes := []int(nil)
		var kserr error
		keySourceMode := PRFKeySourceModePack9Seed
		if mseCompressionDesc.Level > 0 {
			keySourceSlots, kserr = intGenISISSeedSourceTailViewSlots(mSeedViewStart, ncols, int(ringQ.N))
			if kserr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("IntGenISIS compressed PRF seed source slots: %w", kserr)
			}
		} else {
			keySourceSlots, kserr = intGenISISSeedSourceViewSlots(mViewStart, ncols, int(ringQ.N))
			if kserr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("IntGenISIS PRF seed source slots: %w", kserr)
			}
		}
		prfCompanionLayout = &PRFCompanionLayout{
			StartRow:              companionStart,
			PackWidth:             ncols,
			GroupRounds:           prfGroupRounds,
			KeySource:             KeySourceIndependentWitness,
			KeySourceMode:         keySourceMode,
			KeySlots:              packed.KeySlots,
			HiddenSlotSlot:        packed.HiddenSlotSlot,
			HiddenSlotBitSlots:    packed.HiddenSlotBitSlots,
			KeySourceSlots:        keySourceSlots,
			KeySourceDecodeLanes:  keySourceDecodeLanes,
			CheckpointSlots:       packed.CheckpointSlots,
			FinalRoundOutputSlots: packed.FinalRoundOutputSlots,
			FinalTagSlots:         packed.FinalTagSlots,
			HelperFamilies:        []string{"final_tag_state"},
			ReplayRows:            len(packed.Rows),
			PackedRows:            len(packed.Rows),
			PackedLogicalCount:    packed.TotalLogicalScalars,
			HelperRowCount:        helperRows,
			DataRows:              dataRows,
			HelperRows:            helperRows,
			KeyCount:              len(packed.KeySlots),
			HiddenSlotCount:       1,
			HiddenSlotBitCount:    len(packed.HiddenSlotBitSlots),
			CheckpointCount:       len(packed.CheckpointSlots),
			FinalRoundOutputCount: len(packed.FinalRoundOutputSlots),
			TagCount:              len(pub.Tag),
			RelationVersion:       prfCompanionRelationVersion(companionMode),
			RowSemantics:          rowSemantics,
		}
		recordRowPhase("showing.rows.prf_companion", prfCompanionStart)
	}

	muSigViewStartForLayout, x0ViewStartForLayout, x1ViewStartForLayout := muSigStart, x0Start, x1Start
	if structuralV3 {
		muSigViewStartForLayout, x0ViewStartForLayout, x1ViewStartForLayout = -1, -1, -1
	}
	layout = RowLayout{
		RingDegree:         int(ringQ.N),
		SigCount:           len(rows),
		X0Len:              x0Len,
		HasExplicitBaseIdx: true,
		IntGenISISShowing: &IntGenISISShowingRowLayout{
			LayoutVersion:    layoutVersion,
			ReplayProjection: layoutReplayProjection,
			LinearHatSourceMode: func() string {
				if structuralV3 {
					return intGenISISLinearHatSourceMuX0AggregateFused
				}
				return ""
			}(),
			UStart:                     uStart,
			UCount:                     len(cn.Sig),
			MStart:                     mStart,
			MCount:                     1,
			MAttrStart:                 mAttrStart,
			MAttrCount:                 1,
			KStart:                     kStart,
			KCount:                     1,
			SStart:                     sStart,
			SCount:                     len(cn.S),
			EStart:                     eStart,
			ECount:                     len(cn.E),
			MuSigStart:                 muSigStart,
			MuSigCount:                 len(cn.MuSig),
			X0Start:                    x0Start,
			X0Count:                    len(cn.X0),
			X1Start:                    x1Start,
			X1Count:                    1,
			ZStart:                     zStart,
			ZCount:                     1,
			BoundViewStart:             boundViewStart,
			BoundViewCount:             boundViewCount,
			MSECompressionLevel:        mseCompressionDesc.Level,
			MSECompressionPackWidth:    mseCompressionDesc.PackWidth,
			MSECompressionAlphabet:     mseCompressionDesc.Alphabet,
			MSECompressionDecodeDegree: mseCompressionDesc.DecodeDegree,
			MCarrierStart:              mCarrierStart,
			MCarrierCount:              mCarrierCount,
			MCompressedSourceRows:      mCompressedSourceRows,
			MSeedViewStart:             mSeedViewStart,
			MSeedViewCount:             mSeedViewCount,
			SCarrierStart:              sCarrierStart,
			SCarrierCount:              sCarrierCount,
			ECarrierStart:              eCarrierStart,
			ECarrierCount:              eCarrierCount,
			MSECarrierCount:            mCarrierCount + sCarrierCount + eCarrierCount,
			HashSourceCarrierV3:        structuralV3,
			HashCarrierPackWidth: func() int {
				if structuralV3 {
					return ternaryCarrierV3PackWidth
				}
				return 0
			}(),
			HashCarrierDecodeDegree: func() int {
				if structuralV3 {
					return ternaryCarrierV3Alphabet - 1
				}
				return 0
			}(),
			HashCarrierMembershipDegree: func() int {
				if structuralV3 {
					return ternaryCarrierV3Alphabet
				}
				return 0
			}(),
			MuSigCarrierStart:         muSigCarrierStart,
			MuSigCarrierCount:         muSigCarrierCount,
			X0CarrierStart:            x0CarrierStart,
			X0CarrierCount:            x0CarrierCount,
			X1CarrierStart:            x1CarrierStart,
			X1CarrierCount:            x1CarrierCount,
			UViewStart:                uViewStart,
			UShortnessStart:           uShortnessStart,
			UShortnessGroupCount:      len(cn.Sig) * viewRowsPerPoly,
			UShortnessRowsPerGroup:    shortSpec.L,
			UShortnessRadix:           int(shortSpec.R),
			UShortnessDigits:          shortSpec.L,
			UShortnessSourceViewStart: uViewStart,
			UShortnessSourceViewRows:  uShortnessSourceRows,
			UShortnessCapacity:        int64(shortSpec.MaxAbs),
			UShortnessProofMode:       intGenISISUShortnessMode,
			MViewStart:                mViewStart,
			MAttrViewStart:            mAttrStart,
			KViewStart:                kStart,
			SViewStart:                sViewStart,
			EViewStart:                eViewStart,
			YViewStart:                yViewStart,
			YViewCount:                len(yViewRows),
			MuSigViewStart:            muSigViewStartForLayout,
			X0ViewStart:               x0ViewStartForLayout,
			X1ViewStart:               x1ViewStartForLayout,
			ZViewStart:                zStart,
			UHatStart:                 uHatStart,
			UHatCount:                 uHatCount,
			MHatStart:                 -1,
			MHatCount:                 0,
			SHatStart:                 -1,
			SHatCount:                 0,
			EHatStart:                 -1,
			EHatCount:                 0,
			YHatStart:                 yHatStart,
			YHatCount:                 yHatCount,
			MuSigHatStart:             muSigHatStart,
			MuSigHatCount:             muSigHatCount,
			X0HatStart:                x0HatStart,
			X0HatCount:                x0HatCount,
			WHatStart:                 -1,
			WHatCount:                 0,
			X1HatStart:                x1HatStart,
			X1HatCount:                x1HatCount,
			ZHatStart:                 zHatStart,
			ZHatCount:                 zHatCount,
			PRFInputTraceV3Start:      prfInputTraceV3Start,
			PRFInputTraceV3Rows:       prfInputTraceV3Rows,
			PRFInputTraceV3Logical:    prfInputTraceV3Logical,
			PRFInputTraceV3Padding:    prfInputTraceV3Padding,
			PRFInputTraceV3TagCount:   prfInputTraceV3TagCount,
			HatRowsPerPoly:            viewRowsPerPoly,
			ViewRowsPerPoly:           viewRowsPerPoly,
			CoreRowCount:              coreRowCount,
		},
	}
	decsParams = applyDECSCollisionWidth(decs.Params{Degree: int(ringQ.N) - 1, Eta: opts.Eta, TapeBytes: 16}, opts)
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount <= 0 {
		maskRowCount = 1
	}
	witnessCount = len(rows)
	zeroHead := make([]uint64, ncols)
	for i := 0; i < maskRowCount; i++ {
		rows = append(rows, ringQ.NewPoly())
		rowInputs = append(rowInputs, lvcs.RowInput{Head: append([]uint64(nil), zeroHead...)})
	}
	return rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols, nil
}

func intGenISISUShortnessLayoutSpec(ringQ *ring.Ring, l *IntGenISISShowingRowLayout, sigBound int64) (LinfSpec, error) {
	if l == nil {
		return LinfSpec{}, fmt.Errorf("missing IntGenISIS showing layout")
	}
	spec, err := intGenISISUShortnessSpecForOpts(ringQ.Modulus[0], sigBound, SimOpts{SigShortnessRadix: l.UShortnessRadix, SigShortnessL: l.UShortnessDigits})
	if err != nil {
		return LinfSpec{}, err
	}
	expectedGroups := l.UCount * l.ViewRowsPerPoly
	if expectedGroups <= 0 {
		return LinfSpec{}, fmt.Errorf("invalid IntGenISIS u shortness group count %d", expectedGroups)
	}
	if l.UShortnessStart < 0 {
		return LinfSpec{}, fmt.Errorf("missing IntGenISIS u shortness rows")
	}
	if l.UShortnessGroupCount != expectedGroups {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness groups=%d want %d", l.UShortnessGroupCount, expectedGroups)
	}
	if l.UShortnessRowsPerGroup != spec.L {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness rows/group=%d want %d", l.UShortnessRowsPerGroup, spec.L)
	}
	if l.UShortnessRadix != int(spec.R) || l.UShortnessDigits != spec.L {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness metadata R=%d L=%d want R=%d L=%d", l.UShortnessRadix, l.UShortnessDigits, spec.R, spec.L)
	}
	digitOnlyU := intGenISISProjectionUsesDigitOnlyU(l)
	if digitOnlyU {
		if l.UViewStart >= 0 {
			return LinfSpec{}, fmt.Errorf("IntGenISIS digit-only U layout has U coefficient-view start=%d", l.UViewStart)
		}
		if l.UShortnessSourceViewStart >= 0 || l.UShortnessSourceViewRows != 0 {
			return LinfSpec{}, fmt.Errorf("IntGenISIS digit-only U shortness source views start=%d rows=%d want absent", l.UShortnessSourceViewStart, l.UShortnessSourceViewRows)
		}
	} else if l.UShortnessSourceViewStart != l.UViewStart || l.UShortnessSourceViewRows != expectedGroups {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness source views start=%d rows=%d want start=%d rows=%d", l.UShortnessSourceViewStart, l.UShortnessSourceViewRows, l.UViewStart, expectedGroups)
	}
	if l.UShortnessCapacity != int64(spec.MaxAbs) {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness capacity=%d want %d", l.UShortnessCapacity, spec.MaxAbs)
	}
	if l.UShortnessProofMode != intGenISISUShortnessMode {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness mode=%q want %q", l.UShortnessProofMode, intGenISISUShortnessMode)
	}
	if l.BoundViewStart < l.UShortnessStart+l.UShortnessGroupCount*l.UShortnessRowsPerGroup {
		return LinfSpec{}, fmt.Errorf("IntGenISIS bound views overlap u shortness rows")
	}
	return spec, nil
}

func intGenISISUShortnessConstraintRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, l *IntGenISISShowingRowLayout, spec LinfSpec) ([]*ring.Poly, [][]uint64, error) {
	if l == nil {
		return nil, nil, fmt.Errorf("missing IntGenISIS showing layout")
	}
	sourceCount := l.UShortnessGroupCount
	if sourceCount <= 0 {
		return nil, nil, fmt.Errorf("missing IntGenISIS u shortness source rows")
	}
	var packedSourceRows []*ring.Poly
	if !intGenISISProjectionUsesDigitOnlyU(l) {
		if l.UShortnessSourceViewRows != sourceCount {
			return nil, nil, fmt.Errorf("IntGenISIS u shortness source rows=%d want groups=%d", l.UShortnessSourceViewRows, sourceCount)
		}
		packedSourceRows = make([]*ring.Poly, sourceCount)
	}
	packedRows := make([][]*ring.Poly, sourceCount)
	for group := 0; group < sourceCount; group++ {
		if packedSourceRows != nil {
			srcIdx := l.UShortnessSourceViewStart + group
			if srcIdx < 0 || srcIdx >= len(rowsNTT) || rowsNTT[srcIdx] == nil {
				return nil, nil, fmt.Errorf("invalid IntGenISIS u shortness source row %d", srcIdx)
			}
			packedSourceRows[group] = rowsNTT[srcIdx]
		}
		packedRows[group] = make([]*ring.Poly, l.UShortnessRowsPerGroup)
		for lane := 0; lane < l.UShortnessRowsPerGroup; lane++ {
			idx := l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane
			if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
				return nil, nil, fmt.Errorf("invalid IntGenISIS u shortness digit row %d", idx)
			}
			packedRows[group][lane] = rowsNTT[idx]
		}
	}
	return buildSigShortnessPackedMembershipFormalCoeffs(ringQ, packedSourceRows, packedRows, spec)
}

func intGenISISCommitmentLinearYCoeff(ringQ *ring.Ring, pub PublicInputs, cn *CoeffNativeShowingWitness) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, fmt.Errorf("nil showing witness")
	}
	if len(pub.CM) != 1 || len(pub.CM[0]) != 1 {
		return nil, fmt.Errorf("c_m dimensions=%dx? want 1x1", len(pub.CM))
	}
	if len(pub.AS) != 1 || len(pub.AS[0]) != len(cn.S) {
		return nil, fmt.Errorf("a_s dimensions mismatch rows=%d s=%d", len(pub.AS), len(cn.S))
	}
	if len(cn.E) != 1 {
		return nil, fmt.Errorf("e rows=%d want 1", len(cn.E))
	}
	yNTT := ringQ.NewPoly()
	tmpNTT := ringQ.NewPoly()
	sourceNTT := ringQ.NewPoly()
	addProduct := func(label string, publicNTT, sourceCoeff *ring.Poly) error {
		if publicNTT == nil || sourceCoeff == nil {
			return fmt.Errorf("nil %s term", label)
		}
		ring.Copy(sourceCoeff, sourceNTT)
		ringQ.NTT(sourceNTT, sourceNTT)
		ringQ.MulCoeffs(publicNTT, sourceNTT, tmpNTT)
		ringQ.Add(yNTT, tmpNTT, yNTT)
		return nil
	}
	if err := addProduct("C_M*M", pub.CM[0][0], cn.M); err != nil {
		return nil, err
	}
	for i := range cn.S {
		if err := addProduct(fmt.Sprintf("A_s[%d]*s[%d]", i, i), pub.AS[0][i], cn.S[i]); err != nil {
			return nil, err
		}
	}
	ring.Copy(cn.E[0], sourceNTT)
	ringQ.NTT(sourceNTT, sourceNTT)
	ringQ.Add(yNTT, sourceNTT, yNTT)
	yCoeff := ringQ.NewPoly()
	ringQ.InvNTT(yNTT, yCoeff)
	return yCoeff, nil
}

func intGenISISThetaBlockCoeff(ringQ *ring.Ring, p *ring.Poly, omega []uint64, block, blocks int, name string) ([]uint64, error) {
	coeff, err := thetaCoeffFromNTTBlock(ringQ, p, omega, block, blocks)
	if err != nil {
		return nil, fmt.Errorf("theta block %s[%d]: %w", name, block, err)
	}
	return coeff, nil
}

func intGenISISLinearHatSourceMode(l *IntGenISISShowingRowLayout) string {
	if l == nil || l.LinearHatSourceMode == "" {
		return intGenISISLinearHatSourceMaterialized
	}
	return l.LinearHatSourceMode
}

func validateIntGenISISShowingPackedLayout(l *IntGenISISShowingRowLayout, rowCount int) error {
	if l == nil {
		return fmt.Errorf("missing IntGenISIS showing layout")
	}
	projectionMode := intGenISISProjectionModeFromLayout(l)
	switch l.LayoutVersion {
	case intGenISISShowingLayoutVersionYLinearBoundedV2:
		if projectionMode != IntGenISISReplayProjectionNone {
			return fmt.Errorf("IntGenISIS showing layout version %q cannot use replay projection %q", l.LayoutVersion, projectionMode)
		}
	case intGenISISShowingLayoutVersionProjectionUDigitsYViewBoundedV4:
		if projectionMode != IntGenISISReplayProjectionProjectUDigitsYViewV3 {
			return fmt.Errorf("IntGenISIS showing projection layout requires replay projection %q, got %q", IntGenISISReplayProjectionProjectUDigitsYViewV3, projectionMode)
		}
	case intGenISISShowingLayoutVersionProjectionUDigitsYBoundedSourcesV6:
		if projectionMode != IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
			return fmt.Errorf("IntGenISIS showing projection layout requires replay projection %q, got %q", IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6, projectionMode)
		}
	case intGenISISShowingLayoutVersionInputTraceCarrierV3:
		if projectionMode != IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
			return fmt.Errorf("IntGenISIS v3 input-trace layout requires replay projection %q, got %q", IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6, projectionMode)
		}
	default:
		return fmt.Errorf("unsupported IntGenISIS showing layout version %q", l.LayoutVersion)
	}
	digitOnlyU := intGenISISProjectionUsesDigitOnlyU(l)
	projectedUY := intGenISISProjectionUsesProjectedUYHat(l)
	derivedYView := intGenISISProjectionDerivesYView(l)
	if l.CoreRowCount != 0 {
		return fmt.Errorf("IntGenISIS packed showing requires core_row_count=0, got %d", l.CoreRowCount)
	}
	if l.UCount <= 0 || l.MCount != 1 || l.MAttrCount != 1 || l.KCount != 1 || l.MuSigCount != 1 || l.X0Count <= 0 || l.X1Count != 1 || l.ZCount != 1 {
		return fmt.Errorf("invalid IntGenISIS showing row counts")
	}
	if l.ViewRowsPerPoly <= 0 {
		return fmt.Errorf("invalid IntGenISIS view rows/poly=%d", l.ViewRowsPerPoly)
	}
	if l.HatRowsPerPoly != l.ViewRowsPerPoly {
		return fmt.Errorf("IntGenISIS hat rows/poly=%d want %d", l.HatRowsPerPoly, l.ViewRowsPerPoly)
	}
	rpp := l.ViewRowsPerPoly
	structuralV3 := l.LayoutVersion == intGenISISShowingLayoutVersionInputTraceCarrierV3
	if structuralV3 {
		if !l.HashSourceCarrierV3 || l.HashCarrierPackWidth != ternaryCarrierV3PackWidth ||
			l.HashCarrierDecodeDegree != ternaryCarrierV3Alphabet-1 || l.HashCarrierMembershipDegree != ternaryCarrierV3Alphabet {
			return fmt.Errorf("invalid strict v3 hash carrier metadata")
		}
		if l.MuSigViewStart >= 0 || l.X0ViewStart >= 0 || l.X1ViewStart >= 0 {
			return fmt.Errorf("strict v3 must not retain raw mu_sig/x0/x1 source rows")
		}
		if l.MuSigCount*rpp%ternaryCarrierV3PackWidth != 0 || l.X0Count*rpp%ternaryCarrierV3PackWidth != 0 || l.X1Count*rpp%ternaryCarrierV3PackWidth != 0 ||
			l.MuSigCarrierCount != l.MuSigCount*rpp/ternaryCarrierV3PackWidth ||
			l.X0CarrierCount != l.X0Count*rpp/ternaryCarrierV3PackWidth ||
			l.X1CarrierCount != l.X1Count*rpp/ternaryCarrierV3PackWidth {
			return fmt.Errorf("strict v3 hash carrier counts mismatch")
		}
		if l.X0CarrierStart != l.MuSigCarrierStart+l.MuSigCarrierCount || l.X1CarrierStart != l.X0CarrierStart+l.X0CarrierCount {
			return fmt.Errorf("strict v3 hash carriers are not canonical contiguous groups")
		}
		payload, err := canonicalPRFInputTraceV3Layout(l.PRFInputTraceV3Start, l.PRFInputTraceV3TagCount)
		if err != nil {
			return err
		}
		if l.PRFInputTraceV3Rows != payload.PackedRows || l.PRFInputTraceV3Logical != payload.LogicalScalars || l.PRFInputTraceV3Padding != payload.PaddingScalars {
			return fmt.Errorf("strict v3 PRF input-trace geometry mismatch")
		}
	}
	compressed := l.MSECompressionLevel > 0
	if compressed {
		desc, err := intGenISISMSECompressionDescriptorForBound(l.MSECompressionLevel, intGenISISTernaryBound)
		if err != nil {
			return err
		}
		if l.MSECompressionPackWidth != desc.PackWidth || l.MSECompressionAlphabet != desc.Alphabet || l.MSECompressionDecodeDegree != desc.DecodeDegree {
			return fmt.Errorf("IntGenISIS M/s/e compression metadata mismatch level=%d pack=%d alphabet=%d decode_degree=%d",
				l.MSECompressionLevel, l.MSECompressionPackWidth, l.MSECompressionAlphabet, l.MSECompressionDecodeDegree)
		}
		if l.MCompressedSourceRows <= 0 || l.MCompressedSourceRows >= l.MCount*rpp {
			return fmt.Errorf("IntGenISIS compressed M source rows=%d want strict subset of %d", l.MCompressedSourceRows, l.MCount*rpp)
		}
		if l.MSeedViewCount != l.MCount*rpp-l.MCompressedSourceRows {
			return fmt.Errorf("IntGenISIS M seed-tail rows=%d want %d", l.MSeedViewCount, l.MCount*rpp-l.MCompressedSourceRows)
		}
		if l.MCarrierCount != intGenISISCompressedCarrierCount(l.MCompressedSourceRows, desc.PackWidth) ||
			l.SCarrierCount != intGenISISCompressedCarrierCount(l.SCount*rpp, desc.PackWidth) ||
			l.ECarrierCount != intGenISISCompressedCarrierCount(l.ECount*rpp, desc.PackWidth) {
			return fmt.Errorf("IntGenISIS compressed carrier counts mismatch")
		}
		if l.MSECarrierCount != l.MCarrierCount+l.SCarrierCount+l.ECarrierCount {
			return fmt.Errorf("IntGenISIS mse carrier count=%d want %d", l.MSECarrierCount, l.MCarrierCount+l.SCarrierCount+l.ECarrierCount)
		}
	} else if l.MSECompressionPackWidth > 0 && l.MSECompressionPackWidth != 1 {
		return fmt.Errorf("IntGenISIS uncompressed M/s/e has pack width %d", l.MSECompressionPackWidth)
	}
	check := func(name string, start, count int) error {
		if start < 0 || count <= 0 {
			return fmt.Errorf("missing IntGenISIS %s rows start=%d count=%d", name, start, count)
		}
		if start+count > rowCount {
			return fmt.Errorf("IntGenISIS %s rows [%d,%d) exceed rows=%d", name, start, start+count, rowCount)
		}
		return nil
	}
	required := []struct {
		name  string
		start int
		count int
	}{
		{"Z hat", l.ZHatStart, l.ZHatCount},
		{"x1 hat", l.X1HatStart, l.X1HatCount},
	}
	linearHatMode := intGenISISLinearHatSourceMode(l)
	if linearHatMode == intGenISISLinearHatSourceMaterialized {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"mu_sig hat", l.MuSigHatStart, l.MuSigHatCount},
			struct {
				name  string
				start int
				count int
			}{"x0 hat", l.X0HatStart, l.X0HatCount},
		)
	}
	if structuralV3 {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"mu_sig v3 carrier", l.MuSigCarrierStart, l.MuSigCarrierCount},
			struct {
				name  string
				start int
				count int
			}{"x0 v3 carrier", l.X0CarrierStart, l.X0CarrierCount},
			struct {
				name  string
				start int
				count int
			}{"x1 v3 carrier", l.X1CarrierStart, l.X1CarrierCount},
			struct {
				name  string
				start int
				count int
			}{"PRF input-trace v3", l.PRFInputTraceV3Start, l.PRFInputTraceV3Rows},
		)
	} else {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"mu_sig coefficient-view", l.MuSigViewStart, l.MuSigCount * rpp},
			struct {
				name  string
				start int
				count int
			}{"x0 coefficient-view", l.X0ViewStart, l.X0Count * rpp},
			struct {
				name  string
				start int
				count int
			}{"x1 coefficient-view", l.X1ViewStart, l.X1Count * rpp},
		)
	}
	if l.WHatStart >= 0 || l.WHatCount != 0 {
		return fmt.Errorf("IntGenISIS bounded BB-tran must not commit W hats, got start=%d count=%d", l.WHatStart, l.WHatCount)
	}
	if digitOnlyU {
		if l.UViewStart >= 0 {
			return fmt.Errorf("IntGenISIS digit-only U layout must not commit U coefficient-view rows, got start=%d", l.UViewStart)
		}
		if l.UShortnessSourceViewStart >= 0 || l.UShortnessSourceViewRows != 0 {
			return fmt.Errorf("IntGenISIS digit-only U layout must not use U shortness source rows start=%d rows=%d", l.UShortnessSourceViewStart, l.UShortnessSourceViewRows)
		}
	} else {
		required = append(required, struct {
			name  string
			start int
			count int
		}{"u coefficient-view", l.UViewStart, l.UCount * rpp})
	}
	if derivedYView {
		if l.YViewStart >= 0 || l.YViewCount != 0 {
			return fmt.Errorf("IntGenISIS V2 projected showing must not commit Y coefficient-view rows start=%d count=%d", l.YViewStart, l.YViewCount)
		}
	} else {
		required = append(required, struct {
			name  string
			start int
			count int
		}{"Y coefficient-view", l.YViewStart, l.YViewCount})
	}
	if projectedUY {
		for _, part := range []struct {
			name  string
			start int
			count int
		}{
			{"u hat", l.UHatStart, l.UHatCount},
			{"Y hat", l.YHatStart, l.YHatCount},
		} {
			if part.start >= 0 || part.count != 0 {
				return fmt.Errorf("IntGenISIS projected showing must not commit %s rows start=%d count=%d", part.name, part.start, part.count)
			}
		}
	} else {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"u hat", l.UHatStart, l.UHatCount},
			struct {
				name  string
				start int
				count int
			}{"Y hat", l.YHatStart, l.YHatCount},
		)
	}
	for _, part := range []struct {
		name  string
		start int
		count int
	}{
		{"M hat", l.MHatStart, l.MHatCount},
		{"s hat", l.SHatStart, l.SHatCount},
		{"e hat", l.EHatStart, l.EHatCount},
	} {
		if part.start >= 0 || part.count != 0 {
			return fmt.Errorf("IntGenISIS Y-linear showing must not use %s rows start=%d count=%d", part.name, part.start, part.count)
		}
	}
	if compressed {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"M compressed carrier", l.MCarrierStart, l.MCarrierCount},
			struct {
				name  string
				start int
				count int
			}{"M seed-tail coefficient-view", l.MSeedViewStart, l.MSeedViewCount},
			struct {
				name  string
				start int
				count int
			}{"s compressed carrier", l.SCarrierStart, l.SCarrierCount},
			struct {
				name  string
				start int
				count int
			}{"e compressed carrier", l.ECarrierStart, l.ECarrierCount},
		)
	} else {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"M coefficient-view", l.MViewStart, l.MCount * rpp},
			struct {
				name  string
				start int
				count int
			}{"s coefficient-view", l.SViewStart, l.SCount * rpp},
			struct {
				name  string
				start int
				count int
			}{"e coefficient-view", l.EViewStart, l.ECount * rpp},
		)
	}
	for _, part := range required {
		if err := check(part.name, part.start, part.count); err != nil {
			return err
		}
	}
	switch mode := linearHatMode; mode {
	case intGenISISLinearHatSourceMaterialized:
	case intGenISISLinearHatSourceMuX0AggregateFused:
		if !structuralV3 || !projectedUY {
			return fmt.Errorf("IntGenISIS %q requires the strict-v3 projected showing relation", mode)
		}
		for _, part := range []struct {
			name  string
			start int
			count int
		}{
			{"mu_sig", l.MuSigHatStart, l.MuSigHatCount},
			{"x0", l.X0HatStart, l.X0HatCount},
		} {
			if part.start >= 0 || part.count != 0 {
				return fmt.Errorf("IntGenISIS %q must not materialize %s hats start=%d count=%d", mode, part.name, part.start, part.count)
			}
		}
	default:
		return fmt.Errorf("unsupported IntGenISIS linear hat source mode %q", mode)
	}
	for _, part := range []struct {
		name  string
		start int
	}{
		{"m coefficient-view", l.MAttrViewStart},
		{"k coefficient-view", l.KViewStart},
		{"Z coefficient-view", l.ZViewStart},
	} {
		if part.start >= 0 {
			return fmt.Errorf("IntGenISIS compact showing does not use %s rows, got start=%d", part.name, part.start)
		}
	}
	if compressed {
		for _, part := range []struct {
			name  string
			start int
		}{
			{"M coefficient-view", l.MViewStart},
			{"s coefficient-view", l.SViewStart},
			{"e coefficient-view", l.EViewStart},
		} {
			if part.start >= 0 {
				return fmt.Errorf("IntGenISIS compressed showing does not use raw %s rows, got start=%d", part.name, part.start)
			}
		}
	}
	expectedHatCounts := map[string][2]int{
		"Z":  {l.ZHatCount, l.ZCount * rpp},
		"x1": {l.X1HatCount, l.X1Count * rpp},
	}
	if linearHatMode == intGenISISLinearHatSourceMaterialized {
		expectedHatCounts["mu_sig"] = [2]int{l.MuSigHatCount, l.MuSigCount * rpp}
		expectedHatCounts["x0"] = [2]int{l.X0HatCount, l.X0Count * rpp}
	}
	if !projectedUY {
		expectedHatCounts["u"] = [2]int{l.UHatCount, l.UCount * rpp}
		expectedHatCounts["Y"] = [2]int{l.YHatCount, rpp}
	}
	for name, counts := range expectedHatCounts {
		if counts[0] != counts[1] {
			return fmt.Errorf("IntGenISIS %s hat rows=%d want %d", name, counts[0], counts[1])
		}
	}
	if !derivedYView && l.YViewCount != rpp {
		return fmt.Errorf("IntGenISIS Y coefficient-view rows=%d want %d", l.YViewCount, rpp)
	}
	return nil
}

type intGenISISYLinearTermCache struct {
	Name       string
	Source     int
	Components int
	Compressed bool
	H          [][][][]uint64
}

type intGenISISYLinearMapCache struct {
	Lagrange [][]uint64
	Terms    []intGenISISYLinearTermCache
}

var intGenISISYLinearGlobalCache struct {
	sync.RWMutex
	key   [32]byte
	value *intGenISISYLinearMapCache
	ok    bool
}

func intGenISISPublicCoeffFromNTT(ringQ *ring.Ring, pNTT *ring.Poly, name string) ([]uint64, error) {
	if pNTT == nil {
		return nil, fmt.Errorf("nil %s", name)
	}
	coeff, err := coeffFromNTTPoly(ringQ, pNTT)
	if err != nil {
		return nil, fmt.Errorf("%s coeffs: %w", name, err)
	}
	return trimCoeffsCopy(coeff, ringQ.Modulus[0]), nil
}

type intGenISISRowCoeffCache struct {
	ringQ *ring.Ring
	q     uint64
	rows  []*ring.Poly
	coeff [][]uint64
}

func newIntGenISISRowCoeffCache(ringQ *ring.Ring, rowsNTT []*ring.Poly) (*intGenISISRowCoeffCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	cache := &intGenISISRowCoeffCache{
		ringQ: ringQ,
		q:     q,
		rows:  rowsNTT,
		coeff: make([][]uint64, len(rowsNTT)),
	}
	for i := range rowsNTT {
		if rowsNTT[i] == nil {
			return nil, fmt.Errorf("nil row index %d", i)
		}
		tmp := ringQ.NewPoly()
		ringQ.InvNTT(rowsNTT[i], tmp)
		cache.coeff[i] = trimCoeffsCopy(tmp.Coeffs[0], q)
	}
	return cache, nil
}

func (c *intGenISISRowCoeffCache) Row(idx int) ([]uint64, error) {
	if c == nil {
		return nil, fmt.Errorf("missing row coefficient cache")
	}
	if idx < 0 || idx >= len(c.coeff) || c.rows[idx] == nil {
		return nil, fmt.Errorf("invalid row index %d", idx)
	}
	return c.coeff[idx], nil
}

func intGenISISNegacyclicWeight(multCoeff []uint64, outIdx, srcIdx, n int, q uint64) uint64 {
	if n <= 0 || outIdx < 0 || outIdx >= n || srcIdx < 0 || srcIdx >= n || len(multCoeff) == 0 {
		return 0
	}
	diff := outIdx - srcIdx
	if diff >= 0 {
		if diff >= len(multCoeff) {
			return 0
		}
		return multCoeff[diff] % q
	}
	idx := diff + n
	if idx >= len(multCoeff) {
		return 0
	}
	v := multCoeff[idx] % q
	if v == 0 {
		return 0
	}
	return q - v
}

func intGenISISLinearHForMultiplier(ringQ *ring.Ring, omega []uint64, lagrange [][]uint64, multCoeff []uint64, rowsPerPoly int, name string) ([][][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 || rowsPerPoly <= 0 {
		return nil, fmt.Errorf("invalid %s linear map omega=%d rowsPerPoly=%d", name, len(omega), rowsPerPoly)
	}
	ncols := len(omega)
	n := int(ringQ.N)
	if rowsPerPoly*ncols != n {
		return nil, fmt.Errorf("%s linear map rowsPerPoly*ncols=%d want ringN=%d", name, rowsPerPoly*ncols, n)
	}
	if len(lagrange) != ncols {
		return nil, fmt.Errorf("%s lagrange basis=%d want ncols=%d", name, len(lagrange), ncols)
	}
	q := ringQ.Modulus[0]
	out := make([][][]uint64, n)
	interpHead := func(head []uint64) []uint64 {
		acc := make([]uint64, ncols)
		for lane, weight := range head {
			if weight == 0 {
				continue
			}
			addScaledInto(acc, lagrange[lane], weight, q)
		}
		return trimPoly(acc, q)
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 || n < 32 {
		head := make([]uint64, ncols)
		for outIdx := 0; outIdx < n; outIdx++ {
			out[outIdx] = make([][]uint64, rowsPerPoly)
			for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
				for lane := 0; lane < ncols; lane++ {
					srcIdx := srcBlock*ncols + lane
					head[lane] = intGenISISNegacyclicWeight(multCoeff, outIdx, srcIdx, n, q)
				}
				out[outIdx][srcBlock] = interpHead(head)
			}
		}
		return out, nil
	}
	if workers > n {
		workers = n
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	chunk := (n + workers - 1) / workers
	for worker := 0; worker < workers; worker++ {
		start := worker * chunk
		end := start + chunk
		if end > n {
			end = n
		}
		go func(start, end int) {
			defer wg.Done()
			head := make([]uint64, ncols)
			for outIdx := start; outIdx < end; outIdx++ {
				out[outIdx] = make([][]uint64, rowsPerPoly)
				for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
					for lane := 0; lane < ncols; lane++ {
						srcIdx := srcBlock*ncols + lane
						head[lane] = intGenISISNegacyclicWeight(multCoeff, outIdx, srcIdx, n, q)
					}
					out[outIdx][srcBlock] = interpHead(head)
				}
			}
		}(start, end)
	}
	wg.Wait()
	return out, nil
}

func intGenISISYLinearCacheKey(ringQ *ring.Ring, pub PublicInputs, l *IntGenISISShowingRowLayout, omega []uint64) ([32]byte, bool) {
	if ringQ == nil || l == nil || len(ringQ.Modulus) == 0 {
		return [32]byte{}, false
	}
	h := sha256.New()
	var buf [8]byte
	writeU64 := func(v uint64) {
		binary.LittleEndian.PutUint64(buf[:], v)
		_, _ = h.Write(buf[:])
	}
	writeInt := func(v int) {
		writeU64(uint64(v))
	}
	writePoly := func(p *ring.Poly) {
		if p == nil {
			writeU64(^uint64(0))
			return
		}
		writeInt(len(p.Coeffs))
		for i := range p.Coeffs {
			writeInt(len(p.Coeffs[i]))
			for _, v := range p.Coeffs[i] {
				writeU64(v)
			}
		}
	}
	_, _ = h.Write([]byte("intgenisis-y-linear-map-cache-v1"))
	writeU64(ringQ.Modulus[0])
	writeInt(int(ringQ.N))
	writeInt(len(omega))
	for _, v := range omega {
		writeU64(v)
	}
	writeInt(l.ViewRowsPerPoly)
	writeInt(l.MSECompressionLevel)
	writeInt(l.MViewStart)
	writeInt(l.MSeedViewStart)
	writeInt(l.MSeedViewCount)
	writeInt(l.MCompressedSourceRows)
	writeInt(l.SViewStart)
	writeInt(l.EViewStart)
	writeInt(l.MCarrierStart)
	writeInt(l.SCarrierStart)
	writeInt(l.ECarrierStart)
	writeInt(l.MCount)
	writeInt(l.SCount)
	writeInt(l.ECount)
	writeInt(len(pub.CM))
	for i := range pub.CM {
		writeInt(len(pub.CM[i]))
		for j := range pub.CM[i] {
			writePoly(pub.CM[i][j])
		}
	}
	writeInt(len(pub.AS))
	for i := range pub.AS {
		writeInt(len(pub.AS[i]))
		for j := range pub.AS[i] {
			writePoly(pub.AS[i][j])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

func loadIntGenISISYLinearGlobalCache(key [32]byte) (*intGenISISYLinearMapCache, bool) {
	intGenISISYLinearGlobalCache.RLock()
	defer intGenISISYLinearGlobalCache.RUnlock()
	if intGenISISYLinearGlobalCache.ok && intGenISISYLinearGlobalCache.key == key && intGenISISYLinearGlobalCache.value != nil {
		return intGenISISYLinearGlobalCache.value, true
	}
	return nil, false
}

func storeIntGenISISYLinearGlobalCache(key [32]byte, value *intGenISISYLinearMapCache) {
	if value == nil {
		return
	}
	intGenISISYLinearGlobalCache.Lock()
	intGenISISYLinearGlobalCache.key = key
	intGenISISYLinearGlobalCache.value = value
	intGenISISYLinearGlobalCache.ok = true
	intGenISISYLinearGlobalCache.Unlock()
}

func newIntGenISISYLinearMapCache(ringQ *ring.Ring, pub PublicInputs, l *IntGenISISShowingRowLayout, omega []uint64) (*intGenISISYLinearMapCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if l == nil {
		return nil, fmt.Errorf("missing IntGenISIS showing layout")
	}
	cacheKey, cacheable := intGenISISYLinearCacheKey(ringQ, pub, l, omega)
	if cacheable {
		if cached, ok := loadIntGenISISYLinearGlobalCache(cacheKey); ok {
			return cached, nil
		}
	}
	lagrange, err := buildLagrangeBasisCoeffs(omega, ringQ.Modulus[0])
	if err != nil {
		return nil, fmt.Errorf("y linear lagrange basis: %w", err)
	}
	compressed := l.MSECompressionLevel > 0
	buildTerm := func(name string, source, components int, publicNTT []*ring.Poly) (intGenISISYLinearTermCache, error) {
		if source < 0 || components <= 0 || len(publicNTT) != components {
			return intGenISISYLinearTermCache{}, fmt.Errorf("invalid %s Y-linear term source=%d components=%d public=%d", name, source, components, len(publicNTT))
		}
		h := make([][][][]uint64, components)
		for comp := 0; comp < components; comp++ {
			coeff, err := intGenISISPublicCoeffFromNTT(ringQ, publicNTT[comp], fmt.Sprintf("%s[%d]", name, comp))
			if err != nil {
				return intGenISISYLinearTermCache{}, err
			}
			h[comp], err = intGenISISLinearHForMultiplier(ringQ, omega, lagrange, coeff, l.ViewRowsPerPoly, fmt.Sprintf("%s[%d]", name, comp))
			if err != nil {
				return intGenISISYLinearTermCache{}, err
			}
		}
		return intGenISISYLinearTermCache{Name: name, Source: source, Components: components, Compressed: compressed, H: h}, nil
	}
	mSource := l.MViewStart
	sSource := l.SViewStart
	eSource := l.EViewStart
	if compressed {
		mSource = l.MCarrierStart
		sSource = l.SCarrierStart
		eSource = l.ECarrierStart
	}
	if len(pub.CM) != 1 || len(pub.CM[0]) != l.MCount {
		return nil, fmt.Errorf("c_m dimensions mismatch")
	}
	if len(pub.AS) != 1 || len(pub.AS[0]) != l.SCount {
		return nil, fmt.Errorf("a_s dimensions mismatch")
	}
	identity := ringQ.NewPoly()
	identity.Coeffs[0][0] = 1
	ringQ.NTT(identity, identity)
	mTerm, err := buildTerm("M", mSource, l.MCount, pub.CM[0])
	if err != nil {
		return nil, err
	}
	sTerm, err := buildTerm("s", sSource, l.SCount, pub.AS[0])
	if err != nil {
		return nil, err
	}
	eTerm, err := buildTerm("e", eSource, l.ECount, []*ring.Poly{identity})
	if err != nil {
		return nil, err
	}
	out := &intGenISISYLinearMapCache{
		Lagrange: lagrange,
		Terms:    []intGenISISYLinearTermCache{mTerm, sTerm, eTerm},
	}
	if cacheable {
		storeIntGenISISYLinearGlobalCache(cacheKey, out)
	}
	return out, nil
}

func intGenISISYLinearSourceFormalCoeffs(ringQ *ring.Ring, rowsNTT []*ring.Poly, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, cache *intGenISISYLinearMapCache, compressionSpec intGenISISMSECompressionSpec) ([][][][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if l == nil || cache == nil {
		return nil, fmt.Errorf("missing intgenisis y-linear metadata")
	}
	sourceCoeffs := make([][][][]uint64, len(cache.Terms))
	for ti, term := range cache.Terms {
		sourceCoeffs[ti] = make([][][]uint64, term.Components)
		if term.Compressed {
			sourceRows := term.Components * l.ViewRowsPerPoly
			if term.Name == "M" && l.MSeedViewCount > 0 {
				sourceRows = l.MCompressedSourceRows
			}
			decoded, err := intGenISISCompressedSourceFormalCoeffs(ringQ, rowsNTT, term.Source, sourceRows, l.MSECompressionPackWidth, compressionSpec.DecodePolys, term.Name)
			if err != nil {
				return nil, err
			}
			for comp := 0; comp < term.Components; comp++ {
				sourceCoeffs[ti][comp] = make([][]uint64, l.ViewRowsPerPoly)
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					src := comp*l.ViewRowsPerPoly + block
					if term.Name == "M" && l.MSeedViewCount > 0 && src >= l.MCompressedSourceRows {
						seedBlock := src - l.MCompressedSourceRows
						if seedBlock < 0 || seedBlock >= l.MSeedViewCount {
							return nil, fmt.Errorf("m seed-tail block=%d outside count=%d", seedBlock, l.MSeedViewCount)
						}
						coeff, err := rowCache.Row(l.MSeedViewStart + seedBlock)
						if err != nil {
							return nil, err
						}
						sourceCoeffs[ti][comp][block] = coeff
						continue
					}
					sourceCoeffs[ti][comp][block] = decoded[src]
				}
			}
			continue
		}
		for comp := 0; comp < term.Components; comp++ {
			sourceCoeffs[ti][comp] = make([][]uint64, l.ViewRowsPerPoly)
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				coeff, err := rowCache.Row(term.Source + comp*l.ViewRowsPerPoly + block)
				if err != nil {
					return nil, err
				}
				sourceCoeffs[ti][comp][block] = coeff
			}
		}
	}
	return sourceCoeffs, nil
}

func intGenISISYLinearConstraintFormalCoeffs(ringQ *ring.Ring, rowsNTT []*ring.Poly, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, cache *intGenISISYLinearMapCache, compressionSpec intGenISISMSECompressionSpec) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if l == nil || cache == nil {
		return nil, nil, fmt.Errorf("missing IntGenISIS Y-linear metadata")
	}
	q := ringQ.Modulus[0]
	sourceCoeffs, err := intGenISISYLinearSourceFormalCoeffs(ringQ, rowsNTT, rowCache, l, cache, compressionSpec)
	if err != nil {
		return nil, nil, err
	}
	ncols := len(cache.Lagrange)
	fagg := make([]*ring.Poly, 0, l.ViewRowsPerPoly*ncols)
	coeffs := make([][]uint64, 0, l.ViewRowsPerPoly*ncols)
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		yCoeff, err := rowCache.Row(l.YViewStart + block)
		if err != nil {
			return nil, nil, err
		}
		for lane := 0; lane < ncols; lane++ {
			outIdx := block*ncols + lane
			leftCoeff := make([]uint64, int(ringQ.N))
			for ti, term := range cache.Terms {
				for comp := 0; comp < term.Components; comp++ {
					for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
						addMulModXN1Into(leftCoeff, term.H[comp][outIdx][srcBlock], sourceCoeffs[ti][comp][srcBlock], 1, q)
					}
				}
			}
			rightCoeff := make([]uint64, int(ringQ.N))
			mulModXN1(rightCoeff, cache.Lagrange[lane], yCoeff, q)
			res := append([]uint64(nil), leftCoeff...)
			subInto(res, rightCoeff, q)
			res = trimPoly(res, q)
			coeffs = append(coeffs, res)
			fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, res))
		}
	}
	return fagg, coeffs, nil
}

func intGenISISCoeffToHatBridgeFormalCoeffs(ringQ *ring.Ring, rowCache *intGenISISRowCoeffCache, omega []uint64, sourceStart, components, hatStart, rowsPerPoly int, name string) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega for %s bridge", name)
	}
	if sourceStart < 0 || hatStart < 0 || components <= 0 || rowsPerPoly <= 0 {
		return nil, nil, fmt.Errorf("invalid %s bridge layout source=%d hat=%d components=%d rowsPerPoly=%d", name, sourceStart, hatStart, components, rowsPerPoly)
	}
	ncols := len(omega)
	basis, err := newTransformBridgeBasisCache(ringQ, omega, rowsPerPoly*ncols, rowsPerPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("%s bridge basis: %w", name, err)
	}
	q := ringQ.Modulus[0]
	fagg := make([]*ring.Poly, 0, components*rowsPerPoly*ncols)
	coeffs := make([][]uint64, 0, components*rowsPerPoly*ncols)
	for comp := 0; comp < components; comp++ {
		sourceCoeffs := make([][]uint64, rowsPerPoly)
		for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
			coeff, err := rowCache.Row(sourceStart + comp*rowsPerPoly + srcBlock)
			if err != nil {
				return nil, nil, err
			}
			sourceCoeffs[srcBlock] = coeff
		}
		for block := 0; block < rowsPerPoly; block++ {
			hatCoeff, err := rowCache.Row(hatStart + comp*rowsPerPoly + block)
			if err != nil {
				return nil, nil, err
			}
			for lane := 0; lane < ncols; lane++ {
				t := block*ncols + lane
				leftCoeff := make([]uint64, int(ringQ.N))
				for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
					scale := basis.BlockFactors[t][srcBlock] % q
					addMulModXN1Into(leftCoeff, basis.TransformH[t], sourceCoeffs[srcBlock], scale, q)
				}
				rightCoeff := make([]uint64, int(ringQ.N))
				mulModXN1(rightCoeff, basis.LagrangeBasis[lane], hatCoeff, q)
				bridgeCoeff := append([]uint64(nil), leftCoeff...)
				subInto(bridgeCoeff, rightCoeff, q)
				bridgeCoeff = trimPoly(bridgeCoeff, q)
				coeffs = append(coeffs, bridgeCoeff)
				fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	}
	return fagg, coeffs, nil
}

type intGenISISProjectedSignaturePlan struct {
	n      int
	ncols  int
	blocks int
	omega  []uint64
	basis  *transformBridgeBasisCache

	aBlockCoeff      [][][]uint64
	aAtOmega         [][][]uint64
	bBlockCoeff      [][][]uint64
	bBlockCoeffNTT   [][]*ring.Poly
	bAtOmega         [][][]uint64
	cmBlockCoeff     [][]uint64
	cmAtOmega        [][]uint64
	asBlockCoeff     [][][]uint64
	asAtOmega        [][][]uint64
	transformHNTT    []*ring.Poly
	lagrangeBasisNTT []*ring.Poly
}

type intGenISISLinearHatKind string

const (
	intGenISISLinearHatMuSig intGenISISLinearHatKind = "mu_sig"
	intGenISISLinearHatX0    intGenISISLinearHatKind = "x0"
	intGenISISLinearHatX1    intGenISISLinearHatKind = "x1"
)

func intGenISISLinearHatMaterializedRow(l *IntGenISISShowingRowLayout, kind intGenISISLinearHatKind, component, block int) (int, error) {
	if l == nil {
		return -1, fmt.Errorf("missing IntGenISIS showing layout")
	}
	if block < 0 || block >= l.ViewRowsPerPoly {
		return -1, fmt.Errorf("IntGenISIS %s linear hat block=%d outside rows/poly=%d", kind, block, l.ViewRowsPerPoly)
	}
	switch kind {
	case intGenISISLinearHatMuSig:
		if component != 0 {
			return -1, fmt.Errorf("IntGenISIS mu_sig linear hat component=%d want 0", component)
		}
		if l.MuSigHatStart < 0 || l.MuSigHatCount != l.MuSigCount*l.ViewRowsPerPoly {
			return -1, fmt.Errorf("IntGenISIS mu_sig materialized hat rows unavailable start=%d count=%d", l.MuSigHatStart, l.MuSigHatCount)
		}
		return l.MuSigHatStart + block, nil
	case intGenISISLinearHatX0:
		if component < 0 || component >= l.X0Count {
			return -1, fmt.Errorf("IntGenISIS x0 linear hat component=%d outside count=%d", component, l.X0Count)
		}
		if l.X0HatStart < 0 || l.X0HatCount != l.X0Count*l.ViewRowsPerPoly {
			return -1, fmt.Errorf("IntGenISIS x0 materialized hat rows unavailable start=%d count=%d", l.X0HatStart, l.X0HatCount)
		}
		return l.X0HatStart + component*l.ViewRowsPerPoly + block, nil
	case intGenISISLinearHatX1:
		if component != 0 {
			return -1, fmt.Errorf("IntGenISIS x1 linear hat component=%d want 0", component)
		}
		if l.X1HatStart < 0 || l.X1HatCount != l.X1Count*l.ViewRowsPerPoly {
			return -1, fmt.Errorf("IntGenISIS x1 materialized hat rows unavailable start=%d count=%d", l.X1HatStart, l.X1HatCount)
		}
		return l.X1HatStart + block, nil
	default:
		return -1, fmt.Errorf("unknown IntGenISIS linear hat kind %q", kind)
	}
}

func intGenISISLinearHatFormalCoeff(rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, kind intGenISISLinearHatKind, component, block int) ([]uint64, error) {
	if rowCache == nil {
		return nil, fmt.Errorf("missing IntGenISIS row coefficient cache")
	}
	switch mode := intGenISISLinearHatSourceMode(l); mode {
	case intGenISISLinearHatSourceMaterialized:
		row, err := intGenISISLinearHatMaterializedRow(l, kind, component, block)
		if err != nil {
			return nil, err
		}
		return rowCache.Row(row)
	case intGenISISLinearHatSourceMuX0AggregateFused:
		if kind != intGenISISLinearHatX1 {
			return nil, fmt.Errorf("IntGenISIS %s hat is fused into the projected signature aggregate", kind)
		}
		row, err := intGenISISLinearHatMaterializedRow(l, kind, component, block)
		if err != nil {
			return nil, err
		}
		return rowCache.Row(row)
	default:
		return nil, fmt.Errorf("unsupported IntGenISIS linear hat source mode %q", mode)
	}
}

func newIntGenISISProjectedSignaturePlan(ringQ *ring.Ring, pub PublicInputs, l *IntGenISISShowingRowLayout, basis *transformBridgeBasisCache, omega []uint64) (*intGenISISProjectedSignaturePlan, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if l == nil || basis == nil {
		return nil, fmt.Errorf("missing IntGenISIS projected signature metadata")
	}
	q := ringQ.Modulus[0]
	n := int(ringQ.N)
	ncols := len(omega)
	blocks := l.ViewRowsPerPoly
	if blocks*ncols != n {
		return nil, fmt.Errorf("IntGenISIS projected signature rows/poly*ncols=%d want ringN=%d", blocks*ncols, n)
	}
	out := &intGenISISProjectedSignaturePlan{
		n:                n,
		ncols:            ncols,
		blocks:           blocks,
		omega:            omega,
		basis:            basis,
		aBlockCoeff:      make([][][]uint64, l.UCount),
		aAtOmega:         make([][][]uint64, l.UCount),
		bBlockCoeff:      make([][][]uint64, len(pub.B)),
		bBlockCoeffNTT:   make([][]*ring.Poly, len(pub.B)),
		bAtOmega:         make([][][]uint64, len(pub.B)),
		cmBlockCoeff:     nil,
		cmAtOmega:        nil,
		asBlockCoeff:     nil,
		asAtOmega:        nil,
		transformHNTT:    make([]*ring.Poly, len(basis.TransformH)),
		lagrangeBasisNTT: make([]*ring.Poly, len(basis.LagrangeBasis)),
	}
	for t := range basis.TransformH {
		p, ok := nttPolyFromModXN1Coeffs(ringQ, basis.TransformH[t])
		if !ok {
			return nil, fmt.Errorf("projected signature transform H[%d] exceeds ring dimension", t)
		}
		out.transformHNTT[t] = p
	}
	for lane := range basis.LagrangeBasis {
		p, ok := nttPolyFromModXN1Coeffs(ringQ, basis.LagrangeBasis[lane])
		if !ok {
			return nil, fmt.Errorf("projected signature lagrange basis[%d] exceeds ring dimension", lane)
		}
		out.lagrangeBasisNTT[lane] = p
	}
	for i := 0; i < l.UCount; i++ {
		out.aBlockCoeff[i] = make([][]uint64, blocks)
		out.aAtOmega[i] = make([][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.A[0][i], omega, block, blocks, fmt.Sprintf("A[0][%d]", i))
			if err != nil {
				return nil, err
			}
			out.aBlockCoeff[i][block] = coeff
			out.aAtOmega[i][block] = evalCoeffOnOmega(coeff, omega, q)
		}
	}
	for j := range pub.B {
		out.bBlockCoeff[j] = make([][]uint64, blocks)
		out.bBlockCoeffNTT[j] = make([]*ring.Poly, blocks)
		out.bAtOmega[j] = make([][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.B[j], omega, block, blocks, fmt.Sprintf("B[%d]", j))
			if err != nil {
				return nil, err
			}
			out.bBlockCoeff[j][block] = coeff
			out.bAtOmega[j][block] = evalCoeffOnOmega(coeff, omega, q)
			p, ok := nttPolyFromModXN1Coeffs(ringQ, coeff)
			if !ok {
				return nil, fmt.Errorf("projected signature B[%d] block %d exceeds ring dimension", j, block)
			}
			out.bBlockCoeffNTT[j][block] = p
		}
	}
	if intGenISISProjectionDerivesYView(l) {
		out.cmBlockCoeff = make([][]uint64, blocks)
		out.cmAtOmega = make([][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.CM[0][0], omega, block, blocks, "C_M[0][0]")
			if err != nil {
				return nil, err
			}
			out.cmBlockCoeff[block] = coeff
			out.cmAtOmega[block] = evalCoeffOnOmega(coeff, omega, q)
		}
		out.asBlockCoeff = make([][][]uint64, l.SCount)
		out.asAtOmega = make([][][]uint64, l.SCount)
		for i := 0; i < l.SCount; i++ {
			out.asBlockCoeff[i] = make([][]uint64, blocks)
			out.asAtOmega[i] = make([][]uint64, blocks)
			for block := 0; block < blocks; block++ {
				coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.AS[0][i], omega, block, blocks, fmt.Sprintf("A_s[0][%d]", i))
				if err != nil {
					return nil, err
				}
				out.asBlockCoeff[i][block] = coeff
				out.asAtOmega[i][block] = evalCoeffOnOmega(coeff, omega, q)
			}
		}
	}
	return out, nil
}

func evalCoeffOnOmega(coeff, omega []uint64, q uint64) []uint64 {
	out := make([]uint64, len(omega))
	for i := range omega {
		out[i] = EvalPoly(coeff, omega[i]%q, q) % q
	}
	return out
}

func intGenISISUDigitSourceFormalCoeff(rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, rpows []uint64, comp, block, n int, q uint64) ([]uint64, error) {
	if rowCache == nil || l == nil {
		return nil, fmt.Errorf("missing IntGenISIS U digit source metadata")
	}
	if comp < 0 || comp >= l.UCount || block < 0 || block >= l.ViewRowsPerPoly {
		return nil, fmt.Errorf("invalid IntGenISIS U digit source comp=%d block=%d", comp, block)
	}
	if len(rpows) < l.UShortnessRowsPerGroup {
		return nil, fmt.Errorf("IntGenISIS U digit source powers=%d want %d", len(rpows), l.UShortnessRowsPerGroup)
	}
	res := make([]uint64, n)
	group := comp*l.ViewRowsPerPoly + block
	for lane := 0; lane < l.UShortnessRowsPerGroup; lane++ {
		coeff, err := rowCache.Row(l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane)
		if err != nil {
			return nil, err
		}
		addScaledInto(res, coeff, rpows[lane]%q, q)
	}
	return trimPoly(res, q), nil
}

// intGenISISProjectedSignatureFormalCoeffs substitutes the aggregate packed-coeff
// transform into the signature equation. The transform bridge is an Ω-sum
// identity, so public A terms are bound as lane scalars rather than as
// pointwise row polynomials.
func intGenISISProjectedSignatureFormalCoeffs(ringQ *ring.Ring, pub PublicInputs, rowsNTT []*ring.Poly, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, basis *transformBridgeBasisCache, omega []uint64, yLinearCache *intGenISISYLinearMapCache, compressionSpec, hashCompressionSpec intGenISISMSECompressionSpec, phase *PhaseRecorder) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if l == nil || basis == nil {
		return nil, nil, fmt.Errorf("missing IntGenISIS projected signature metadata")
	}
	if len(omega) == 0 || len(basis.LagrangeBasis) != len(omega) {
		return nil, nil, fmt.Errorf("invalid IntGenISIS projected signature omega=%d lagrange=%d", len(omega), len(basis.LagrangeBasis))
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount || len(pub.B) != 3+l.X0Count {
		return nil, nil, fmt.Errorf("IntGenISIS projected signature public dimensions mismatch")
	}
	q := ringQ.Modulus[0]
	n := int(ringQ.N)
	ncols := len(omega)
	if l.ViewRowsPerPoly*ncols != n {
		return nil, nil, fmt.Errorf("IntGenISIS projected signature rows/poly*ncols=%d want ringN=%d", l.ViewRowsPerPoly*ncols, n)
	}
	stage := func(label string, fn func() error) error {
		start := phaseTimingStart(phase)
		err := fn()
		if phase != nil {
			phase.RecordDuration(label, time.Since(start))
		}
		return err
	}
	plan, err := newIntGenISISProjectedSignaturePlan(ringQ, pub, l, basis, omega)
	if err != nil {
		return nil, nil, err
	}
	buildSourceTransformFallback := func(sourceCoeffs [][]uint64, t int, scratch *negacyclicProductScratch) ([]uint64, error) {
		if t < 0 || t >= len(basis.TransformH) || t >= len(basis.BlockFactors) {
			return nil, fmt.Errorf("projected signature transform lane t=%d out of range", t)
		}
		if len(sourceCoeffs) != l.ViewRowsPerPoly {
			return nil, fmt.Errorf("projected signature source blocks=%d want %d", len(sourceCoeffs), l.ViewRowsPerPoly)
		}
		left := make([]uint64, n)
		for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
			scale := basis.BlockFactors[t][srcBlock] % q
			if !addMulModXN1PrecomputedNTTInto(ringQ, left, plan.transformHNTT[t], sourceCoeffs[srcBlock], scale, scratch) {
				addMulModXN1Into(left, basis.TransformH[t], sourceCoeffs[srcBlock], scale, q)
			}
		}
		return trimPoly(left, q), nil
	}
	buildSourceTransformNTT := func(sourceNTT []*ring.Poly, sourceCoeffs [][]uint64, t int, scratch *negacyclicProductScratch) ([]uint64, error) {
		if t < 0 || t >= len(plan.transformHNTT) || t >= len(basis.BlockFactors) {
			return nil, fmt.Errorf("projected signature transform lane t=%d out of range", t)
		}
		if len(sourceNTT) != l.ViewRowsPerPoly || len(sourceCoeffs) != l.ViewRowsPerPoly {
			return nil, fmt.Errorf("projected signature source blocks ntt=%d coeff=%d want %d", len(sourceNTT), len(sourceCoeffs), l.ViewRowsPerPoly)
		}
		if scratch == nil || scratch.acc == nil {
			return buildSourceTransformFallback(sourceCoeffs, t, scratch)
		}
		resetRingPolyCoeffs(scratch.acc)
		for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
			scale := basis.BlockFactors[t][srcBlock] % q
			if !addMulNTTIntoAccumulator(ringQ, scratch.acc, plan.transformHNTT[t], sourceNTT[srcBlock], scale, scratch) {
				return buildSourceTransformFallback(sourceCoeffs, t, scratch)
			}
		}
		left := make([]uint64, n)
		if !flushNTTAccumulatorInto(ringQ, left, scratch.acc, scratch) {
			return buildSourceTransformFallback(sourceCoeffs, t, scratch)
		}
		return trimPoly(left, q), nil
	}
	buildFlatTransforms := func(sourceCoeffs [][][]uint64) ([][][]uint64, error) {
		out := make([][][]uint64, len(sourceCoeffs))
		for comp := range sourceCoeffs {
			out[comp] = make([][]uint64, l.ViewRowsPerPoly*ncols)
		}
		sourceNTT := make([][]*ring.Poly, len(sourceCoeffs))
		for comp := range sourceCoeffs {
			if len(sourceCoeffs[comp]) != l.ViewRowsPerPoly {
				return nil, fmt.Errorf("projected signature source component %d blocks=%d want %d", comp, len(sourceCoeffs[comp]), l.ViewRowsPerPoly)
			}
			sourceNTT[comp] = make([]*ring.Poly, l.ViewRowsPerPoly)
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				p := ringQ.NewPoly()
				if !coeffsToNTTPolyInto(ringQ, p, sourceCoeffs[comp][block]) {
					return nil, fmt.Errorf("projected signature source component %d block %d exceeds ring dimension", comp, block)
				}
				sourceNTT[comp][block] = p
			}
		}
		total := len(sourceCoeffs) * l.ViewRowsPerPoly * ncols
		if total == 0 {
			return out, nil
		}
		emitOne := func(idx int, scratch *negacyclicProductScratch) error {
			outputsPerComp := l.ViewRowsPerPoly * ncols
			comp := idx / outputsPerComp
			t := idx % outputsPerComp
			coeff, err := buildSourceTransformNTT(sourceNTT[comp], sourceCoeffs[comp], t, scratch)
			if err != nil {
				return err
			}
			out[comp][t] = coeff
			return nil
		}
		workers := minInt(runtime.GOMAXPROCS(0), total)
		if workers <= 1 {
			scratch := newNegacyclicProductScratch(ringQ)
			for idx := 0; idx < total; idx++ {
				if err := emitOne(idx, scratch); err != nil {
					return nil, err
				}
			}
			return out, nil
		}
		var wg sync.WaitGroup
		var errOnce sync.Once
		var firstErr error
		setErr := func(err error) {
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
				})
			}
		}
		for worker := 0; worker < workers; worker++ {
			start := worker * total / workers
			end := (worker + 1) * total / workers
			if start >= end {
				continue
			}
			wg.Add(1)
			go func(start, end int) {
				defer wg.Done()
				scratch := newNegacyclicProductScratch(ringQ)
				for idx := start; idx < end; idx++ {
					if err := emitOne(idx, scratch); err != nil {
						setErr(err)
						return
					}
				}
			}(start, end)
		}
		wg.Wait()
		if firstErr != nil {
			return nil, firstErr
		}
		return out, nil
	}
	var ySourceCoeffs [][][][]uint64
	if intGenISISProjectionDerivesYView(l) {
		var yerr error
		ySourceCoeffs, yerr = intGenISISYLinearSourceFormalCoeffs(ringQ, rowsNTT, rowCache, l, yLinearCache, compressionSpec)
		if yerr != nil {
			return nil, nil, yerr
		}
	}
	var uDigitRPows []uint64
	if intGenISISProjectionUsesDigitOnlyU(l) {
		sigBound, serr := intGenISISSignatureBoundFromPublic(pub)
		if serr != nil {
			return nil, nil, serr
		}
		shortSpec, serr := intGenISISUShortnessLayoutSpec(ringQ, l, sigBound)
		if serr != nil {
			return nil, nil, serr
		}
		uDigitRPows = shortSpec.RPows
	}
	var uTrans [][][]uint64
	var yTrans [][][][]uint64
	var yViewTrans [][][]uint64
	var fusedBTrans [][][]uint64
	if err := stage("showing.constraints.projected.transform_cache", func() error {
		uSourceCoeffs := make([][][]uint64, l.UCount)
		for comp := 0; comp < l.UCount; comp++ {
			uSourceCoeffs[comp] = make([][]uint64, l.ViewRowsPerPoly)
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				if intGenISISProjectionUsesDigitOnlyU(l) {
					coeff, err := intGenISISUDigitSourceFormalCoeff(rowCache, l, uDigitRPows, comp, block, n, q)
					if err != nil {
						return err
					}
					uSourceCoeffs[comp][block] = coeff
				} else {
					coeff, err := rowCache.Row(l.UViewStart + comp*l.ViewRowsPerPoly + block)
					if err != nil {
						return err
					}
					uSourceCoeffs[comp][block] = coeff
				}
			}
		}
		var terr error
		uTrans, terr = buildFlatTransforms(uSourceCoeffs)
		if terr != nil {
			return terr
		}
		if intGenISISLinearHatSourceMode(l) == intGenISISLinearHatSourceMuX0AggregateFused {
			if !l.HashSourceCarrierV3 || len(hashCompressionSpec.DecodePolys) < l.HashCarrierPackWidth {
				return fmt.Errorf("projected signature fused mu/x0 source decoder is unavailable")
			}
			muDecoded, derr := intGenISISCompressedSourceFormalCoeffs(
				ringQ, rowsNTT, l.MuSigCarrierStart, l.MuSigCount*l.ViewRowsPerPoly,
				l.HashCarrierPackWidth, hashCompressionSpec.DecodePolys, "mu_sig fused source",
			)
			if derr != nil {
				return derr
			}
			x0Decoded, derr := intGenISISCompressedSourceFormalCoeffs(
				ringQ, rowsNTT, l.X0CarrierStart, l.X0Count*l.ViewRowsPerPoly,
				l.HashCarrierPackWidth, hashCompressionSpec.DecodePolys, "x0 fused source",
			)
			if derr != nil {
				return derr
			}
			bSourceCoeffs := make([][][]uint64, 1+l.X0Count)
			bSourceCoeffs[0] = make([][]uint64, l.ViewRowsPerPoly)
			copy(bSourceCoeffs[0], muDecoded)
			for comp := 0; comp < l.X0Count; comp++ {
				start := comp * l.ViewRowsPerPoly
				bSourceCoeffs[1+comp] = make([][]uint64, l.ViewRowsPerPoly)
				copy(bSourceCoeffs[1+comp], x0Decoded[start:start+l.ViewRowsPerPoly])
			}
			fusedBTrans, terr = buildFlatTransforms(bSourceCoeffs)
			if terr != nil {
				return terr
			}
		}
		if intGenISISProjectionDerivesYView(l) {
			yTrans = make([][][][]uint64, len(ySourceCoeffs))
			for ti := range ySourceCoeffs {
				yTrans[ti], terr = buildFlatTransforms(ySourceCoeffs[ti])
				if terr != nil {
					return terr
				}
			}
		} else {
			ySource := [][][]uint64{make([][]uint64, l.ViewRowsPerPoly)}
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				coeff, err := rowCache.Row(l.YViewStart + block)
				if err != nil {
					return err
				}
				ySource[0][block] = coeff
			}
			yViewTrans, terr = buildFlatTransforms(ySource)
			if terr != nil {
				return terr
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	totalOutputs := l.ViewRowsPerPoly * ncols
	outCoeff := make([][]uint64, totalOutputs)
	if err := stage("showing.constraints.projected.emit", func() error {
		workers := minInt(runtime.GOMAXPROCS(0), l.ViewRowsPerPoly)
		if workers <= 1 {
			return emitProjectedSignatureCoeffRange(ringQ, rowCache, l, plan, basis, uTrans, fusedBTrans, yTrans, yViewTrans, outCoeff, q, 0, l.ViewRowsPerPoly)
		}
		var wg sync.WaitGroup
		var errOnce sync.Once
		var firstErr error
		setErr := func(err error) {
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
				})
			}
		}
		for worker := 0; worker < workers; worker++ {
			startBlock := worker * l.ViewRowsPerPoly / workers
			endBlock := (worker + 1) * l.ViewRowsPerPoly / workers
			if startBlock >= endBlock {
				continue
			}
			wg.Add(1)
			go func(startBlock, endBlock int) {
				defer wg.Done()
				setErr(emitProjectedSignatureCoeffRange(ringQ, rowCache, l, plan, basis, uTrans, fusedBTrans, yTrans, yViewTrans, outCoeff, q, startBlock, endBlock))
			}(startBlock, endBlock)
		}
		wg.Wait()
		return firstErr
	}); err != nil {
		return nil, nil, err
	}
	fagg := make([]*ring.Poly, 0, totalOutputs)
	coeffs := make([][]uint64, 0, totalOutputs)
	for t := 0; t < totalOutputs; t++ {
		coeffs = append(coeffs, outCoeff[t])
		fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, outCoeff[t]))
	}
	return fagg, coeffs, nil
}

func emitProjectedSignatureCoeffRange(ringQ *ring.Ring, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, plan *intGenISISProjectedSignaturePlan, basis *transformBridgeBasisCache, uTrans, fusedBTrans [][][]uint64, yTrans [][][][]uint64, yViewTrans [][][]uint64, outCoeff [][]uint64, q uint64, startBlock, endBlock int) error {
	n := plan.n
	ncols := plan.ncols
	fusedMuX0 := intGenISISLinearHatSourceMode(l) == intGenISISLinearHatSourceMuX0AggregateFused
	if fusedMuX0 && len(fusedBTrans) != 1+l.X0Count {
		return fmt.Errorf("projected signature fused B sources=%d want %d", len(fusedBTrans), 1+l.X0Count)
	}
	scratch := newNegacyclicProductScratch(ringQ)
	for block := startBlock; block < endBlock; block++ {
		zCoeff, err := rowCache.Row(l.ZHatStart + block)
		if err != nil {
			return err
		}
		rhs := make([]uint64, n)
		addScaledInto(rhs, plan.bBlockCoeff[0][block], 1, q)
		bSources := make([][]uint64, 0, 1+l.X0Count)
		if !fusedMuX0 {
			muCoeff, err := intGenISISLinearHatFormalCoeff(rowCache, l, intGenISISLinearHatMuSig, 0, block)
			if err != nil {
				return err
			}
			bSources = append(bSources, muCoeff)
			for i := 0; i < l.X0Count; i++ {
				x0Coeff, err := intGenISISLinearHatFormalCoeff(rowCache, l, intGenISISLinearHatX0, i, block)
				if err != nil {
					return err
				}
				bSources = append(bSources, x0Coeff)
			}
		}
		accOK := scratch != nil && scratch.acc != nil && scratch.b != nil
		if accOK {
			resetRingPolyCoeffs(scratch.acc)
			for i, coeff := range bSources {
				publicIdx := 1 + i
				if !coeffsToNTTPolyInto(ringQ, scratch.b, coeff) ||
					!addMulNTTIntoAccumulator(ringQ, scratch.acc, plan.bBlockCoeffNTT[publicIdx][block], scratch.b, 1, scratch) {
					accOK = false
					break
				}
			}
			if accOK {
				accOK = flushNTTAccumulatorInto(ringQ, rhs, scratch.acc, scratch)
			}
		}
		if !accOK {
			for i, coeff := range bSources {
				publicIdx := 1 + i
				if !addMulModXN1PrecomputedNTTInto(ringQ, rhs, plan.bBlockCoeffNTT[publicIdx][block], coeff, 1, scratch) {
					addMulModXN1Into(rhs, plan.bBlockCoeff[publicIdx][block], coeff, 1, q)
				}
			}
		}
		addScaledInto(rhs, zCoeff, 1, q)
		rhsNTTReady := scratch != nil && scratch.a != nil && coeffsToNTTPolyInto(ringQ, scratch.a, rhs)
		for lane := 0; lane < ncols; lane++ {
			t := block*ncols + lane
			res := make([]uint64, n)
			for i := 0; i < l.UCount; i++ {
				aVal := plan.aAtOmega[i][block][lane]
				addScaledInto(res, uTrans[i][t], aVal, q)
			}
			laneRHS := make([]uint64, n)
			if !rhsNTTReady || !addMulModXN1PrecomputedBothNTTInto(ringQ, laneRHS, plan.lagrangeBasisNTT[lane], scratch.a, 1, scratch) {
				mulModXN1(laneRHS, basis.LagrangeBasis[lane], rhs, q)
			}
			subInto(res, laneRHS, q)
			if fusedMuX0 {
				for i := range fusedBTrans {
					if t >= len(fusedBTrans[i]) {
						return fmt.Errorf("projected signature fused B source %d transform t=%d outside %d", i, t, len(fusedBTrans[i]))
					}
					publicIdx := 1 + i
					if publicIdx >= len(plan.bAtOmega) || block >= len(plan.bAtOmega[publicIdx]) || lane >= len(plan.bAtOmega[publicIdx][block]) {
						return fmt.Errorf("projected signature fused B target coordinate [%d][%d][%d] unavailable", publicIdx, block, lane)
					}
					addScaledInto(res, fusedBTrans[i][t], q-plan.bAtOmega[publicIdx][block][lane], q)
				}
			}
			if intGenISISProjectionDerivesYView(l) {
				if len(yTrans) != 3 {
					return fmt.Errorf("projected Y source terms=%d want 3", len(yTrans))
				}
				addScaledInto(res, yTrans[0][0][t], q-plan.cmAtOmega[block][lane], q)
				for i := 0; i < l.SCount; i++ {
					addScaledInto(res, yTrans[1][i][t], q-plan.asAtOmega[i][block][lane], q)
				}
				subInto(res, yTrans[2][0][t], q)
			} else {
				if len(yViewTrans) == 0 || len(yViewTrans[0]) <= t {
					return fmt.Errorf("projected Y view transform t=%d out of range", t)
				}
				subInto(res, yViewTrans[0][t], q)
			}
			outCoeff[t] = append([]uint64(nil), trimPoly(res, q)...)
		}
	}
	return nil
}

func buildIntGenISISShowingConstraintSetFromRows(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, prfCompanionLayout *PRFCompanionLayout, phase *PhaseRecorder, opts SimOpts) (ConstraintSet, error) {
	params, err := loadBoundPRFParamsForOpts(opts)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("load prf params: %w", err)
	}
	prepared := &IntGenISISShowingPreparedContext{prfParams: params}
	return buildIntGenISISShowingConstraintSetFromRowsPrepared(ringQ, pub, layout, rowsNTT, omega, prfCompanionLayout, phase, prepared)
}

func buildIntGenISISShowingConstraintSetFromRowsPrepared(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, prfCompanionLayout *PRFCompanionLayout, phase *PhaseRecorder, prepared *IntGenISISShowingPreparedContext) (ConstraintSet, error) {
	return buildIntGenISISShowingConstraintSetFromRowsPreparedMode(ringQ, pub, layout, rowsNTT, omega, prfCompanionLayout, phase, prepared, false)
}

func buildIntGenISISShowingSemanticMetadataV3(
	ringQ *ring.Ring,
	pub PublicInputs,
	layout RowLayout,
	rowsNTT []*ring.Poly,
	omega []uint64,
	compressionSpec, hashCompressionSpec intGenISISMSECompressionSpec,
	replay *intGenISISShowingReplayConfig,
) (ConstraintSet, error) {
	if ringQ == nil || layout.IntGenISISShowing == nil || len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("strict v3 semantic metadata: missing ring, layout, or omega")
	}
	// Strict v3 never feeds formal coefficient families into Q construction:
	// one shared semantic evaluator is authoritative for both prover and
	// verifier. Derive its family cardinalities structurally from the immutable
	// replay plan; do not execute the relation on dummy witness rows.
	if replay == nil {
		return ConstraintSet{}, fmt.Errorf("strict v3 semantic metadata: missing prepared replay plan")
	}
	fparCount, faggCount, err := replay.semanticConstraintShapeV3()
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("strict v3 semantic metadata shape: %w", err)
	}
	l := layout.IntGenISISShowing
	fparIntCount := 2 * l.ViewRowsPerPoly
	if intGenISISProjectionUsesProjectedUYHat(l) {
		fparIntCount = l.ViewRowsPerPoly
	}
	if fparIntCount < 0 || fparIntCount > fparCount {
		return ConstraintSet{}, fmt.Errorf("strict v3 semantic metadata: parallel integer count=%d outside total=%d", fparIntCount, fparCount)
	}
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		return ConstraintSet{}, err
	}
	shortSpec, err := intGenISISUShortnessLayoutSpec(ringQ, l, sigBound)
	if err != nil {
		return ConstraintSet{}, err
	}
	shortDegree, err := signatureShortnessMaxDegree(shortSpec, SimOpts{})
	if err != nil {
		return ConstraintSet{}, err
	}
	shortDegree = maxInt(shortDegree, intGenISISDirectSignatureRangeDegree(sigBound))
	parallelDegree := maxInt(maxInt(maxInt(maxInt(2, intGenISISMembershipDegree(pub.BoundB)), intGenISISMembershipDegree(intGenISISSeedBound)), ternaryCarrierV3Alphabet), maxInt(shortDegree, compressionSpec.Descriptor.MembershipDeg))
	aggregateDegree := maxInt(maxInt(maxInt(2, compressionSpec.Descriptor.DecodeDegree), hashCompressionSpec.Descriptor.DecodeDegree), 3)
	return ConstraintSet{
		FparInt:          make([]*ring.Poly, fparIntCount),
		FparIntCoeffs:    make([][]uint64, fparIntCount),
		FparNorm:         make([]*ring.Poly, fparCount-fparIntCount),
		FparNormCoeffs:   make([][]uint64, fparCount-fparIntCount),
		FaggNorm:         make([]*ring.Poly, faggCount),
		FaggNormCoeffs:   make([][]uint64, faggCount),
		ParallelAlgDeg:   parallelDegree,
		AggregatedAlgDeg: aggregateDegree,
	}, nil
}

// forceFormalV3 exists only for equivalence tests. Production strict-v3 call
// sites always use semantic metadata and never construct formal Q families.
func buildIntGenISISShowingConstraintSetFromRowsPreparedMode(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, prfCompanionLayout *PRFCompanionLayout, phase *PhaseRecorder, prepared *IntGenISISShowingPreparedContext, forceFormalV3 bool) (ConstraintSet, error) {
	constraintsStart := phaseTimingStart(phase)
	if phase != nil {
		defer func() {
			phase.RecordDuration("showing.constraints.total", time.Since(constraintsStart))
		}()
	}
	stage := func(label string, fn func() error) error {
		start := phaseTimingStart(phase)
		err := fn()
		if phase != nil {
			phase.RecordDuration(label, time.Since(start))
		}
		return err
	}
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	if !pub.IntGenISIS {
		return ConstraintSet{}, fmt.Errorf("IntGenISIS showing constraints require IntGenISIS public inputs")
	}
	if pub.HashInputBound != credential.IntGenISISHashInputBound {
		return ConstraintSet{}, fmt.Errorf("hash_input_bound=%d want %d", pub.HashInputBound, credential.IntGenISISHashInputBound)
	}
	l := layout.IntGenISISShowing
	if err := validateIntGenISISShowingPackedLayout(l, len(rowsNTT)); err != nil {
		return ConstraintSet{}, err
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount {
		return ConstraintSet{}, fmt.Errorf("a dimensions=%dx? want 1x%d", len(pub.A), l.UCount)
	}
	if len(pub.B) != 3+l.X0Count {
		return ConstraintSet{}, fmt.Errorf("b length=%d want %d", len(pub.B), 3+l.X0Count)
	}
	if len(pub.CM) != l.ECount || len(pub.CM[0]) != l.MCount || len(pub.AS) != l.ECount || len(pub.AS[0]) != l.SCount {
		return ConstraintSet{}, fmt.Errorf("commitment public dimensions mismatch")
	}
	q := ringQ.Modulus[0]
	projectedUY := intGenISISProjectionUsesProjectedUYHat(l)
	derivedYView := intGenISISProjectionDerivesYView(l)
	compressedMSE := l.MSECompressionLevel > 0
	structuralV3 := l.LayoutVersion == intGenISISShowingLayoutVersionInputTraceCarrierV3
	compressionSpec := intGenISISMSECompressionSpec{}
	if compressedMSE {
		var cerr error
		compressionSpec, cerr = newIntGenISISMSECompressionSpecForBound(q, l.MSECompressionLevel, pub.BoundB)
		if cerr != nil {
			return ConstraintSet{}, cerr
		}
	}
	hashCompressionSpec := intGenISISMSECompressionSpec{}
	if structuralV3 {
		var cerr error
		hashCompressionSpec, cerr = newIntGenISISMSECompressionSpecForBound(q, 1, pub.HashInputBound)
		if cerr != nil {
			return ConstraintSet{}, cerr
		}
		if hashCompressionSpec.Descriptor.PackWidth != ternaryCarrierV3PackWidth || hashCompressionSpec.Descriptor.DecodeDegree != ternaryCarrierV3Alphabet-1 || hashCompressionSpec.Descriptor.MembershipDeg != ternaryCarrierV3Alphabet {
			return ConstraintSet{}, fmt.Errorf("strict v3 hash carrier compiler mismatch")
		}
		if prfCompanionLayout != nil {
			return ConstraintSet{}, fmt.Errorf("strict v3 semantic relation must not carry a PRF companion layout")
		}
		if !forceFormalV3 {
			replayDomain := []uint64(nil)
			if prepared != nil {
				replayDomain = prepared.domainPoints
			}
			if len(replayDomain) == 0 {
				// Compatibility-only callers that do not own a prepared domain
				// still need a non-empty domain to construct the immutable shape.
				// The target prepared path always supplies the complete domain.
				replayDomain = []uint64{omega[0] % q}
			}
			var replay *intGenISISShowingReplayConfig
			if err := stage("showing.constraints.replay_plan", func() error {
				var rerr error
				replay, rerr = prepared.loadOrBuildStrictReplay(ringQ, pub, layout, omega, replayDomain, prfCompanionLayout)
				return rerr
			}); err != nil {
				return ConstraintSet{}, fmt.Errorf("strict v3 showing replay plan: %w", err)
			}
			var semanticSet ConstraintSet
			if err := stage("showing.constraints.semantic_metadata_v3", func() error {
				var serr error
				semanticSet, serr = buildIntGenISISShowingSemanticMetadataV3(ringQ, pub, layout, rowsNTT, omega, compressionSpec, hashCompressionSpec, replay)
				return serr
			}); err != nil {
				return ConstraintSet{}, err
			}
			return semanticSet, nil
		}
	}
	var yLinearCache *intGenISISYLinearMapCache
	yLinearKey, yLinearCacheable := intGenISISYLinearCacheKey(ringQ, pub, l, omega)
	if yLinearCacheable {
		yLinearCache = prepared.loadYLinearCache(yLinearKey)
	}
	if yLinearCache == nil {
		if err := stage("showing.constraints.y_linear_plan", func() error {
			var yerr error
			yLinearCache, yerr = newIntGenISISYLinearMapCache(ringQ, pub, l, omega)
			return yerr
		}); err != nil {
			return ConstraintSet{}, err
		}
		if yLinearCacheable {
			prepared.storeYLinearCache(yLinearKey, yLinearCache)
		}
	} else if phase != nil {
		phase.RecordDuration("showing.constraints.y_linear_plan.cached", 0)
	}
	var rowCache *intGenISISRowCoeffCache
	if err := stage("showing.constraints.projected.row_coeff_cache", func() error {
		var rerr error
		rowCache, rerr = newIntGenISISRowCoeffCache(ringQ, rowsNTT)
		return rerr
	}); err != nil {
		return ConstraintSet{}, err
	}
	coeffs := make([][]uint64, 0, 2*l.ViewRowsPerPoly)
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		zCoeff, err := rowCache.Row(l.ZHatStart + block)
		if err != nil {
			return ConstraintSet{}, err
		}
		if !projectedUY {
			sig := []uint64{0}
			for i := 0; i < l.UCount; i++ {
				aCoeff, err := intGenISISThetaBlockCoeff(ringQ, pub.A[0][i], omega, block, l.ViewRowsPerPoly, fmt.Sprintf("A[0][%d]", i))
				if err != nil {
					return ConstraintSet{}, err
				}
				uCoeff, err := rowCache.Row(l.UHatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return ConstraintSet{}, err
				}
				sig = polyAdd(sig, polyMul(aCoeff, uCoeff, q), q)
			}
			b0, err := intGenISISThetaBlockCoeff(ringQ, pub.B[0], omega, block, l.ViewRowsPerPoly, "B[0]")
			if err != nil {
				return ConstraintSet{}, err
			}
			sig = polySub(sig, b0, q)
			b1, err := intGenISISThetaBlockCoeff(ringQ, pub.B[1], omega, block, l.ViewRowsPerPoly, "B[1]")
			if err != nil {
				return ConstraintSet{}, err
			}
			muCoeff, err := intGenISISLinearHatFormalCoeff(rowCache, l, intGenISISLinearHatMuSig, 0, block)
			if err != nil {
				return ConstraintSet{}, err
			}
			sig = polySub(sig, polyMul(b1, muCoeff, q), q)
			for i := 0; i < l.X0Count; i++ {
				bCoeff, err := intGenISISThetaBlockCoeff(ringQ, pub.B[2+i], omega, block, l.ViewRowsPerPoly, fmt.Sprintf("B[%d]", 2+i))
				if err != nil {
					return ConstraintSet{}, err
				}
				x0Coeff, err := intGenISISLinearHatFormalCoeff(rowCache, l, intGenISISLinearHatX0, i, block)
				if err != nil {
					return ConstraintSet{}, err
				}
				sig = polySub(sig, polyMul(bCoeff, x0Coeff, q), q)
			}
			sig = polySub(sig, zCoeff, q)
			yHatCoeff, err := rowCache.Row(l.YHatStart + block)
			if err != nil {
				return ConstraintSet{}, err
			}
			sig = polySub(sig, yHatCoeff, q)
			coeffs = append(coeffs, trimPoly(sig, q))
		}

		b3Coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.B[len(pub.B)-1], omega, block, l.ViewRowsPerPoly, fmt.Sprintf("B[%d]", len(pub.B)-1))
		if err != nil {
			return ConstraintSet{}, err
		}
		x1Coeff, err := intGenISISLinearHatFormalCoeff(rowCache, l, intGenISISLinearHatX1, 0, block)
		if err != nil {
			return ConstraintSet{}, err
		}
		inv := polySub(polyMul(polySub(b3Coeff, x1Coeff, q), zCoeff, q), []uint64{1 % q}, q)
		coeffs = append(coeffs, trimPoly(inv, q))

	}
	keyBindCoeffs := make([][]uint64, 0)
	keyBindPolys := make([]*ring.Poly, 0)
	if err := stage("showing.constraints.key_bind", func() error {
		if prfCompanionLayout != nil && prfCompanionLayout.KeyCount > 0 {
			_, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
			if err != nil {
				return fmt.Errorf("key source selectors: %w", err)
			}
			keySourceMode := prfCompanionLayout.KeySourceMode
			if keySourceMode == "" {
				keySourceMode = PRFKeySourceModeDirect
			}
			if keySourceMode == PRFKeySourceModePack9Seed {
				if len(prfCompanionLayout.KeySourceDecodeLanes) > 0 {
					return fmt.Errorf("Pack9 seed key source must not use compressed decode lanes")
				}
				wantSources := prfCompanionLayout.KeyCount * credential.IntGenISISPRFSeedDigitsPerLane
				if len(prfCompanionLayout.KeySourceSlots) != wantSources {
					return fmt.Errorf("PRF seed source slots=%d want %d", len(prfCompanionLayout.KeySourceSlots), wantSources)
				}
				for i := 0; i < prfCompanionLayout.KeyCount; i++ {
					if i >= len(prfCompanionLayout.KeySlots) {
						return fmt.Errorf("PRF key slot %d out of range", i)
					}
					keySlot := prfCompanionLayout.KeySlots[i]
					if keySlot.Coeff < 0 || keySlot.Coeff >= len(selectorCoeff) {
						return fmt.Errorf("PRF key binding slot out of range")
					}
					keyCoeff, err := rowCache.Row(keySlot.Row)
					if err != nil {
						return fmt.Errorf("PRF key row: %w", err)
					}
					res := make([]uint64, int(ringQ.N))
					addMulModXN1Into(res, selectorCoeff[keySlot.Coeff], keyCoeff, 1, q)
					pow := uint64(1)
					constant := uint64(0)
					for j := 0; j < credential.IntGenISISPRFSeedDigitsPerLane; j++ {
						srcSlot := prfCompanionLayout.KeySourceSlots[i*credential.IntGenISISPRFSeedDigitsPerLane+j]
						if srcSlot.Coeff < 0 || srcSlot.Coeff >= len(selectorCoeff) {
							return fmt.Errorf("PRF seed binding slot out of range")
						}
						srcCoeff, err := rowCache.Row(srcSlot.Row)
						if err != nil {
							return fmt.Errorf("PRF seed source row: %w", err)
						}
						addMulModXN1Into(res, selectorCoeff[srcSlot.Coeff], srcCoeff, (q-pow)%q, q)
						constant = (constant + (uint64(credential.IntGenISISPRFSeedBound)%q)*pow) % q
						pow = (pow * uint64(credential.IntGenISISPRFSeedPackBase)) % q
					}
					if constant != 0 {
						addMulModXN1Into(res, selectorCoeff[keySlot.Coeff], []uint64{1}, (q-constant)%q, q)
					}
					res = trimPoly(res, q)
					keyBindCoeffs = append(keyBindCoeffs, res)
					keyBindPolys = append(keyBindPolys, nttPolyFromFormalCoeffsIfFits(ringQ, res))
				}
				return nil
			}
			if keySourceMode != PRFKeySourceModeDirect {
				return fmt.Errorf("unsupported PRF key source mode %q", keySourceMode)
			}
			if len(prfCompanionLayout.KeySourceSlots) != len(prfCompanionLayout.KeySlots) {
				return fmt.Errorf("PRF key source slots=%d want key slots=%d", len(prfCompanionLayout.KeySourceSlots), len(prfCompanionLayout.KeySlots))
			}
			for i := 0; i < prfCompanionLayout.KeyCount; i++ {
				if i >= len(prfCompanionLayout.KeySlots) || i >= len(prfCompanionLayout.KeySourceSlots) {
					return fmt.Errorf("PRF key slot %d out of range", i)
				}
				keySlot := prfCompanionLayout.KeySlots[i]
				srcSlot := prfCompanionLayout.KeySourceSlots[i]
				if keySlot.Coeff < 0 || keySlot.Coeff >= len(selectorCoeff) || srcSlot.Coeff < 0 || srcSlot.Coeff >= len(selectorCoeff) {
					return fmt.Errorf("PRF key binding slot out of range")
				}
				keyCoeff, err := rowCache.Row(keySlot.Row)
				if err != nil {
					return fmt.Errorf("PRF key row: %w", err)
				}
				var srcCoeff []uint64
				if len(prfCompanionLayout.KeySourceDecodeLanes) > 0 {
					if i >= len(prfCompanionLayout.KeySourceDecodeLanes) {
						return fmt.Errorf("missing PRF key source decode lane %d", i)
					}
					srcCoeff, err = intGenISISCompressedCarrierLaneFormalCoeff(ringQ, rowsNTT, srcSlot.Row, prfCompanionLayout.KeySourceDecodeLanes[i], compressionSpec.DecodePolys, "PRF key source")
					if err != nil {
						return err
					}
				} else {
					srcCoeff, err = rowCache.Row(srcSlot.Row)
					if err != nil {
						return fmt.Errorf("PRF key source row: %w", err)
					}
				}
				res := make([]uint64, int(ringQ.N))
				addMulModXN1Into(res, selectorCoeff[keySlot.Coeff], keyCoeff, 1, q)
				addMulModXN1Into(res, selectorCoeff[srcSlot.Coeff], srcCoeff, q-1, q)
				res = trimPoly(res, q)
				keyBindCoeffs = append(keyBindCoeffs, res)
				keyBindPolys = append(keyBindPolys, nttPolyFromFormalCoeffsIfFits(ringQ, res))
			}
		}
		return nil
	}); err != nil {
		return ConstraintSet{}, err
	}
	fpar := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		if len(coeffs[i]) <= int(ringQ.N) {
			fpar[i] = nttPolyFromFormalCoeffsIfFits(ringQ, coeffs[i])
		}
	}
	var sigBound int64
	var shortSpec LinfSpec
	var shortPolys []*ring.Poly
	var shortCoeffs [][]uint64
	var boundPolys []*ring.Poly
	var boundCoeffs [][]uint64
	var radixPolys []*ring.Poly
	var radixCoeffs [][]uint64
	if err := stage("showing.constraints.bounds", func() error {
		var berr error
		sigBound, berr = intGenISISSignatureBoundFromPublic(pub)
		if berr != nil {
			return berr
		}
		shortSpec, berr = intGenISISUShortnessLayoutSpec(ringQ, l, sigBound)
		if berr != nil {
			return berr
		}
		if intGenISISUseDirectSignatureRange(sigBound) {
			if intGenISISProjectionUsesDigitOnlyU(l) {
				return fmt.Errorf("IntGenISIS digit-only U does not support direct signature range constraints")
			}
			shortRows := intGenISISViewRowIndices(l.UViewStart, l.UCount*l.ViewRowsPerPoly)
			shortPolys, shortCoeffs, berr = intGenISISRangeMembershipRows(ringQ, rowsNTT, shortRows, sigBound)
			if berr != nil {
				return berr
			}
		}
		if compressedMSE {
			carrierRows := make([]int, 0, l.MCarrierCount+l.SCarrierCount+l.ECarrierCount)
			carrierRows = append(carrierRows, intGenISISViewRowIndices(l.MCarrierStart, l.MCarrierCount)...)
			carrierRows = append(carrierRows, intGenISISViewRowIndices(l.SCarrierStart, l.SCarrierCount)...)
			carrierRows = append(carrierRows, intGenISISViewRowIndices(l.ECarrierStart, l.ECarrierCount)...)
			boundPolys, boundCoeffs, berr = intGenISISCompressedCarrierMembershipRows(ringQ, rowsNTT, carrierRows, compressionSpec)
			if berr != nil {
				return berr
			}
			seedRows := intGenISISViewRowIndices(l.MSeedViewStart, l.MSeedViewCount)
			seedPolys, seedCoeffs, serr := intGenISISRangeMembershipRows(ringQ, rowsNTT, seedRows, intGenISISSeedBound)
			if serr != nil {
				return serr
			}
			boundPolys = append(boundPolys, seedPolys...)
			boundCoeffs = append(boundCoeffs, seedCoeffs...)
		} else {
			mOrdinaryRows, mSeedRows, serr := intGenISISSplitMViewRowIndicesForPack9Tail(l.MViewStart, int(ringQ.N), len(omega))
			if serr != nil {
				return serr
			}
			ordinaryRows := make([]int, 0, len(mOrdinaryRows)+l.SCount*l.ViewRowsPerPoly+l.ECount*l.ViewRowsPerPoly)
			ordinaryRows = append(ordinaryRows, mOrdinaryRows...)
			ordinaryRows = append(ordinaryRows, intGenISISViewRowIndices(l.SViewStart, l.SCount*l.ViewRowsPerPoly)...)
			ordinaryRows = append(ordinaryRows, intGenISISViewRowIndices(l.EViewStart, l.ECount*l.ViewRowsPerPoly)...)
			boundPolys, boundCoeffs, berr = intGenISISLiveMembershipRows(ringQ, rowsNTT, ordinaryRows, pub.BoundB)
			if berr != nil {
				return berr
			}
			seedPolys, seedCoeffs, serr := intGenISISRangeMembershipRows(ringQ, rowsNTT, mSeedRows, intGenISISSeedBound)
			if serr != nil {
				return serr
			}
			boundPolys = append(boundPolys, seedPolys...)
			boundCoeffs = append(boundCoeffs, seedCoeffs...)
		}
		hashRows := make([]int, 0, (l.MuSigCount+l.X0Count+l.X1Count)*l.ViewRowsPerPoly)
		if structuralV3 {
			hashRows = append(hashRows, intGenISISViewRowIndices(l.MuSigCarrierStart, l.MuSigCarrierCount)...)
			hashRows = append(hashRows, intGenISISViewRowIndices(l.X0CarrierStart, l.X0CarrierCount)...)
			hashRows = append(hashRows, intGenISISViewRowIndices(l.X1CarrierStart, l.X1CarrierCount)...)
		} else {
			hashRows = append(hashRows, intGenISISViewRowIndices(l.MuSigViewStart, l.MuSigCount*l.ViewRowsPerPoly)...)
			hashRows = append(hashRows, intGenISISViewRowIndices(l.X0ViewStart, l.X0Count*l.ViewRowsPerPoly)...)
			hashRows = append(hashRows, intGenISISViewRowIndices(l.X1ViewStart, l.X1Count*l.ViewRowsPerPoly)...)
		}
		var hashPolys []*ring.Poly
		var hashCoeffs [][]uint64
		var herr error
		if structuralV3 {
			hashPolys, hashCoeffs, herr = intGenISISCompressedCarrierMembershipRows(ringQ, rowsNTT, hashRows, hashCompressionSpec)
		} else {
			hashPolys, hashCoeffs, herr = intGenISISRangeMembershipRows(ringQ, rowsNTT, hashRows, pub.HashInputBound)
		}
		if herr != nil {
			return herr
		}
		boundPolys = append(boundPolys, hashPolys...)
		boundCoeffs = append(boundCoeffs, hashCoeffs...)
		radixPolys, radixCoeffs, berr = intGenISISUShortnessConstraintRows(ringQ, rowsNTT, l, shortSpec)
		return berr
	}); err != nil {
		return ConstraintSet{}, err
	}
	boundPolys = append(shortPolys, boundPolys...)
	boundCoeffs = append(shortCoeffs, boundCoeffs...)
	boundPolys = append(boundPolys, radixPolys...)
	boundCoeffs = append(boundCoeffs, radixCoeffs...)

	bridgePolys := append([]*ring.Poly{}, keyBindPolys...)
	bridgeCoeffs := append([][]uint64{}, keyBindCoeffs...)
	prfDirectFullDegree := 0
	if !derivedYView {
		yPolys, yCoeffs, err := intGenISISYLinearConstraintFormalCoeffs(ringQ, rowsNTT, rowCache, l, yLinearCache, compressionSpec)
		if err != nil {
			return ConstraintSet{}, err
		}
		bridgePolys = append(bridgePolys, yPolys...)
		bridgeCoeffs = append(bridgeCoeffs, yCoeffs...)
	}
	if prfCompanionLayout != nil && prfCompanionLayout.RelationVersion == 2 {
		var prfFullPolys []*ring.Poly
		var prfFullCoeffs [][]uint64
		if err := stage("showing.constraints.prf_direct_full", func() error {
			params := (*prf.Params)(nil)
			if prepared != nil {
				params = prepared.prfParams
			}
			if params == nil {
				var perr error
				params, perr = loadPRFParamsForOpts(SimOpts{})
				if perr != nil {
					return fmt.Errorf("load prf params: %w", perr)
				}
			}
			var degree int
			var ferr error
			prfFullPolys, prfFullCoeffs, degree, ferr = buildPRFCompanionDirectFullFormalCoeffs(
				ringQ,
				params,
				rowsNTT,
				rowCache,
				prfCompanionLayout,
				pub.Tag,
				pub.Context,
				omega,
				prfCompanionLayout.GroupRounds,
			)
			if ferr != nil {
				return ferr
			}
			prfDirectFullDegree = degree
			return nil
		}); err != nil {
			return ConstraintSet{}, err
		}
		bridgePolys = append(bridgePolys, prfFullPolys...)
		bridgeCoeffs = append(bridgeCoeffs, prfFullCoeffs...)
	}
	if structuralV3 {
		var relation *prfInputTraceV3Relation
		var prfV3Polys []*ring.Poly
		var prfV3Coeffs [][]uint64
		if err := stage("showing.constraints.prf_input_trace_v3", func() error {
			params := (*prf.Params)(nil)
			if prepared != nil {
				params = prepared.prfParams
			}
			var rerr error
			relation, rerr = newPRFInputTraceV3RelationForShowing(ringQ, pub, l, omega, params, len(rowsNTT))
			if rerr != nil {
				return rerr
			}
			var degree int
			prfV3Polys, prfV3Coeffs, degree, rerr = relation.FormalCoeffs(ringQ, rowCache)
			if rerr != nil {
				return rerr
			}
			if degree != 3 {
				return fmt.Errorf("strict v3 PRF compiler degree=%d want 3", degree)
			}
			prfDirectFullDegree = degree
			return nil
		}); err != nil {
			return ConstraintSet{}, err
		}
		bridgePolys = append(bridgePolys, prfV3Polys...)
		bridgeCoeffs = append(bridgeCoeffs, prfV3Coeffs...)
	}
	if projectedUY {
		var projectedPolys []*ring.Poly
		var projectedCoeffs [][]uint64
		if err := stage("showing.constraints.projected_signature", func() error {
			outputCount := l.ViewRowsPerPoly * len(omega)
			sourceBlocks := l.ViewRowsPerPoly
			basis := prepared.loadProjectedBasis(outputCount, sourceBlocks)
			if basis == nil {
				var berr error
				basis, berr = newTransformBridgeBasisCache(ringQ, omega, outputCount, sourceBlocks)
				if berr != nil {
					return fmt.Errorf("IntGenISIS projected signature bridge basis: %w", berr)
				}
				prepared.storeProjectedBasis(outputCount, sourceBlocks, basis)
			}
			var perr error
			projectedPolys, projectedCoeffs, perr = intGenISISProjectedSignatureFormalCoeffs(ringQ, pub, rowsNTT, rowCache, l, basis, omega, yLinearCache, compressionSpec, hashCompressionSpec, phase)
			return perr
		}); err != nil {
			return ConstraintSet{}, err
		}
		bridgePolys = append(bridgePolys, projectedPolys...)
		bridgeCoeffs = append(bridgeCoeffs, projectedCoeffs...)
	} else {
		for _, bridge := range []struct {
			name       string
			source     int
			components int
			hat        int
			compressed bool
		}{
			{"u", l.UViewStart, l.UCount, l.UHatStart, false},
			{"Y", l.YViewStart, 1, l.YHatStart, false},
		} {
			source := bridge.source
			if bridge.compressed {
				switch bridge.name {
				case "M":
					source = l.MCarrierStart
				case "s":
					source = l.SCarrierStart
				case "e":
					source = l.ECarrierStart
				}
			}
			var polys []*ring.Poly
			var coeffs [][]uint64
			var berr error
			if bridge.compressed {
				polys, coeffs, berr = intGenISISCompressedCoeffToHatBridgeFormalCoeffs(ringQ, rowsNTT, omega, source, bridge.components, bridge.hat, l.ViewRowsPerPoly, l.MSECompressionPackWidth, compressionSpec.DecodePolys, bridge.name)
			} else {
				polys, coeffs, berr = intGenISISCoeffToHatBridgeFormalCoeffs(ringQ, rowCache, omega, source, bridge.components, bridge.hat, l.ViewRowsPerPoly, bridge.name)
			}
			if berr != nil {
				return ConstraintSet{}, berr
			}
			bridgePolys = append(bridgePolys, polys...)
			bridgeCoeffs = append(bridgeCoeffs, coeffs...)
		}
	}
	linearHatBridges := []struct {
		name       string
		source     int
		components int
		hat        int
		compressed bool
	}{
		{"x1", func() int {
			if structuralV3 {
				return l.X1CarrierStart
			}
			return l.X1ViewStart
		}(), l.X1Count, l.X1HatStart, structuralV3},
	}
	if intGenISISLinearHatSourceMode(l) == intGenISISLinearHatSourceMaterialized {
		linearHatBridges = append([]struct {
			name       string
			source     int
			components int
			hat        int
			compressed bool
		}{
			{"mu_sig", func() int {
				if structuralV3 {
					return l.MuSigCarrierStart
				}
				return l.MuSigViewStart
			}(), l.MuSigCount, l.MuSigHatStart, structuralV3},
			{"x0", func() int {
				if structuralV3 {
					return l.X0CarrierStart
				}
				return l.X0ViewStart
			}(), l.X0Count, l.X0HatStart, structuralV3},
		}, linearHatBridges...)
	}
	for _, bridge := range linearHatBridges {
		var polys []*ring.Poly
		var coeffs [][]uint64
		var berr error
		if bridge.compressed {
			polys, coeffs, berr = intGenISISCompressedCoeffToHatBridgeFormalCoeffs(ringQ, rowsNTT, omega, bridge.source, bridge.components, bridge.hat, l.ViewRowsPerPoly, ternaryCarrierV3PackWidth, hashCompressionSpec.DecodePolys, bridge.name)
		} else {
			polys, coeffs, berr = intGenISISCoeffToHatBridgeFormalCoeffs(ringQ, rowCache, omega, bridge.source, bridge.components, bridge.hat, l.ViewRowsPerPoly, bridge.name)
		}
		if berr != nil {
			return ConstraintSet{}, berr
		}
		bridgePolys = append(bridgePolys, polys...)
		bridgeCoeffs = append(bridgeCoeffs, coeffs...)
	}
	shortDegree, err := signatureShortnessMaxDegree(shortSpec, SimOpts{})
	if err != nil {
		return ConstraintSet{}, err
	}
	shortDegree = maxInt(shortDegree, intGenISISDirectSignatureRangeDegree(sigBound))
	return ConstraintSet{
		FparInt:        fpar,
		FparIntCoeffs:  coeffs,
		FparNorm:       boundPolys,
		FparNormCoeffs: boundCoeffs,
		FaggNorm:       bridgePolys,
		FaggNormCoeffs: bridgeCoeffs,
		ParallelAlgDeg: maxInt(maxInt(maxInt(maxInt(2, intGenISISMembershipDegree(pub.BoundB)), intGenISISMembershipDegree(intGenISISSeedBound)), func() int {
			if structuralV3 {
				return ternaryCarrierV3Alphabet
			}
			return intGenISISMembershipDegree(pub.HashInputBound)
		}()), maxInt(shortDegree, compressionSpec.Descriptor.MembershipDeg)),
		AggregatedAlgDeg: maxInt(maxInt(maxInt(2, compressionSpec.Descriptor.DecodeDegree), func() int {
			if structuralV3 {
				return ternaryCarrierV3Alphabet - 1
			}
			return 0
		}()), prfDirectFullDegree),
	}, nil
}

func rejectIntGenISISUnsafeSigLookup(opts SimOpts) error {
	if sigLookupShadowR121L2EnabledForOpts(opts) {
		return fmt.Errorf("IntGenISIS showing does not support unsafe R121/L2 signature lookup shadow mode")
	}
	if opts.SigShortnessRadix == sigLookupShadowR121L2Radix && opts.SigShortnessL == sigLookupShadowR121L2Digits {
		return fmt.Errorf("IntGenISIS showing does not support R121/L2 signature shortness overrides")
	}
	return nil
}

// PrepareIntGenISISShowingContext precomputes public/domain state for repeated
// IntGenISIS showing proofs. The returned context does not contain witness
// material and does not affect proof verification.
func PrepareIntGenISISShowingContext(pub PublicInputs, opts SimOpts) (*IntGenISISShowingPreparedContext, error) {
	opts.applyDefaults()
	if err := validateIntGenISISV2TranscriptOpts(opts); err != nil {
		return nil, err
	}
	if err := rejectIntGenISISUnsafeSigLookup(opts); err != nil {
		return nil, err
	}
	if err := rejectIntGenISISUnsupportedDegreeCappedModes(opts); err != nil {
		return nil, err
	}
	if !opts.Credential || !opts.CoeffPacking {
		return nil, fmt.Errorf("IntGenISIS showing requires credential coeff-packing mode")
	}
	ownedPublic, err := clonePublicInputsOwned(pub)
	if err != nil {
		return nil, fmt.Errorf("clone prepared IntGenISIS public inputs: %w", err)
	}
	pub = ownedPublic
	pub.IntGenISIS = true
	opts.EnablePackedPRFWitnessRows = true
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		// Input-trace v3 is the complete PRF relation for the target path.
		// Companion controls are legacy-only metadata and must not be revived by
		// preparation defaults after the preset has deliberately cleared them.
		opts.EnablePRFCompanion = false
		opts.PRFCompanionMode = ""
		opts.PRFGroupRounds = 0
		opts.PRFCheckpointSamples = 0
	} else {
		opts.EnablePRFCompanion = true
		if normalizePRFCompanionMode(opts.PRFCompanionMode) == "" {
			opts.PRFCompanionMode = PRFCompanionModeDirectFull
		}
	}
	var (
		ringQ          *ring.Ring
		omega          []uint64
		domainPoints   []uint64
		preparedDomain *swDomain.Prepared
		pcsNCols       int
	)
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		ringQ, err = loadParamsRingForOpts(opts)
		if err != nil {
			return nil, fmt.Errorf("load params: %w", err)
		}
		witnessNCols := opts.NCols
		if witnessNCols <= 0 {
			witnessNCols = int(ringQ.N)
		}
		pcsNCols = resolvePCSNCols(opts, witnessNCols)
		if pcsNCols < witnessNCols {
			return nil, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", pcsNCols, witnessNCols)
		}
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		domainStart := phaseTimingStart(opts.PhaseRecorder)
		preparedDomain, _, err = prepareExplicitDomainForRelation(ringQ.Modulus[0], nLeaves, witnessNCols, pcsNCols, opts.Ell, pub.HashRelation)
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration("showing.domain_preparation", time.Since(domainStart))
		}
		if err != nil {
			return nil, fmt.Errorf("explicit domain: %w", err)
		}
		omega = preparedDomain.CopyRange(0, pcsNCols)
		domainPoints = preparedDomain.CopyPoints()
	} else {
		ringQ, omega, pcsNCols, err = loadParamsAndOmegaForRelation(opts, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("load params: %w", err)
		}
	}
	pub, err = bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), opts)
	if err != nil {
		return nil, err
	}
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		if err := validateCanonicalTargetPublicBindingsV3(pub, opts, CanonicalProofShowing); err != nil {
			return nil, fmt.Errorf("PIOP: strict-v3 showing target binding: %w", err)
		}
	}
	var publicBinding []byte
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		publicBinding, err = canonicalPublicInputsBytesV3(pub)
		if err != nil {
			return nil, fmt.Errorf("PIOP: canonical prepared public binding: %w", err)
		}
	}
	witnessNCols := opts.NCols
	if witnessNCols <= 0 {
		witnessNCols = pcsNCols
	}
	if opts.DomainMode == DomainModeExplicit && preparedDomain == nil {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		if pcsNCols < witnessNCols {
			pcsNCols = witnessNCols
		}
		var derr error
		omega, domainPoints, derr = deriveExplicitDomainForRelation(ringQ.Modulus[0], nLeaves, witnessNCols, pcsNCols, opts.Ell, pub.HashRelation)
		if derr != nil {
			return nil, fmt.Errorf("explicit domain: %w", derr)
		}
	}
	var params *prf.Params
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		params, _, err = loadTargetPRFParamsForOptsV3(opts)
	} else {
		params, err = loadPRFParamsForOpts(opts)
	}
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}
	groupRounds := opts.PRFGroupRounds
	if groupRounds <= 0 {
		groupRounds = 1
	}
	storedOpts := opts
	storedOpts.PhaseRecorder = nil
	storedOpts.ExecutionPolicy = ExecutionPolicy{}
	storedOpts.Mutate = nil
	return &IntGenISISShowingPreparedContext{
		pub:            pub,
		opts:           storedOpts,
		ringQ:          ringQ,
		omega:          append([]uint64(nil), omega...),
		domainPoints:   append([]uint64(nil), domainPoints...),
		preparedDomain: preparedDomain,
		publicBinding:  append([]byte(nil), publicBinding...),
		pcsNCols:       pcsNCols,
		prfParams:      params,
		groupRounds:    groupRounds,
	}, nil
}

func BuildIntGenISISShowingCombined(pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	prepared, err := PrepareIntGenISISShowingContext(pub, opts)
	if err != nil {
		return nil, err
	}
	return BuildIntGenISISShowingCombinedPrepared(pub, wit, opts, prepared)
}

func validateIntGenISISShowingPreparedReuse(ctx *IntGenISISShowingPreparedContext, pub PublicInputs, opts SimOpts) error {
	if ctx == nil || ctx.ringQ == nil {
		return fmt.Errorf("prepared IntGenISIS showing context is incomplete")
	}
	opts.applyDefaults()
	pub.IntGenISIS = true
	opts.EnablePackedPRFWitnessRows = true
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		opts.EnablePRFCompanion = false
		opts.PRFCompanionMode = ""
		opts.PRFGroupRounds = 0
		opts.PRFCheckpointSamples = 0
	} else {
		opts.EnablePRFCompanion = true
		if normalizePRFCompanionMode(opts.PRFCompanionMode) == "" {
			opts.PRFCompanionMode = PRFCompanionModeDirectFull
		}
	}
	ownedPublic, err := clonePublicInputsOwned(pub)
	if err != nil {
		return fmt.Errorf("clone IntGenISIS showing public inputs: %w", err)
	}
	boundPublic, err := bindIntGenISISPublicExtrasWithOpts(ownedPublic, int(ctx.ringQ.N), opts)
	if err != nil {
		return err
	}
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		if err := validateCanonicalTargetPublicBindingsV3(boundPublic, opts, CanonicalProofShowing); err != nil {
			return fmt.Errorf("PIOP: strict-v3 showing target binding: %w", err)
		}
		binding, err := canonicalPublicInputsBytesV3(boundPublic)
		if err != nil {
			return fmt.Errorf("PIOP: canonical prepared public binding: %w", err)
		}
		if !bytes.Equal(binding, ctx.publicBinding) {
			return fmt.Errorf("prepared IntGenISIS showing public-input binding mismatch")
		}
		cachedBinding, err := canonicalPublicInputsBytesV3(ctx.pub)
		if err != nil {
			return fmt.Errorf("PIOP: cached prepared public binding: %w", err)
		}
		if !bytes.Equal(cachedBinding, ctx.publicBinding) {
			return fmt.Errorf("prepared IntGenISIS showing cached public inputs changed after preparation")
		}
	} else if !reflect.DeepEqual(boundPublic, ctx.pub) {
		return fmt.Errorf("prepared IntGenISIS showing public inputs mismatch")
	}
	opts.PhaseRecorder = nil
	opts.ExecutionPolicy = ExecutionPolicy{}
	opts.Mutate = nil
	if !reflect.DeepEqual(opts, ctx.opts) {
		return fmt.Errorf("prepared IntGenISIS showing proof options mismatch")
	}
	return nil
}

// BuildIntGenISISShowingCombinedPrepared builds an IntGenISIS showing proof
// using a reusable public prepared context.
func BuildIntGenISISShowingCombinedPrepared(pub PublicInputs, wit WitnessInputs, opts SimOpts, prepared *IntGenISISShowingPreparedContext) (*Proof, error) {
	proof, _, err := buildIntGenISISShowingCombinedPreparedWithState(pub, wit, opts, prepared)
	return proof, err
}

func buildIntGenISISShowingCombinedPreparedWithState(pub PublicInputs, wit WitnessInputs, opts SimOpts, ctx *IntGenISISShowingPreparedContext) (*Proof, *preparedCredentialBuild, error) {
	opts.applyDefaults()
	if err := validateIntGenISISV2TranscriptOpts(opts); err != nil {
		return nil, nil, err
	}
	if ctx == nil {
		var err error
		ctx, err = PrepareIntGenISISShowingContext(pub, opts)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := validateIntGenISISShowingPreparedReuse(ctx, pub, opts); err != nil {
		return nil, nil, err
	}
	if wit.CoeffNativeShowing == nil {
		return nil, nil, fmt.Errorf("IntGenISIS showing requires coeff-native witness")
	}
	pub = ctx.pub
	phaseRecorder := opts.PhaseRecorder
	executionPolicy := opts.ExecutionPolicy
	mutationHook := opts.Mutate
	opts = ctx.opts
	if err := validateIntGenISISV2TranscriptOpts(opts); err != nil {
		return nil, nil, err
	}
	if phaseRecorder != nil {
		opts.PhaseRecorder = phaseRecorder
	}
	opts.ExecutionPolicy = executionPolicy
	if mutationHook != nil {
		opts.Mutate = mutationHook
	}
	ringQ := ctx.ringQ
	if ringQ == nil {
		return nil, nil, fmt.Errorf("prepared IntGenISIS showing context has nil ring")
	}
	if len(ctx.omega) == 0 {
		return nil, nil, fmt.Errorf("prepared IntGenISIS showing context has empty omega")
	}
	{
		omega := append([]uint64(nil), ctx.omega...)
		pcsNCols := ctx.pcsNCols
		witnessNCols := opts.NCols
		if witnessNCols <= 0 {
			witnessNCols = pcsNCols
		}
		if pcsNCols < witnessNCols {
			return nil, nil, fmt.Errorf("prepared IntGenISIS showing context lvcs ncols=%d < witness ncols=%d", pcsNCols, witnessNCols)
		}
		rowsStart := phaseTimingStart(opts.PhaseRecorder)
		rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, _, witnessCount, _, builtNCols, err := buildCredentialRowsShowingIntGenISIS(ringQ, pub, wit, ctx.prfParams.LenKey, ctx.prfParams.LenNonce, ctx.prfParams.RF, ctx.prfParams.RP, ctx.groupRounds, opts, omega[:witnessNCols])
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration("showing.rows", time.Since(rowsStart))
		}
		if err != nil {
			return nil, nil, fmt.Errorf("build IntGenISIS showing rows: %w", err)
		}
		requiredPCSNCols := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
		if requiredPCSNCols > pcsNCols {
			return nil, nil, fmt.Errorf("prepared explicit PCS width %d is too small for committed row degree; need at least %d", pcsNCols, requiredPCSNCols)
		}
		rowsNTTStart := phaseTimingStart(opts.PhaseRecorder)
		rowsNTT := make([]*ring.Poly, len(rows))
		for i := range rows {
			rowsNTT[i] = ringQ.NewPoly()
			ring.Copy(rows[i], rowsNTT[i])
			ringQ.NTT(rowsNTT[i], rowsNTT[i])
		}
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration("showing.rows_ntt", time.Since(rowsNTTStart))
		}
		postSet, err := buildIntGenISISShowingConstraintSetFromRowsPrepared(ringQ, pub, layout, rowsNTT, omega[:builtNCols], prfCompanionLayout, opts.PhaseRecorder, ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("build IntGenISIS showing constraints: %w", err)
		}
		set := ConstraintSet{
			FparInt:            postSet.FparInt,
			FparIntCoeffs:      postSet.FparIntCoeffs,
			FparNorm:           postSet.FparNorm,
			FparNormCoeffs:     postSet.FparNormCoeffs,
			FaggInt:            postSet.FaggInt,
			FaggIntCoeffs:      postSet.FaggIntCoeffs,
			FaggNorm:           postSet.FaggNorm,
			FaggNormCoeffs:     postSet.FaggNormCoeffs,
			ParallelAlgDeg:     postSet.ParallelAlgDeg,
			AggregatedAlgDeg:   postSet.AggregatedAlgDeg,
			PRFLayout:          prfLayout,
			PRFCompanionLayout: prfCompanionLayout,
		}
		credentialBuild := &preparedCredentialBuild{
			ringQ:                 ringQ,
			rows:                  rows,
			rowInputs:             rowInputs,
			rowLayout:             layout,
			decsParams:            decsParams,
			maskRowOffset:         maskRowOffset,
			witnessCount:          witnessCount,
			witnessNCols:          builtNCols,
			omega:                 omega,
			omegaWitness:          append([]uint64(nil), omega[:builtNCols]...),
			domainPoints:          append([]uint64(nil), ctx.domainPoints...),
			preparedDomain:        ctx.preparedDomain,
			relationIdentity:      pub.HashRelation,
			strictRowProvenance:   transcriptUsesSmallWood2025V3(opts.TranscriptVersion),
			showingReplay:         ctx.strictReplayConfig(),
			skipConstraintRebuild: true,
		}
		opts.Credential = true
		proof, err := buildWithConstraintsPrepared(pub, wit, set, opts, FSModeCredential, credentialBuild)
		if err != nil {
			return nil, nil, err
		}
		return proof, credentialBuild, nil
	}
}

func VerifyIntGenISISShowing(pub PublicInputs, proof *Proof, opts SimOpts) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	opts.applyDefaults()
	if err := validateIntGenISISVerifierOptionsV2(pub, opts); err != nil {
		return false, err
	}
	if err := rejectIntGenISISUnsafeSigLookup(opts); err != nil {
		return false, err
	}
	if err := rejectIntGenISISUnsupportedDegreeCappedModes(opts); err != nil {
		return false, err
	}
	pub.IntGenISIS = true
	var err error
	pub, err = bindIntGenISISPublicExtrasWithOpts(pub, pub.RingDegree, opts)
	if err != nil {
		return false, err
	}
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		if err := validateCanonicalTargetPublicBindingsV3(pub, opts, CanonicalProofShowing); err != nil {
			return false, fmt.Errorf("PIOP: strict-v3 showing target binding: %w", err)
		}
	}
	ringQ, err := credential.LoadRingWithDegree(pub.RingDegree)
	if err != nil {
		return false, err
	}
	expectedLayout, expectedCompanion, err := expectedIntGenISISShowingLayoutsV2(ringQ, pub, opts)
	if err != nil {
		return false, err
	}
	if err := validateIntGenISISProofDegreeMetadata(proof, pub, opts); err != nil {
		return false, err
	}
	if err := validateIntGenISISProofEnvelopeV2(proof, expectedLayout, expectedCompanion, pub, opts); err != nil {
		return false, err
	}
	verifySet := ConstraintSet{PRFCompanionLayout: expectedCompanion}
	return VerifyWithConstraints(proof, verifySet, pub, opts, FSModeCredential)
}
