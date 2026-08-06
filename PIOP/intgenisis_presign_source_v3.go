package PIOP

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	swDomain "vSIS-Signature/internal/domain"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	// These identifiers are deliberately phase-specific. They are included in
	// both the canonical row-layout statement and the strict-v3 public extras,
	// so the retired core/view relation cannot be accepted under this evaluator.
	intGenISISPreSignLayoutVersionSourceOnlyCarrierV3 = "intgenisis_presign_source_only_ternary_carrier_v3"
	intGenISISPreSignRelationVersionSourceOnlyV3      = "intgenisis_presign_full_ring_source_only_v3"

	intGenISISPreSignSourceNCols         = 32
	intGenISISPreSignSourcePackWidth     = 2
	intGenISISPreSignSourceCompression   = 1
	intGenISISPreSignSourceAlphabet      = 9
	intGenISISPreSignSourceDecodeDegree  = 8
	intGenISISPreSignSourceMembershipDeg = 9
)

// expectedIntGenISISPreSignSourceOnlyLayoutV3 derives the only accepted
// strict-v3 issuance layout from trusted public parameters. It intentionally
// does not accept transmitted dimensions or a legacy core/view inventory.
func expectedIntGenISISPreSignSourceOnlyLayoutV3(ringQ *ring.Ring, pub PublicInputs, opts SimOpts) (RowLayout, error) {
	if ringQ == nil {
		return RowLayout{}, fmt.Errorf("PIOP: nil ring")
	}
	if int(ringQ.N) != 1024 || opts.NCols != intGenISISPreSignSourceNCols {
		return RowLayout{}, fmt.Errorf("PIOP: strict-v3 source-only issuance requires N=1024 and ncols=32 (got N=%d ncols=%d)", ringQ.N, opts.NCols)
	}
	if opts.IntGenISISMSECompression != intGenISISPreSignSourceCompression {
		return RowLayout{}, fmt.Errorf("PIOP: strict-v3 source-only issuance requires carrier compression level %d (got %d)", intGenISISPreSignSourceCompression, opts.IntGenISISMSECompression)
	}
	if len(pub.Com) != 1 || len(pub.CM) != 1 || len(pub.CM[0]) != 1 || len(pub.AS) != 1 || len(pub.AS[0]) != 1 {
		return RowLayout{}, fmt.Errorf("PIOP: strict-v3 source-only issuance requires commitment geometry Com/CM/AS=1/1x1/1x1")
	}
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return RowLayout{}, err
	}
	ordinaryCoeffs := int(ringQ.N) - credential.IntGenISISPRFSeedTailReserve
	if ordinaryCoeffs <= 0 || ordinaryCoeffs%opts.NCols != 0 || credential.IntGenISISPRFSeedTailReserve%opts.NCols != 0 {
		return RowLayout{}, fmt.Errorf("PIOP: strict-v3 source-only semantic tail is not aligned")
	}
	mSources := ordinaryCoeffs / opts.NCols
	mTail := credential.IntGenISISPRFSeedTailReserve / opts.NCols
	sSources := int(ringQ.N) / opts.NCols
	eSources := int(ringQ.N) / opts.NCols
	mCarriers := intGenISISCompressedCarrierCount(mSources, intGenISISPreSignSourcePackWidth)
	sCarriers := intGenISISCompressedCarrierCount(sSources, intGenISISPreSignSourcePackWidth)
	eCarriers := intGenISISCompressedCarrierCount(eSources, intGenISISPreSignSourcePackWidth)
	cursor := 0
	mCarrierStart := cursor
	cursor += mCarriers
	mSeedStart := cursor
	cursor += mTail
	sCarrierStart := cursor
	cursor += sCarriers
	eCarrierStart := cursor
	cursor += eCarriers

	l := &IntGenISISPreSignRowLayout{
		LayoutVersion:              intGenISISPreSignLayoutVersionSourceOnlyCarrierV3,
		RelationVersion:            intGenISISPreSignRelationVersionSourceOnlyV3,
		MStart:                     -1,
		MCount:                     1,
		MAttrStart:                 -1,
		MAttrCount:                 1,
		KStart:                     -1,
		KCount:                     1,
		SStart:                     -1,
		SCount:                     1,
		EStart:                     -1,
		ECount:                     1,
		CoreRowCount:               0,
		BoundViewStart:             0,
		BoundViewCount:             cursor,
		MViewStart:                 -1,
		MAttrViewStart:             -1,
		KViewStart:                 -1,
		SViewStart:                 -1,
		EViewStart:                 -1,
		ViewRowsPerPoly:            int(ringQ.N) / opts.NCols,
		CommitmentRows:             1,
		MSECompressionLevel:        intGenISISPreSignSourceCompression,
		MSECompressionPackWidth:    intGenISISPreSignSourcePackWidth,
		MSECompressionAlphabet:     intGenISISPreSignSourceAlphabet,
		MSECompressionDecodeDegree: intGenISISPreSignSourceDecodeDegree,
		MSEMembershipDegree:        intGenISISPreSignSourceMembershipDeg,
		MCarrierStart:              mCarrierStart,
		MCarrierCount:              mCarriers,
		MCompressedSourceRows:      mSources,
		MSeedViewStart:             mSeedStart,
		MSeedViewCount:             mTail,
		SCarrierStart:              sCarrierStart,
		SCarrierCount:              sCarriers,
		SCompressedSourceRows:      sSources,
		ECarrierStart:              eCarrierStart,
		ECarrierCount:              eCarriers,
		ECompressedSourceRows:      eSources,
	}
	return RowLayout{
		RingDegree:        int(ringQ.N),
		SigCount:          cursor,
		X0Len:             x0Len,
		IntGenISISPreSign: l,
	}, nil
}

func validateIntGenISISPreSignSourceOnlyLayoutV3(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, ncols int) error {
	opts := SimOpts{NCols: ncols, IntGenISISMSECompression: intGenISISPreSignSourceCompression}
	expected, err := expectedIntGenISISPreSignSourceOnlyLayoutV3(ringQ, pub, opts)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(layout, expected) {
		return fmt.Errorf("PIOP: strict-v3 source-only issuance layout differs from trusted layout")
	}
	return nil
}

func intGenISISPreSignDomainsV3(ringQ *ring.Ring, pub PublicInputs, opts SimOpts) (omega, omegaWitness, domainPoints []uint64, prepared *swDomain.Prepared, err error) {
	domainStart := phaseTimingStart(opts.PhaseRecorder)
	if opts.PhaseRecorder != nil {
		defer func() {
			opts.PhaseRecorder.RecordDuration("issuance.domain_preparation", time.Since(domainStart))
		}()
	}
	ncols := opts.NCols
	lvcsNCols := opts.LVCSNCols
	if ncols != intGenISISPreSignSourceNCols || lvcsNCols < ncols {
		return nil, nil, nil, nil, fmt.Errorf("strict-v3 source-only issuance requires ncols=32 and lvcs_ncols>=32")
	}
	if opts.DomainMode != DomainModeExplicit {
		return nil, nil, nil, nil, fmt.Errorf("strict-v3 source-only issuance requires the explicit domain")
	}
	if lvcsNCols+opts.Ell > opts.NLeaves {
		return nil, nil, nil, nil, fmt.Errorf("explicit domain: need lvcs_ncols+ell <= nleaves")
	}
	prepared, omegaWitness, err = prepareExplicitDomainForRelation(ringQ.Modulus[0], opts.NLeaves, ncols, lvcsNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("derive explicit domain: %w", err)
	}
	omega = prepared.CopyRange(0, lvcsNCols)
	domainPoints = prepared.CopyPoints()
	return omega, omegaWitness, domainPoints, prepared, nil
}

func buildIntGenISISPreSignSourceOnlyRowsV3(ringQ *ring.Ring, pub PublicInputs, wit WitnessInputs, opts SimOpts, x0Len int) ([]*ring.Poly, []lvcs.RowInput, RowLayout, []uint64, []uint64, []uint64, *swDomain.Prepared, error) {
	var emptyLayout RowLayout
	layout, err := expectedIntGenISISPreSignSourceOnlyLayoutV3(ringQ, pub, opts)
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	if layout.X0Len != x0Len {
		return nil, nil, emptyLayout, nil, nil, nil, nil, fmt.Errorf("strict-v3 source-only x0 layout changed during construction")
	}
	omega, omegaWitness, domainPoints, preparedDomain, err := intGenISISPreSignDomainsV3(ringQ, pub, opts)
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	interp, err := newOmegaInterpolationPlan(omegaWitness, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	makeRow := func(head []uint64) *ring.Poly { return interp.coeffPolyFromHead(ringQ, head) }
	mViews, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, wit.M, opts.NCols, interp)
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, fmt.Errorf("M source views: %w", err)
	}
	mOrdinary, mTail, err := intGenISISSplitMViewRowsForPack9Tail(mViews, int(ringQ.N), opts.NCols)
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	mCarriers, err := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omegaWitness, mOrdinary, intGenISISPreSignSourcePackWidth, interp, makeRow, "pre-sign M")
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	sViews, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, wit.S, opts.NCols, interp)
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, fmt.Errorf("s source views: %w", err)
	}
	sCarriers, err := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omegaWitness, sViews, intGenISISPreSignSourcePackWidth, interp, makeRow, "pre-sign s")
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	eViews, err := intGenISISCoeffViewRowMaterials(ringQ, omegaWitness, wit.E, opts.NCols, interp)
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, fmt.Errorf("e source views: %w", err)
	}
	eCarriers, err := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omegaWitness, eViews, intGenISISPreSignSourcePackWidth, interp, makeRow, "pre-sign e")
	if err != nil {
		return nil, nil, emptyLayout, nil, nil, nil, nil, err
	}
	materials := make([]intGenISISRowMaterial, 0, layout.SigCount)
	materials = append(materials, mCarriers...)
	materials = append(materials, mTail...)
	materials = append(materials, sCarriers...)
	materials = append(materials, eCarriers...)
	if len(materials) != layout.SigCount || len(materials) != 49 {
		return nil, nil, emptyLayout, nil, nil, nil, nil, fmt.Errorf("strict-v3 source-only rows=%d want %d", len(materials), layout.SigCount)
	}
	rows := intGenISISRowMaterialPolys(materials)
	rowInputs := make([]lvcs.RowInput, len(materials))
	q := ringQ.Modulus[0]
	for i := range materials {
		rowInputs[i] = lvcs.RowInput{
			Head:        append([]uint64(nil), materials[i].Head...),
			Poly:        materials[i].Poly,
			PolyCoeffs:  trimCoeffsCopy(materials[i].Poly.Coeffs[0], q),
			TrustedHead: true,
		}
	}
	return rows, rowInputs, layout, omega, omegaWitness, domainPoints, preparedDomain, nil
}

func buildIntGenISISPreSignSourceOnlyV3(ringQ *ring.Ring, pub PublicInputs, wit WitnessInputs, opts SimOpts, x0Len int) (*Proof, error) {
	rowsStart := phaseTimingStart(opts.PhaseRecorder)
	rows, rowInputs, layout, omega, omegaWitness, domainPoints, preparedDomain, err := buildIntGenISISPreSignSourceOnlyRowsV3(ringQ, pub, wit, opts, x0Len)
	if opts.PhaseRecorder != nil {
		opts.PhaseRecorder.RecordDuration("issuance.rows", time.Since(rowsStart))
	}
	if err != nil {
		return nil, err
	}
	replayStart := phaseTimingStart(opts.PhaseRecorder)
	set, err := buildIntGenISISPreSignSourceOnlyConstraintShapeV3(ringQ, pub, layout, omegaWitness)
	if opts.PhaseRecorder != nil {
		opts.PhaseRecorder.RecordDuration("issuance.replay_preparation", time.Since(replayStart))
	}
	if err != nil {
		return nil, err
	}
	rho := opts.Rho
	if rho <= 0 {
		rho = 1
	}
	for i := 0; i < rho; i++ {
		rows = append(rows, ringQ.NewPoly())
		rowInputs = append(rowInputs, lvcs.RowInput{})
	}
	prepared := &preparedCredentialBuild{
		ringQ:                 ringQ,
		rows:                  rows,
		rowInputs:             rowInputs,
		rowLayout:             layout,
		decsParams:            decs.Params{},
		maskRowOffset:         layout.SigCount,
		witnessCount:          layout.SigCount,
		witnessNCols:          opts.NCols,
		omega:                 omega,
		omegaWitness:          omegaWitness,
		domainPoints:          domainPoints,
		preparedDomain:        preparedDomain,
		relationIdentity:      pub.HashRelation,
		strictRowProvenance:   true,
		skipConstraintRebuild: true,
	}
	opts.Credential = true
	return buildWithConstraintsPrepared(pub, wit, set, opts, FSModeCredential, prepared)
}

// buildIntGenISISPreSignSourceOnlyConstraintShapeV3 is the production strict-v3
// compiler surface. The semantic relation IR constructs Q directly, so the
// prover needs the exact family cardinalities and algebraic degrees but must
// not materialize 1,024 audit-only aggregate polynomials. The full formal
// builder remains below as an independent test/oracle implementation.
func buildIntGenISISPreSignSourceOnlyConstraintShapeV3(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil || len(omega) != intGenISISPreSignSourceNCols {
		return ConstraintSet{}, fmt.Errorf("invalid strict-v3 source-only constraint shape domain")
	}
	if err := validateIntGenISISPreSignSourceOnlyLayoutV3(ringQ, pub, layout, len(omega)); err != nil {
		return ConstraintSet{}, err
	}
	l := layout.IntGenISISPreSign
	policyRows, err := intGenISISPreSignSourceOnlyPolicyRowsV3(ringQ, pub, omega)
	if err != nil {
		return ConstraintSet{}, err
	}
	parallelSemantic := 1 + len(policyRows)
	parallelMembership := l.MCarrierCount + l.SCarrierCount + l.ECarrierCount + l.MSeedViewCount
	aggregate := l.CommitmentRows * int(ringQ.N)
	if aggregate <= 0 {
		return ConstraintSet{}, fmt.Errorf("invalid strict-v3 source-only aggregate family count %d", aggregate)
	}
	return ConstraintSet{
		FparInt:          make([]*ring.Poly, parallelSemantic),
		FparNorm:         make([]*ring.Poly, parallelMembership),
		FaggInt:          make([]*ring.Poly, aggregate),
		ParallelAlgDeg:   intGenISISPreSignSourceMembershipDeg,
		AggregatedAlgDeg: intGenISISPreSignSourceDecodeDegree,
	}, nil
}

type intGenISISPreSignSourceOnlyReplayConfig struct {
	Ring             *ring.Ring
	Layout           IntGenISISPreSignRowLayout
	DomainPoints     []uint64
	Omega            []uint64
	Basis            *transformBridgeBasisCache
	Compression      intGenISISMSECompressionSpec
	ReservedSelector []uint64
	PolicyRows       [][]uint64
	CM               [][]uint64
	AS               [][]uint64
	Com              [][]uint64
}

func intGenISISPreSignSourceOnlyPolicyRowsV3(ringQ *ring.Ring, pub PublicInputs, omega []uint64) ([][]uint64, error) {
	policy, err := intGenISISPolicyFromPublic(pub)
	if err != nil {
		return nil, err
	}
	semantic, err := intGenISISSemanticLayout(int(ringQ.N), pub.BoundB)
	if err != nil {
		return nil, err
	}
	rows, err := intGenISISPolicyCoeffViewCoeffs(ringQ, policy, semantic, omega, len(omega))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ordinary := (int(ringQ.N) - credential.IntGenISISPRFSeedTailReserve) / len(omega)
	want := int(ringQ.N) / len(omega)
	if len(rows) != want {
		return nil, fmt.Errorf("strict-v3 source-only policy rows=%d want %d", len(rows), want)
	}
	q := ringQ.Modulus[0]
	for i := ordinary; i < len(rows); i++ {
		for _, c := range rows[i] {
			if c%q != 0 {
				return nil, fmt.Errorf("strict-v3 source-only policy assigns nonzero data to reserved/seed tail row %d", i)
			}
		}
	}
	return rows[:ordinary], nil
}

func copyNTTLimbV3(p *ring.Poly, n int, q uint64, name string) ([]uint64, error) {
	if p == nil || len(p.Coeffs) == 0 || len(p.Coeffs[0]) < n {
		return nil, fmt.Errorf("invalid %s polynomial", name)
	}
	out := append([]uint64(nil), p.Coeffs[0][:n]...)
	for i := range out {
		out[i] %= q
	}
	return out, nil
}

func newIntGenISISPreSignSourceOnlyReplayConfigV3(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64) (*intGenISISPreSignSourceOnlyReplayConfig, error) {
	if ringQ == nil || len(omegaWitness) != intGenISISPreSignSourceNCols || len(domainPoints) == 0 {
		return nil, fmt.Errorf("invalid strict-v3 source-only replay domain")
	}
	if err := validateIntGenISISPreSignSourceOnlyLayoutV3(ringQ, pub, layout, len(omegaWitness)); err != nil {
		return nil, err
	}
	l := layout.IntGenISISPreSign
	compression, err := newIntGenISISMSECompressionSpecForBound(ringQ.Modulus[0], intGenISISPreSignSourceCompression, pub.BoundB)
	if err != nil {
		return nil, err
	}
	basis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, int(ringQ.N), l.ViewRowsPerPoly)
	if err != nil {
		return nil, fmt.Errorf("strict-v3 source-only transform basis: %w", err)
	}
	reserved := []uint64{0}
	for lane := 0; lane < credential.IntGenISISPRFSeedTailReserve-credential.IntGenISISPRFSeedLen; lane++ {
		reserved = polyAdd(reserved, basis.LagrangeBasis[lane], ringQ.Modulus[0])
	}
	policyRows, err := intGenISISPreSignSourceOnlyPolicyRowsV3(ringQ, pub, omegaWitness)
	if err != nil {
		return nil, err
	}
	cm := make([][]uint64, len(pub.CM))
	as := make([][]uint64, len(pub.AS))
	com := make([][]uint64, len(pub.Com))
	for out := range pub.Com {
		cm[out], err = copyNTTLimbV3(pub.CM[out][0], int(ringQ.N), ringQ.Modulus[0], fmt.Sprintf("C_M[%d][0]", out))
		if err != nil {
			return nil, err
		}
		as[out], err = copyNTTLimbV3(pub.AS[out][0], int(ringQ.N), ringQ.Modulus[0], fmt.Sprintf("A_s[%d][0]", out))
		if err != nil {
			return nil, err
		}
		com[out], err = copyNTTLimbV3(pub.Com[out], int(ringQ.N), ringQ.Modulus[0], fmt.Sprintf("Com[%d]", out))
		if err != nil {
			return nil, err
		}
	}
	return &intGenISISPreSignSourceOnlyReplayConfig{
		Ring:             ringQ,
		Layout:           *l,
		DomainPoints:     append([]uint64(nil), domainPoints...),
		Omega:            append([]uint64(nil), omegaWitness...),
		Basis:            basis,
		Compression:      compression,
		ReservedSelector: reserved,
		PolicyRows:       policyRows,
		CM:               cm,
		AS:               as,
		Com:              com,
	}, nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) sourceValueF(rows []uint64, start, sourceCount, source int) (uint64, error) {
	if source < 0 || source >= sourceCount {
		return 0, fmt.Errorf("source %d outside count %d", source, sourceCount)
	}
	idx := start + source/cfg.Layout.MSECompressionPackWidth
	if idx < 0 || idx >= len(rows) {
		return 0, fmt.Errorf("source carrier row %d outside rows=%d", idx, len(rows))
	}
	lane := source % cfg.Layout.MSECompressionPackWidth
	return EvalPoly(cfg.Compression.DecodePolys[lane], rows[idx]%cfg.Ring.Modulus[0], cfg.Ring.Modulus[0]), nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) transformF(x uint64, t int, rows []uint64, kind byte) (uint64, error) {
	q := cfg.Ring.Modulus[0]
	blocks := cfg.Layout.ViewRowsPerPoly
	sum := uint64(0)
	for block := 0; block < blocks; block++ {
		var value uint64
		var err error
		switch kind {
		case 'm':
			if block < cfg.Layout.MCompressedSourceRows {
				value, err = cfg.sourceValueF(rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, block)
			} else {
				idx := cfg.Layout.MSeedViewStart + block - cfg.Layout.MCompressedSourceRows
				if idx < 0 || idx >= len(rows) {
					return 0, fmt.Errorf("M tail row %d outside rows=%d", idx, len(rows))
				}
				value = rows[idx] % q
			}
		case 's':
			value, err = cfg.sourceValueF(rows, cfg.Layout.SCarrierStart, cfg.Layout.SCompressedSourceRows, block)
		case 'e':
			value, err = cfg.sourceValueF(rows, cfg.Layout.ECarrierStart, cfg.Layout.ECompressedSourceRows, block)
		default:
			return 0, fmt.Errorf("unknown source kind %q", kind)
		}
		if err != nil {
			return 0, err
		}
		sum = modAdd(sum, modMul(cfg.Basis.BlockFactors[t][block], value, q), q)
	}
	return modMul(EvalPoly(cfg.Basis.TransformH[t], x, q), sum, q), nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) CoreEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil strict-v3 source-only replay config")
		}
		if int(evalIdx) >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("strict-v3 source-only eval index %d outside domain", evalIdx)
		}
		if len(rows) < cfg.Layout.WitnessRows() {
			return nil, nil, fmt.Errorf("strict-v3 source-only rows=%d want at least %d", len(rows), cfg.Layout.WitnessRows())
		}
		q := cfg.Ring.Modulus[0]
		x := cfg.DomainPoints[int(evalIdx)] % q
		fpar := make([]uint64, 0, 1+len(cfg.PolicyRows)+cfg.Layout.MCarrierCount+cfg.Layout.SCarrierCount+cfg.Layout.ECarrierCount+cfg.Layout.MSeedViewCount)
		reserved := EvalPoly(cfg.ReservedSelector, x, q)
		fpar = append(fpar, modMul(reserved, rows[cfg.Layout.MSeedViewStart]%q, q))
		for i := range cfg.PolicyRows {
			m, err := cfg.sourceValueF(rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, i)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, modSub(m, EvalPoly(cfg.PolicyRows[i], x, q), q))
		}
		for _, segment := range []struct{ start, count int }{{cfg.Layout.MCarrierStart, cfg.Layout.MCarrierCount}, {cfg.Layout.SCarrierStart, cfg.Layout.SCarrierCount}, {cfg.Layout.ECarrierStart, cfg.Layout.ECarrierCount}} {
			for i := 0; i < segment.count; i++ {
				fpar = append(fpar, intGenISISEvalMembership(q, cfg.Compression.MembershipPoly, rows[segment.start+i]%q))
			}
		}
		seedSpec := NewRangeMembershipSpec(q, int(intGenISISSeedBound)).Coeffs
		for i := 0; i < cfg.Layout.MSeedViewCount; i++ {
			fpar = append(fpar, intGenISISEvalMembership(q, seedSpec, rows[cfg.Layout.MSeedViewStart+i]%q))
		}
		fagg := make([]uint64, 0, cfg.Layout.CommitmentRows*int(cfg.Ring.N))
		for out := 0; out < cfg.Layout.CommitmentRows; out++ {
			for t := 0; t < int(cfg.Ring.N); t++ {
				m, err := cfg.transformF(x, t, rows, 'm')
				if err != nil {
					return nil, nil, err
				}
				s, err := cfg.transformF(x, t, rows, 's')
				if err != nil {
					return nil, nil, err
				}
				e, err := cfg.transformF(x, t, rows, 'e')
				if err != nil {
					return nil, nil, err
				}
				v := modAdd(modMul(cfg.CM[out][t], m, q), modMul(cfg.AS[out][t], s, q), q)
				v = modAdd(v, e, q)
				selector := EvalPoly(cfg.Basis.LagrangeBasis[t%len(cfg.Omega)], x, q)
				v = modSub(v, modMul(selector, cfg.Com[out][t], q), q)
				fagg = append(fagg, v)
			}
		}
		return fpar, fagg, nil
	}
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) sourceValueK(K *kf.Field, rows []kf.Elem, start, sourceCount, source int) (kf.Elem, error) {
	if source < 0 || source >= sourceCount {
		return K.Zero(), fmt.Errorf("source %d outside count %d", source, sourceCount)
	}
	idx := start + source/cfg.Layout.MSECompressionPackWidth
	if idx < 0 || idx >= len(rows) {
		return K.Zero(), fmt.Errorf("source carrier row %d outside rows=%d", idx, len(rows))
	}
	lane := source % cfg.Layout.MSECompressionPackWidth
	return K.EvalFPolyAtK(cfg.Compression.DecodePolys[lane], rows[idx]), nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) sourceValueKInto(K *kf.Field, dst *kf.Elem, rows []kf.Elem, start, sourceCount, source int) error {
	if source < 0 || source >= sourceCount {
		return fmt.Errorf("source %d outside count %d", source, sourceCount)
	}
	idx := start + source/cfg.Layout.MSECompressionPackWidth
	if idx < 0 || idx >= len(rows) {
		return fmt.Errorf("source carrier row %d outside rows=%d", idx, len(rows))
	}
	lane := source % cfg.Layout.MSECompressionPackWidth
	K.EvalFPolyAtKInto(dst, cfg.Compression.DecodePolys[lane], rows[idx])
	return nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) transformK(K *kf.Field, e kf.Elem, t int, rows []kf.Elem, kind byte) (kf.Elem, error) {
	blocks := cfg.Layout.ViewRowsPerPoly
	sum := K.Zero()
	for block := 0; block < blocks; block++ {
		var value kf.Elem
		var err error
		switch kind {
		case 'm':
			if block < cfg.Layout.MCompressedSourceRows {
				value, err = cfg.sourceValueK(K, rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, block)
			} else {
				idx := cfg.Layout.MSeedViewStart + block - cfg.Layout.MCompressedSourceRows
				if idx < 0 || idx >= len(rows) {
					return K.Zero(), fmt.Errorf("M tail row %d outside rows=%d", idx, len(rows))
				}
				value = rows[idx]
			}
		case 's':
			value, err = cfg.sourceValueK(K, rows, cfg.Layout.SCarrierStart, cfg.Layout.SCompressedSourceRows, block)
		case 'e':
			value, err = cfg.sourceValueK(K, rows, cfg.Layout.ECarrierStart, cfg.Layout.ECompressedSourceRows, block)
		default:
			return K.Zero(), fmt.Errorf("unknown source kind %q", kind)
		}
		if err != nil {
			return K.Zero(), err
		}
		K.AddMulBaseInto(&sum, value, cfg.Basis.BlockFactors[t][block]%K.Q)
	}
	return K.Mul(K.EvalFPolyAtK(cfg.Basis.TransformH[t], e), sum), nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) evalParallelK(K *kf.Field, e kf.Elem, rows []kf.Elem) ([]kf.Elem, error) {
	if cfg == nil || cfg.Ring == nil || K == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only K replay config")
	}
	if len(rows) < cfg.Layout.WitnessRows() {
		return nil, fmt.Errorf("strict-v3 source-only K rows=%d want at least %d", len(rows), cfg.Layout.WitnessRows())
	}
	fpar := make([]kf.Elem, 0, 1+len(cfg.PolicyRows)+cfg.Layout.MCarrierCount+cfg.Layout.SCarrierCount+cfg.Layout.ECarrierCount+cfg.Layout.MSeedViewCount)
	reserved := K.EvalFPolyAtK(cfg.ReservedSelector, e)
	fpar = append(fpar, K.Mul(reserved, rows[cfg.Layout.MSeedViewStart]))
	for i := range cfg.PolicyRows {
		m, err := cfg.sourceValueK(K, rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, i)
		if err != nil {
			return nil, err
		}
		fpar = append(fpar, K.Sub(m, K.EvalFPolyAtK(cfg.PolicyRows[i], e)))
	}
	for _, segment := range []struct{ start, count int }{{cfg.Layout.MCarrierStart, cfg.Layout.MCarrierCount}, {cfg.Layout.SCarrierStart, cfg.Layout.SCarrierCount}, {cfg.Layout.ECarrierStart, cfg.Layout.ECarrierCount}} {
		for i := 0; i < segment.count; i++ {
			fpar = append(fpar, intGenISISEvalKPolyAtElem(K, cfg.Compression.MembershipPoly, rows[segment.start+i]))
		}
	}
	seedSpec := NewRangeMembershipSpec(K.Q, int(intGenISISSeedBound)).Coeffs
	for i := 0; i < cfg.Layout.MSeedViewCount; i++ {
		fpar = append(fpar, intGenISISEvalKPolyAtElem(K, seedSpec, rows[cfg.Layout.MSeedViewStart+i]))
	}
	return fpar, nil
}

type intGenISISPreSignParallelKScratchV3 struct {
	temps []kf.Elem
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) parallelConstraintCountK() int {
	if cfg == nil {
		return 0
	}
	return 1 + len(cfg.PolicyRows) + cfg.Layout.MCarrierCount + cfg.Layout.SCarrierCount + cfg.Layout.ECarrierCount + cfg.Layout.MSeedViewCount
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) evalParallelKInto(K *kf.Field, e kf.Elem, rows, dst []kf.Elem, scratch *intGenISISPreSignParallelKScratchV3) error {
	if cfg == nil || cfg.Ring == nil || K == nil || scratch == nil || len(scratch.temps) < 3 {
		return fmt.Errorf("nil strict-v3 source-only K Into replay context")
	}
	if len(rows) < cfg.Layout.WitnessRows() {
		return fmt.Errorf("strict-v3 source-only K rows=%d want at least %d", len(rows), cfg.Layout.WitnessRows())
	}
	want := cfg.parallelConstraintCountK()
	if len(dst) != want {
		return fmt.Errorf("strict-v3 source-only K parallel destination=%d want %d", len(dst), want)
	}
	pos := 0
	K.EvalFPolyAtKInto(&scratch.temps[0], cfg.ReservedSelector, e)
	K.MulInto(&dst[pos], scratch.temps[0], rows[cfg.Layout.MSeedViewStart])
	pos++
	for i := range cfg.PolicyRows {
		if err := cfg.sourceValueKInto(K, &scratch.temps[0], rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, i); err != nil {
			return err
		}
		K.EvalFPolyAtKInto(&scratch.temps[1], cfg.PolicyRows[i], e)
		K.SubInto(&dst[pos], scratch.temps[0], scratch.temps[1])
		pos++
	}
	for _, segment := range []struct{ start, count int }{{cfg.Layout.MCarrierStart, cfg.Layout.MCarrierCount}, {cfg.Layout.SCarrierStart, cfg.Layout.SCarrierCount}, {cfg.Layout.ECarrierStart, cfg.Layout.ECarrierCount}} {
		for i := 0; i < segment.count; i++ {
			K.EvalFPolyAtKInto(&dst[pos], cfg.Compression.MembershipPoly, rows[segment.start+i])
			pos++
		}
	}
	seedSpec := NewRangeMembershipSpec(K.Q, int(intGenISISSeedBound)).Coeffs
	for i := 0; i < cfg.Layout.MSeedViewCount; i++ {
		K.EvalFPolyAtKInto(&dst[pos], seedSpec, rows[cfg.Layout.MSeedViewStart+i])
		pos++
	}
	if pos != want {
		return fmt.Errorf("strict-v3 source-only K parallel output=%d want %d", pos, want)
	}
	return nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) ParallelKIntoEvaluatorV3(K *kf.Field) (*semanticKConstraintIntoV3, error) {
	if cfg == nil || cfg.Ring == nil || K == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only K Into replay config")
	}
	count := cfg.parallelConstraintCountK()
	return &semanticKConstraintIntoV3{
		ParallelCount: count,
		NewScratch: func() any {
			return &intGenISISPreSignParallelKScratchV3{temps: makeKElementBuffer(3, K.Theta)}
		},
		EvalInto: func(e kf.Elem, rows, fpar, fagg []kf.Elem, raw any) error {
			if len(fagg) != 0 {
				return fmt.Errorf("strict-v3 source-only K parallel aggregate destination must be empty")
			}
			scratch, ok := raw.(*intGenISISPreSignParallelKScratchV3)
			if !ok {
				return fmt.Errorf("strict-v3 source-only K parallel scratch type %T", raw)
			}
			return cfg.evalParallelKInto(K, e, rows, fpar, scratch)
		},
	}, nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) ParallelKEvaluator(K *kf.Field) (KParallelConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil || K == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only K replay config")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, error) {
		return cfg.evalParallelK(K, e, rows)
	}, nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil || K == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only K replay config")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		fpar, err := cfg.evalParallelK(K, e, rows)
		if err != nil {
			return nil, nil, err
		}
		fagg := make([]kf.Elem, 0, cfg.Layout.CommitmentRows*int(cfg.Ring.N))
		for out := 0; out < cfg.Layout.CommitmentRows; out++ {
			for t := 0; t < int(cfg.Ring.N); t++ {
				m, err := cfg.transformK(K, e, t, rows, 'm')
				if err != nil {
					return nil, nil, err
				}
				s, err := cfg.transformK(K, e, t, rows, 's')
				if err != nil {
					return nil, nil, err
				}
				errVal, err := cfg.transformK(K, e, t, rows, 'e')
				if err != nil {
					return nil, nil, err
				}
				v := K.Zero()
				K.AddMulBaseInto(&v, m, cfg.CM[out][t])
				K.AddMulBaseInto(&v, s, cfg.AS[out][t])
				v = K.Add(v, errVal)
				selector := K.EvalFPolyAtK(cfg.Basis.LagrangeBasis[t%len(cfg.Omega)], e)
				v = K.Sub(v, K.Mul(selector, K.EmbedF(cfg.Com[out][t])))
				fagg = append(fagg, v)
			}
		}
		return fpar, fagg, nil
	}, nil
}

// intGenISISPreSignWeightedKPolyV3 is a polynomial in X with coefficients in
// K, stored limb-wise. Its degree is at most |Omega|-1. It is compiled only
// from the public transform matrices and the Fiat--Shamir aggregate challenge.
type intGenISISPreSignWeightedKPolyV3 struct {
	Limbs [][]uint64
}

type intGenISISPreSignAggregateDotPlanV3 struct {
	K      *kf.Field
	Config *intGenISISPreSignSourceOnlyReplayConfig
	M      []intGenISISPreSignWeightedKPolyV3
	S      []intGenISISPreSignWeightedKPolyV3
	E      []intGenISISPreSignWeightedKPolyV3
	Public intGenISISPreSignWeightedKPolyV3
}

func newIntGenISISPreSignWeightedKPolyV3(theta, degree int) intGenISISPreSignWeightedKPolyV3 {
	out := intGenISISPreSignWeightedKPolyV3{Limbs: make([][]uint64, theta)}
	for limb := range out.Limbs {
		out.Limbs[limb] = make([]uint64, degree+1)
	}
	return out
}

func addGammaScaledBasePolyV3(K *kf.Field, dst *intGenISISPreSignWeightedKPolyV3, gamma KScalar, basePoly []uint64, scalar uint64) {
	if K == nil || dst == nil || scalar%K.Q == 0 {
		return
	}
	scalar %= K.Q
	for limb := 0; limb < K.Theta && limb < len(gamma); limb++ {
		g := gamma[limb] % K.Q
		if g == 0 {
			continue
		}
		gs := modMul(g, scalar, K.Q)
		for degree, coeff := range basePoly {
			if degree >= len(dst.Limbs[limb]) || coeff%K.Q == 0 {
				continue
			}
			dst.Limbs[limb][degree] = modAdd(dst.Limbs[limb][degree], modMul(gs, coeff%K.Q, K.Q), K.Q)
		}
	}
}

func evalIntGenISISPreSignWeightedKPolyV3(K *kf.Field, poly intGenISISPreSignWeightedKPolyV3, e kf.Elem) kf.Elem {
	if x, embedded := embeddedFqValueV3(K, e); embedded {
		out := K.Zero()
		for limb := 0; limb < K.Theta && limb < len(poly.Limbs); limb++ {
			out.Limb[limb] = EvalPoly(poly.Limbs[limb], x, K.Q)
		}
		return out
	}
	out := K.Zero()
	coeff := K.Zero()
	degree := -1
	for limb := range poly.Limbs {
		if len(poly.Limbs[limb])-1 > degree {
			degree = len(poly.Limbs[limb]) - 1
		}
	}
	for d := degree; d >= 0; d-- {
		K.MulInto(&out, out, e)
		clear(coeff.Limb)
		for limb := 0; limb < K.Theta && limb < len(poly.Limbs); limb++ {
			if d < len(poly.Limbs[limb]) {
				coeff.Limb[limb] = poly.Limbs[limb][d] % K.Q
			}
		}
		K.AddInto(&out, out, coeff)
	}
	return out
}

func evalIntGenISISPreSignWeightedKPolyIntoV3(K *kf.Field, dst *kf.Elem, poly intGenISISPreSignWeightedKPolyV3, e kf.Elem, coeff *kf.Elem) {
	if x, embedded := embeddedFqValueV3(K, e); embedded {
		K.ZeroInto(dst)
		for limb := 0; limb < K.Theta && limb < len(poly.Limbs); limb++ {
			dst.Limb[limb] = EvalPoly(poly.Limbs[limb], x, K.Q)
		}
		return
	}
	K.ZeroInto(dst)
	degree := -1
	for limb := range poly.Limbs {
		if len(poly.Limbs[limb])-1 > degree {
			degree = len(poly.Limbs[limb]) - 1
		}
	}
	for d := degree; d >= 0; d-- {
		K.MulInto(dst, *dst, e)
		K.ZeroInto(coeff)
		for limb := 0; limb < K.Theta && limb < len(poly.Limbs); limb++ {
			if d < len(poly.Limbs[limb]) {
				coeff.Limb[limb] = poly.Limbs[limb][d] % K.Q
			}
		}
		K.AddInto(dst, *dst, *coeff)
	}
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) AggregateConstraintCount() int {
	if cfg == nil || cfg.Ring == nil {
		return 0
	}
	return cfg.Layout.CommitmentRows * int(cfg.Ring.N)
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) newAggregateDotPlanK(K *kf.Field, gamma []KScalar, requestedWorkers ...int) (*intGenISISPreSignAggregateDotPlanV3, error) {
	if cfg == nil || cfg.Ring == nil || cfg.Basis == nil || K == nil || K.Q != cfg.Ring.Modulus[0] {
		return nil, fmt.Errorf("invalid strict-v3 source-only aggregate-dot context")
	}
	if len(gamma) != cfg.AggregateConstraintCount() {
		return nil, fmt.Errorf("strict-v3 source-only aggregate gamma width=%d want %d", len(gamma), cfg.AggregateConstraintCount())
	}
	degree := len(cfg.Omega) - 1
	plan := &intGenISISPreSignAggregateDotPlanV3{
		K:      K,
		Config: cfg,
		M:      make([]intGenISISPreSignWeightedKPolyV3, cfg.Layout.ViewRowsPerPoly),
		S:      make([]intGenISISPreSignWeightedKPolyV3, cfg.Layout.ViewRowsPerPoly),
		E:      make([]intGenISISPreSignWeightedKPolyV3, cfg.Layout.ViewRowsPerPoly),
		Public: newIntGenISISPreSignWeightedKPolyV3(K.Theta, degree),
	}
	for block := 0; block < cfg.Layout.ViewRowsPerPoly; block++ {
		plan.M[block] = newIntGenISISPreSignWeightedKPolyV3(K.Theta, degree)
		plan.S[block] = newIntGenISISPreSignWeightedKPolyV3(K.Theta, degree)
		plan.E[block] = newIntGenISISPreSignWeightedKPolyV3(K.Theta, degree)
	}
	for index, challenge := range gamma {
		if len(challenge) != K.Theta {
			return nil, fmt.Errorf("strict-v3 source-only aggregate gamma[%d] limbs=%d want %d", index, len(challenge), K.Theta)
		}
	}
	workers := 1
	if len(requestedWorkers) > 1 {
		return nil, fmt.Errorf("strict-v3 source-only aggregate received multiple worker counts")
	}
	if len(requestedWorkers) == 1 && requestedWorkers[0] > 1 {
		workers = requestedWorkers[0]
	}
	type aggregatePlanJob struct {
		block  int
		limb   int
		public bool
	}
	jobs := make([]aggregatePlanJob, 0, (cfg.Layout.ViewRowsPerPoly+1)*K.Theta)
	for block := 0; block < cfg.Layout.ViewRowsPerPoly; block++ {
		for limb := 0; limb < K.Theta; limb++ {
			jobs = append(jobs, aggregatePlanJob{block: block, limb: limb})
		}
	}
	for limb := 0; limb < K.Theta; limb++ {
		jobs = append(jobs, aggregatePlanJob{limb: limb, public: true})
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	red := lvcs.NewReducer64(K.Q)
	runJob := func(job aggregatePlanJob) {
		if job.public {
			cfg.fillAggregatePublicLimbV3(plan.Public.Limbs[job.limb], gamma, job.limb, red)
			return
		}
		cfg.fillAggregateSourceLimbV3(plan.M[job.block].Limbs[job.limb], plan.S[job.block].Limbs[job.limb], plan.E[job.block].Limbs[job.limb], gamma, job.block, job.limb, red)
	}
	if workers <= 1 {
		for _, job := range jobs {
			runJob(job)
		}
		return plan, nil
	}
	queue := make(chan aggregatePlanJob)
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for job := range queue {
				runJob(job)
			}
		}()
	}
	for _, job := range jobs {
		queue <- job
	}
	close(queue)
	wg.Wait()
	return plan, nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) fillAggregateSourceLimbV3(mDst, sDst, eDst []uint64, gamma []KScalar, block, limb int, red lvcs.Reducer64) {
	q := cfg.Ring.Modulus[0]
	for out := 0; out < cfg.Layout.CommitmentRows; out++ {
		for t := 0; t < int(cfg.Ring.N); t++ {
			g := gamma[out*int(cfg.Ring.N)+t][limb] % q
			if g == 0 {
				continue
			}
			factor := red.Reduce(cfg.Basis.BlockFactors[t][block])
			gf := red.MulReduce(g, factor)
			mScale := red.MulReduce(gf, red.Reduce(cfg.CM[out][t]))
			sScale := red.MulReduce(gf, red.Reduce(cfg.AS[out][t]))
			for degree, coefficient := range cfg.Basis.TransformH[t] {
				coefficient = red.Reduce(coefficient)
				if coefficient == 0 {
					continue
				}
				mDst[degree] = modAddReduced(mDst[degree], red.MulReduce(mScale, coefficient), q)
				sDst[degree] = modAddReduced(sDst[degree], red.MulReduce(sScale, coefficient), q)
				eDst[degree] = modAddReduced(eDst[degree], red.MulReduce(gf, coefficient), q)
			}
		}
	}
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) fillAggregatePublicLimbV3(dst []uint64, gamma []KScalar, limb int, red lvcs.Reducer64) {
	q := cfg.Ring.Modulus[0]
	for out := 0; out < cfg.Layout.CommitmentRows; out++ {
		for t := 0; t < int(cfg.Ring.N); t++ {
			g := gamma[out*int(cfg.Ring.N)+t][limb] % q
			scale := red.MulReduce(g, red.Reduce(cfg.Com[out][t]))
			if scale == 0 {
				continue
			}
			for degree, coefficient := range cfg.Basis.LagrangeBasis[t%len(cfg.Omega)] {
				coefficient = red.Reduce(coefficient)
				if coefficient != 0 {
					dst[degree] = modAddReduced(dst[degree], red.MulReduce(scale, coefficient), q)
				}
			}
		}
	}
}

func (plan *intGenISISPreSignAggregateDotPlanV3) sourceValuesK(rows []kf.Elem, kind byte) ([]kf.Elem, error) {
	if plan == nil || plan.K == nil || plan.Config == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only aggregate-dot plan")
	}
	cfg := plan.Config
	values := make([]kf.Elem, cfg.Layout.ViewRowsPerPoly)
	for block := range values {
		var err error
		switch kind {
		case 'm':
			if block < cfg.Layout.MCompressedSourceRows {
				values[block], err = cfg.sourceValueK(plan.K, rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, block)
			} else {
				idx := cfg.Layout.MSeedViewStart + block - cfg.Layout.MCompressedSourceRows
				if idx < 0 || idx >= len(rows) {
					return nil, fmt.Errorf("M tail row %d outside rows=%d", idx, len(rows))
				}
				values[block] = rows[idx]
			}
		case 's':
			values[block], err = cfg.sourceValueK(plan.K, rows, cfg.Layout.SCarrierStart, cfg.Layout.SCompressedSourceRows, block)
		case 'e':
			values[block], err = cfg.sourceValueK(plan.K, rows, cfg.Layout.ECarrierStart, cfg.Layout.ECompressedSourceRows, block)
		default:
			return nil, fmt.Errorf("unknown source kind %q", kind)
		}
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (plan *intGenISISPreSignAggregateDotPlanV3) sourceValuesKInto(values []kf.Elem, rows []kf.Elem, kind byte) error {
	if plan == nil || plan.K == nil || plan.Config == nil {
		return fmt.Errorf("nil strict-v3 source-only aggregate-dot plan")
	}
	cfg := plan.Config
	if len(values) != cfg.Layout.ViewRowsPerPoly {
		return fmt.Errorf("strict-v3 source-only aggregate source destination=%d want %d", len(values), cfg.Layout.ViewRowsPerPoly)
	}
	for block := range values {
		var err error
		switch kind {
		case 'm':
			if block < cfg.Layout.MCompressedSourceRows {
				err = cfg.sourceValueKInto(plan.K, &values[block], rows, cfg.Layout.MCarrierStart, cfg.Layout.MCompressedSourceRows, block)
			} else {
				idx := cfg.Layout.MSeedViewStart + block - cfg.Layout.MCompressedSourceRows
				if idx < 0 || idx >= len(rows) {
					return fmt.Errorf("M tail row %d outside rows=%d", idx, len(rows))
				}
				plan.K.SetInto(&values[block], rows[idx])
			}
		case 's':
			err = cfg.sourceValueKInto(plan.K, &values[block], rows, cfg.Layout.SCarrierStart, cfg.Layout.SCompressedSourceRows, block)
		case 'e':
			err = cfg.sourceValueKInto(plan.K, &values[block], rows, cfg.Layout.ECarrierStart, cfg.Layout.ECompressedSourceRows, block)
		default:
			return fmt.Errorf("unknown source kind %q", kind)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type intGenISISPreSignAggregateDotScratchV3 struct {
	m, s, e []kf.Elem
	weight  kf.Elem
	term    kf.Elem
	coeff   kf.Elem
	public  kf.Elem
}

func newIntGenISISPreSignAggregateDotScratchV3(K *kf.Field, blocks int) *intGenISISPreSignAggregateDotScratchV3 {
	values := makeKElementBuffer(3*blocks+4, K.Theta)
	return &intGenISISPreSignAggregateDotScratchV3{
		m: values[:blocks], s: values[blocks : 2*blocks], e: values[2*blocks : 3*blocks],
		weight: values[3*blocks], term: values[3*blocks+1], coeff: values[3*blocks+2], public: values[3*blocks+3],
	}
}

func (plan *intGenISISPreSignAggregateDotPlanV3) EvalInto(dst *kf.Elem, e kf.Elem, rows []kf.Elem, scratch *intGenISISPreSignAggregateDotScratchV3) error {
	if plan == nil || plan.K == nil || plan.Config == nil || scratch == nil {
		return fmt.Errorf("nil strict-v3 source-only aggregate-dot Into plan")
	}
	if len(rows) < plan.Config.Layout.WitnessRows() {
		return fmt.Errorf("strict-v3 source-only aggregate-dot rows=%d want at least %d", len(rows), plan.Config.Layout.WitnessRows())
	}
	if err := plan.sourceValuesKInto(scratch.m, rows, 'm'); err != nil {
		return err
	}
	if err := plan.sourceValuesKInto(scratch.s, rows, 's'); err != nil {
		return err
	}
	if err := plan.sourceValuesKInto(scratch.e, rows, 'e'); err != nil {
		return err
	}
	plan.K.ZeroInto(dst)
	for block := 0; block < plan.Config.Layout.ViewRowsPerPoly; block++ {
		evalIntGenISISPreSignWeightedKPolyIntoV3(plan.K, &scratch.weight, plan.M[block], e, &scratch.coeff)
		plan.K.MulInto(&scratch.term, scratch.weight, scratch.m[block])
		plan.K.AddInto(dst, *dst, scratch.term)
		evalIntGenISISPreSignWeightedKPolyIntoV3(plan.K, &scratch.weight, plan.S[block], e, &scratch.coeff)
		plan.K.MulInto(&scratch.term, scratch.weight, scratch.s[block])
		plan.K.AddInto(dst, *dst, scratch.term)
		evalIntGenISISPreSignWeightedKPolyIntoV3(plan.K, &scratch.weight, plan.E[block], e, &scratch.coeff)
		plan.K.MulInto(&scratch.term, scratch.weight, scratch.e[block])
		plan.K.AddInto(dst, *dst, scratch.term)
	}
	evalIntGenISISPreSignWeightedKPolyIntoV3(plan.K, &scratch.public, plan.Public, e, &scratch.coeff)
	plan.K.SubInto(dst, *dst, scratch.public)
	return nil
}

func (plan *intGenISISPreSignAggregateDotPlanV3) Eval(e kf.Elem, rows []kf.Elem) (kf.Elem, error) {
	if plan == nil || plan.K == nil || plan.Config == nil {
		return kf.Elem{}, fmt.Errorf("nil strict-v3 source-only aggregate-dot plan")
	}
	if len(rows) < plan.Config.Layout.WitnessRows() {
		return kf.Elem{}, fmt.Errorf("strict-v3 source-only aggregate-dot rows=%d want at least %d", len(rows), plan.Config.Layout.WitnessRows())
	}
	m, err := plan.sourceValuesK(rows, 'm')
	if err != nil {
		return kf.Elem{}, err
	}
	s, err := plan.sourceValuesK(rows, 's')
	if err != nil {
		return kf.Elem{}, err
	}
	errValues, err := plan.sourceValuesK(rows, 'e')
	if err != nil {
		return kf.Elem{}, err
	}
	result := plan.K.Zero()
	term := plan.K.Zero()
	for block := 0; block < plan.Config.Layout.ViewRowsPerPoly; block++ {
		weight := evalIntGenISISPreSignWeightedKPolyV3(plan.K, plan.M[block], e)
		plan.K.MulInto(&term, weight, m[block])
		plan.K.AddInto(&result, result, term)
		weight = evalIntGenISISPreSignWeightedKPolyV3(plan.K, plan.S[block], e)
		plan.K.MulInto(&term, weight, s[block])
		plan.K.AddInto(&result, result, term)
		weight = evalIntGenISISPreSignWeightedKPolyV3(plan.K, plan.E[block], e)
		plan.K.MulInto(&term, weight, errValues[block])
		plan.K.AddInto(&result, result, term)
	}
	public := evalIntGenISISPreSignWeightedKPolyV3(plan.K, plan.Public, e)
	plan.K.SubInto(&result, result, public)
	return result, nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) AggregateDotFactoryK(K *kf.Field, execution ...ExecutionPolicy) (KAggregateDotFactory, error) {
	if cfg == nil || cfg.Ring == nil || K == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only aggregate-dot config")
	}
	if len(execution) > 1 {
		return nil, fmt.Errorf("multiple execution policies supplied")
	}
	workers := 1
	if len(execution) == 1 {
		if err := execution[0].Validate(); err != nil {
			return nil, err
		}
		workers = execution[0].issuancePlanWorkerCount()
	}
	return func(gamma []KScalar) (KAggregateDotEvaluator, error) {
		plan, err := cfg.newAggregateDotPlanK(K, gamma, workers)
		if err != nil {
			return nil, err
		}
		return plan.Eval, nil
	}, nil
}

func (cfg *intGenISISPreSignSourceOnlyReplayConfig) AggregateDotIntoFactoryK(K *kf.Field, execution ...ExecutionPolicy) (semanticKAggregateDotFactoryIntoV3, error) {
	if cfg == nil || cfg.Ring == nil || K == nil {
		return nil, fmt.Errorf("nil strict-v3 source-only aggregate-dot Into config")
	}
	if len(execution) > 1 {
		return nil, fmt.Errorf("multiple execution policies supplied")
	}
	workers := 1
	if len(execution) == 1 {
		if err := execution[0].Validate(); err != nil {
			return nil, err
		}
		workers = execution[0].issuancePlanWorkerCount()
	}
	return func(gamma []KScalar) (*semanticKAggregateDotIntoV3, error) {
		plan, err := cfg.newAggregateDotPlanK(K, gamma, workers)
		if err != nil {
			return nil, err
		}
		return &semanticKAggregateDotIntoV3{
			NewScratch: func() any {
				return newIntGenISISPreSignAggregateDotScratchV3(K, cfg.Layout.ViewRowsPerPoly)
			},
			EvalInto: func(dst *kf.Elem, e kf.Elem, rows []kf.Elem, raw any) error {
				scratch, ok := raw.(*intGenISISPreSignAggregateDotScratchV3)
				if !ok {
					return fmt.Errorf("strict-v3 source-only aggregate-dot scratch type %T", raw)
				}
				return plan.EvalInto(dst, e, rows, scratch)
			},
		}, nil
	}, nil
}

func sourceOnlyRowCoeffV3(ringQ *ring.Ring, rowsNTT []*ring.Poly, idx int) ([]uint64, error) {
	if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
		return nil, fmt.Errorf("invalid strict-v3 source-only row index %d", idx)
	}
	coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
	if err != nil {
		return nil, err
	}
	return trimPoly(coeff, ringQ.Modulus[0]), nil
}

func sourceOnlyTransformFormalV3(ringQ *ring.Ring, basis *transformBridgeBasisCache, sources [][]uint64, t int) []uint64 {
	q := ringQ.Modulus[0]
	out := []uint64{0}
	for block := range sources {
		term := reducePolyModXN1(polyMul(basis.TransformH[t], sources[block], q), int(ringQ.N), q)
		if scale := basis.BlockFactors[t][block] % q; scale != 1 {
			term = scalePoly(term, scale, q)
		}
		out = polyAdd(out, term, q)
	}
	return reducePolyModXN1(out, int(ringQ.N), q)
}

func buildIntGenISISPreSignSourceOnlyConstraintSetV3(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil || len(omega) != intGenISISPreSignSourceNCols {
		return ConstraintSet{}, fmt.Errorf("invalid strict-v3 source-only formal domain")
	}
	if err := validateIntGenISISPreSignSourceOnlyLayoutV3(ringQ, pub, layout, len(omega)); err != nil {
		return ConstraintSet{}, err
	}
	l := layout.IntGenISISPreSign
	if len(rowsNTT) < l.WitnessRows() {
		return ConstraintSet{}, fmt.Errorf("strict-v3 source-only formal rows=%d want at least %d", len(rowsNTT), l.WitnessRows())
	}
	q := ringQ.Modulus[0]
	compression, err := newIntGenISISMSECompressionSpecForBound(q, intGenISISPreSignSourceCompression, pub.BoundB)
	if err != nil {
		return ConstraintSet{}, err
	}
	basis, err := newTransformBridgeBasisCache(ringQ, omega, int(ringQ.N), l.ViewRowsPerPoly)
	if err != nil {
		return ConstraintSet{}, err
	}
	mSources, err := intGenISISCompressedSourceFormalCoeffs(ringQ, rowsNTT, l.MCarrierStart, l.MCompressedSourceRows, l.MSECompressionPackWidth, compression.DecodePolys, "pre-sign M")
	if err != nil {
		return ConstraintSet{}, err
	}
	for i := 0; i < l.MSeedViewCount; i++ {
		coeff, err := sourceOnlyRowCoeffV3(ringQ, rowsNTT, l.MSeedViewStart+i)
		if err != nil {
			return ConstraintSet{}, err
		}
		mSources = append(mSources, coeff)
	}
	sSources, err := intGenISISCompressedSourceFormalCoeffs(ringQ, rowsNTT, l.SCarrierStart, l.SCompressedSourceRows, l.MSECompressionPackWidth, compression.DecodePolys, "pre-sign s")
	if err != nil {
		return ConstraintSet{}, err
	}
	eSources, err := intGenISISCompressedSourceFormalCoeffs(ringQ, rowsNTT, l.ECarrierStart, l.ECompressedSourceRows, l.MSECompressionPackWidth, compression.DecodePolys, "pre-sign e")
	if err != nil {
		return ConstraintSet{}, err
	}
	reservedSelector := []uint64{0}
	for lane := 0; lane < credential.IntGenISISPRFSeedTailReserve-credential.IntGenISISPRFSeedLen; lane++ {
		reservedSelector = polyAdd(reservedSelector, basis.LagrangeBasis[lane], q)
	}
	reservedCoeff := reducePolyModXN1(polyMul(reservedSelector, mSources[l.MCompressedSourceRows], q), int(ringQ.N), q)
	fparIntCoeffs := [][]uint64{reservedCoeff}
	policyRows, err := intGenISISPreSignSourceOnlyPolicyRowsV3(ringQ, pub, omega)
	if err != nil {
		return ConstraintSet{}, err
	}
	for i := range policyRows {
		fparIntCoeffs = append(fparIntCoeffs, trimPoly(polySub(mSources[i], policyRows[i], q), q))
	}
	fparInt := make([]*ring.Poly, len(fparIntCoeffs))
	for i := range fparIntCoeffs {
		fparInt[i] = nttPolyFromFormalCoeffsIfFits(ringQ, fparIntCoeffs[i])
	}
	carrierRows := make([]int, 0, l.MCarrierCount+l.SCarrierCount+l.ECarrierCount)
	carrierRows = append(carrierRows, intGenISISViewRowIndices(l.MCarrierStart, l.MCarrierCount)...)
	carrierRows = append(carrierRows, intGenISISViewRowIndices(l.SCarrierStart, l.SCarrierCount)...)
	carrierRows = append(carrierRows, intGenISISViewRowIndices(l.ECarrierStart, l.ECarrierCount)...)
	fparNorm, fparNormCoeffs, err := intGenISISCompressedCarrierMembershipRows(ringQ, rowsNTT, carrierRows, compression)
	if err != nil {
		return ConstraintSet{}, err
	}
	seedRows := intGenISISViewRowIndices(l.MSeedViewStart, l.MSeedViewCount)
	seedPolys, seedCoeffs, err := intGenISISRangeMembershipRows(ringQ, rowsNTT, seedRows, intGenISISSeedBound)
	if err != nil {
		return ConstraintSet{}, err
	}
	fparNorm = append(fparNorm, seedPolys...)
	fparNormCoeffs = append(fparNormCoeffs, seedCoeffs...)
	faggCoeffs := make([][]uint64, 0, l.CommitmentRows*int(ringQ.N))
	fagg := make([]*ring.Poly, 0, l.CommitmentRows*int(ringQ.N))
	for out := 0; out < l.CommitmentRows; out++ {
		for t := 0; t < int(ringQ.N); t++ {
			mTransform := sourceOnlyTransformFormalV3(ringQ, basis, mSources, t)
			sTransform := sourceOnlyTransformFormalV3(ringQ, basis, sSources, t)
			eTransform := sourceOnlyTransformFormalV3(ringQ, basis, eSources, t)
			res := scalePoly(mTransform, pub.CM[out][0].Coeffs[0][t]%q, q)
			res = polyAdd(res, scalePoly(sTransform, pub.AS[out][0].Coeffs[0][t]%q, q), q)
			res = polyAdd(res, eTransform, q)
			publicTerm := scalePoly(basis.LagrangeBasis[t%len(omega)], pub.Com[out].Coeffs[0][t]%q, q)
			res = reducePolyModXN1(polySub(res, publicTerm, q), int(ringQ.N), q)
			faggCoeffs = append(faggCoeffs, res)
			fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, res))
		}
	}
	return ConstraintSet{
		FparInt:          fparInt,
		FparIntCoeffs:    fparIntCoeffs,
		FparNorm:         fparNorm,
		FparNormCoeffs:   fparNormCoeffs,
		FaggInt:          fagg,
		FaggIntCoeffs:    faggCoeffs,
		ParallelAlgDeg:   intGenISISPreSignSourceMembershipDeg,
		AggregatedAlgDeg: intGenISISPreSignSourceDecodeDegree,
	}, nil
}
