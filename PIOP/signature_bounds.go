package PIOP

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	ntrurio "vSIS-Signature/ntru/io"
)

// Signature showing-time coefficient bounds.
const (
	signatureCoeffLinfL = 4

	signatureNTTBridgeChecks = 6

	signatureRadixOverrideEnv = "SPRUCE_SIGNATURE_RADIX_OVERRIDE"

	SigShortnessProfileR11L4Production  = "r11_l4_production"
	SigShortnessProfileR24L3Compact     = "r24_l3_compact"
	SigShortnessProfileR111L2Compact    = "r111_l2_compact"
	SigShortnessProfileR12285L1Research = "r12285_l1_research"
	SigShortnessProfileR12L3Default     = "r12_l3_default"
	SigShortnessProfileR13L3Legacy      = "r13_l3_legacy"
	SigShortnessProfileR7L4Experimental = "r7_l4_experimental"
	SigShortnessProfileCustomBalanced   = "custom_balanced"

	signaturePackedProductionRadix   = 11
	signaturePackedProductionL       = 4
	signaturePackedCompactL3Radix    = 24
	signaturePackedCompactL3L        = 3
	signaturePackedCompactL2Radix    = 111
	signaturePackedCompactL2L        = 2
	signaturePackedResearchL1Radix   = 12285
	signaturePackedResearchL1L       = 1
	signaturePackedDefaultRadix      = 12
	signaturePackedDefaultL          = 3
	signaturePackedLegacyRadix       = 13
	signaturePackedLegacyL           = 3
	signaturePackedExperimentalRadix = 7
	signaturePackedExperimentalL     = 4
)

var (
	productionSignatureCoeffLinfBetaOnce  sync.Once
	productionSignatureCoeffLinfBetaValue uint64
	productionSignatureCoeffLinfBetaErr   error
	signatureChainSpecCache               sync.Map
)

type signatureChainSpecCacheKey struct {
	Q       uint64
	Model   string
	L       int
	Radix   int
	Profile string
}

type signatureChainSpecCacheValue struct {
	Spec LinfSpec
	Err  error
}

func signatureDefaultCaps(L int) []int {
	return nil
}

func signaturePackedV2Caps() []int {
	return []int{6, 6, 4}
}

func sigShortnessProfileDigits(profile string) int {
	switch normalizeSigShortnessProfile(profile) {
	case SigShortnessProfileR11L4Production:
		return signaturePackedProductionL
	case SigShortnessProfileR24L3Compact:
		return signaturePackedCompactL3L
	case SigShortnessProfileR111L2Compact:
		return signaturePackedCompactL2L
	case SigShortnessProfileR12285L1Research:
		return signaturePackedResearchL1L
	case SigShortnessProfileR7L4Experimental:
		return signaturePackedExperimentalL
	case SigShortnessProfileR13L3Legacy:
		return signaturePackedLegacyL
	case SigShortnessProfileR12L3Default:
		fallthrough
	default:
		return signaturePackedDefaultL
	}
}

func sigShortnessFixedShape(profile string) (base int, L int, caps []int, ok bool) {
	switch normalizeSigShortnessProfile(profile) {
	case SigShortnessProfileR11L4Production:
		return signaturePackedProductionRadix, signaturePackedProductionL, nil, true
	case SigShortnessProfileR24L3Compact:
		return signaturePackedCompactL3Radix, signaturePackedCompactL3L, nil, true
	case SigShortnessProfileR111L2Compact:
		return signaturePackedCompactL2Radix, signaturePackedCompactL2L, nil, true
	case SigShortnessProfileR12285L1Research:
		return signaturePackedResearchL1Radix, signaturePackedResearchL1L, nil, true
	case SigShortnessProfileR12L3Default:
		return signaturePackedDefaultRadix, signaturePackedDefaultL, nil, true
	case SigShortnessProfileR13L3Legacy:
		return signaturePackedLegacyRadix, signaturePackedLegacyL, signaturePackedV2Caps(), true
	case SigShortnessProfileR7L4Experimental:
		return signaturePackedExperimentalRadix, signaturePackedExperimentalL, nil, true
	default:
		return 0, 0, nil, false
	}
}

func normalizeSigShortnessProfile(profile string) string {
	switch profile {
	case "", SigShortnessProfileR11L4Production:
		return SigShortnessProfileR11L4Production
	case SigShortnessProfileR24L3Compact:
		return SigShortnessProfileR24L3Compact
	case SigShortnessProfileR111L2Compact:
		return SigShortnessProfileR111L2Compact
	case SigShortnessProfileR12285L1Research:
		return SigShortnessProfileR12285L1Research
	case SigShortnessProfileR12L3Default:
		return SigShortnessProfileR12L3Default
	case SigShortnessProfileR13L3Legacy:
		return SigShortnessProfileR13L3Legacy
	case SigShortnessProfileR7L4Experimental:
		return SigShortnessProfileR7L4Experimental
	default:
		return SigShortnessProfileR11L4Production
	}
}

func sigShortnessRawOverrideActive(opts SimOpts) bool {
	return opts.SigShortnessL > 0 || opts.SigShortnessRadix > 0
}

// ResolveSignatureShortnessProfileLabelForOpts returns the effective reporting
// label for the selected shortness shape. Raw radix/digit overrides are
// reported as custom_balanced even when the base profile is a named default.
func ResolveSignatureShortnessProfileLabelForOpts(opts SimOpts) string {
	if sigShortnessRawOverrideActive(opts) {
		return SigShortnessProfileCustomBalanced
	}
	return normalizeSigShortnessProfile(opts.SigShortnessProfile)
}

func signatureShortnessProfileLabelFromMetrics(radix, digits int) string {
	switch {
	case radix == signaturePackedProductionRadix && digits == signaturePackedProductionL:
		return SigShortnessProfileR11L4Production
	case radix == signaturePackedCompactL3Radix && digits == signaturePackedCompactL3L:
		return SigShortnessProfileR24L3Compact
	case radix == signaturePackedCompactL2Radix && digits == signaturePackedCompactL2L:
		return SigShortnessProfileR111L2Compact
	case radix == signaturePackedResearchL1Radix && digits == signaturePackedResearchL1L:
		return SigShortnessProfileR12285L1Research
	case radix == signaturePackedDefaultRadix && digits == signaturePackedDefaultL:
		return SigShortnessProfileR12L3Default
	case radix == signaturePackedLegacyRadix && digits == signaturePackedLegacyL:
		return SigShortnessProfileR13L3Legacy
	case radix == signaturePackedExperimentalRadix && digits == signaturePackedExperimentalL:
		return SigShortnessProfileR7L4Experimental
	case radix > 0 && digits > 0:
		return SigShortnessProfileCustomBalanced
	default:
		return ""
	}
}

func normalizeChainCaps(label string, caps []int, L int) ([]int, error) {
	if len(caps) == 0 {
		return nil, nil
	}
	if L <= 0 {
		return nil, fmt.Errorf("%s: invalid L=%d for caps", label, L)
	}
	if len(caps) > L {
		return nil, fmt.Errorf("%s: caps len=%d exceeds L=%d", label, len(caps), L)
	}
	out := make([]int, L)
	copy(out, caps)
	for i := 0; i < len(out); i++ {
		if out[i] < 0 {
			return nil, fmt.Errorf("%s: caps[%d]=%d must be >=0", label, i, out[i])
		}
	}
	return out, nil
}

func validateChainCapsSigned(label string, maxAbs int, caps []int) error {
	if len(caps) == 0 {
		return nil
	}
	if maxAbs <= 0 {
		return fmt.Errorf("%s: invalid maxAbs=%d", label, maxAbs)
	}
	for i := 0; i < len(caps); i++ {
		if caps[i] == 0 {
			continue
		}
		if caps[i] > maxAbs {
			return fmt.Errorf("%s: caps[%d]=%d exceeds signed digit bound %d", label, i, caps[i], maxAbs)
		}
	}
	return nil
}

func productionSignatureCoeffLinfBeta() (uint64, error) {
	productionSignatureCoeffLinfBetaOnce.Do(func() {
		par, err := ntrurio.LoadParams(resolve("internal/source_data/Parameters.json"), true)
		if err != nil {
			productionSignatureCoeffLinfBetaErr = fmt.Errorf("load params: %w", err)
			return
		}
		if par.Beta == 0 {
			productionSignatureCoeffLinfBetaErr = fmt.Errorf("missing beta in internal/source_data/Parameters.json")
			return
		}
		productionSignatureCoeffLinfBetaValue = par.Beta
	})
	return productionSignatureCoeffLinfBetaValue, productionSignatureCoeffLinfBetaErr
}

func signatureShortnessDigitsForOpts(opts SimOpts) int {
	if opts.SigShortnessL > 0 {
		return opts.SigShortnessL
	}
	return signatureCoeffLinfL
}

func balancedDigitMax(radix int) int {
	if radix < 2 {
		return 0
	}
	if radix%2 == 0 {
		return radix / 2
	}
	return (radix - 1) / 2
}

func balancedPositiveDigitMax(radix uint64) uint64 {
	if radix < 2 {
		return 0
	}
	if radix%2 == 0 {
		return radix/2 - 1
	}
	return (radix - 1) / 2
}

func minimalBalancedRadixForBeta(beta, q uint64, L int) (int, error) {
	if L <= 0 {
		return 0, fmt.Errorf("invalid L=%d", L)
	}
	if q == 0 {
		return 0, fmt.Errorf("invalid q=0")
	}
	for radix := 2; uint64(radix) < q; radix++ {
		if signedBalancedCapacity(uint64(radix), L) >= beta {
			return radix, nil
		}
	}
	return 0, fmt.Errorf("no radix < q=%d covers beta=%d with L=%d", q, beta, L)
}

func signedBalancedCapacity(radix uint64, L int) uint64 {
	if radix < 2 || L <= 0 {
		return 0
	}
	digitMax := balancedPositiveDigitMax(radix)
	weight := uint64(1)
	maxAbs := uint64(0)
	for i := 0; i < L; i++ {
		maxAbs += digitMax * weight
		if i+1 < L {
			weight *= radix
		}
	}
	return maxAbs
}

func signatureBoundShapeForOptsV1(q uint64, opts SimOpts) (base int, L int, beta uint64, caps []int, err error) {
	beta, err = productionSignatureCoeffLinfBeta()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	L = signatureShortnessDigitsForOpts(opts)
	if L <= 0 {
		return 0, 0, 0, nil, fmt.Errorf("invalid signature shortness L=%d", L)
	}
	base, overridden, err := signatureRadixOverride(beta, q, L)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if !overridden {
		if opts.SigShortnessRadix > 0 {
			base = opts.SigShortnessRadix
			if base < 2 || uint64(base) >= q {
				return 0, 0, 0, nil, fmt.Errorf("invalid signature shortness radix=%d for q=%d", base, q)
			}
			if signedBalancedCapacity(uint64(base), L) < beta {
				return 0, 0, 0, nil, fmt.Errorf("signature shortness radix=%d does not cover beta=%d with L=%d", base, beta, L)
			}
		} else {
			base, err = minimalBalancedRadixForBeta(beta, q, L)
			if err != nil {
				return 0, 0, 0, nil, err
			}
		}
	}
	caps = signatureDefaultCaps(L)
	err = validateChainCapsSigned("production signature bound", balancedDigitMax(base), caps)
	return
}

func signatureBoundShapeForOpts(q uint64, opts SimOpts) (base int, L int, beta uint64, caps []int, err error) {
	model := resolveCoeffNativeSigModel(opts)
	switch model {
	case CoeffNativeSigModelLiteralPackedAggregatedV3:
		beta, err = productionSignatureCoeffLinfBeta()
		if err != nil {
			return 0, 0, 0, nil, err
		}
		profile := normalizeSigShortnessProfile(opts.SigShortnessProfile)
		if profile == SigShortnessProfileR13L3Legacy {
			if opts.SigShortnessL > 0 || opts.SigShortnessRadix > 0 {
				return 0, 0, 0, nil, fmt.Errorf("signature shortness profile %q cannot be combined with raw shortness overrides", profile)
			}
		}
		if sigShortnessRawOverrideActive(opts) {
			L = sigShortnessProfileDigits(profile)
			if opts.SigShortnessL > 0 {
				L = opts.SigShortnessL
			}
			if L <= 0 {
				return 0, 0, 0, nil, fmt.Errorf("invalid signature shortness L=%d", L)
			}
			if opts.SigShortnessRadix > 0 {
				base = opts.SigShortnessRadix
				if base < 2 || uint64(base) >= q {
					return 0, 0, 0, nil, fmt.Errorf("invalid signature shortness radix=%d for q=%d", base, q)
				}
				if signedBalancedCapacity(uint64(base), L) < beta {
					return 0, 0, 0, nil, fmt.Errorf("signature shortness radix=%d does not cover beta=%d with L=%d", base, beta, L)
				}
			} else {
				base, err = minimalBalancedRadixForBeta(beta, q, L)
				if err != nil {
					return 0, 0, 0, nil, err
				}
			}
			return base, L, beta, nil, nil
		}
		base, L, caps, ok := sigShortnessFixedShape(profile)
		if !ok {
			return 0, 0, 0, nil, fmt.Errorf("unsupported signature shortness profile %q", profile)
		}
		if base < 2 || uint64(base) >= q {
			return 0, 0, 0, nil, fmt.Errorf("signature shortness profile %q has invalid radix=%d for q=%d", profile, base, q)
		}
		if signedBalancedCapacity(uint64(base), L) < beta {
			return 0, 0, 0, nil, fmt.Errorf("signature shortness profile %q with radix=%d L=%d does not cover beta=%d", profile, base, L, beta)
		}
		if err := validateChainCapsSigned("production signature bound "+profile, balancedDigitMax(base), caps); err != nil {
			return 0, 0, 0, nil, err
		}
		return base, L, beta, caps, nil
	default:
		return 0, 0, 0, nil, fmt.Errorf("unsupported coeff-native signature model %q", model)
	}
}

func signatureBoundShape(q uint64) (base int, L int, beta uint64, caps []int, err error) {
	return signatureBoundShapeForOpts(q, SimOpts{})
}

func ResolveSignatureBoundShapeForOpts(q uint64, opts SimOpts) (base int, L int, caps []int, err error) {
	base, L, _, caps, err = signatureBoundShapeForOpts(q, opts)
	return
}

func signatureRadixOverride(beta, q uint64, L int) (int, bool, error) {
	raw := strings.TrimSpace(os.Getenv(signatureRadixOverrideEnv))
	if raw == "" {
		return 0, false, nil
	}
	base, err := strconv.Atoi(raw)
	if err != nil {
		return 0, true, fmt.Errorf("parse %s=%q: %w", signatureRadixOverrideEnv, raw, err)
	}
	if base < 2 || uint64(base) >= q {
		return 0, true, fmt.Errorf("%s=%d must satisfy 2 <= R < q=%d", signatureRadixOverrideEnv, base, q)
	}
	if signedBalancedCapacity(uint64(base), L) < beta {
		return 0, true, fmt.Errorf("%s=%d does not cover beta=%d with L=%d", signatureRadixOverrideEnv, base, beta, L)
	}
	return base, true, nil
}

func ResolveSignatureBoundShape(q uint64) (base int, L int, caps []int, err error) {
	base, L, _, caps, err = signatureBoundShape(q)
	return
}

func signatureCoeffLinfSpecChecked(q uint64, base int, L int, beta uint64, caps []int) (spec LinfSpec, err error) {
	if len(caps) == 0 {
		caps = signatureDefaultCaps(L)
	}
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("signature chain spec: %v", rec)
			spec = LinfSpec{}
		}
	}()
	if err = validateChainCapsSigned("production signature bound", balancedDigitMax(base), caps); err != nil {
		return LinfSpec{}, err
	}
	spec = NewSignedLinfChainSpecRadix(q, uint64(base), L, 1, beta, caps)
	if !signatureSpecNoWrapOK(spec) {
		return LinfSpec{}, fmt.Errorf("signature chain spec violates no-wrap bound: maxAbs=%d q=%d", spec.MaxAbs, spec.Q)
	}
	return spec, nil
}

func signatureCoeffLinfSpec(q uint64) LinfSpec {
	spec, err := signatureChainSpecForOpts(q, SimOpts{})
	if err != nil {
		panic(err)
	}
	return spec
}

func signatureChainRowsPerSig(spec LinfSpec) int {
	if spec.UsesAbsRow {
		return 1 + spec.L
	}
	return spec.L
}

func signatureChainConstraintCountPerSig(spec LinfSpec) int {
	// Membership constraints are always L; reconstruction is always 1.
	if spec.UsesAbsRow {
		return 2 + spec.L
	}
	return 1 + spec.L
}

func signatureChainSpecFromLayout(q uint64, layout RowLayout) LinfSpec {
	spec, err := signatureChainSpecForLayoutAndOpts(q, layout, SimOpts{})
	if err != nil {
		panic(err)
	}
	return spec
}

func signatureChainSpecForLayoutAndOpts(q uint64, layout RowLayout, opts SimOpts) (LinfSpec, error) {
	if layout.CoeffNativeSig.Enabled && layout.CoeffNativeSig.Model != "" {
		opts.CoeffNativeSigModel = layout.CoeffNativeSig.Model
	}
	return signatureChainSpecForOpts(q, opts)
}

func signatureChainSpecForOpts(q uint64, opts SimOpts) (LinfSpec, error) {
	key := signatureChainSpecCacheKey{
		Q:       q,
		Model:   resolveCoeffNativeSigModel(opts),
		L:       opts.SigShortnessL,
		Radix:   opts.SigShortnessRadix,
		Profile: normalizeSigShortnessProfile(opts.SigShortnessProfile),
	}
	if cached, ok := signatureChainSpecCache.Load(key); ok {
		out := cached.(signatureChainSpecCacheValue)
		return out.Spec, out.Err
	}
	base, L, beta, caps, err := signatureBoundShapeForOpts(q, opts)
	if err != nil {
		return LinfSpec{}, err
	}
	spec, err := signatureCoeffLinfSpecChecked(q, base, L, beta, caps)
	out := signatureChainSpecCacheValue{Spec: spec, Err: err}
	signatureChainSpecCache.Store(key, out)
	return out.Spec, out.Err
}

func signatureChainSpec(q uint64) (LinfSpec, error) {
	return signatureChainSpecForOpts(q, SimOpts{})
}

func ResolveSignatureShortnessMetricsForOpts(q uint64, opts SimOpts) (base int, L int, rowsPerSig int, degree int, err error) {
	spec, err := signatureChainSpecForOpts(q, opts)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	base = int(spec.R)
	L = spec.L
	rowsPerSig = signatureChainRowsPerSig(spec)
	degree, err = signatureShortnessMaxDegree(spec, opts)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return
}

func nonSigChainRowsPer(spec LinfSpec) int {
	if spec.UsesAbsRow {
		return 1 + spec.L
	}
	return spec.L
}

func nonSigChainConstraintCountPer(spec LinfSpec) int {
	if spec.UsesAbsRow {
		return 2 + spec.L
	}
	return 1 + spec.L
}

func signatureSpecNoWrapOK(spec LinfSpec) bool {
	if spec.Q == 0 {
		return false
	}
	return spec.MaxAbs < (spec.Q / 2)
}

func decomposeLinfDigitsAbs(absValue int64, spec LinfSpec) ([]int64, error) {
	if absValue < 0 {
		return nil, fmt.Errorf("abs decomposition expects non-negative value, got %d", absValue)
	}
	R := int64(spec.R)
	if R <= 1 {
		return nil, fmt.Errorf("invalid radix %d", spec.R)
	}
	digits := make([]int64, spec.L)
	remaining := absValue
	for i := 0; i < spec.L; i++ {
		if i == spec.L-1 {
			d := remaining
			lo := int64(spec.DigitLo[i])
			hi := int64(spec.DigitHi[i])
			if d < lo || d > hi {
				return nil, fmt.Errorf("digit %d out of range: %d not in [%d,%d]", i, d, lo, hi)
			}
			digits[i] = d
			remaining = 0
			continue
		}
		d := remaining % R
		remaining /= R
		lo := int64(spec.DigitLo[i])
		hi := int64(spec.DigitHi[i])
		for d > hi {
			d -= R
			remaining++
		}
		for d < lo {
			d += R
			remaining--
		}
		if d < lo || d > hi {
			return nil, fmt.Errorf("digit %d out of range: %d not in [%d,%d]", i, d, lo, hi)
		}
		digits[i] = d
	}
	if remaining != 0 {
		return nil, fmt.Errorf("leftover carry %d after abs decomposition", remaining)
	}
	return digits, nil
}

func decomposeLinfDigitsSigned(value int64, spec LinfSpec) ([]int64, error) {
	R := int64(spec.R)
	if R <= 1 {
		return nil, fmt.Errorf("invalid radix %d", spec.R)
	}
	digits := make([]int64, spec.L)
	remaining := value
	for i := 0; i < spec.L; i++ {
		d := remaining % R
		if d < 0 {
			d += R
		}
		lo := int64(spec.DigitLo[i])
		hi := int64(spec.DigitHi[i])
		for d > hi {
			d -= R
		}
		for d < lo {
			d += R
		}
		if d < lo || d > hi {
			return nil, fmt.Errorf("digit %d out of range: %d not in [%d,%d]", i, d, lo, hi)
		}
		digits[i] = d
		remaining = (remaining - d) / R
	}
	if remaining != 0 {
		return nil, fmt.Errorf("leftover carry %d after signed decomposition", remaining)
	}
	return digits, nil
}

func recomposeLinfDigits(digits []int64, spec LinfSpec) int64 {
	value := int64(0)
	weight := int64(1)
	R := int64(spec.R)
	for i := 0; i < len(digits); i++ {
		value += digits[i] * weight
		weight *= R
	}
	return value
}
