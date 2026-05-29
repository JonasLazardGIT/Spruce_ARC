package PIOP

import (
	"encoding/json"
	"fmt"
	"strconv"

	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const intGenISISPRFKeyLen = 8
const intGenISISMaxDirectSignatureRangeBound = 64
const intGenISISTernaryBound = 1
const intGenISISTernaryMembershipDegree = 3
const intGenISISDefaultBound = 4
const intGenISISDegreeModePaperEq3V1 = credential.IntGenISISDegreeModePaperEq3V1
const intGenISISUShortnessVersion = "intgenisis_u_shortness_r11_l4_v1"
const intGenISISUShortnessMode = "radix_beta_aware_top_digit_cap_v1"
const intGenISISUShortnessRadix = 11
const intGenISISUShortnessDigits = 4
const intGenISISUShortnessDigitBound = 5
const intGenISISUShortnessCapacity = 7320

type intGenISISRowMaterial struct {
	Poly *ring.Poly
	Head []uint64
}

func intGenISISRowMaterialPolys(rows []intGenISISRowMaterial) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		out[i] = rows[i].Poly
	}
	return out
}

type intGenISISUShortnessDescriptor struct {
	Version        string `json:"version"`
	Radix          int    `json:"radix"`
	Digits         int    `json:"digits"`
	DigitMin       int    `json:"digit_min"`
	DigitMax       int    `json:"digit_max"`
	DigitCaps      []int  `json:"digit_caps,omitempty"`
	Capacity       int64  `json:"capacity"`
	SignatureBound int64  `json:"signature_bound"`
	Mode           string `json:"mode"`
}

type intGenISISUShortnessShape struct {
	Version    string
	Radix      int
	Digits     int
	DigitBound int
	Capacity   int64
}

func intGenISISSemanticLayout(ringN int, bound int64) (credential.SemanticMessageLayout, error) {
	profile, ok := credential.LookupIntGenISISProfileByRingDegree(ringN)
	if !ok {
		return credential.SemanticMessageLayout{}, fmt.Errorf("IntGenISIS semantic layout does not support ring_degree=%d", ringN)
	}
	if bound > 0 {
		profile.B = bound
	}
	return credential.DefaultSemanticMessageLayout(profile, intGenISISPRFKeyLen)
}

func bindIntGenISISPublicExtras(pub PublicInputs, ringN int) (PublicInputs, error) {
	return bindIntGenISISPublicExtrasWithOpts(pub, ringN, SimOpts{})
}

func bindIntGenISISPublicExtrasWithOpts(pub PublicInputs, ringN int, opts SimOpts) (PublicInputs, error) {
	layout, err := intGenISISSemanticLayout(ringN, pub.BoundB)
	if err != nil {
		return pub, err
	}
	if pub.Extras == nil {
		pub.Extras = make(map[string]interface{})
	}
	policyBytes, err := intGenISISPolicyBytesFromPublic(pub)
	if err != nil {
		return pub, err
	}
	pub.Extras["IntGenISIS.semantic_message_layout"] = layout.Digest()
	pub.Extras["IntGenISIS.mse_domain"] = []byte(layout.MSEDomain)
	pub.Extras["IntGenISIS.key_domain"] = []byte(layout.KeyDomain)
	pub.Extras["IntGenISIS.degree_mode"] = []byte(intGenISISDegreeModePaperEq3V1)
	compressionBytes, err := intGenISISMSECompressionDescriptorBytesForBound(opts.IntGenISISMSECompression, 0, pub.BoundB)
	if err != nil {
		return pub, err
	}
	pub.Extras["IntGenISIS.compression_mode"] = compressionBytes
	if normalizeIntGenISISReplayProjection(opts.IntGenISISReplayProjection) != IntGenISISReplayProjectionNone {
		projectionBytes, err := intGenISISReplayProjectionDescriptorBytes(opts.IntGenISISReplayProjection)
		if err != nil {
			return pub, err
		}
		pub.Extras["IntGenISIS.replay_projection"] = projectionBytes
	}
	pub.Extras["IntGenISIS.policy"] = policyBytes
	pub.Extras["IntGenISIS.sampler_profile"] = []byte(credential.IntGenISISSamplerUniformRQV1)
	pub.Extras["IntGenISIS.presentation_schema"] = []byte("intgenisis_presentation_v1")
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		return pub, err
	}
	shortnessBytes, err := intGenISISUShortnessDescriptorBytesWithOpts(sigBound, opts)
	if err != nil {
		return pub, err
	}
	pub.Extras["IntGenISIS.signature_bound"] = []byte(strconv.FormatInt(sigBound, 10))
	pub.Extras["IntGenISIS.u_shortness"] = shortnessBytes
	return pub, nil
}

func intGenISISX0LenFromPublic(pub PublicInputs) (int, error) {
	if pub.X0Len > 0 {
		return pub.X0Len, nil
	}
	if len(pub.B) > 3 {
		return len(pub.B) - 3, nil
	}
	return 0, fmt.Errorf("missing IntGenISIS x0 length")
}

func intGenISISSignatureBoundFromPublic(pub PublicInputs) (int64, error) {
	if pub.Extras != nil {
		if raw, ok := pub.Extras["IntGenISIS.signature_bound"].([]byte); ok && len(raw) > 0 {
			v, err := strconv.ParseInt(string(raw), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse IntGenISIS signature bound: %w", err)
			}
			if v <= 0 {
				return 0, fmt.Errorf("invalid IntGenISIS signature bound %d", v)
			}
			return v, nil
		}
		switch v := pub.Extras["IntGenISIS.signature_bound_value"].(type) {
		case int64:
			if v <= 0 {
				return 0, fmt.Errorf("invalid IntGenISIS signature bound %d", v)
			}
			return v, nil
		case int:
			if v <= 0 {
				return 0, fmt.Errorf("invalid IntGenISIS signature bound %d", v)
			}
			return int64(v), nil
		case uint64:
			if v == 0 || v > uint64(^uint64(0)>>1) {
				return 0, fmt.Errorf("invalid IntGenISIS signature bound %d", v)
			}
			return int64(v), nil
		}
	}
	if pub.BoundB <= 0 {
		return 0, fmt.Errorf("missing IntGenISIS signature bound")
	}
	return pub.BoundB, nil
}

func intGenISISUseDirectSignatureRange(sigBound int64) bool {
	return sigBound > 0 && sigBound <= intGenISISMaxDirectSignatureRangeBound
}

func intGenISISDirectSignatureRangeDegree(sigBound int64) int {
	if !intGenISISUseDirectSignatureRange(sigBound) {
		return 0
	}
	return int(2*sigBound + 1)
}

func intGenISISUShortnessShapeFromOpts(opts SimOpts) (intGenISISUShortnessShape, error) {
	radix := opts.SigShortnessRadix
	digits := opts.SigShortnessL
	if radix == 0 && digits == 0 {
		radix = intGenISISUShortnessRadix
		digits = intGenISISUShortnessDigits
	}
	if radix <= 0 || digits <= 0 {
		return intGenISISUShortnessShape{}, fmt.Errorf("IntGenISIS shortness requires both radix and digit count, got R=%d L=%d", radix, digits)
	}
	return intGenISISUShortnessShapeForRadixDigits(radix, digits)
}

func intGenISISUShortnessShapeForRadixDigits(radix, digits int) (intGenISISUShortnessShape, error) {
	if radix <= 1 || radix%2 == 0 {
		return intGenISISUShortnessShape{}, fmt.Errorf("IntGenISIS shortness radix must be odd and >1, got %d", radix)
	}
	if digits <= 0 {
		return intGenISISUShortnessShape{}, fmt.Errorf("invalid IntGenISIS shortness digit count %d", digits)
	}
	if radix == sigLookupShadowR121L2Radix && digits == sigLookupShadowR121L2Digits {
		return intGenISISUShortnessShape{}, fmt.Errorf("IntGenISIS showing does not support R121/L2 signature shortness")
	}
	digitBound := (radix - 1) / 2
	capacity := int64(0)
	pow := int64(1)
	for i := 0; i < digits; i++ {
		capacity += int64(digitBound) * pow
		if i+1 < digits {
			if pow > (1<<62)/int64(radix) {
				return intGenISISUShortnessShape{}, fmt.Errorf("IntGenISIS shortness capacity overflow for R=%d L=%d", radix, digits)
			}
			pow *= int64(radix)
		}
	}
	version := fmt.Sprintf("intgenisis_u_shortness_r%d_l%d_v1", radix, digits)
	if radix == intGenISISUShortnessRadix && digits == intGenISISUShortnessDigits {
		version = intGenISISUShortnessVersion
	}
	return intGenISISUShortnessShape{
		Version:    version,
		Radix:      radix,
		Digits:     digits,
		DigitBound: digitBound,
		Capacity:   capacity,
	}, nil
}

func intGenISISUShortnessDescriptorForBound(sigBound int64) (intGenISISUShortnessDescriptor, error) {
	return intGenISISUShortnessDescriptorForBoundAndOpts(sigBound, SimOpts{})
}

func intGenISISUShortnessDescriptorForBoundAndOpts(sigBound int64, opts SimOpts) (intGenISISUShortnessDescriptor, error) {
	if sigBound <= 0 {
		return intGenISISUShortnessDescriptor{}, fmt.Errorf("invalid IntGenISIS signature bound %d", sigBound)
	}
	shape, err := intGenISISUShortnessShapeFromOpts(opts)
	if err != nil {
		return intGenISISUShortnessDescriptor{}, err
	}
	if sigBound > shape.Capacity {
		return intGenISISUShortnessDescriptor{}, fmt.Errorf("IntGenISIS signature bound %d exceeds R%d/L%d capacity %d", sigBound, shape.Radix, shape.Digits, shape.Capacity)
	}
	caps, capacity, err := intGenISISUShortnessCapsForBound(shape, sigBound)
	if err != nil {
		return intGenISISUShortnessDescriptor{}, err
	}
	return intGenISISUShortnessDescriptor{
		Version:        shape.Version,
		Radix:          shape.Radix,
		Digits:         shape.Digits,
		DigitMin:       -shape.DigitBound,
		DigitMax:       shape.DigitBound,
		DigitCaps:      caps,
		Capacity:       capacity,
		SignatureBound: sigBound,
		Mode:           intGenISISUShortnessMode,
	}, nil
}

func intGenISISUShortnessCapsForBound(shape intGenISISUShortnessShape, sigBound int64) ([]int, int64, error) {
	if sigBound <= 0 {
		return nil, 0, fmt.Errorf("invalid IntGenISIS signature bound %d", sigBound)
	}
	if shape.Radix <= 1 || shape.Digits <= 0 || shape.DigitBound <= 0 {
		return nil, 0, fmt.Errorf("invalid IntGenISIS shortness shape R=%d L=%d digit_bound=%d", shape.Radix, shape.Digits, shape.DigitBound)
	}
	if sigBound > shape.Capacity {
		return nil, 0, fmt.Errorf("IntGenISIS signature bound %d exceeds R%d/L%d capacity %d", sigBound, shape.Radix, shape.Digits, shape.Capacity)
	}
	if shape.Digits == 1 {
		return nil, shape.Capacity, nil
	}
	radix := int64(shape.Radix)
	digitBound := int64(shape.DigitBound)
	lowerCapacity := int64(0)
	weight := int64(1)
	for i := 0; i < shape.Digits-1; i++ {
		if lowerCapacity > (1<<62)-digitBound*weight {
			return nil, 0, fmt.Errorf("IntGenISIS shortness lower capacity overflow")
		}
		lowerCapacity += digitBound * weight
		if i+1 < shape.Digits {
			if weight > (1<<62)/radix {
				return nil, 0, fmt.Errorf("IntGenISIS shortness weight overflow")
			}
			weight *= radix
		}
	}
	topWeight := weight
	neededTopCap := int64(1)
	if sigBound > lowerCapacity {
		neededTopCap = (sigBound - lowerCapacity + topWeight - 1) / topWeight
		if neededTopCap < 1 {
			neededTopCap = 1
		}
	}
	if neededTopCap >= digitBound {
		return nil, shape.Capacity, nil
	}
	caps := make([]int, shape.Digits)
	caps[shape.Digits-1] = int(neededTopCap)
	capacity := lowerCapacity + neededTopCap*topWeight
	return caps, capacity, nil
}

func intGenISISUShortnessDescriptorBytes(sigBound int64) ([]byte, error) {
	return intGenISISUShortnessDescriptorBytesWithOpts(sigBound, SimOpts{})
}

func intGenISISUShortnessDescriptorBytesWithOpts(sigBound int64, opts SimOpts) ([]byte, error) {
	desc, err := intGenISISUShortnessDescriptorForBoundAndOpts(sigBound, opts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(desc)
}

func intGenISISUShortnessSpec(q uint64, sigBound int64) (spec LinfSpec, err error) {
	return intGenISISUShortnessSpecForOpts(q, sigBound, SimOpts{})
}

func intGenISISUShortnessSpecForOpts(q uint64, sigBound int64, opts SimOpts) (spec LinfSpec, err error) {
	desc, err := intGenISISUShortnessDescriptorForBoundAndOpts(sigBound, opts)
	if err != nil {
		return LinfSpec{}, err
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("build IntGenISIS R%d/L%d shortness spec: %v", desc.Radix, desc.Digits, r)
		}
	}()
	spec = NewSignedLinfChainSpecRadix(q, uint64(desc.Radix), desc.Digits, 1, uint64(sigBound), desc.DigitCaps)
	if len(spec.RPows) != desc.Digits || len(spec.PDi) != desc.Digits {
		return LinfSpec{}, fmt.Errorf("unexpected IntGenISIS shortness spec dimensions powers=%d memberships=%d", len(spec.RPows), len(spec.PDi))
	}
	if int64(spec.MaxAbs) != desc.Capacity {
		return LinfSpec{}, fmt.Errorf("unexpected IntGenISIS shortness capacity %d want %d", spec.MaxAbs, desc.Capacity)
	}
	return spec, nil
}

func intGenISISPolicyBytesFromPublic(pub PublicInputs) ([]byte, error) {
	if pub.Extras != nil {
		if raw, ok := pub.Extras["IntGenISIS.policy"].([]byte); ok && len(raw) > 0 {
			p, err := credential.ParseIntGenISISPolicy(raw)
			if err != nil {
				return nil, err
			}
			return p.CanonicalBytes()
		}
		if raw, ok := pub.Extras["IntGenISIS.policy_json"].(string); ok && raw != "" {
			p, err := credential.ParseIntGenISISPolicy([]byte(raw))
			if err != nil {
				return nil, err
			}
			return p.CanonicalBytes()
		}
	}
	return credential.NoopIntGenISISPolicy().CanonicalBytes()
}

func intGenISISPolicyFromPublic(pub PublicInputs) (credential.IntGenISISPolicy, error) {
	raw, err := intGenISISPolicyBytesFromPublic(pub)
	if err != nil {
		return credential.IntGenISISPolicy{}, err
	}
	return credential.ParseIntGenISISPolicy(raw)
}

func validateIntGenISISSemanticPolys(ringQ *ring.Ring, bound int64, M, mAttr, k []*ring.Poly) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	layout, err := intGenISISSemanticLayout(int(ringQ.N), bound)
	if err != nil {
		return err
	}
	msg := credential.SemanticMessage{
		M:     intGenISISPolyRowsToInt64(ringQ, M),
		MAttr: intGenISISPolyRowsToInt64(ringQ, mAttr),
		K:     intGenISISPolyRowsToInt64(ringQ, k),
	}
	return credential.ValidateSemanticMessage(layout, msg)
}

func validateIntGenISISPolicyPolys(ringQ *ring.Ring, pub PublicInputs, M, mAttr, k []*ring.Poly) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	layout, err := intGenISISSemanticLayout(int(ringQ.N), pub.BoundB)
	if err != nil {
		return err
	}
	policy, err := intGenISISPolicyFromPublic(pub)
	if err != nil {
		return err
	}
	msg := credential.SemanticMessage{
		M:     intGenISISPolyRowsToInt64(ringQ, M),
		MAttr: intGenISISPolyRowsToInt64(ringQ, mAttr),
		K:     intGenISISPolyRowsToInt64(ringQ, k),
	}
	return credential.ValidateIntGenISISPolicy(layout, policy, msg)
}

func validateIntGenISISBoundedPolys(ringQ *ring.Ring, bound int64, name string, rows []*ring.Poly) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if bound <= 0 {
		return fmt.Errorf("invalid %s bound %d", name, bound)
	}
	q := ringQ.Modulus[0]
	for i, row := range rows {
		if row == nil || len(row.Coeffs) == 0 || len(row.Coeffs[0]) != int(ringQ.N) {
			return fmt.Errorf("%s row %d has invalid width", name, i)
		}
		for j, c := range row.Coeffs[0] {
			v := centeredLift(c%q, q)
			if v < -bound || v > bound {
				return fmt.Errorf("%s[%d][%d]=%d outside [-%d,%d]", name, i, j, v, bound, bound)
			}
		}
	}
	return nil
}

func validateIntGenISISTernaryPolys(ringQ *ring.Ring, name string, rows []*ring.Poly) error {
	return validateIntGenISISBoundedPolys(ringQ, intGenISISTernaryBound, name, rows)
}

func validateIntGenISISLiveBoundPolys(ringQ *ring.Ring, bound int64, name string, rows []*ring.Poly) error {
	return validateIntGenISISBoundedPolys(ringQ, bound, name, rows)
}

func intGenISISPolyRowsToInt64(ringQ *ring.Ring, rows []*ring.Poly) [][]int64 {
	out := make([][]int64, len(rows))
	if ringQ == nil {
		return out
	}
	q := ringQ.Modulus[0]
	for i, row := range rows {
		out[i] = make([]int64, int(ringQ.N))
		if row == nil || len(row.Coeffs) == 0 {
			continue
		}
		for j := 0; j < int(ringQ.N) && j < len(row.Coeffs[0]); j++ {
			out[i][j] = centeredLift(row.Coeffs[0][j]%q, q)
		}
	}
	return out
}

func extractIntGenISISPRFKeyElemsFromSemanticM(ringQ *ring.Ring, bound int64, M []*ring.Poly) ([]prf.Elem, error) {
	layout, err := intGenISISSemanticLayout(int(ringQ.N), bound)
	if err != nil {
		return nil, err
	}
	key, err := credential.PRFKeyFromSemanticMessage(layout, intGenISISPolyRowsToInt64(ringQ, M))
	if err != nil {
		return nil, err
	}
	out := make([]prf.Elem, len(key))
	for i, v := range key {
		out[i] = prf.Elem(liftToField(ringQ.Modulus[0], v))
	}
	return out, nil
}

func intGenISISKeySourceSlots(mRow, lenKey, ringDegree int) ([]CoeffSlot, error) {
	if ringDegree <= lenKey {
		return nil, fmt.Errorf("ring degree %d too small for key length %d", ringDegree, lenKey)
	}
	out := make([]CoeffSlot, lenKey)
	start := ringDegree - lenKey
	for i := range out {
		out[i] = CoeffSlot{Row: mRow, Coeff: start + i}
	}
	return out, nil
}

func intGenISISKeySourceViewSlots(mViewStart, keyLen, ncols, ringDegree int) ([]CoeffSlot, error) {
	if mViewStart < 0 {
		return nil, fmt.Errorf("invalid M view start %d", mViewStart)
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("invalid key length %d", keyLen)
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	if ringDegree <= keyLen {
		return nil, fmt.Errorf("ring degree %d too small for key length %d", ringDegree, keyLen)
	}
	slots := make([]CoeffSlot, keyLen)
	keyStart := ringDegree - keyLen
	for i := 0; i < keyLen; i++ {
		semanticCoeff := keyStart + i
		slots[i] = CoeffSlot{Row: mViewStart + semanticCoeff/ncols, Coeff: semanticCoeff % ncols}
	}
	return slots, nil
}

func intGenISISKeySourceCarrierSlots(mCarrierStart, keyLen, ncols, ringDegree, packWidth int) ([]CoeffSlot, []int, error) {
	if mCarrierStart < 0 {
		return nil, nil, fmt.Errorf("invalid M carrier start %d", mCarrierStart)
	}
	if packWidth <= 1 {
		return nil, nil, fmt.Errorf("invalid compressed key-source pack width %d", packWidth)
	}
	if keyLen <= 0 {
		return nil, nil, fmt.Errorf("invalid key length %d", keyLen)
	}
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	if ringDegree <= keyLen {
		return nil, nil, fmt.Errorf("ring degree %d too small for key length %d", ringDegree, keyLen)
	}
	slots := make([]CoeffSlot, keyLen)
	lanes := make([]int, keyLen)
	keyStart := ringDegree - keyLen
	for i := 0; i < keyLen; i++ {
		semanticCoeff := keyStart + i
		sourceRow := semanticCoeff / ncols
		slots[i] = CoeffSlot{Row: mCarrierStart + sourceRow/packWidth, Coeff: semanticCoeff % ncols}
		lanes[i] = sourceRow % packWidth
	}
	return slots, lanes, nil
}

func intGenISISHatRowsFromCoeffViews(ringQ *ring.Ring, omega []uint64, coeffRows []*ring.Poly, rowsPerPoly int, makeRowFromHead func([]uint64) *ring.Poly, name string) ([]*ring.Poly, error) {
	mats := make([]intGenISISRowMaterial, len(coeffRows))
	for i, row := range coeffRows {
		mats[i] = intGenISISRowMaterial{Poly: row}
	}
	hatMats, err := intGenISISHatRowMaterialsFromCoeffViews(ringQ, omega, mats, rowsPerPoly, nil, makeRowFromHead, name)
	if err != nil {
		return nil, err
	}
	return intGenISISRowMaterialPolys(hatMats), nil
}

func intGenISISHatRowMaterialsFromCoeffViews(ringQ *ring.Ring, omega []uint64, coeffRows []intGenISISRowMaterial, rowsPerPoly int, interp *omegaInterpolationPlan, makeRowFromHead func([]uint64) *ring.Poly, name string) ([]intGenISISRowMaterial, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega for %s hats", name)
	}
	if rowsPerPoly <= 0 {
		return nil, fmt.Errorf("invalid rows-per-poly=%d for %s hats", rowsPerPoly, name)
	}
	if len(coeffRows) == 0 || len(coeffRows)%rowsPerPoly != 0 {
		return nil, fmt.Errorf("%s coefficient view rows=%d not divisible by rows-per-poly=%d", name, len(coeffRows), rowsPerPoly)
	}
	if makeRowFromHead == nil {
		if interp == nil {
			var err error
			interp, err = newOmegaInterpolationPlan(omega, ringQ.Modulus[0])
			if err != nil {
				return nil, err
			}
		}
		makeRowFromHead = func(head []uint64) *ring.Poly {
			return interp.coeffPolyFromHead(ringQ, head)
		}
	}
	out := make([]intGenISISRowMaterial, 0, len(coeffRows))
	components := len(coeffRows) / rowsPerPoly
	for comp := 0; comp < components; comp++ {
		start := comp * rowsPerPoly
		sourceHeads := make([][]uint64, rowsPerPoly)
		for i := 0; i < rowsPerPoly; i++ {
			row := coeffRows[start+i]
			if len(row.Head) == len(omega) {
				sourceHeads[i] = row.Head
				continue
			}
			if row.Poly == nil {
				return nil, fmt.Errorf("%s[%d] source row %d missing material", name, comp, i)
			}
			head, herr := rowHeadOnOmega(ringQ, omega, row.Poly, len(omega))
			if herr != nil {
				return nil, fmt.Errorf("source head %s[%d][%d]: %w", name, comp, i, herr)
			}
			sourceHeads[i] = head
		}
		heads, err := buildReplayHeadsFromSourceHeads(ringQ, sourceHeads, omega, rowsPerPoly, fmt.Sprintf("%s[%d]", name, comp))
		if err != nil {
			return nil, err
		}
		for block := 0; block < rowsPerPoly; block++ {
			head := heads[block]
			out = append(out, intGenISISRowMaterial{Poly: makeRowFromHead(head), Head: head})
		}
	}
	return out, nil
}

func intGenISISMessageBindingResiduals(ringQ *ring.Ring, M, mAttr, k []*ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(M) != len(mAttr) || len(M) != len(k) {
		return nil, fmt.Errorf("semantic rows mismatch M=%d m=%d k=%d", len(M), len(mAttr), len(k))
	}
	out := make([]*ring.Poly, len(M))
	for i := range M {
		if M[i] == nil || mAttr[i] == nil || k[i] == nil {
			return nil, fmt.Errorf("nil semantic row %d", i)
		}
		res := ringQ.NewPoly()
		ring.Copy(M[i], res)
		ringQ.Sub(res, mAttr[i], res)
		ringQ.Sub(res, k[i], res)
		ringQ.NTT(res, res)
		out[i] = res
	}
	return out, nil
}

func intGenISISRangeMembershipRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, indices []int, bound int64) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if bound <= 0 {
		return nil, nil, fmt.Errorf("invalid IntGenISIS bound %d", bound)
	}
	if len(indices) == 0 {
		return nil, nil, nil
	}
	selected := make([]*ring.Poly, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return nil, nil, fmt.Errorf("invalid IntGenISIS bound row index %d", idx)
		}
		selected = append(selected, rowsNTT[idx])
	}
	spec := NewRangeMembershipSpec(ringQ.Modulus[0], int(bound))
	return buildFparRangeMembershipComposeFormalCoeffs(ringQ, selected, spec)
}

func intGenISISTernaryMembershipRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, indices []int) ([]*ring.Poly, [][]uint64, error) {
	return intGenISISRangeMembershipRows(ringQ, rowsNTT, indices, intGenISISTernaryBound)
}

func intGenISISLiveMembershipRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, indices []int, bound int64) ([]*ring.Poly, [][]uint64, error) {
	return intGenISISRangeMembershipRows(ringQ, rowsNTT, indices, bound)
}

func intGenISISMembershipDegree(bound int64) int {
	if bound <= 0 {
		bound = intGenISISDefaultBound
	}
	return int(2*bound + 1)
}

func rejectIntGenISISMSECompressionForBound(bound int64, level int) error {
	if level <= 0 {
		return nil
	}
	if bound != intGenISISTernaryBound {
		return fmt.Errorf("IntGenISIS M/s/e compression level %d requires ternary bound 1; B=%d bounded-range compression is disabled", level, bound)
	}
	return nil
}

type IntGenISISDegreeMetadata struct {
	ParallelAlgDegree    int    `json:"parallel_alg_degree"`
	AggregatedAlgDegree  int    `json:"aggregated_alg_degree"`
	PaperConservativeDQ  int    `json:"paper_conservative_dq"`
	MaskDegreeBound      int    `json:"mask_degree_bound"`
	DominantDegreeSource string `json:"dominant_degree_source"`
	TernaryDegree        int    `json:"ternary_degree"`
	ShortnessDegree      int    `json:"shortness_degree,omitempty"`
	PolicyDegree         int    `json:"policy_degree,omitempty"`
	SignatureDegree      int    `json:"signature_degree,omitempty"`
	CompressionLevel     int    `json:"compression_level,omitempty"`
	CompressionPackWidth int    `json:"compression_pack_width,omitempty"`
	CompressionDegree    int    `json:"compression_degree,omitempty"`
}

func intGenISISPolicyDegree(_ credential.IntGenISISPolicy) int {
	return 1
}

func intGenISISDegreeMetadataForLayout(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, opts SimOpts) (IntGenISISDegreeMetadata, error) {
	if ringQ == nil {
		return IntGenISISDegreeMetadata{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	s := opts.NCols
	if s <= 0 {
		s = layout.RingDegree
	}
	if s <= 0 {
		s = int(ringQ.N)
	}
	ell := opts.Ell
	if ell <= 0 {
		ell = 1
	}
	meta := IntGenISISDegreeMetadata{
		TernaryDegree: intGenISISMembershipDegree(pub.BoundB),
		PolicyDegree:  1,
	}
	compressionDesc, err := intGenISISMSECompressionDescriptorForBound(opts.IntGenISISMSECompression, pub.BoundB)
	if err != nil {
		return IntGenISISDegreeMetadata{}, err
	}
	meta.CompressionLevel = compressionDesc.Level
	meta.CompressionPackWidth = compressionDesc.PackWidth
	if compressionDesc.Level > 0 {
		meta.CompressionDegree = compressionDesc.MembershipDeg
	}
	switch {
	case layout.IntGenISISPreSign != nil:
		policy, err := intGenISISPolicyFromPublic(pub)
		if err != nil {
			return IntGenISISDegreeMetadata{}, err
		}
		meta.PolicyDegree = intGenISISPolicyDegree(policy)
		meta.ParallelAlgDegree = maxInt(maxInt(1, meta.TernaryDegree), meta.PolicyDegree)
		meta.AggregatedAlgDegree = 1
		meta.DominantDegreeSource = intGenISISDominantDegreeSource([]struct {
			name string
			deg  int
		}{
			{"bounded_range", meta.TernaryDegree},
			{"policy", meta.PolicyDegree},
			{"linear", 1},
		})
	case layout.IntGenISISShowing != nil:
		l := layout.IntGenISISShowing
		if compressionDesc.Level > 0 {
			meta.TernaryDegree = compressionDesc.MembershipDeg
		}
		sigBound, err := intGenISISSignatureBoundFromPublic(pub)
		if err != nil {
			return IntGenISISDegreeMetadata{}, err
		}
		shortSpec, err := intGenISISUShortnessLayoutSpec(ringQ, l, sigBound)
		if err != nil {
			return IntGenISISDegreeMetadata{}, err
		}
		shortDegree, err := signatureShortnessMaxDegree(shortSpec, SimOpts{})
		if err != nil {
			return IntGenISISDegreeMetadata{}, err
		}
		meta.ShortnessDegree = maxInt(shortDegree, intGenISISDirectSignatureRangeDegree(sigBound))
		meta.SignatureDegree = 2
		meta.ParallelAlgDegree = maxInt(maxInt(maxInt(meta.SignatureDegree, meta.TernaryDegree), meta.ShortnessDegree), meta.PolicyDegree)
		meta.AggregatedAlgDegree = 2
		if compressionDesc.Level > 0 {
			meta.AggregatedAlgDegree = maxInt(meta.AggregatedAlgDegree, compressionDesc.DecodeDegree)
		}
		meta.DominantDegreeSource = intGenISISDominantDegreeSource([]struct {
			name string
			deg  int
		}{
			{"shortness", meta.ShortnessDegree},
			{"compression", meta.CompressionDegree},
			{"bounded_range", meta.TernaryDegree},
			{"signature", meta.SignatureDegree},
			{"policy", meta.PolicyDegree},
		})
	default:
		return IntGenISISDegreeMetadata{}, fmt.Errorf("proof is not an IntGenISIS relation")
	}
	meta.PaperConservativeDQ = computeDQFromConstraintDegrees(meta.ParallelAlgDegree, meta.AggregatedAlgDegree, s, ell)
	if opts.DQOverride > 0 {
		if opts.DQOverride < meta.PaperConservativeDQ {
			return IntGenISISDegreeMetadata{}, fmt.Errorf("dQ override=%d below IntGenISIS paper-conservative dQ=%d", opts.DQOverride, meta.PaperConservativeDQ)
		}
		meta.PaperConservativeDQ = opts.DQOverride
	}
	meta.MaskDegreeBound = meta.PaperConservativeDQ
	return meta, nil
}

func IntGenISISDegreeMetadataForProof(proof *Proof, pub PublicInputs, opts SimOpts) (IntGenISISDegreeMetadata, error) {
	if proof == nil {
		return IntGenISISDegreeMetadata{}, fmt.Errorf("nil proof")
	}
	ringN := proof.RingDegree
	if ringN == 0 {
		ringN = proof.RowLayout.RingDegree
	}
	ringQ, err := credential.LoadRingWithDegree(ringN)
	if err != nil {
		return IntGenISISDegreeMetadata{}, err
	}
	if proof.NColsUsed > 0 {
		opts.NCols = proof.NColsUsed
	}
	return intGenISISDegreeMetadataForLayout(ringQ, pub, proof.RowLayout, opts)
}

func validateIntGenISISProofDegreeMetadata(proof *Proof, pub PublicInputs, opts SimOpts) error {
	if proof != nil && proof.RowLayout.IntGenISISShowing != nil {
		got := proof.RowLayout.IntGenISISShowing.MSECompressionLevel
		want := opts.IntGenISISMSECompression
		if want < 0 {
			want = 0
		}
		if got != want {
			return fmt.Errorf("IntGenISIS M/s/e compression level=%d want verifier option %d", got, want)
		}
		gotProjection := intGenISISProjectionModeFromLayout(proof.RowLayout.IntGenISISShowing)
		wantProjection := normalizeIntGenISISReplayProjection(opts.IntGenISISReplayProjection)
		if gotProjection != wantProjection {
			return fmt.Errorf("IntGenISIS replay projection=%q want verifier option %q", gotProjection, wantProjection)
		}
	}
	meta, err := IntGenISISDegreeMetadataForProof(proof, pub, opts)
	if err != nil {
		return err
	}
	if proof.MaskDegreeBound != meta.MaskDegreeBound {
		return fmt.Errorf("IntGenISIS mask_degree_bound=%d want paper-conservative dQ=%d", proof.MaskDegreeBound, meta.MaskDegreeBound)
	}
	if proof.QDegreeBound != meta.PaperConservativeDQ {
		return fmt.Errorf("IntGenISIS q_degree_bound=%d want paper-conservative dQ=%d", proof.QDegreeBound, meta.PaperConservativeDQ)
	}
	return nil
}

func intGenISISDominantDegreeSource(items []struct {
	name string
	deg  int
}) string {
	bestName := ""
	bestDeg := -1
	for _, item := range items {
		if item.deg > bestDeg {
			bestDeg = item.deg
			bestName = item.name
		}
	}
	return bestName
}

func intGenISISCoeffViewRowMaterials(ringQ *ring.Ring, omega []uint64, rows []*ring.Poly, ncols int, interp *omegaInterpolationPlan) ([]intGenISISRowMaterial, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) < ncols {
		return nil, fmt.Errorf("omega len=%d < ncols=%d", len(omega), ncols)
	}
	if ncols <= 0 || int(ringQ.N)%ncols != 0 {
		return nil, fmt.Errorf("invalid coefficient view ncols=%d for ring_degree=%d", ncols, ringQ.N)
	}
	if interp == nil {
		var err error
		interp, err = newOmegaInterpolationPlan(omega[:ncols], ringQ.Modulus[0])
		if err != nil {
			return nil, err
		}
	}
	q := ringQ.Modulus[0]
	out := make([]intGenISISRowMaterial, 0, len(rows)*int(ringQ.N)/ncols)
	for rowIdx, row := range rows {
		if row == nil || len(row.Coeffs) == 0 || len(row.Coeffs[0]) != int(ringQ.N) {
			return nil, fmt.Errorf("invalid coefficient view source row %d", rowIdx)
		}
		for start := 0; start < int(ringQ.N); start += ncols {
			head := make([]uint64, ncols)
			for i := 0; i < ncols; i++ {
				head[i] = row.Coeffs[0][start+i] % q
			}
			coeff := interp.coeffPolyFromHead(ringQ, head)
			out = append(out, intGenISISRowMaterial{Poly: coeff, Head: head})
		}
	}
	return out, nil
}

func intGenISISCoeffViewRows(ringQ *ring.Ring, omega []uint64, rows []*ring.Poly, ncols int) ([]*ring.Poly, error) {
	mats, err := intGenISISCoeffViewRowMaterials(ringQ, omega, rows, ncols, nil)
	if err != nil {
		return nil, err
	}
	return intGenISISRowMaterialPolys(mats), nil
}

func intGenISISUShortnessDigitRowMaterials(ringQ *ring.Ring, omega []uint64, uRows []*ring.Poly, ncols int, spec LinfSpec, interp *omegaInterpolationPlan) ([]intGenISISRowMaterial, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if spec.UsesAbsRow {
		return nil, fmt.Errorf("IntGenISIS u shortness requires signed digit spec")
	}
	if spec.R <= 1 || spec.R%2 == 0 || spec.L <= 0 {
		return nil, fmt.Errorf("unexpected IntGenISIS shortness spec R=%d L=%d", spec.R, spec.L)
	}
	if len(omega) < ncols {
		return nil, fmt.Errorf("omega len=%d < ncols=%d", len(omega), ncols)
	}
	if ncols <= 0 || int(ringQ.N)%ncols != 0 {
		return nil, fmt.Errorf("invalid coefficient view ncols=%d for ring_degree=%d", ncols, ringQ.N)
	}
	if interp == nil {
		var err error
		interp, err = newOmegaInterpolationPlan(omega[:ncols], ringQ.Modulus[0])
		if err != nil {
			return nil, err
		}
	}
	q := ringQ.Modulus[0]
	out := make([]intGenISISRowMaterial, 0, len(uRows)*(int(ringQ.N)/ncols)*spec.L)
	for rowIdx, row := range uRows {
		if row == nil || len(row.Coeffs) == 0 || len(row.Coeffs[0]) != int(ringQ.N) {
			return nil, fmt.Errorf("invalid u shortness source row %d", rowIdx)
		}
		for start := 0; start < int(ringQ.N); start += ncols {
			heads := make([][]uint64, spec.L)
			for lane := range heads {
				heads[lane] = make([]uint64, ncols)
			}
			for j := 0; j < ncols; j++ {
				value := centeredLift(row.Coeffs[0][start+j]%q, q)
				digits, err := decomposeLinfDigitsSigned(value, spec)
				if err != nil {
					return nil, fmt.Errorf("u shortness row %d coeff %d: %w", rowIdx, start+j, err)
				}
				for lane, digit := range digits {
					heads[lane][j] = liftToField(q, digit)
				}
			}
			for lane := 0; lane < spec.L; lane++ {
				head := append([]uint64(nil), heads[lane]...)
				coeff := interp.coeffPolyFromHead(ringQ, head)
				out = append(out, intGenISISRowMaterial{Poly: coeff, Head: head})
			}
		}
	}
	return out, nil
}

func intGenISISUShortnessDigitRows(ringQ *ring.Ring, omega []uint64, uRows []*ring.Poly, ncols int, spec LinfSpec) ([]*ring.Poly, error) {
	mats, err := intGenISISUShortnessDigitRowMaterials(ringQ, omega, uRows, ncols, spec, nil)
	if err != nil {
		return nil, err
	}
	return intGenISISRowMaterialPolys(mats), nil
}

func intGenISISViewRowIndices(start, count int) []int {
	out := make([]int, count)
	for i := range out {
		out[i] = start + i
	}
	return out
}

func intGenISISEvalMembership(q uint64, coeffs []uint64, v uint64) uint64 {
	return EvalPoly(coeffs, v%q, q) % q
}

func intGenISISEvalKPolyAtElem(K *kf.Field, coeffs []uint64, x kf.Elem) kf.Elem {
	if K == nil || len(coeffs) == 0 {
		return K.Zero()
	}
	out := K.EmbedF(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		out = K.Add(K.Mul(out, x), K.EmbedF(coeffs[i]))
	}
	return out
}

func intGenISISPolicyRows(
	ringQ *ring.Ring,
	policy credential.IntGenISISPolicy,
	layout credential.SemanticMessageLayout,
	omega []uint64,
) ([][]uint64, error) {
	if policy.ID == "" || policy.ID == credential.IntGenISISPolicyNoop {
		return nil, nil
	}
	if policy.ID != credential.IntGenISISPolicyMEquals {
		return nil, fmt.Errorf("unsupported IntGenISIS policy %q", policy.ID)
	}
	var data credential.IntGenISISMEqualsPolicyData
	if err := json.Unmarshal(policy.Data, &data); err != nil {
		return nil, fmt.Errorf("decode m_eq policy data: %w", err)
	}
	if len(data.MAttr) != layout.AttributeRows {
		return nil, fmt.Errorf("policy m rows=%d want %d", len(data.MAttr), layout.AttributeRows)
	}
	out := make([][]uint64, len(data.MAttr))
	for i := range data.MAttr {
		if len(data.MAttr[i]) != layout.RingDegree {
			return nil, fmt.Errorf("policy m[%d] length=%d want %d", i, len(data.MAttr[i]), layout.RingDegree)
		}
		theta, err := thetaPolyFromCoeff(ringQ, data.MAttr[i], omega)
		if err != nil {
			return nil, fmt.Errorf("policy m[%d] theta: %w", i, err)
		}
		coeff, err := coeffFromNTTPoly(ringQ, theta)
		if err != nil {
			return nil, fmt.Errorf("policy m[%d] coeffs: %w", i, err)
		}
		out[i] = trimPoly(coeff, ringQ.Modulus[0])
	}
	return out, nil
}

func intGenISISPolicyCoeffViewCoeffs(
	ringQ *ring.Ring,
	policy credential.IntGenISISPolicy,
	layout credential.SemanticMessageLayout,
	omega []uint64,
	ncols int,
) ([][]uint64, error) {
	if policy.ID == "" || policy.ID == credential.IntGenISISPolicyNoop {
		return nil, nil
	}
	if policy.ID != credential.IntGenISISPolicyMEquals {
		return nil, fmt.Errorf("unsupported IntGenISIS policy %q", policy.ID)
	}
	var data credential.IntGenISISMEqualsPolicyData
	if err := json.Unmarshal(policy.Data, &data); err != nil {
		return nil, fmt.Errorf("decode m_eq policy data: %w", err)
	}
	if len(data.MAttr) != layout.AttributeRows {
		return nil, fmt.Errorf("policy m rows=%d want %d", len(data.MAttr), layout.AttributeRows)
	}
	polys := make([]*ring.Poly, len(data.MAttr))
	q := int64(ringQ.Modulus[0])
	for i := range data.MAttr {
		if len(data.MAttr[i]) != layout.RingDegree {
			return nil, fmt.Errorf("policy m[%d] length=%d want %d", i, len(data.MAttr[i]), layout.RingDegree)
		}
		polys[i] = ringQ.NewPoly()
		for j, v := range data.MAttr[i] {
			v %= q
			if v < 0 {
				v += q
			}
			polys[i].Coeffs[0][j] = uint64(v)
		}
	}
	viewRows, err := intGenISISCoeffViewRows(ringQ, omega, polys, ncols)
	if err != nil {
		return nil, err
	}
	out := make([][]uint64, len(viewRows))
	for i := range viewRows {
		ntt := ringQ.NewPoly()
		ring.Copy(viewRows[i], ntt)
		ringQ.NTT(ntt, ntt)
		coeff, err := coeffFromNTTPoly(ringQ, ntt)
		if err != nil {
			return nil, err
		}
		out[i] = trimPoly(coeff, ringQ.Modulus[0])
	}
	return out, nil
}
