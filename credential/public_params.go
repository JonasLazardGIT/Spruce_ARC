package credential

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"

	"vSIS-Signature/commitment"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const DefaultPublicParamsPath = "internal/source_data/credential_public.intgenisis_profile_b.json"
const PublicParamsVersion = 8
const MuLayoutFullCapacityHalvesV1 = "full_capacity_halves_v1"

// PublicParams captures the stable credential-side public parameters used by
// issuance and showing.
type PublicParams struct {
	Version              int                           `json:"version"`
	Profile              string                        `json:"profile"`
	PresetID             string                        `json:"preset_id"`
	PresetVersion        int                           `json:"preset_version"`
	PrimitiveProfileID   string                        `json:"primitive_profile_id"`
	PRFProfile           string                        `json:"prf_profile"`
	TranscriptMode       string                        `json:"transcript_mode"`
	PresetManifestDigest string                        `json:"preset_manifest_digest"`
	RateLimitPolicy      RateLimitPolicy               `json:"rate_limit_policy"`
	Modulus              uint64                        `json:"q,omitempty"`
	HashRelation         string                        `json:"hash_relation"`
	Ac                   commitment.CoeffMatrix        `json:"Ac,omitempty"`
	CM                   commitment.CoeffMatrix        `json:"C_M,omitempty"`
	AS                   commitment.CoeffMatrix        `json:"A_s,omitempty"`
	BPath                string                        `json:"BPath"`
	BoundB               int64                         `json:"BoundB"`
	CommitmentBound      int64                         `json:"B,omitempty"`
	EllM                 int                           `json:"ell_M,omitempty"`
	KS                   int                           `json:"k_s,omitempty"`
	NC                   int                           `json:"n_c,omitempty"`
	EllMuSig             int                           `json:"ell_mu_sig,omitempty"`
	EllX0                int                           `json:"ell_x0,omitempty"`
	EllX1                int                           `json:"ell_x1,omitempty"`
	HashInputBound       int64                         `json:"hash_input_bound,omitempty"`
	SignaturePreimageLen int                           `json:"signature_preimage_len,omitempty"`
	MLWEHidingBits       float64                       `json:"mlwe_hiding_bits,omitempty"`
	MSISBindingBits      float64                       `json:"msis_binding_bits,omitempty"`
	CommitmentSecurity   *IntGenISISCommitmentSecurity `json:"commitment_security,omitempty"`
	X0Len                int                           `json:"X0Len,omitempty"`
	X0CoeffBound         int64                         `json:"X0CoeffBound,omitempty"`
	TargetDim            int                           `json:"TargetDim,omitempty"`
	TargetHidingLambda   int                           `json:"TargetHidingLambda,omitempty"`
	RingDegree           int                           `json:"ring_degree,omitempty"`
	X0Distribution       string                        `json:"X0Distribution,omitempty"`
	LenMu                int                           `json:"LenMu,omitempty"`
	MuLayout             string                        `json:"MuLayout,omitempty"`
	LenM                 int                           `json:"LenM,omitempty"`
	LenK                 int                           `json:"LenK,omitempty"`
	LenR0H               int                           `json:"LenR0H,omitempty"`
	LenR1H               int                           `json:"LenR1H,omitempty"`
	LenRBar              int                           `json:"LenRBar,omitempty"`
}

func (pp PublicParams) UsesIntGenISIS() bool {
	if pp.Profile != "" {
		if _, ok := LookupIntGenISISProfile(pp.Profile); ok {
			return true
		}
	}
	return len(pp.CM) > 0 || len(pp.AS) > 0
}

func (pp *PublicParams) Validate() error {
	if pp == nil {
		return fmt.Errorf("nil public parameters")
	}
	if pp.Version != PublicParamsVersion {
		return noMigrationSchemaError("public-parameters", pp.Version, PublicParamsVersion)
	}
	if err := pp.RateLimitPolicy.ValidateV2(); err != nil {
		return err
	}
	if err := ValidateHashRelation(pp.HashRelation); err != nil {
		return err
	}
	if pp.BPath == "" {
		return fmt.Errorf("missing BPath")
	}
	if pp.BoundB <= 0 {
		return fmt.Errorf("invalid BoundB=%d", pp.BoundB)
	}
	if pp.Modulus != 0 {
		if err := validateCoeffMatrixModulus("Ac", pp.Ac, pp.Modulus); err != nil {
			return err
		}
		if err := validateCoeffMatrixModulus("C_M", pp.CM, pp.Modulus); err != nil {
			return err
		}
		if err := validateCoeffMatrixModulus("A_s", pp.AS, pp.Modulus); err != nil {
			return err
		}
	}
	if !pp.UsesIntGenISIS() {
		return fmt.Errorf("public-parameters schema %d supports only canonical IntGenISIS artifacts", PublicParamsVersion)
	}
	if err := pp.validatePresetBinding(); err != nil {
		return err
	}
	return pp.validateIntGenISIS()
}

func (pp PublicParams) HasPresetBinding() bool {
	return pp.PresetID != "" || pp.PresetVersion != 0 || pp.PrimitiveProfileID != "" || pp.PRFProfile != "" || pp.TranscriptMode != "" || pp.PresetManifestDigest != ""
}

func (pp *PublicParams) BindIntGenISISPreset(preset IntGenISISPreset) error {
	if preset.CanonicalID == "" || preset.PresetVersion <= 0 {
		return fmt.Errorf("preset %q is missing canonical manifest metadata", preset.Name)
	}
	if pp.Profile != "" && pp.Profile != preset.Profile {
		return fmt.Errorf("public parameter profile %q does not match preset primitive profile %q", pp.Profile, preset.Profile)
	}
	pp.PresetID = preset.CanonicalID
	pp.PresetVersion = preset.PresetVersion
	pp.PrimitiveProfileID = preset.PrimitiveProfileID
	pp.PRFProfile = preset.PRFProfile
	pp.TranscriptMode = preset.Showing.TranscriptMode
	pp.PresetManifestDigest = IntGenISISPresetManifestDigest(preset)
	pp.RateLimitPolicy = preset.RateLimitPolicy
	return pp.validatePresetBinding()
}

func (pp PublicParams) ValidateIntGenISISPreset(preset IntGenISISPreset) error {
	if !pp.HasPresetBinding() {
		return fmt.Errorf("public parameters are not bound to a canonical preset manifest")
	}
	if pp.PresetID != preset.CanonicalID {
		return fmt.Errorf("public parameter preset_id=%q does not match selected preset %q", pp.PresetID, preset.CanonicalID)
	}
	if pp.PresetVersion != preset.PresetVersion {
		return fmt.Errorf("public parameter preset_version=%d does not match selected preset version %d", pp.PresetVersion, preset.PresetVersion)
	}
	if pp.Profile != preset.Profile || pp.PrimitiveProfileID != preset.PrimitiveProfileID {
		return fmt.Errorf("public parameter primitive profile does not match selected preset")
	}
	if pp.PRFProfile != preset.PRFProfile || pp.TranscriptMode != preset.Showing.TranscriptMode {
		return fmt.Errorf("public parameter PRF/transcript binding does not match selected preset")
	}
	if pp.RateLimitPolicy != preset.RateLimitPolicy {
		return fmt.Errorf("public parameter rate-limit policy does not match selected preset")
	}
	wantDigest := IntGenISISPresetManifestDigest(preset)
	if pp.PresetManifestDigest != wantDigest {
		return fmt.Errorf("public parameter preset manifest digest=%q want=%q", pp.PresetManifestDigest, wantDigest)
	}
	return nil
}

// PresetTranscriptExtras returns canonical byte values suitable for PIOP's
// public-input Fiat-Shamir binding. Existing entries are copied.
func (pp PublicParams) PresetTranscriptExtras(existing map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(existing)+19)
	for key, value := range existing {
		out[key] = value
	}
	out["IntGenISIS.preset_id"] = []byte(pp.PresetID)
	out["IntGenISIS.preset_version"] = []byte(fmt.Sprintf("%d", pp.PresetVersion))
	out["IntGenISIS.primitive_profile_id"] = []byte(pp.PrimitiveProfileID)
	out["IntGenISIS.prf_profile"] = []byte(pp.PRFProfile)
	out["IntGenISIS.transcript_mode"] = []byte(pp.TranscriptMode)
	_, transcriptVersion, err := ResolveIntGenISISTranscript(pp.TranscriptMode)
	if err != nil {
		panic("resolve bound IntGenISIS transcript: " + err.Error())
	}
	out["IntGenISIS.transcript_version"] = []byte(transcriptVersion)
	out["IntGenISIS.preset_manifest_digest"] = []byte(pp.PresetManifestDigest)
	if transcriptVersion == IntGenISISTranscriptVersionV3 || transcriptVersion == IntGenISISTranscriptVersionV4 {
		preset, ok := LookupIntGenISISPreset(pp.PresetID)
		wantManifestVersion := IntGenISISPresetManifestVersionV3
		if transcriptVersion == IntGenISISTranscriptVersionV4 {
			wantManifestVersion = IntGenISISPresetManifestVersionV4
		}
		if !ok || preset.PresetVersion != wantManifestVersion {
			panic("strict public parameters do not resolve to the matching preset-manifest epoch")
		}
		profile, ok := kf.LookupSmallWoodFieldProfileV3(pp.Modulus, preset.Showing.Theta)
		if !ok || profile.ID != preset.FieldProfileID {
			panic("strict public parameters do not resolve to their fixed field profile")
		}
		out["IntGenISIS.field_profile_id"] = []byte(profile.ID)
		out["IntGenISIS.field_profile_digest"] = []byte(preset.FieldProfileDigest)
		// The complete profile is absorbed. Its digest is an identity/checksum,
		// not a security-critical compression of Chi or omegaExtra.
		out["IntGenISIS.field_profile"] = profile.CanonicalBytes()
		params, canonicalPRF, err := prf.LoadEmbeddedTargetParamsV3(preset.PRFParamsPath)
		if err != nil {
			panic("load bound strict PRF profile: " + err.Error())
		}
		embeddedDigest, err := prf.EmbeddedTargetParamsFileDigestV3(preset.PRFParamsPath)
		if err != nil || embeddedDigest != preset.PRFParamsDigest {
			panic("embedded strict PRF source does not match its pinned preset digest")
		}
		wantTag, ok := IntGenISISPRFProfileTagElements(preset.PRFProfile)
		if !ok || params.Q != pp.Modulus || params.LenTag != wantTag {
			panic("strict PRF profile does not match its preset/public field binding")
		}
		// As with the field profile, absorb every executed PRF constant. The
		// historical SHA-256 file digest remains an identifier/checksum only.
		out["IntGenISIS.prf_params"] = canonicalPRF
		// Bind the complete schema-v3 manifest directly. The historical
		// SHA-256 manifest digest remains an identifier, never the sole
		// security-critical statement binding on the v3 path.
		out["IntGenISIS.preset_manifest"] = IntGenISISPresetManifestCanonicalBytes(preset)
		out["IntGenISIS.proof_schema_version"] = []byte(fmt.Sprintf("%d", preset.ProofSchemaVersion))
		out["IntGenISIS.relation_version"] = []byte(fmt.Sprintf("%d", preset.RelationVersion))
		out["IntGenISIS.layout_version"] = []byte(fmt.Sprintf("%d", preset.LayoutVersion))
		out["IntGenISIS.state_format_version"] = []byte(fmt.Sprintf("%d", preset.StateFormatVersion))
		out["IntGenISIS.presentation_format_version"] = []byte(fmt.Sprintf("%d", preset.PresentationVersion))
		out["IntGenISIS.issuance_artifact_format_version"] = []byte(fmt.Sprintf("%d", preset.IssuanceVersion))
		out["IntGenISIS.holder_usage_format_version"] = []byte(fmt.Sprintf("%d", preset.HolderUsageVersion))
	}
	policy, err := json.Marshal(pp.RateLimitPolicy)
	if err != nil {
		panic("marshal fixed IntGenISIS rate-limit policy: " + err.Error())
	}
	out["IntGenISIS.rate_limit_policy"] = policy
	return out
}

func (pp *PublicParams) validatePresetBinding() error {
	if !pp.HasPresetBinding() {
		return fmt.Errorf("public parameters are not bound to a canonical preset manifest")
	}
	if pp.PresetID == "" || pp.PresetVersion <= 0 || pp.PrimitiveProfileID == "" || pp.PRFProfile == "" || pp.TranscriptMode == "" || pp.PresetManifestDigest == "" {
		return fmt.Errorf("incomplete IntGenISIS preset binding")
	}
	preset, ok := LookupIntGenISISPreset(pp.PresetID)
	if !ok {
		return fmt.Errorf("unknown bound IntGenISIS preset %q", pp.PresetID)
	}
	if pp.Profile != preset.Profile || pp.PrimitiveProfileID != preset.PrimitiveProfileID {
		return fmt.Errorf("bound primitive profile mismatch")
	}
	if pp.PRFProfile != preset.PRFProfile || pp.TranscriptMode != preset.Showing.TranscriptMode {
		return fmt.Errorf("bound PRF/transcript profile mismatch")
	}
	return pp.ValidateIntGenISISPreset(preset)
}

func (pp *PublicParams) validateIntGenISIS() error {
	profile, ok := LookupIntGenISISProfile(pp.Profile)
	if !ok || pp.Profile == "" {
		return fmt.Errorf("unsupported IntGenISIS profile %q", pp.Profile)
	}
	if len(pp.Ac) != 0 || pp.X0CoeffBound != 0 || pp.TargetHidingLambda != 0 || pp.X0Distribution != "" || pp.LenMu != 0 || pp.MuLayout != "" || pp.LenM != 0 || pp.LenK != 0 || pp.LenR0H != 0 || pp.LenR1H != 0 || pp.LenRBar != 0 {
		return fmt.Errorf("public-parameters schema %d contains removed legacy commitment fields", PublicParamsVersion)
	}
	if pp.CommitmentBound <= 0 {
		return fmt.Errorf("invalid commitment bound B=%d", pp.CommitmentBound)
	}
	if pp.BoundB != profile.B || pp.CommitmentBound != profile.B {
		return fmt.Errorf("IntGenISIS bounds must match profile B=%d, got BoundB=%d B=%d", profile.B, pp.BoundB, pp.CommitmentBound)
	}
	if pp.Modulus != profile.Q {
		return fmt.Errorf("q=%d want profile modulus %d", pp.Modulus, profile.Q)
	}
	if pp.RingDegree != profile.N {
		return fmt.Errorf("ring_degree=%d want %d", pp.RingDegree, profile.N)
	}
	if pp.EllM != profile.EllM || pp.KS != profile.KS || pp.NC != profile.NC {
		return fmt.Errorf("commitment dimensions ell_M/k_s/n_c=%d/%d/%d want %d/%d/%d", pp.EllM, pp.KS, pp.NC, profile.EllM, profile.KS, profile.NC)
	}
	if pp.EllMuSig != profile.EllMuSig || pp.EllX0 != profile.EllX0 || pp.EllX1 != profile.EllX1 {
		return fmt.Errorf("hash dimensions ell_mu_sig/ell_x0/ell_x1=%d/%d/%d want %d/%d/%d", pp.EllMuSig, pp.EllX0, pp.EllX1, profile.EllMuSig, profile.EllX0, profile.EllX1)
	}
	if pp.HashInputBound != profile.HashInputBound {
		return fmt.Errorf("hash_input_bound=%d want %d", pp.HashInputBound, profile.HashInputBound)
	}
	if pp.SignaturePreimageLen != profile.SignaturePreimageLen {
		return fmt.Errorf("signature_preimage_len=%d want %d", pp.SignaturePreimageLen, profile.SignaturePreimageLen)
	}
	if pp.TargetDim != pp.NC {
		return fmt.Errorf("target_dim=%d must match n_c=%d", pp.TargetDim, pp.NC)
	}
	if pp.X0Len != pp.EllX0 {
		return fmt.Errorf("stored X0Len=%d must match ell_x0=%d", pp.X0Len, pp.EllX0)
	}
	if !closeSecurityFloat(pp.MLWEHidingBits, profile.MLWEHidingBits) || !closeSecurityFloat(pp.MSISBindingBits, profile.MSISBindingBits) || pp.CommitmentSecurity == nil || !equalIntGenISISCommitmentSecurity(*pp.CommitmentSecurity, profile.CommitmentSecurity) {
		return fmt.Errorf("commitment security metadata does not match profile %q", profile.Name)
	}
	if err := validateCoeffMatrixDims("C_M", pp.CM, pp.NC, pp.EllM, pp.RingDegree); err != nil {
		return err
	}
	if err := validateCoeffMatrixDims("A_s", pp.AS, pp.NC, pp.KS, pp.RingDegree); err != nil {
		return err
	}
	return nil
}

func closeSecurityFloat(a, b float64) bool {
	const tolerance = 1e-9
	return math.Abs(a-b) <= tolerance
}

// equalIntGenISISCommitmentSecurity keeps exact checks for identities,
// assumptions, bounds, and models while allowing harmless decimal round-trip
// differences in estimator outputs stored in JSON fixtures.
func equalIntGenISISCommitmentSecurity(a, b IntGenISISCommitmentSecurity) bool {
	floatFieldsEqual := closeSecurityFloat(a.MLWEHidingBits, b.MLWEHidingBits) &&
		closeSecurityFloat(a.MSISBindingBits, b.MSISBindingBits) &&
		closeSecurityFloat(a.MSISBindingL2Bound, b.MSISBindingL2Bound) &&
		closeSecurityFloat(a.BindingDiffSpaceBits, b.BindingDiffSpaceBits) &&
		closeSecurityFloat(a.StatisticalHidingSlackBits, b.StatisticalHidingSlackBits) &&
		closeSecurityFloat(a.StatisticalBindingSlackBits, b.StatisticalBindingSlackBits)
	a.MLWEHidingBits, b.MLWEHidingBits = 0, 0
	a.MSISBindingBits, b.MSISBindingBits = 0, 0
	a.MSISBindingL2Bound, b.MSISBindingL2Bound = 0, 0
	a.BindingDiffSpaceBits, b.BindingDiffSpaceBits = 0, 0
	a.StatisticalHidingSlackBits, b.StatisticalHidingSlackBits = 0, 0
	a.StatisticalBindingSlackBits, b.StatisticalBindingSlackBits = 0, 0
	return floatFieldsEqual && reflect.DeepEqual(a, b)
}

func validateCoeffMatrixDims(name string, mat commitment.CoeffMatrix, rows, cols, degree int) error {
	if len(mat) != rows {
		return fmt.Errorf("%s rows=%d want %d", name, len(mat), rows)
	}
	for i := range mat {
		if len(mat[i]) != cols {
			return fmt.Errorf("%s row %d cols=%d want %d", name, i, len(mat[i]), cols)
		}
		for j := range mat[i] {
			if len(mat[i][j]) != degree {
				return fmt.Errorf("%s[%d][%d] coefficient length=%d want ring_degree=%d", name, i, j, len(mat[i][j]), degree)
			}
		}
	}
	return nil
}

func validateCoeffMatrixModulus(name string, mat commitment.CoeffMatrix, q uint64) error {
	if q == 0 {
		return nil
	}
	for i := range mat {
		for j := range mat[i] {
			for k, coeff := range mat[i][j] {
				if coeff >= q {
					return fmt.Errorf("%s[%d][%d][%d]=%d outside modulus q=%d", name, i, j, k, coeff, q)
				}
			}
		}
	}
	return nil
}

func LoadPublicParams(path string) (PublicParams, error) {
	var out PublicParams
	data, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("read public params: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &out, "public-parameters", PublicParamsVersion); err != nil {
		return out, fmt.Errorf("decode public params: %w", err)
	}
	if err := (&out).Validate(); err != nil {
		return out, fmt.Errorf("validate public params %s: %w", path, err)
	}
	return out, nil
}

func SavePublicParams(path string, params PublicParams) error {
	if err := (&params).Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal public params: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write public params: %w", err)
	}
	return nil
}

func (pp PublicParams) ToIssuanceParams(ringQ *ring.Ring) (*Params, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if err := (&pp).Validate(); err != nil {
		return nil, err
	}
	if pp.Modulus != 0 && pp.Modulus != ringQ.Modulus[0] {
		return nil, fmt.Errorf("public params q=%d incompatible with selected ring q=%d", pp.Modulus, ringQ.Modulus[0])
	}
	var ac commitment.Matrix
	var err error
	if len(pp.Ac) > 0 {
		ac, err = commitment.MatrixFromCoeff(ringQ, pp.Ac)
		if err != nil {
			return nil, fmt.Errorf("lift Ac to NTT: %w", err)
		}
	}
	var cm commitment.Matrix
	if len(pp.CM) > 0 {
		cm, err = commitment.MatrixFromCoeff(ringQ, pp.CM)
		if err != nil {
			return nil, fmt.Errorf("lift C_M to NTT: %w", err)
		}
	}
	var as commitment.Matrix
	if len(pp.AS) > 0 {
		as, err = commitment.MatrixFromCoeff(ringQ, pp.AS)
		if err != nil {
			return nil, fmt.Errorf("lift A_s to NTT: %w", err)
		}
	}
	return &Params{
		HashRelation:         pp.HashRelation,
		Ac:                   ac,
		CM:                   cm,
		AS:                   as,
		BPath:                pp.BPath,
		Profile:              pp.Profile,
		BoundB:               pp.BoundB,
		CommitmentBound:      pp.CommitmentBound,
		EllM:                 pp.EllM,
		KS:                   pp.KS,
		NC:                   pp.NC,
		EllMuSig:             pp.EllMuSig,
		EllX0:                pp.EllX0,
		EllX1:                pp.EllX1,
		HashInputBound:       pp.HashInputBound,
		SignaturePreimageLen: pp.SignaturePreimageLen,
		X0Len:                pp.X0Len,
		X0CoeffBound:         pp.X0CoeffBound,
		TargetDim:            pp.TargetDim,
		TargetHidingLambda:   pp.TargetHidingLambda,
		RingDegree:           pp.RingDegree,
		X0Distribution:       pp.X0Distribution,
		LenMu:                pp.LenMu,
		MuLayout:             pp.MuLayout,
		LenM:                 pp.LenM,
		LenK:                 pp.LenK,
		LenR0H:               pp.LenR0H,
		LenR1H:               pp.LenR1H,
		LenRBar:              pp.LenRBar,
		RingQ:                ringQ,
	}, nil
}

func (pp PublicParams) ToCommitmentParams(ringQ *ring.Ring) (commitment.TargetParams, error) {
	params, err := pp.ToIssuanceParams(ringQ)
	if err != nil {
		return commitment.TargetParams{}, err
	}
	if len(params.CM) == 0 || len(params.AS) == 0 {
		return commitment.TargetParams{}, fmt.Errorf("public params do not contain IntGenISIS C_M/A_s matrices")
	}
	out := commitment.TargetParams{
		RingQ: ringQ,
		CM:    params.CM,
		AS:    params.AS,
		EllM:  params.EllM,
		KS:    params.KS,
		NC:    params.NC,
		Bound: params.CommitmentBound,
	}
	if err := out.Validate(); err != nil {
		return commitment.TargetParams{}, err
	}
	return out, nil
}
