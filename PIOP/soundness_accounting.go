package PIOP

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	decs "vSIS-Signature/DECS"
)

// FullGameSoundnessReport composes issuance/showing one-proof budgets under
// accepted-proof counts.
type FullGameSoundnessReport struct {
	AcceptedIssuance              int     `json:"accepted_issuance"`
	AcceptedShowing               int     `json:"accepted_showing"`
	IssuanceQueryCaps             [5]int  `json:"issuance_query_caps"`
	ShowingQueryCaps              [5]int  `json:"showing_query_caps"`
	GlobalQueryCaps               [5]int  `json:"global_query_caps"`
	CollisionSpaceBits            int     `json:"collision_space_bits"`
	ConservativeFullGameError     float64 `json:"full_game_conservative"`
	ConservativeFullGameBits      float64 `json:"full_game_conservative_bits"`
	GlobalCollisionFullGameError  float64 `json:"full_game_global_collision"`
	GlobalCollisionFullGameBits   float64 `json:"full_game_global_collision_bits"`
	GlobalCollisionError          float64 `json:"global_collision"`
	GlobalCollisionBits           float64 `json:"global_collision_bits"`
	IssuanceAlgebraicContribution float64 `json:"issuance_algebraic_contribution"`
	ShowingAlgebraicContribution  float64 `json:"showing_algebraic_contribution"`
}

// ParseROQueryCaps parses Q0,Q1,Q2,Q3,Q4 for SmallWood ROM accounting.
func ParseROQueryCaps(s string) ([5]int, error) {
	var caps [5]int
	parts := strings.Split(s, ",")
	if len(parts) != len(caps) {
		return caps, fmt.Errorf("ro-query-caps: expected 5 comma-separated integers Q0,Q1,Q2,Q3,Q4")
	}
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return caps, fmt.Errorf("ro-query-caps: empty Q%d", i)
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return caps, fmt.Errorf("ro-query-caps: invalid Q%d %q", i, part)
		}
		if v < 0 {
			return caps, fmt.Errorf("ro-query-caps: Q%d must be nonnegative", i)
		}
		caps[i] = v
	}
	return caps, nil
}

func ResolveDECSCollisionBits(bits int) int {
	if bits > 0 && bits%8 == 0 && decs.IsSupportedHashBytes(bits/8) {
		return bits
	}
	return decs.DefaultHashBytes * 8
}

func ValidateDECSCollisionBits(bits int) error {
	if bits > 0 && bits%8 == 0 && decs.IsSupportedHashBytes(bits/8) {
		return nil
	}
	return fmt.Errorf("DECS collision bits must be one of %s", DECSCollisionBitsUsage())
}

func ValidateDECSCollisionBytes(hashBytes int) error {
	if decs.IsSupportedHashBytes(hashBytes) {
		return nil
	}
	return fmt.Errorf("DECS collision bytes must be one of %s", decs.SupportedHashBytesList())
}

func DECSCollisionBitsUsage() string {
	return "128,136,144,160,192,224,256"
}

func decsCollisionBytesForOpts(opts SimOpts) int {
	return ResolveDECSCollisionBits(opts.DECSCollisionBits) / 8
}

func applyDECSCollisionWidth(params decs.Params, opts SimOpts) decs.Params {
	width := decsCollisionBytesForOpts(opts)
	params.NonceBytes = width
	params.HashBytes = width
	return params
}

func proofRootBytes(proof *Proof) []byte {
	if proof == nil {
		return nil
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
	if len(proof.QRootHash) > 0 {
		return proof.QRootHash
	}
	return proof.QRoot[:]
}

func proofQRootSerializedSize(proof *Proof) int {
	if proof == nil {
		return 0
	}
	size := len(proof.QRoot)
	if len(proof.QRootHash) > 0 {
		size += len(proof.QRootHash)
	}
	return size
}

func proofHashField(root [16]byte, rootHash []byte) []byte {
	if len(rootHash) > len(root) {
		return append([]byte(nil), rootHash...)
	}
	return nil
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
	if open.NonceBytes > 0 {
		return open.NonceBytes
	}
	min := 0
	for _, nonce := range open.Nonces {
		min = minPositiveInt(min, len(nonce))
	}
	if len(open.NonceSeed) > 0 {
		min = minPositiveInt(min, len(open.NonceSeed))
	}
	return min
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
	var globalCaps [5]int
	for i := range globalCaps {
		globalCaps[i] = acceptedIssuance*issuance.QueryCaps[i] + acceptedShowing*showing.QueryCaps[i]
	}
	globalCollision := collisionError(globalCaps, collisionBits)
	issuanceAlgTotal := soundnessAlgebraicTotal(issuance)
	showingAlgTotal := soundnessAlgebraicTotal(showing)
	issuanceOneProof := soundnessOneProofTotal(issuance)
	showingOneProof := soundnessOneProofTotal(showing)
	issuanceAlg := float64(acceptedIssuance) * issuanceAlgTotal
	showingAlg := float64(acceptedShowing) * showingAlgTotal
	conservative := clampProbability(float64(acceptedIssuance)*issuanceOneProof + float64(acceptedShowing)*showingOneProof)
	global := clampProbability(globalCollision + issuanceAlg + showingAlg)
	return FullGameSoundnessReport{
		AcceptedIssuance:              acceptedIssuance,
		AcceptedShowing:               acceptedShowing,
		IssuanceQueryCaps:             issuance.QueryCaps,
		ShowingQueryCaps:              showing.QueryCaps,
		GlobalQueryCaps:               globalCaps,
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

func collisionError(caps [5]int, collisionSpaceBits int) float64 {
	if collisionSpaceBits <= 0 {
		return 0
	}
	querySquares := 0.0
	for _, cap := range caps {
		if cap > 0 {
			querySquares += float64(cap) * float64(cap)
		}
	}
	if querySquares <= 0 {
		return 0
	}
	return clampProbability(querySquares * math.Pow(2, -float64(collisionSpaceBits)))
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
