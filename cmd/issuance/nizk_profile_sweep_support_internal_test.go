package main

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"vSIS-Signature/PIOP"
)

const (
	nizkProfileMaxSupportedGrinding               = 13
	nizkProfileProjectionProjectUDigitsYWResidual = PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5
)

type nizkProfileBucketDigest struct {
	Q            int `json:"q"`
	R            int `json:"r"`
	Pdecs        int `json:"pdecs"`
	Mdecs        int `json:"mdecs,omitempty"`
	Auth         int `json:"auth"`
	Tapes        int `json:"tapes,omitempty"`
	SigShortness int `json:"sig_shortness"`
	VTargets     int `json:"vtargets"`
	BarSets      int `json:"barsets"`
}

type nizkProfileMetricDigest struct {
	PaperTranscriptBytes     int                               `json:"paper_transcript_bytes"`
	PaperTranscriptKB        float64                           `json:"paper_transcript_kb"`
	Buckets                  nizkProfileBucketDigest           `json:"buckets"`
	TranscriptAudit          PIOP.PaperTranscriptAudit         `json:"transcript_audit,omitempty"`
	TheoremTotalBits         float64                           `json:"theorem_total_bits"`
	CollisionBits            float64                           `json:"collision_bits"`
	AlgebraicBits            [4]float64                        `json:"algebraic_bits"`
	RawRoundBits             [4]float64                        `json:"raw_round_bits"`
	Clamped                  [4]bool                           `json:"clamped"`
	DQ                       int                               `json:"dq"`
	DDECS                    int                               `json:"ddecs"`
	RowsBlock                int                               `json:"rows_block"`
	OpeningCols              int                               `json:"opening_cols"`
	ShortnessRows            int                               `json:"shortness_rows"`
	Theta                    int                               `json:"theta"`
	Rho                      int                               `json:"rho"`
	EllPrime                 int                               `json:"ell_prime"`
	DECSHashBits             int                               `json:"decs_hash_bits"`
	DECSTapeBits             int                               `json:"decs_tape_bits"`
	PDecsBitWidth            int                               `json:"pdecs_bit_width,omitempty"`
	VTargetsBitWidth         int                               `json:"vtargets_bit_width,omitempty"`
	ParallelAlgDegree        int                               `json:"parallel_alg_degree,omitempty"`
	AggregatedAlgDegree      int                               `json:"aggregated_alg_degree,omitempty"`
	DominantDegreeSource     string                            `json:"dominant_degree_source,omitempty"`
	RelationCandidate        benchmarkIntGenISISRelationReport `json:"relation_candidate,omitempty"`
	TranscriptSecurityStatus string                            `json:"transcript_security_status,omitempty"`
	ProvingMS                float64                           `json:"proving_ms"`
	VerificationMS           float64                           `json:"verification_ms"`
}

func nizkProfileMetricDigestFromMetrics(m benchmarkIntGenISISMetrics) nizkProfileMetricDigest {
	return nizkProfileMetricDigest{
		PaperTranscriptBytes: m.PaperTranscriptBytes,
		PaperTranscriptKB:    m.PaperTranscriptKB,
		TranscriptAudit:      m.TranscriptAudit,
		Buckets: nizkProfileBucketDigest{
			Q:            m.QBytes,
			R:            m.RBytes,
			Pdecs:        m.PdecsBytes,
			Mdecs:        m.MdecsBytes,
			Auth:         m.AuthBytes,
			Tapes:        m.TapesBytes,
			SigShortness: m.SigShortnessBytes,
			VTargets:     m.VTargetsBytes,
			BarSets:      m.BarSetsBytes,
		},
		TheoremTotalBits:         m.TheoremTotalBits,
		CollisionBits:            m.CollisionBits,
		AlgebraicBits:            m.AlgebraicBits,
		RawRoundBits:             m.RawRoundBits,
		Clamped:                  m.Clamped,
		DQ:                       m.DQ,
		DDECS:                    m.DDECS,
		RowsBlock:                m.RowsBlock,
		OpeningCols:              m.OpeningCols,
		ShortnessRows:            m.ShortnessRows,
		Theta:                    m.Theta,
		Rho:                      m.Rho,
		EllPrime:                 m.EllPrime,
		DECSHashBits:             m.DECSHashBits,
		DECSTapeBits:             m.DECSTapeBits,
		PDecsBitWidth:            m.PDecsBitWidth,
		VTargetsBitWidth:         m.VTargetsBitWidth,
		ParallelAlgDegree:        m.ParallelAlgDegree,
		AggregatedAlgDegree:      m.AggregatedAlgDegree,
		DominantDegreeSource:     m.DominantDegreeSource,
		RelationCandidate:        m.RelationCandidate,
		TranscriptSecurityStatus: m.TranscriptSecurityStatus,
		ProvingMS:                m.ProvingMS,
		VerificationMS:           m.VerificationMS,
	}
}

func nizkProfileIssuanceFromShowing(showing intGenISISTuning) intGenISISTuning {
	issuance := showing
	issuance.PRFCompanionMode = ""
	issuance.PRFGroupRounds = 0
	issuance.CheckpointSamples = 0
	issuance.SigShortnessRadix = 0
	issuance.SigShortnessDigits = 0
	issuance.CompressedRows = 0
	issuance.ReplayProjection = ""
	return issuance
}

func nizkProfileBoundedUniqueInts(vals []int, lower, upper int) []int {
	seen := make(map[int]struct{}, len(vals))
	out := make([]int, 0, len(vals))
	for _, v := range vals {
		if v < lower || v > upper {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func nizkProfileUniqueStrings(vals []string) []string {
	seen := make(map[string]struct{}, len(vals))
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func nizkProfileSanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "", "-", "", ".", "", "/", "").Replace(s)
}

func nizkProfileEnvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func nizkProfileEnvBool(name string) bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func positiveWindow(center, radius int) []int {
	out := make([]int, 0, 2*radius+1)
	for v := center - radius; v <= center+radius; v++ {
		if v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func ceilDivInt(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
