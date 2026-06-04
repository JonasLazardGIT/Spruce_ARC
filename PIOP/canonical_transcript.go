package PIOP

import (
	"math"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/internal/packedwidth"
)

// PaperTranscriptBucket tracks one paper transcript bucket in bits first, with
// bytes derived by ceiling division only for presentation.
type PaperTranscriptBucket struct {
	NaiveBits      float64 `json:"naive_bits"`
	OptimizedBits  float64 `json:"optimized_bits"`
	NaiveBytes     int     `json:"naive_bytes"`
	OptimizedBytes int     `json:"optimized_bytes"`
}

// PaperTranscriptReport tracks the paper-facing proof transcript buckets. This
// is the optimization target; it intentionally differs from the live verifier
// payload retained in the current Proof object.
type PaperTranscriptReport struct {
	RingDegree   int                   `json:"ring_degree"`
	X0Len        int                   `json:"x0_len"`
	Counters     PaperTranscriptBucket `json:"counters"`
	SaltRoot     PaperTranscriptBucket `json:"salt_root"`
	ExtraHash    PaperTranscriptBucket `json:"extra_hash"`
	R            PaperTranscriptBucket `json:"r"`
	Q            PaperTranscriptBucket `json:"q"`
	SigShortness PaperTranscriptBucket `json:"sig_shortness"`
	VTargets     PaperTranscriptBucket `json:"vtargets"`
	BarSets      PaperTranscriptBucket `json:"barsets"`
	Pdecs        PaperTranscriptBucket `json:"pdecs"`
	Mdecs        PaperTranscriptBucket `json:"mdecs"`
	Auth         PaperTranscriptBucket `json:"auth"`
	Tapes        PaperTranscriptBucket `json:"tapes"`

	NaiveBits      float64 `json:"naive_bits"`
	OptimizedBits  float64 `json:"optimized_bits"`
	NaiveBytes     int     `json:"naive_bytes"`
	OptimizedBytes int     `json:"optimized_bytes"`
}

type openingPaperReport struct {
	PdecsBits float64
	MdecsBits float64
	AuthBits  float64
	TapeBits  float64
}

type paperTranscriptParams struct {
	Lambda     int
	RingDegree int
	X0Len      int
	Eta        int
	Ell        int
	EllPrime   int
	Rho        int
	Theta      int
	DQ         int
	DDECS      int
}

func buildPaperTranscriptReportLeaf(proof *Proof, q uint64, p paperTranscriptParams) PaperTranscriptReport {
	if proof == nil {
		return PaperTranscriptReport{}
	}
	proof.syncPCSCompat()
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()

	logQ := math.Log2(float64(q))
	if p.Lambda <= 0 {
		p.Lambda = 128
	}
	if p.Rho < 1 {
		p.Rho = 1
	}
	if p.Theta < 1 {
		p.Theta = 1
	}
	if p.EllPrime < 1 {
		p.EllPrime = 1
	}
	if p.RingDegree <= 0 {
		p.RingDegree = resolvedProofRingDegree(proof, 0)
	}
	if p.X0Len <= 0 {
		p.X0Len = rowLayoutX0Len(proof.RowLayout)
	}

	rowOpening := resolveProofPCSOpening(proof)
	openingRep := BuildOpeningPaperReport(rowOpening)
	smallField2025Bits := float64(len(smallField2025TranscriptBytes(proof.SmallField2025)) * 8)
	extraMetadataBits := smallField2025Bits

	out := PaperTranscriptReport{
		RingDegree: p.RingDegree,
		X0Len:      p.X0Len,
		Counters:   newPaperBucket(128, 128),
		SaltRoot:   newPaperBucket(float64(4*p.Lambda), float64(4*p.Lambda)),
		ExtraHash:  newPaperBucket(extraMetadataBits, float64(2*p.Lambda)+extraMetadataBits),
		R: newPaperBucket(
			float64(p.Eta)*float64(maxInt(p.DDECS+1, 0))*logQ,
			float64(p.Eta)*float64(maxInt(p.DDECS+1-p.Ell, 0))*logQ,
		),
		Q: newPaperBucket(
			float64(p.Rho*p.DQ*qThetaMultiplier(p.Theta))*logQ,
			float64(p.Rho*maxInt(p.DQ-(p.EllPrime+1), 0)*qThetaMultiplier(p.Theta))*logQ,
		),
		SigShortness: newPaperBucket(sigShortnessPayloadBits(proof.SigShortness), sigShortnessPayloadBits(proof.SigShortness)),
		VTargets:     newPaperBucket(bitsForPackedMatrixPayload(proof.VTargetsBits, proof.VTargets), bitsForPackedMatrixPayload(proof.VTargetsBits, proof.VTargets)),
		BarSets:      newPaperBucket(bitsForPackedMatrixPayload(proof.BarSetsBits, proof.BarSets), bitsForPackedMatrixPayload(proof.BarSetsBits, proof.BarSets)),
		Pdecs:        newPaperBucket(openingRep.PdecsBits, openingRep.PdecsBits),
		Mdecs:        newPaperBucket(openingRep.MdecsBits, openingRep.MdecsBits),
		Auth:         newPaperBucket(openingRep.AuthBits, openingRep.AuthBits),
		Tapes:        newPaperBucket(openingRep.TapeBits, openingRep.TapeBits),
	}
	finalizePaperTranscriptReport(&out)
	return out
}

// BuildOpeningPaperReport decomposes a DECS opening into the four paper-facing
// components used in the proof-size formulas: P residues, M residues,
// authentication material, and tapes/nonces.
func BuildOpeningPaperReport(open *decs.DECSOpening) openingPaperReport {
	if open == nil {
		return openingPaperReport{}
	}
	pdecsBits := residueMetadataBits(open.FormatVersion, open.PColsEncoded, open.POmitCols)
	pdecsBits += residueStreamBits(open.Pvals, open.PvalsBits, open.PvalsBitWidth, open.PvalsColumnWidths, openingAuditPCols(open))

	mdecsBits := residueMetadataBits(open.MFormatVersion, open.MColsEncoded, open.MOmitCols)
	mdecsBits += residueStreamBits(open.Mvals, open.MvalsBits, open.MvalsBitWidth, open.MvalsColumnWidths, openingAuditMCols(open))

	authBits := 0.0
	if open.MaskCount > 0 {
		authBits += float64(8 * (varintSize(open.MaskBase) + varintSize(open.MaskCount)))
	}
	if len(open.IndexBits) > 0 && open.TailCount > 0 && len(open.Indices) == 0 {
		authBits += float64(len(open.IndexBits) * 8)
		if open.IndexBitWidth > 0 {
			authBits += 8
		}
		authBits += float64(8 * varintSize(open.TailCount))
	} else {
		for _, idx := range open.Indices {
			authBits += float64(8 * varintSize(idx))
		}
	}
	for _, node := range open.Nodes {
		authBits += float64(len(node) * 8)
	}
	if len(open.PathBits) > 0 && open.PathDepth > 0 && open.PathBitWidth > 0 && len(open.PathIndex) == 0 {
		authBits += float64(len(open.PathBits) * 8)
		authBits += 8
		authBits += float64(8 * varintSize(open.PathDepth))
	} else if open.PathDepth > 0 && len(open.PathIndex) == 0 && len(open.PathBits) == 0 && len(open.Nodes) == open.EntryCount()*open.PathDepth {
		authBits += float64(8 * varintSize(open.PathDepth))
	} else {
		for _, pi := range open.PathIndex {
			authBits += float64(len(pi) * 32)
		}
	}

	tapeBits := 0.0
	if len(open.Nonces) > 0 {
		for _, nonce := range open.Nonces {
			tapeBits += float64(len(nonce) * 8)
		}
	} else if len(open.NonceSeed) > 0 {
		tapeBits += float64(len(open.NonceSeed) * 8)
	}
	if open.NonceBytes > 0 {
		tapeBits += float64(8 * varintSize(open.NonceBytes))
	}

	return openingPaperReport{
		PdecsBits: pdecsBits,
		MdecsBits: mdecsBits,
		AuthBits:  authBits,
		TapeBits:  tapeBits,
	}
}

func newPaperBucket(naiveBits, optimizedBits float64) PaperTranscriptBucket {
	b := PaperTranscriptBucket{
		NaiveBits:     naiveBits,
		OptimizedBits: optimizedBits,
	}
	finalizePaperBucket(&b)
	return b
}

func finalizePaperBucket(b *PaperTranscriptBucket) {
	if b == nil {
		return
	}
	b.NaiveBytes = bitsToBytes(b.NaiveBits)
	b.OptimizedBytes = bitsToBytes(b.OptimizedBits)
}

func finalizePaperTranscriptReport(r *PaperTranscriptReport) {
	if r == nil {
		return
	}
	buckets := []*PaperTranscriptBucket{
		&r.Counters,
		&r.SaltRoot,
		&r.ExtraHash,
		&r.R,
		&r.Q,
		&r.SigShortness,
		&r.VTargets,
		&r.BarSets,
		&r.Pdecs,
		&r.Mdecs,
		&r.Auth,
		&r.Tapes,
	}
	r.NaiveBits = 0
	r.OptimizedBits = 0
	for _, bucket := range buckets {
		finalizePaperBucket(bucket)
		r.NaiveBits += bucket.NaiveBits
		r.OptimizedBits += bucket.OptimizedBits
	}
	r.NaiveBytes = bitsToBytes(r.NaiveBits)
	r.OptimizedBytes = bitsToBytes(r.OptimizedBits)
}

func sigShortnessPayloadBits(sig *SigShortnessProof) float64 {
	if sig == nil {
		return 0
	}
	return float64(sizeSigShortnessProof(sig) * 8)
}

func residueMetadataBits(formatVersion uint8, encodedCols int, omitCols []int) float64 {
	bits := 0.0
	if formatVersion != 0 {
		bits += 8
	}
	if encodedCols > 0 {
		bits += float64(8 * varintSize(encodedCols))
	}
	for _, col := range omitCols {
		bits += float64(8 * varintSize(col))
	}
	return bits
}

func residueStreamBits(rows [][]uint64, bits []byte, width uint8, columnWidths []uint8, cols int) float64 {
	if len(bits) > 0 {
		out := float64(len(bits) * 8)
		if width != 0 {
			out += 8
		}
		out += float64(len(columnWidths) * 8)
		return out
	}
	if len(rows) == 0 || cols <= 0 {
		return 0
	}
	bitWidth := int(width)
	if bitWidth == 0 {
		bitWidth = packedwidth.ExactForMax(matrixAuditMaxValue(rows))
	}
	return 8 + float64(len(rows)*cols*bitWidth)
}

func bitsForPackedMatrixPayload(bits []byte, mat [][]uint64) float64 {
	if len(bits) > 0 {
		return float64(len(bits) * 8)
	}
	if len(mat) == 0 {
		return 0
	}
	packed, _, _, _ := decs.PackUintMatrix(mat)
	return float64(len(packed) * 8)
}

func qThetaMultiplier(theta int) int {
	if theta > 1 {
		return theta
	}
	return 1
}

func bitsToBytes(bits float64) int {
	if bits <= 0 {
		return 0
	}
	return int(math.Ceil(bits / 8.0))
}

func maxInt(a, b int) int {
	if a >= b {
		return a
	}
	return b
}
