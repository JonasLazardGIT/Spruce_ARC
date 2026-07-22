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
	Audit        PaperTranscriptAudit  `json:"audit,omitempty"`

	NaiveBits      float64 `json:"naive_bits"`
	OptimizedBits  float64 `json:"optimized_bits"`
	NaiveBytes     int     `json:"naive_bytes"`
	OptimizedBytes int     `json:"optimized_bytes"`
}

// PaperTranscriptAudit decomposes the broad paper transcript buckets into the
// concrete serializer subcomponents that are most useful for transcript-reduction
// research. It is diagnostic only; it does not alter the proof payload.
type PaperTranscriptAudit struct {
	Pdecs    OpeningResiduePaperAudit `json:"pdecs,omitempty"`
	Mdecs    OpeningResiduePaperAudit `json:"mdecs,omitempty"`
	Auth     OpeningAuthPaperAudit    `json:"auth,omitempty"`
	Tapes    OpeningTapePaperAudit    `json:"tapes,omitempty"`
	VTargets MatrixPayloadPaperAudit  `json:"vtargets,omitempty"`
	BarSets  MatrixPayloadPaperAudit  `json:"barsets,omitempty"`
}

type OpeningResiduePaperAudit struct {
	MetadataBytes           int     `json:"metadata_bytes,omitempty"`
	StreamBytes             int     `json:"stream_bytes,omitempty"`
	TotalBytes              int     `json:"total_bytes,omitempty"`
	EncodedCols             int     `json:"encoded_cols,omitempty"`
	OmittedCols             []int   `json:"omitted_cols,omitempty"`
	BitWidth                int     `json:"bit_width,omitempty"`
	ColumnWidths            []uint8 `json:"column_widths,omitempty"`
	Rows                    int     `json:"rows,omitempty"`
	Omitted                 bool    `json:"omitted,omitempty"`
	ReconstructedBytesSaved int     `json:"reconstructed_bytes_saved,omitempty"`
	OmissionMapBytes        int     `json:"omission_map_bytes,omitempty"`
	NonReconstructibleBytes int     `json:"non_reconstructible_bytes,omitempty"`
}

type OpeningAuthPaperAudit struct {
	MaskMetadataBytes int `json:"mask_metadata_bytes,omitempty"`
	IndexBytes        int `json:"index_bytes,omitempty"`
	IndexBitWidth     int `json:"index_bit_width,omitempty"`
	TailCount         int `json:"tail_count,omitempty"`
	NodeBytes         int `json:"node_bytes,omitempty"`
	NodeCount         int `json:"node_count,omitempty"`
	PathBitsBytes     int `json:"path_bits_bytes,omitempty"`
	PathBitWidth      int `json:"path_bit_width,omitempty"`
	PathDepth         int `json:"path_depth,omitempty"`
	PathIndexBytes    int `json:"path_index_bytes,omitempty"`
	EntryCount        int `json:"entry_count,omitempty"`
	TotalBytes        int `json:"total_bytes,omitempty"`
}

type OpeningTapePaperAudit struct {
	NonceBytes         int `json:"nonce_bytes,omitempty"`
	NonceCount         int `json:"nonce_count,omitempty"`
	NonceSeedBytes     int `json:"nonce_seed_bytes,omitempty"`
	NonceMetadataBytes int `json:"nonce_metadata_bytes,omitempty"`
	TotalBytes         int `json:"total_bytes,omitempty"`
}

type MatrixPayloadPaperAudit struct {
	Bytes                   int  `json:"bytes,omitempty"`
	Rows                    int  `json:"rows,omitempty"`
	Cols                    int  `json:"cols,omitempty"`
	BitWidth                int  `json:"bit_width,omitempty"`
	Omitted                 bool `json:"omitted,omitempty"`
	ReconstructedBytesSaved int  `json:"reconstructed_bytes_saved,omitempty"`
	OmissionMapBytes        int  `json:"omission_map_bytes,omitempty"`
	NonReconstructibleBytes int  `json:"non_reconstructible_bytes,omitempty"`
}

type openingPaperReport struct {
	PdecsBits float64
	MdecsBits float64
	AuthBits  float64
	TapeBits  float64
	Audit     PaperTranscriptAudit
}

type paperTranscriptParams struct {
	Lambda       int
	SaltBits     int
	DECSHashBits int
	RingDegree   int
	X0Len        int
	Eta          int
	Ell          int
	EllPrime     int
	Rho          int
	Theta        int
	DQ           int
	DDECS        int
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
	omission := (*SmallField2025TranscriptOmission)(nil)
	omissionMapBytes := 0
	if proof.SmallField2025 != nil {
		omission = proof.SmallField2025.TranscriptOmission
		omissionMapBytes = len(smallField2025TranscriptOmissionBytes(omission))
	}
	vTargetsBits := bitsForPackedMatrixPayload(proof.VTargetsBits, proof.VTargets)
	barSetsBits := bitsForPackedMatrixPayload(proof.BarSetsBits, proof.BarSets)

	saltRootBits := float64(4 * p.Lambda)
	if p.SaltBits > 0 && p.DECSHashBits > 0 {
		saltRootBits = float64(p.SaltBits + p.DECSHashBits)
	}
	out := PaperTranscriptReport{
		RingDegree: p.RingDegree,
		X0Len:      p.X0Len,
		Counters:   newPaperBucket(128, 128),
		SaltRoot:   newPaperBucket(saltRootBits, saltRootBits),
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
		VTargets:     newPaperBucket(vTargetsBits, vTargetsBits),
		BarSets:      newPaperBucket(barSetsBits, barSetsBits),
		Pdecs:        newPaperBucket(openingRep.PdecsBits, openingRep.PdecsBits),
		Mdecs:        newPaperBucket(openingRep.MdecsBits, openingRep.MdecsBits),
		Auth:         newPaperBucket(openingRep.AuthBits, openingRep.AuthBits),
		Tapes:        newPaperBucket(openingRep.TapeBits, openingRep.TapeBits),
		Audit:        openingRep.Audit,
	}
	out.Audit.VTargets = matrixPayloadPaperAudit(proof.VTargetsBits, proof.VTargets, proof.VTargetsRows, proof.VTargetsCols, proof.VTargetsBitWidth)
	out.Audit.BarSets = matrixPayloadPaperAudit(proof.BarSetsBits, proof.BarSets, proof.BarSetsRows, proof.BarSetsCols, proof.BarSetsBitWidth)
	if omission != nil && omission.OmitPdecsReconstructibleCols {
		out.Audit.Pdecs.Omitted = true
		out.Audit.Pdecs.ReconstructedBytesSaved = openingReconstructedResidueBytesSaved(rowOpening, out.Audit.Pdecs)
		out.Audit.Pdecs.OmissionMapBytes = omissionMapBytes
		out.Audit.Pdecs.NonReconstructibleBytes = out.Audit.Pdecs.TotalBytes
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
	pMetaBits := residueMetadataBits(open.FormatVersion, open.PColsEncoded, open.POmitCols)
	pStreamBits := residueStreamBits(open.Pvals, open.PvalsBits, open.PvalsBitWidth, open.PvalsColumnWidths, openingAuditPCols(open))
	pdecsBits := pMetaBits + pStreamBits

	mMetaBits := residueMetadataBits(open.MFormatVersion, open.MColsEncoded, open.MOmitCols)
	mStreamBits := residueStreamBits(open.Mvals, open.MvalsBits, open.MvalsBitWidth, open.MvalsColumnWidths, openingAuditMCols(open))
	mdecsBits := mMetaBits + mStreamBits

	authBits := 0.0
	authAudit := OpeningAuthPaperAudit{EntryCount: open.EntryCount()}
	if open.MaskCount > 0 {
		authAudit.MaskMetadataBytes = varintSize(open.MaskBase) + varintSize(open.MaskCount)
		authBits += float64(8 * authAudit.MaskMetadataBytes)
	}
	if len(open.IndexBits) > 0 && open.TailCount > 0 && len(open.Indices) == 0 {
		authAudit.IndexBytes = len(open.IndexBits)
		authBits += float64(authAudit.IndexBytes * 8)
		if open.IndexBitWidth > 0 {
			authAudit.IndexBytes++
			authAudit.IndexBitWidth = int(open.IndexBitWidth)
			authBits += 8
		}
		authAudit.TailCount = open.TailCount
		tailBytes := varintSize(open.TailCount)
		authAudit.IndexBytes += tailBytes
		authBits += float64(8 * tailBytes)
	} else {
		for _, idx := range open.Indices {
			n := varintSize(idx)
			authAudit.IndexBytes += n
			authBits += float64(8 * n)
		}
	}
	for _, node := range open.Nodes {
		authAudit.NodeBytes += len(node)
		authAudit.NodeCount++
		authBits += float64(len(node) * 8)
	}
	if len(open.PathBits) > 0 && open.PathDepth > 0 && open.PathBitWidth > 0 && len(open.PathIndex) == 0 {
		authAudit.PathBitsBytes = len(open.PathBits)
		authAudit.PathBitWidth = int(open.PathBitWidth)
		authAudit.PathDepth = open.PathDepth
		authBits += float64(authAudit.PathBitsBytes * 8)
		authAudit.PathBitsBytes++
		authBits += 8
		depthBytes := varintSize(open.PathDepth)
		authAudit.PathBitsBytes += depthBytes
		authBits += float64(8 * depthBytes)
	} else if open.PathDepth > 0 && len(open.PathIndex) == 0 && len(open.PathBits) == 0 && len(open.Nodes) == open.EntryCount()*open.PathDepth {
		authAudit.PathDepth = open.PathDepth
		depthBytes := varintSize(open.PathDepth)
		authAudit.PathIndexBytes += depthBytes
		authBits += float64(8 * depthBytes)
	} else {
		for _, pi := range open.PathIndex {
			n := len(pi) * 4
			authAudit.PathIndexBytes += n
			authBits += float64(n * 8)
		}
	}
	authAudit.TotalBytes = bitsToBytes(authBits)

	tapeBits := 0.0
	tapeAudit := OpeningTapePaperAudit{}
	if len(open.Nonces) > 0 {
		for _, nonce := range open.Nonces {
			tapeAudit.NonceBytes += len(nonce)
			tapeAudit.NonceCount++
			tapeBits += float64(len(nonce) * 8)
		}
	} else if len(open.NonceSeed) > 0 {
		tapeAudit.NonceSeedBytes = len(open.NonceSeed)
		tapeBits += float64(tapeAudit.NonceSeedBytes * 8)
	}
	if open.NonceBytes > 0 {
		tapeAudit.NonceMetadataBytes = varintSize(open.NonceBytes)
		tapeBits += float64(8 * tapeAudit.NonceMetadataBytes)
	}
	tapeAudit.TotalBytes = bitsToBytes(tapeBits)

	return openingPaperReport{
		PdecsBits: pdecsBits,
		MdecsBits: mdecsBits,
		AuthBits:  authBits,
		TapeBits:  tapeBits,
		Audit: PaperTranscriptAudit{
			Pdecs: residuePaperAudit(pMetaBits, pStreamBits, open.FormatVersion, open.PColsEncoded, open.POmitCols, open.Pvals, open.PvalsBitWidth, open.PvalsColumnWidths, openingAuditPCols(open)),
			Mdecs: residuePaperAudit(mMetaBits, mStreamBits, open.MFormatVersion, open.MColsEncoded, open.MOmitCols, open.Mvals, open.MvalsBitWidth, open.MvalsColumnWidths, openingAuditMCols(open)),
			Auth:  authAudit,
			Tapes: tapeAudit,
		},
	}
}

func addOpeningPaperAudit(dst *PaperTranscriptAudit, src PaperTranscriptAudit) {
	if dst == nil {
		return
	}
	dst.Pdecs = addResiduePaperAudit(dst.Pdecs, src.Pdecs)
	dst.Mdecs = addResiduePaperAudit(dst.Mdecs, src.Mdecs)
	dst.Auth = addAuthPaperAudit(dst.Auth, src.Auth)
	dst.Tapes = addTapePaperAudit(dst.Tapes, src.Tapes)
}

func residuePaperAudit(metadataBits, streamBits float64, formatVersion uint8, encodedCols int, omitCols []int, rows [][]uint64, width uint8, columnWidths []uint8, cols int) OpeningResiduePaperAudit {
	bitWidth := int(width)
	if bitWidth == 0 && len(columnWidths) > 0 {
		bitWidth = maxUint8(columnWidths)
	}
	if bitWidth == 0 && len(rows) > 0 && cols > 0 {
		bitWidth = packedwidth.ExactForMax(matrixAuditMaxValue(rows))
	}
	out := OpeningResiduePaperAudit{
		MetadataBytes: bitsToBytes(metadataBits),
		StreamBytes:   bitsToBytes(streamBits),
		TotalBytes:    bitsToBytes(metadataBits + streamBits),
		EncodedCols:   cols,
		OmittedCols:   append([]int(nil), omitCols...),
		BitWidth:      bitWidth,
		ColumnWidths:  append([]uint8(nil), columnWidths...),
		Rows:          len(rows),
	}
	if formatVersion != decs.OpeningFormatPlain && encodedCols > 0 {
		out.EncodedCols = encodedCols
	}
	return out
}

func addResiduePaperAudit(a, b OpeningResiduePaperAudit) OpeningResiduePaperAudit {
	a.MetadataBytes += b.MetadataBytes
	a.StreamBytes += b.StreamBytes
	a.TotalBytes += b.TotalBytes
	a.EncodedCols += b.EncodedCols
	a.Rows += b.Rows
	a.OmittedCols = append(a.OmittedCols, b.OmittedCols...)
	a.ColumnWidths = append(a.ColumnWidths, b.ColumnWidths...)
	if b.BitWidth > a.BitWidth {
		a.BitWidth = b.BitWidth
	}
	a.Omitted = a.Omitted || b.Omitted
	a.ReconstructedBytesSaved += b.ReconstructedBytesSaved
	a.OmissionMapBytes += b.OmissionMapBytes
	a.NonReconstructibleBytes += b.NonReconstructibleBytes
	return a
}

func openingReconstructedResidueBytesSaved(open *decs.DECSOpening, audit OpeningResiduePaperAudit) int {
	if open == nil {
		return 0
	}
	omittedCols := len(open.POmitCols)
	if omittedCols == 0 && open.R > open.PColsEncoded {
		omittedCols = open.R - open.PColsEncoded
	}
	if omittedCols <= 0 {
		return 0
	}
	rows := audit.Rows
	if rows <= 0 {
		rows = len(open.Pvals)
	}
	if rows <= 0 && open.Eta > 0 {
		rows = open.Eta
	}
	width := audit.BitWidth
	if width <= 0 {
		width = int(open.PvalsBitWidth)
	}
	if width <= 0 {
		width = 20
	}
	return bitsToBytes(float64(rows * omittedCols * width))
}

func addAuthPaperAudit(a, b OpeningAuthPaperAudit) OpeningAuthPaperAudit {
	a.MaskMetadataBytes += b.MaskMetadataBytes
	a.IndexBytes += b.IndexBytes
	a.TailCount += b.TailCount
	a.NodeBytes += b.NodeBytes
	a.NodeCount += b.NodeCount
	a.PathBitsBytes += b.PathBitsBytes
	a.PathIndexBytes += b.PathIndexBytes
	a.EntryCount += b.EntryCount
	a.TotalBytes += b.TotalBytes
	if b.IndexBitWidth > a.IndexBitWidth {
		a.IndexBitWidth = b.IndexBitWidth
	}
	if b.PathBitWidth > a.PathBitWidth {
		a.PathBitWidth = b.PathBitWidth
	}
	if b.PathDepth > a.PathDepth {
		a.PathDepth = b.PathDepth
	}
	return a
}

func addTapePaperAudit(a, b OpeningTapePaperAudit) OpeningTapePaperAudit {
	a.NonceBytes += b.NonceBytes
	a.NonceCount += b.NonceCount
	a.NonceSeedBytes += b.NonceSeedBytes
	a.NonceMetadataBytes += b.NonceMetadataBytes
	a.TotalBytes += b.TotalBytes
	return a
}

func matrixPayloadPaperAudit(bits []byte, mat [][]uint64, rows, cols int, width uint8) MatrixPayloadPaperAudit {
	if rows <= 0 {
		rows = len(mat)
	}
	if cols <= 0 {
		cols = matrixAuditCols(mat)
	}
	bitWidth := int(width)
	if bitWidth == 0 && (len(bits) > 0 || len(mat) > 0) {
		bitWidth = packedwidth.ExactForMax(matrixAuditMaxValue(mat))
	}
	return MatrixPayloadPaperAudit{
		Bytes:    bitsToBytes(bitsForPackedMatrixPayload(bits, mat)),
		Rows:     rows,
		Cols:     cols,
		BitWidth: bitWidth,
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
