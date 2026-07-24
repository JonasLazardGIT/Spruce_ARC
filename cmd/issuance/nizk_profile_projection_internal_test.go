package main

import (
	"fmt"
	"math"
	"sync"
	"testing"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/packedwidth"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const nizkProfilePackedMatrixHeaderBytes = 10

type nizkProfilePaperProjectionParams struct {
	Q                      uint64
	Lambda                 int
	SaltBits               int
	DECSHashBits           int
	DECSTapeBits           int
	RingDegree             int
	NCols                  int
	LVCSNCols              int
	NLeaves                int
	Eta                    int
	Ell                    int
	EllPrime               int
	Rho                    int
	Theta                  int
	DQ                     int
	LogicalRows            int
	TranscriptOmissionMode string
}

type nizkProfilePaperProjection struct {
	Transcript        PIOP.PaperTranscriptReport
	WitnessLayers     int
	ReplayWitnessRows int
	MaskRows          int
	OpeningRows       int
	QueryCount        int
	PColsEncoded      int
}

var (
	nizkProfileProjectionRingOnce sync.Once
	nizkProfileProjectionRing     *ring.Ring
	nizkProfileProjectionRingErr  error
)

func nizkProfileProjectPaperTranscript(params nizkProfilePaperProjectionParams) (nizkProfilePaperProjection, error) {
	if err := nizkProfileValidatePaperProjectionParams(params); err != nil {
		return nizkProfilePaperProjection{}, err
	}
	ringQ, err := nizkProfilePaperProjectionRing(params)
	if err != nil {
		return nizkProfilePaperProjection{}, err
	}

	fieldBitWidth := packedwidth.ExactForMax(params.Q - 1)
	witnessLayers := ceilDivInt(params.LogicalRows, params.LVCSNCols)
	replayWitnessRows := witnessLayers * (params.NCols + params.Theta)
	maskChunks := params.DQ/params.LVCSNCols + 1
	maskRows := maskChunks * params.Theta * params.Rho
	openingRows := replayWitnessRows + maskRows
	queryCount := (witnessLayers + 1) * params.Theta
	pColsEncoded := openingRows - queryCount
	if pColsEncoded <= 0 {
		return nizkProfilePaperProjection{}, fmt.Errorf(
			"smallfield2025 projection has no encoded P columns: opening_rows=%d query_count=%d",
			openingRows,
			queryCount,
		)
	}

	pathDepth := int(math.Ceil(math.Log2(float64(params.NLeaves))))
	hashBytes := nizkProfileBytesForBits(params.DECSHashBits)
	tapeBytes := nizkProfileBytesForBits(params.DECSTapeBits)
	opening := &decs.DECSOpening{
		FormatVersion:  decs.OpeningFormatOmitCols,
		PColsEncoded:   pColsEncoded,
		MFormatVersion: decs.OpeningFormatOmitCols,
		MColsEncoded:   0,
		TailCount:      params.Ell,
		IndexBits:      make([]byte, (params.Ell*pathDepth+7)/8),
		IndexBitWidth:  uint8(pathDepth),
		PvalsBits:      make([]byte, (params.Ell*pColsEncoded*fieldBitWidth+7)/8),
		PvalsBitWidth:  uint8(fieldBitWidth),
		R:              openingRows,
		Eta:            params.Eta,
		PathDepth:      pathDepth,
		NonceSeed:      make([]byte, tapeBytes),
		NonceBytes:     tapeBytes,
	}
	node := make([]byte, hashBytes)
	opening.Nodes = make([][]byte, params.Ell*pathDepth)
	for i := range opening.Nodes {
		opening.Nodes[i] = node
	}

	vTargetsBytes := nizkProfilePackedMatrixBytes(queryCount, params.LVCSNCols, fieldBitWidth)
	barSetsBytes := nizkProfilePackedMatrixBytes(queryCount, params.Ell, fieldBitWidth)
	proof := &PIOP.Proof{
		RingDegree:        params.RingDegree,
		RootHash:          make([]byte, hashBytes),
		Lambda:            params.Lambda,
		Theta:             params.Theta,
		Salt:              make([]byte, nizkProfileBytesForBits(params.SaltBits)),
		PCSOpening:        opening,
		RowOpening:        opening,
		VTargetsBits:      make([]byte, vTargetsBytes),
		VTargetsRows:      queryCount,
		VTargetsCols:      params.LVCSNCols,
		VTargetsBitWidth:  uint8(fieldBitWidth),
		BarSetsBits:       make([]byte, barSetsBytes),
		BarSetsRows:       queryCount,
		BarSetsCols:       params.Ell,
		BarSetsBitWidth:   uint8(fieldBitWidth),
		MaskRowOffset:     replayWitnessRows,
		MaskRowCount:      maskRows,
		NColsUsed:         params.NCols,
		PCSNColsUsed:      params.LVCSNCols,
		LVCSNColsUsed:     params.LVCSNCols,
		NLeavesUsed:       params.NLeaves,
		QDegreeBound:      params.DQ,
		MaskDegreeBound:   params.DQ,
		TranscriptVersion: PIOP.TranscriptVersionSmallWood2025,
		SmallField2025: &PIOP.SmallField2025LVCSProof{
			Version:          1,
			Mode:             PIOP.TranscriptProtocolSmallField2025V1,
			Status:           PIOP.SmallField2025StatusLive,
			ReductionEnabled: true,
			HeadDomainMode:   PIOP.SmallField2025HeadDomainV1,
			NRows:            openingRows,
			NCols:            params.LVCSNCols,
			Theta:            params.Theta,
			WitnessLayers:    witnessLayers,
			MaskRows:         params.Ell,
			QueryCount:       queryCount,
			VHeadRows:        queryCount,
			VHeadCols:        params.LVCSNCols,
			VBarRows:         queryCount,
			VBarCols:         params.Ell,
			MatrixDigest:     make([]byte, 32),
			PayloadDigest:    make([]byte, 32),
		},
	}
	report, err := PIOP.BuildProofReport(proof, PIOP.SimOpts{
		Rho:                    params.Rho,
		EllPrime:               params.EllPrime,
		Ell:                    params.Ell,
		Eta:                    params.Eta,
		NLeaves:                params.NLeaves,
		Theta:                  params.Theta,
		RingDegree:             params.RingDegree,
		DECSCollisionBits:      params.DECSHashBits,
		DECSHashBits:           params.DECSHashBits,
		DECSTapeBits:           params.DECSTapeBits,
		SaltBits:               params.SaltBits,
		NCols:                  params.NCols,
		PCSNCols:               params.LVCSNCols,
		LVCSNCols:              params.LVCSNCols,
		DQOverride:             params.DQ,
		Lambda:                 params.Lambda,
		TranscriptOmissionMode: params.TranscriptOmissionMode,
		TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V1,
		TranscriptVersion:      PIOP.TranscriptVersionSmallWood2025,
	}, ringQ)
	if err != nil {
		return nizkProfilePaperProjection{}, err
	}
	return nizkProfilePaperProjection{
		Transcript:        report.PaperTranscript,
		WitnessLayers:     witnessLayers,
		ReplayWitnessRows: replayWitnessRows,
		MaskRows:          maskRows,
		OpeningRows:       openingRows,
		QueryCount:        queryCount,
		PColsEncoded:      pColsEncoded,
	}, nil
}

func nizkProfilePaperProjectionRing(params nizkProfilePaperProjectionParams) (*ring.Ring, error) {
	if params.Q != credential.IntGenISISSharedModulusQ || params.RingDegree != 1024 {
		return nil, fmt.Errorf(
			"paper projection supports the N=1024 IntGenISIS sweep ring, got N=%d q=%d",
			params.RingDegree,
			params.Q,
		)
	}
	nizkProfileProjectionRingOnce.Do(func() {
		nizkProfileProjectionRing, nizkProfileProjectionRingErr = ring.NewRing(
			params.RingDegree,
			[]uint64{params.Q},
		)
	})
	return nizkProfileProjectionRing, nizkProfileProjectionRingErr
}

func nizkProfileValidatePaperProjectionParams(params nizkProfilePaperProjectionParams) error {
	switch {
	case params.Q <= 2:
		return fmt.Errorf("smallfield2025 projection requires q>2")
	case params.NCols <= 0:
		return fmt.Errorf("smallfield2025 projection requires ncols>0")
	case params.LVCSNCols < params.NCols:
		return fmt.Errorf("smallfield2025 projection lvcs_ncols=%d below ncols=%d", params.LVCSNCols, params.NCols)
	case params.NLeaves <= 1:
		return fmt.Errorf("smallfield2025 projection requires nleaves>1")
	case uint64(params.NLeaves) >= params.Q:
		return fmt.Errorf("smallfield2025 projection requires nleaves<q: nleaves=%d q=%d", params.NLeaves, params.Q)
	case params.Eta <= 0 || params.Ell <= 0 || params.EllPrime <= 0 || params.Rho <= 0:
		return fmt.Errorf("smallfield2025 projection requires positive eta, ell, ell_prime, and rho")
	case params.Theta <= 1:
		return fmt.Errorf("smallfield2025 projection requires theta>1")
	case params.DQ <= 0:
		return fmt.Errorf("smallfield2025 projection requires dQ>0")
	case params.LogicalRows <= 0:
		return fmt.Errorf("smallfield2025 projection requires logical_rows>0")
	case params.DECSHashBits <= 0 || params.DECSTapeBits <= 0 || params.SaltBits <= 0:
		return fmt.Errorf("smallfield2025 projection requires positive transcript widths")
	case params.TranscriptOmissionMode != "":
		return fmt.Errorf("smallfield2025 exact projection does not model serializer omissions")
	}
	return nil
}

func nizkProfilePackedMatrixBytes(rows, cols, width int) int {
	return nizkProfilePackedMatrixHeaderBytes + (rows*cols*width+7)/8
}

func nizkProfileBytesForBits(bits int) int {
	return (bits + 7) / 8
}

func TestNIZKProfilePaperProjectionMatchesMeasuredBQ64Shapes(t *testing.T) {
	params := nizkProfilePaperProjectionParams{
		Q:            credential.IntGenISISSharedModulusQ,
		Lambda:       256,
		SaltBits:     200,
		DECSHashBits: 264,
		DECSTapeBits: 200,
		RingDegree:   1024,
		NCols:        32,
		LVCSNCols:    43,
		NLeaves:      786432,
		Eta:          54,
		Ell:          14,
		EllPrime:     1,
		Rho:          1,
		Theta:        10,
		DQ:           436,
		LogicalRows:  165,
	}
	issuance, err := nizkProfileProjectPaperTranscript(params)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := issuance.Transcript.OptimizedBytes, 41518; got != want {
		t.Fatalf("legacy issuance projection=%d want measured %d: %+v", got, want, issuance.Transcript)
	}
	params.LogicalRows = 472
	showing, err := nizkProfileProjectPaperTranscript(params)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := showing.Transcript.OptimizedBytes, 59333; got != want {
		t.Fatalf("legacy showing projection=%d want measured %d", got, want)
	}

	params.NLeaves = 917504
	params.Eta = 53
	params.Ell = 13
	params.DQ = 427
	params.LogicalRows = 165
	issuance, err = nizkProfileProjectPaperTranscript(params)
	if err != nil {
		t.Fatal(err)
	}
	params.LogicalRows = 472
	showing, err = nizkProfileProjectPaperTranscript(params)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := issuance.Transcript.OptimizedBytes, 39504; got != want {
		t.Fatalf("promoted issuance projection=%d want measured %d", got, want)
	}
	if got, want := showing.Transcript.OptimizedBytes, 56584; got != want {
		t.Fatalf("promoted showing projection=%d want measured %d", got, want)
	}
}

func TestNIZKProfilePaperProjectionRejectsDomainAtFieldSize(t *testing.T) {
	_, err := nizkProfileProjectPaperTranscript(nizkProfilePaperProjectionParams{
		Q:            credential.IntGenISISSharedModulusQ,
		Lambda:       256,
		SaltBits:     200,
		DECSHashBits: 264,
		DECSTapeBits: 200,
		RingDegree:   1024,
		NCols:        32,
		LVCSNCols:    43,
		NLeaves:      int(credential.IntGenISISSharedModulusQ),
		Eta:          53,
		Ell:          13,
		EllPrime:     1,
		Rho:          1,
		Theta:        10,
		DQ:           427,
		LogicalRows:  165,
	})
	if err == nil {
		t.Fatal("expected nleaves>=q to be rejected")
	}
}
