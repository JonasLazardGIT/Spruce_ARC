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
	nizkProfileProjectionRingsMu sync.Mutex
	nizkProfileProjectionRings   = make(map[int]*ring.Ring)
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
		Version:        decs.OpeningVersionV2,
		Role:           decs.CommitmentRoleMain,
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
		Tapes:          make([][]byte, params.Ell),
		TapeBytes:      tapeBytes,
	}
	for i := range opening.Tapes {
		opening.Tapes[i] = make([]byte, tapeBytes)
	}
	node := make([]byte, hashBytes)
	opening.Nodes = make([][]byte, params.Ell*pathDepth)
	for i := range opening.Nodes {
		opening.Nodes[i] = node
	}

	vTargetsBytes := nizkProfilePackedMatrixBytes(queryCount, params.LVCSNCols, fieldBitWidth)
	barSetsBytes := nizkProfilePackedMatrixBytes(queryCount, params.Ell, fieldBitWidth)
	proof := &PIOP.Proof{
		SchemaVersion:          PIOP.ProofSchemaVersionV2,
		RingDegree:             params.RingDegree,
		RootHash:               make([]byte, hashBytes),
		Lambda:                 params.Lambda,
		Theta:                  params.Theta,
		Salt:                   make([]byte, nizkProfileBytesForBits(params.SaltBits)),
		PCSOpening:             opening,
		RowOpening:             opening,
		VTargetsBits:           make([]byte, vTargetsBytes),
		VTargetsRows:           queryCount,
		VTargetsCols:           params.LVCSNCols,
		VTargetsBitWidth:       uint8(fieldBitWidth),
		BarSetsBits:            make([]byte, barSetsBytes),
		BarSetsRows:            queryCount,
		BarSetsCols:            params.Ell,
		BarSetsBitWidth:        uint8(fieldBitWidth),
		MaskRowOffset:          replayWitnessRows,
		MaskRowCount:           maskRows,
		NColsUsed:              params.NCols,
		PCSNColsUsed:           params.LVCSNCols,
		LVCSNColsUsed:          params.LVCSNCols,
		NLeavesUsed:            params.NLeaves,
		QDegreeBound:           params.DQ,
		MaskDegreeBound:        params.DQ,
		TranscriptVersion:      PIOP.TranscriptVersionSmallWood2025V2,
		TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V2,
		PCSGeometry: PIOP.PCSGeometry{
			Kind:               PIOP.PCSGeometryKindSmallFieldMatrixV2,
			WitnessPackingCols: params.NCols,
			PCSNCols:           params.LVCSNCols,
			Theta:              params.Theta,
			Ell:                params.Ell,
		},
		SmallField2025: &PIOP.SmallField2025LVCSProof{
			Version:          2,
			Mode:             PIOP.TranscriptProtocolSmallField2025V2,
			Status:           PIOP.SmallField2025StatusLive,
			ReductionEnabled: true,
			HeadDomainMode:   PIOP.SmallField2025HeadDomainV2,
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
		TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V2,
		TranscriptVersion:      PIOP.TranscriptVersionSmallWood2025V2,
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
	if params.Q != credential.IntGenISISSharedModulusQ || (params.RingDegree != 512 && params.RingDegree != 1024) {
		return nil, fmt.Errorf(
			"paper projection supports the maintained N=512/N=1024 IntGenISIS sweep rings, got N=%d q=%d",
			params.RingDegree,
			params.Q,
		)
	}
	nizkProfileProjectionRingsMu.Lock()
	defer nizkProfileProjectionRingsMu.Unlock()
	if cached := nizkProfileProjectionRings[params.RingDegree]; cached != nil {
		return cached, nil
	}
	created, err := ring.NewRing(params.RingDegree, []uint64{params.Q})
	if err != nil {
		return nil, err
	}
	nizkProfileProjectionRings[params.RingDegree] = created
	return created, nil
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
	case params.TranscriptOmissionMode != "" && params.TranscriptOmissionMode != credential.IntGenISISTranscriptOmissionModeV2:
		return fmt.Errorf("smallfield2025 exact projection does not model transcript omission mode %q", params.TranscriptOmissionMode)
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
	assertV2SelectiveTapes := func(label string, projection nizkProfilePaperProjection, wantCount, wantWidth int) {
		t.Helper()
		audit := projection.Transcript.Audit.Tapes
		if audit.TapeCount != wantCount {
			t.Fatalf("%s tape count=%d want=%d: %+v", label, audit.TapeCount, wantCount, audit)
		}
		if audit.TapeBytes != wantCount*wantWidth {
			t.Fatalf("%s disclosed tape bytes=%d want=%d: %+v", label, audit.TapeBytes, wantCount*wantWidth, audit)
		}
		if audit.TapeMetadataBytes <= 0 || audit.TotalBytes != audit.TapeBytes+audit.TapeMetadataBytes {
			t.Fatalf("%s malformed tape accounting: %+v", label, audit)
		}
		if projection.Transcript.Tapes.OptimizedBytes != audit.TotalBytes {
			t.Fatalf("%s tape bucket=%d want audit total=%d", label, projection.Transcript.Tapes.OptimizedBytes, audit.TotalBytes)
		}
		if projection.Transcript.OptimizedBytes <= projection.Transcript.Tapes.OptimizedBytes {
			t.Fatalf("%s transcript does not include non-tape payloads: %+v", label, projection.Transcript)
		}
	}
	assertV2SelectiveTapes("first issuance", issuance, params.Ell, nizkProfileBytesForBits(params.DECSTapeBits))
	params.LogicalRows = 472
	showing, err := nizkProfileProjectPaperTranscript(params)
	if err != nil {
		t.Fatal(err)
	}
	assertV2SelectiveTapes("first showing", showing, params.Ell, nizkProfileBytesForBits(params.DECSTapeBits))
	if showing.Transcript.OptimizedBytes <= issuance.Transcript.OptimizedBytes {
		t.Fatalf("showing transcript=%d must exceed issuance transcript=%d for the larger relation", showing.Transcript.OptimizedBytes, issuance.Transcript.OptimizedBytes)
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
	assertV2SelectiveTapes("second issuance", issuance, params.Ell, nizkProfileBytesForBits(params.DECSTapeBits))
	assertV2SelectiveTapes("second showing", showing, params.Ell, nizkProfileBytesForBits(params.DECSTapeBits))
	if showing.Transcript.OptimizedBytes <= issuance.Transcript.OptimizedBytes {
		t.Fatalf("showing transcript=%d must exceed issuance transcript=%d for the larger relation", showing.Transcript.OptimizedBytes, issuance.Transcript.OptimizedBytes)
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
