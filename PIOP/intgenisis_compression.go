package PIOP

import (
	"encoding/json"
	"fmt"

	"vSIS-Signature/credential"
	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	intGenISISMSECompressionNone = 0
	intGenISISMSECompressionMax  = 3
	intGenISISMSECompressionMode = "smallwood_ternary_carrier_v1"
)

type intGenISISMSECompressionDescriptor struct {
	Version        string `json:"version"`
	Level          int    `json:"level"`
	PackWidth      int    `json:"pack_width"`
	Alphabet       int64  `json:"alphabet"`
	SourceDomain   string `json:"source_domain"`
	CarrierSet     string `json:"carrier_set"`
	DecodeDegree   int    `json:"decode_degree"`
	MembershipDeg  int    `json:"membership_degree"`
	CompressedRows int    `json:"compressed_rows,omitempty"`
}

type intGenISISMSECompressionSpec struct {
	Descriptor     intGenISISMSECompressionDescriptor
	DecodePolys    [][]uint64
	MembershipPoly []uint64
}

func intGenISISMSECompressionPackWidth(level int) (int, error) {
	if level < 0 {
		return 0, fmt.Errorf("invalid IntGenISIS M/s/e compression level %d", level)
	}
	if level == intGenISISMSECompressionNone {
		return 1, nil
	}
	if level > intGenISISMSECompressionMax {
		return 0, fmt.Errorf("IntGenISIS M/s/e compression level %d unsupported; supported levels are 0..%d", level, intGenISISMSECompressionMax)
	}
	return level + 1, nil
}

func intGenISISMSECompressionDescriptorForLevel(level int) (intGenISISMSECompressionDescriptor, error) {
	return intGenISISMSECompressionDescriptorForBound(level, intGenISISDefaultBound)
}

func intGenISISMSECompressionDescriptorForBound(level int, bound int64) (intGenISISMSECompressionDescriptor, error) {
	packWidth, err := intGenISISMSECompressionPackWidth(level)
	if err != nil {
		return intGenISISMSECompressionDescriptor{}, err
	}
	if bound <= 0 {
		return intGenISISMSECompressionDescriptor{}, fmt.Errorf("invalid IntGenISIS M/s/e bound %d", bound)
	}
	if level == intGenISISMSECompressionNone {
		sourceDomain := credential.IntGenISISDomainBoundedRangeV1
		if bound == intGenISISTernaryBound {
			sourceDomain = credential.IntGenISISDomainTernaryV1
		}
		return intGenISISMSECompressionDescriptor{
			Version:       "none",
			Level:         0,
			PackWidth:     1,
			Alphabet:      2*bound + 1,
			SourceDomain:  sourceDomain,
			CarrierSet:    "uncompressed",
			DecodeDegree:  1,
			MembershipDeg: intGenISISMembershipDegree(bound),
		}, nil
	}
	if err := rejectIntGenISISMSECompressionForBound(bound, level); err != nil {
		return intGenISISMSECompressionDescriptor{}, err
	}
	alphabet, err := packedMuCarrierAlphabetSize(intGenISISTernaryBound, packWidth)
	if err != nil {
		return intGenISISMSECompressionDescriptor{}, err
	}
	return intGenISISMSECompressionDescriptor{
		Version:       intGenISISMSECompressionMode,
		Level:         level,
		PackWidth:     packWidth,
		Alphabet:      alphabet,
		SourceDomain:  "ternary_v1",
		CarrierSet:    fmt.Sprintf("0..%d", alphabet-1),
		DecodeDegree:  int(alphabet - 1),
		MembershipDeg: int(alphabet),
	}, nil
}

func intGenISISMSECompressionDescriptorBytes(level int, compressedRows int) ([]byte, error) {
	return intGenISISMSECompressionDescriptorBytesForBound(level, compressedRows, intGenISISDefaultBound)
}

func intGenISISMSECompressionDescriptorBytesForBound(level int, compressedRows int, bound int64) ([]byte, error) {
	desc, err := intGenISISMSECompressionDescriptorForBound(level, bound)
	if err != nil {
		return nil, err
	}
	desc.CompressedRows = compressedRows
	return json.Marshal(desc)
}

func newIntGenISISMSECompressionSpec(q uint64, level int) (intGenISISMSECompressionSpec, error) {
	return newIntGenISISMSECompressionSpecForBound(q, level, intGenISISDefaultBound)
}

func newIntGenISISMSECompressionSpecForBound(q uint64, level int, bound int64) (intGenISISMSECompressionSpec, error) {
	desc, err := intGenISISMSECompressionDescriptorForBound(level, bound)
	if err != nil {
		return intGenISISMSECompressionSpec{}, err
	}
	if level == intGenISISMSECompressionNone {
		return intGenISISMSECompressionSpec{Descriptor: desc}, nil
	}
	decode, err := buildPackedMuCarrierDecodePolys(intGenISISTernaryBound, desc.PackWidth, q)
	if err != nil {
		return intGenISISMSECompressionSpec{}, err
	}
	member, err := buildPackedMuCarrierMembershipPoly(intGenISISTernaryBound, desc.PackWidth, q)
	if err != nil {
		return intGenISISMSECompressionSpec{}, err
	}
	return intGenISISMSECompressionSpec{
		Descriptor:     desc,
		DecodePolys:    decode,
		MembershipPoly: member,
	}, nil
}

func intGenISISCompressedCarrierCount(sourceRows, packWidth int) int {
	if sourceRows <= 0 || packWidth <= 1 {
		return 0
	}
	return (sourceRows + packWidth - 1) / packWidth
}

func intGenISISBuildTernaryCarrierRows(ringQ *ring.Ring, omega []uint64, sourceRows []*ring.Poly, packWidth int, makeRowFromHead func([]uint64) *ring.Poly, name string) ([]*ring.Poly, error) {
	sourceMaterials := make([]intGenISISRowMaterial, len(sourceRows))
	for i, row := range sourceRows {
		head, err := rowHeadOnOmega(ringQ, omega, row, len(omega))
		if err != nil {
			return nil, fmt.Errorf("%s source row %d head: %w", name, i, err)
		}
		sourceMaterials[i] = intGenISISRowMaterial{Poly: row, Head: head}
	}
	mats, err := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omega, sourceMaterials, packWidth, nil, makeRowFromHead, name)
	if err != nil {
		return nil, err
	}
	return intGenISISRowMaterialPolys(mats), nil
}

func intGenISISBuildTernaryCarrierRowMaterials(ringQ *ring.Ring, omega []uint64, sourceRows []intGenISISRowMaterial, packWidth int, interp *omegaInterpolationPlan, makeRowFromHead func([]uint64) *ring.Poly, name string) ([]intGenISISRowMaterial, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega for %s carriers", name)
	}
	if packWidth <= 1 {
		return nil, fmt.Errorf("%s carrier pack width=%d is not compressed", name, packWidth)
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
	carrierCount := intGenISISCompressedCarrierCount(len(sourceRows), packWidth)
	out := make([]intGenISISRowMaterial, 0, carrierCount)
	q := ringQ.Modulus[0]
	sourceHeads := make([][]uint64, len(sourceRows))
	for i := range sourceRows {
		if len(sourceRows[i].Head) != len(omega) {
			if sourceRows[i].Poly == nil {
				return nil, fmt.Errorf("%s source row %d missing head", name, i)
			}
			head, err := rowHeadOnOmega(ringQ, omega, sourceRows[i].Poly, len(omega))
			if err != nil {
				return nil, fmt.Errorf("%s source row %d head: %w", name, i, err)
			}
			sourceHeads[i] = head
			continue
		}
		sourceHeads[i] = sourceRows[i].Head
	}
	for carrier := 0; carrier < carrierCount; carrier++ {
		head := make([]uint64, len(omega))
		for col := range omega {
			vals := make([]int64, packWidth)
			for lane := 0; lane < packWidth; lane++ {
				src := carrier*packWidth + lane
				if src >= len(sourceHeads) {
					vals[lane] = 0
					continue
				}
				v := centeredLift(sourceHeads[src][col]%q, q)
				if v < -intGenISISTernaryBound || v > intGenISISTernaryBound {
					return nil, fmt.Errorf("%s source row %d col %d value=%d outside ternary domain", name, src, col, v)
				}
				vals[lane] = v
			}
			code, err := encodePackedMuCarrier(vals, intGenISISTernaryBound)
			if err != nil {
				return nil, fmt.Errorf("%s carrier row %d col %d: %w", name, carrier, col, err)
			}
			head[col] = code % q
		}
		out = append(out, intGenISISRowMaterial{Poly: makeRowFromHead(head), Head: head})
	}
	return out, nil
}

func intGenISISCompressedSourceFormalCoeffs(ringQ *ring.Ring, rowsNTT []*ring.Poly, carrierStart, sourceRows, packWidth int, decodePolys [][]uint64, name string) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if carrierStart < 0 || sourceRows <= 0 || packWidth <= 1 {
		return nil, fmt.Errorf("invalid %s compressed source layout start=%d rows=%d pack=%d", name, carrierStart, sourceRows, packWidth)
	}
	if len(decodePolys) < packWidth {
		return nil, fmt.Errorf("%s decode lanes=%d want at least %d", name, len(decodePolys), packWidth)
	}
	q := ringQ.Modulus[0]
	carrierCount := intGenISISCompressedCarrierCount(sourceRows, packWidth)
	carrierFormal := make([]fpoly.Poly, carrierCount)
	for i := 0; i < carrierCount; i++ {
		idx := carrierStart + i
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return nil, fmt.Errorf("invalid %s carrier row index %d", name, idx)
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
		if err != nil {
			return nil, fmt.Errorf("%s carrier row %d coeffs: %w", name, i, err)
		}
		carrierFormal[i] = fpoly.New(q, trimPoly(coeff, q))
	}
	out := make([][]uint64, sourceRows)
	for src := 0; src < sourceRows; src++ {
		carrier := src / packWidth
		lane := src % packWidth
		decoded := fpoly.New(q, decodePolys[lane]).Compose(carrierFormal[carrier])
		out[src] = trimPoly(append([]uint64(nil), decoded.Coeffs...), q)
	}
	return out, nil
}

func intGenISISCompressedCarrierLaneFormalCoeff(ringQ *ring.Ring, rowsNTT []*ring.Poly, carrierRow, lane int, decodePolys [][]uint64, name string) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if carrierRow < 0 || carrierRow >= len(rowsNTT) || rowsNTT[carrierRow] == nil {
		return nil, fmt.Errorf("invalid %s carrier row %d", name, carrierRow)
	}
	if lane < 0 || lane >= len(decodePolys) {
		return nil, fmt.Errorf("%s decode lane=%d outside lanes=%d", name, lane, len(decodePolys))
	}
	q := ringQ.Modulus[0]
	coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[carrierRow])
	if err != nil {
		return nil, fmt.Errorf("%s carrier row %d coeffs: %w", name, carrierRow, err)
	}
	decoded := fpoly.New(q, decodePolys[lane]).Compose(fpoly.New(q, trimPoly(coeff, q)))
	return trimPoly(append([]uint64(nil), decoded.Coeffs...), q), nil
}

func intGenISISCompressedCoeffToHatBridgeFormalCoeffs(ringQ *ring.Ring, rowsNTT []*ring.Poly, omega []uint64, carrierStart, components, hatStart, rowsPerPoly, packWidth int, decodePolys [][]uint64, name string) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega for %s compressed bridge", name)
	}
	if carrierStart < 0 || hatStart < 0 || components <= 0 || rowsPerPoly <= 0 || packWidth <= 1 {
		return nil, nil, fmt.Errorf("invalid %s compressed bridge layout carrier=%d hat=%d components=%d rowsPerPoly=%d pack=%d", name, carrierStart, hatStart, components, rowsPerPoly, packWidth)
	}
	sourceCount := components * rowsPerPoly
	decodedSources, err := intGenISISCompressedSourceFormalCoeffs(ringQ, rowsNTT, carrierStart, sourceCount, packWidth, decodePolys, name)
	if err != nil {
		return nil, nil, err
	}
	ncols := len(omega)
	basis, err := newTransformBridgeBasisCache(ringQ, omega, rowsPerPoly*ncols, rowsPerPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("%s compressed bridge basis: %w", name, err)
	}
	q := ringQ.Modulus[0]
	rowCoeff := func(idx int) ([]uint64, error) {
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return nil, fmt.Errorf("invalid %s bridge row index %d", name, idx)
		}
		tmp := ringQ.NewPoly()
		ringQ.InvNTT(rowsNTT[idx], tmp)
		return trimCoeffsCopy(tmp.Coeffs[0], q), nil
	}
	fagg := make([]*ring.Poly, 0, components*rowsPerPoly*ncols)
	coeffs := make([][]uint64, 0, components*rowsPerPoly*ncols)
	for comp := 0; comp < components; comp++ {
		for block := 0; block < rowsPerPoly; block++ {
			hatCoeff, err := rowCoeff(hatStart + comp*rowsPerPoly + block)
			if err != nil {
				return nil, nil, err
			}
			for lane := 0; lane < ncols; lane++ {
				t := block*ncols + lane
				leftCoeff := []uint64{0}
				for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
					sourceCoeff := decodedSources[comp*rowsPerPoly+srcBlock]
					term := reducePolyModXN1(polyMul(basis.TransformH[t], sourceCoeff, q), int(ringQ.N), q)
					scale := basis.BlockFactors[t][srcBlock] % q
					if scale != 1 {
						term = scalePoly(term, scale, q)
					}
					leftCoeff = polyAdd(leftCoeff, term, q)
				}
				rightCoeff := reducePolyModXN1(polyMul(basis.LagrangeBasis[lane], hatCoeff, q), int(ringQ.N), q)
				bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
				coeffs = append(coeffs, bridgeCoeff)
				fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	}
	return fagg, coeffs, nil
}

func intGenISISCompressedCarrierMembershipRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, indices []int, spec intGenISISMSECompressionSpec) ([]*ring.Poly, [][]uint64, error) {
	if len(indices) == 0 {
		return nil, nil, nil
	}
	if len(spec.MembershipPoly) == 0 {
		return nil, nil, fmt.Errorf("missing IntGenISIS compressed carrier membership polynomial")
	}
	selected := make([]*ring.Poly, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return nil, nil, fmt.Errorf("invalid IntGenISIS compressed carrier row index %d", idx)
		}
		selected = append(selected, rowsNTT[idx])
	}
	return buildFparRangeMembershipComposeFormalCoeffs(ringQ, selected, RangeMembershipSpec{B: intGenISISTernaryBound, Coeffs: spec.MembershipPoly})
}
