package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ShowingCoeffNativeRouteMatrix encodes the negacyclic coefficient-domain linear
// map of one public ring polynomial under the current block decomposition.
//
// Weights[outBlock][inBlock][outCol][inCol] is the coefficient multiplying the
// input coefficient at (inBlock,inCol) when producing the output coefficient at
// (outBlock,outCol).
type ShowingCoeffNativeRouteMatrix struct {
	Blocks  int
	NCols   int
	Weights [][][][]uint64
}

// ShowingCoeffNativeTables captures coefficient-domain public operators used by
// compile-time checks and packing audits. These tables are not part of the
// active verifier replay surface.
type ShowingCoeffNativeTables struct {
	Q          uint64
	Blocks     int
	NCols      int
	OutputRows int
	SigUCount  int

	ARoutes    [][]ShowingCoeffNativeRouteMatrix
	B1ARoutes  [][]ShowingCoeffNativeRouteMatrix
	B0Const    [][][]uint64
	B0Msg      [][]uint64
	B0Rnd      [][]uint64
	B0MsgRoute [][]ShowingCoeffNativeRouteMatrix
	B0RndRoute [][]ShowingCoeffNativeRouteMatrix
}

func splitCoeffBlocksFromPoly(ringQ *ring.Ring, src *ring.Poly, ncols int) ([][]uint64, error) {
	if ringQ == nil || src == nil {
		return nil, fmt.Errorf("nil coeff block source")
	}
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return nil, fmt.Errorf("invalid coeff block width %d for ringN=%d", ncols, ringQ.N)
	}
	coeff := ringQ.NewPoly()
	ringQ.InvNTT(src, coeff)
	blocks := ringQ.N / ncols
	out := make([][]uint64, blocks)
	q := ringQ.Modulus[0]
	for b := 0; b < blocks; b++ {
		start := b * ncols
		end := start + ncols
		head := append([]uint64(nil), coeff.Coeffs[0][start:end]...)
		for i := range head {
			head[i] %= q
		}
		out[b] = head
	}
	return out, nil
}

func buildShowingCoeffNativeRouteMatrix(ringQ *ring.Ring, src *ring.Poly, ncols int) (ShowingCoeffNativeRouteMatrix, error) {
	if ringQ == nil || src == nil {
		return ShowingCoeffNativeRouteMatrix{}, fmt.Errorf("nil route-matrix input")
	}
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return ShowingCoeffNativeRouteMatrix{}, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	coeff := ringQ.NewPoly()
	ringQ.InvNTT(src, coeff)
	a := coeff.Coeffs[0]
	q := ringQ.Modulus[0]
	blocks := ringQ.N / ncols
	out := ShowingCoeffNativeRouteMatrix{
		Blocks:  blocks,
		NCols:   ncols,
		Weights: make([][][][]uint64, blocks),
	}
	for outBlock := 0; outBlock < blocks; outBlock++ {
		out.Weights[outBlock] = make([][][]uint64, blocks)
		for inBlock := 0; inBlock < blocks; inBlock++ {
			out.Weights[outBlock][inBlock] = make([][]uint64, ncols)
			for outCol := 0; outCol < ncols; outCol++ {
				row := make([]uint64, ncols)
				k := outBlock*ncols + outCol
				for inCol := 0; inCol < ncols; inCol++ {
					j := inBlock*ncols + inCol
					if k >= j {
						row[inCol] = a[k-j] % q
					} else {
						neg := a[ringQ.N+k-j] % q
						if neg == 0 {
							row[inCol] = 0
						} else {
							row[inCol] = (q - neg) % q
						}
					}
				}
				out.Weights[outBlock][inBlock][outCol] = row
			}
		}
	}
	return out, nil
}

func buildShowingCoeffNativeConstBlocks(ringQ *ring.Ring, src *ring.Poly, ncols int) ([][]uint64, error) {
	if ringQ == nil || src == nil {
		return nil, fmt.Errorf("nil const-block input")
	}
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return nil, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	coeff := ringQ.NewPoly()
	ringQ.InvNTT(src, coeff)
	blocks := ringQ.N / ncols
	out := make([][]uint64, blocks)
	q := ringQ.Modulus[0]
	for b := 0; b < blocks; b++ {
		start := b * ncols
		end := start + ncols
		head := append([]uint64(nil), coeff.Coeffs[0][start:end]...)
		for i := range head {
			head[i] %= q
		}
		out[b] = head
	}
	return out, nil
}

func BuildShowingCoeffNativeTables(ringQ *ring.Ring, pub PublicInputs, ncols int) (*ShowingCoeffNativeTables, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(pub.A) == 0 || len(pub.B) < 4 {
		return nil, fmt.Errorf("missing A/B for coeff-native tables")
	}
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return nil, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	blocks := ringQ.N / ncols
	outRows := len(pub.A)
	sigUCount := len(pub.A[0])
	tables := &ShowingCoeffNativeTables{
		Q:          ringQ.Modulus[0],
		Blocks:     blocks,
		NCols:      ncols,
		OutputRows: outRows,
		SigUCount:  sigUCount,
		ARoutes:    make([][]ShowingCoeffNativeRouteMatrix, outRows),
		B1ARoutes:  make([][]ShowingCoeffNativeRouteMatrix, outRows),
		B0Const:    make([][][]uint64, outRows),
		B0Msg:      nil,
		B0Rnd:      nil,
		B0MsgRoute: make([][]ShowingCoeffNativeRouteMatrix, 2),
		B0RndRoute: make([][]ShowingCoeffNativeRouteMatrix, 1),
	}
	for i := range tables.B0MsgRoute {
		tables.B0MsgRoute[i] = make([]ShowingCoeffNativeRouteMatrix, outRows)
	}
	for i := range tables.B0RndRoute {
		tables.B0RndRoute[i] = make([]ShowingCoeffNativeRouteMatrix, outRows)
	}
	constBlocks, err := buildShowingCoeffNativeConstBlocks(ringQ, pub.B[0], ncols)
	if err != nil {
		return nil, fmt.Errorf("B0Const route: %w", err)
	}
	msgRoute, err := buildShowingCoeffNativeRouteMatrix(ringQ, pub.B[1], ncols)
	if err != nil {
		return nil, fmt.Errorf("B0Msg route: %w", err)
	}
	msgBlocks, err := buildShowingCoeffNativeConstBlocks(ringQ, pub.B[1], ncols)
	if err != nil {
		return nil, fmt.Errorf("B0Msg blocks: %w", err)
	}
	rndRoute, err := buildShowingCoeffNativeRouteMatrix(ringQ, pub.B[2], ncols)
	if err != nil {
		return nil, fmt.Errorf("B0Rnd route: %w", err)
	}
	rndBlocks, err := buildShowingCoeffNativeConstBlocks(ringQ, pub.B[2], ncols)
	if err != nil {
		return nil, fmt.Errorf("B0Rnd blocks: %w", err)
	}
	tables.B0Msg = msgBlocks
	tables.B0Rnd = rndBlocks
	for j := 0; j < outRows; j++ {
		if len(pub.A[j]) != sigUCount {
			return nil, fmt.Errorf("A row %d has len=%d want %d", j, len(pub.A[j]), sigUCount)
		}
		tables.ARoutes[j] = make([]ShowingCoeffNativeRouteMatrix, sigUCount)
		tables.B1ARoutes[j] = make([]ShowingCoeffNativeRouteMatrix, sigUCount)
		b1aTmp := ringQ.NewPoly()
		for t := 0; t < sigUCount; t++ {
			aRoute, err := buildShowingCoeffNativeRouteMatrix(ringQ, pub.A[j][t], ncols)
			if err != nil {
				return nil, fmt.Errorf("A[%d][%d] route: %w", j, t, err)
			}
			tables.ARoutes[j][t] = aRoute
			ringQ.MulCoeffs(pub.B[3], pub.A[j][t], b1aTmp)
			b1aRoute, err := buildShowingCoeffNativeRouteMatrix(ringQ, b1aTmp, ncols)
			if err != nil {
				return nil, fmt.Errorf("(b1*A)[%d][%d] route: %w", j, t, err)
			}
			tables.B1ARoutes[j][t] = b1aRoute
		}
		tables.B0Const[j] = constBlocks
		tables.B0MsgRoute[0][j] = msgRoute
		tables.B0MsgRoute[1][j] = msgRoute
		tables.B0RndRoute[0][j] = rndRoute
	}
	return tables, nil
}

func evalShowingCoeffNativeRouteMatrix(mat ShowingCoeffNativeRouteMatrix, inBlocks [][]uint64, q uint64) ([][]uint64, error) {
	if len(inBlocks) != mat.Blocks {
		return nil, fmt.Errorf("route input block count mismatch: have=%d want=%d", len(inBlocks), mat.Blocks)
	}
	out := make([][]uint64, mat.Blocks)
	for outBlock := 0; outBlock < mat.Blocks; outBlock++ {
		row := make([]uint64, mat.NCols)
		for inBlock := 0; inBlock < mat.Blocks; inBlock++ {
			if len(inBlocks[inBlock]) != mat.NCols {
				return nil, fmt.Errorf("route input block %d width=%d want=%d", inBlock, len(inBlocks[inBlock]), mat.NCols)
			}
			for outCol := 0; outCol < mat.NCols; outCol++ {
				for inCol := 0; inCol < mat.NCols; inCol++ {
					row[outCol] = modAdd(row[outCol], modMul(mat.Weights[outBlock][inBlock][outCol][inCol], inBlocks[inBlock][inCol]%q, q), q)
				}
			}
		}
		out[outBlock] = row
	}
	return out, nil
}

func evalShowingCoeffNativeStatementBlocks(
	tables *ShowingCoeffNativeTables,
	sigBlocks [][][]uint64,
	msgBlocks [][][]uint64,
	rndBlocks [][][]uint64,
	x1Blocks [][]uint64,
) ([][]uint64, error) {
	if tables == nil {
		return nil, fmt.Errorf("nil coeff-native tables")
	}
	if len(sigBlocks) != tables.SigUCount {
		return nil, fmt.Errorf("sig block count mismatch: have=%d want=%d", len(sigBlocks), tables.SigUCount)
	}
	if len(msgBlocks) != len(tables.B0MsgRoute) {
		return nil, fmt.Errorf("msg block family mismatch: have=%d want=%d", len(msgBlocks), len(tables.B0MsgRoute))
	}
	if len(rndBlocks) != len(tables.B0RndRoute) {
		return nil, fmt.Errorf("rnd block family mismatch: have=%d want=%d", len(rndBlocks), len(tables.B0RndRoute))
	}
	if len(x1Blocks) != tables.Blocks {
		return nil, fmt.Errorf("x1 block count mismatch: have=%d want=%d", len(x1Blocks), tables.Blocks)
	}
	if len(tables.B0Msg) != tables.Blocks || len(tables.B0Rnd) != tables.Blocks {
		return nil, fmt.Errorf("missing coeff-native constant blocks for B0 message/randomness")
	}
	q := tables.Q
	residuals := make([][]uint64, tables.Blocks)
	for b := 0; b < tables.Blocks; b++ {
		residuals[b] = make([]uint64, tables.NCols)
	}
	scalarFromConstantBlocks := func(blockFamily [][][]uint64, label string, idx int) (uint64, error) {
		if idx < 0 || idx >= len(blockFamily) {
			return 0, fmt.Errorf("%s block family index %d out of range (%d)", label, idx, len(blockFamily))
		}
		if len(blockFamily[idx]) != tables.Blocks {
			return 0, fmt.Errorf("%s block count mismatch: have=%d want=%d", label, len(blockFamily[idx]), tables.Blocks)
		}
		var value uint64
		haveValue := false
		for b := 0; b < tables.Blocks; b++ {
			if len(blockFamily[idx][b]) != tables.NCols {
				return 0, fmt.Errorf("%s block %d width=%d want=%d", label, b, len(blockFamily[idx][b]), tables.NCols)
			}
			for col := 0; col < tables.NCols; col++ {
				v := blockFamily[idx][b][col] % q
				if !haveValue {
					value = v
					haveValue = true
					continue
				}
				if v != value {
					return 0, fmt.Errorf("%s block family %d is not column-constant (first=%d got=%d at block=%d col=%d)", label, idx, value, v, b, col)
				}
			}
		}
		if !haveValue {
			return 0, fmt.Errorf("empty %s block family %d", label, idx)
		}
		return value, nil
	}
	msgScalars := make([]uint64, len(msgBlocks))
	for i := range msgBlocks {
		v, err := scalarFromConstantBlocks(msgBlocks, "message", i)
		if err != nil {
			return nil, err
		}
		msgScalars[i] = v
	}
	rndScalars := make([]uint64, len(rndBlocks))
	for i := range rndBlocks {
		v, err := scalarFromConstantBlocks(rndBlocks, "randomness", i)
		if err != nil {
			return nil, err
		}
		rndScalars[i] = v
	}
	for outRow := 0; outRow < tables.OutputRows; outRow++ {
		left1 := make([][]uint64, tables.Blocks)
		left2 := make([][]uint64, tables.Blocks)
		right := make([][]uint64, tables.Blocks)
		for b := 0; b < tables.Blocks; b++ {
			left1[b] = make([]uint64, tables.NCols)
			left2[b] = make([]uint64, tables.NCols)
			right[b] = append([]uint64(nil), tables.B0Const[outRow][b]...)
		}
		for t := 0; t < tables.SigUCount; t++ {
			b1as, err := evalShowingCoeffNativeRouteMatrix(tables.B1ARoutes[outRow][t], sigBlocks[t], q)
			if err != nil {
				return nil, err
			}
			as, err := evalShowingCoeffNativeRouteMatrix(tables.ARoutes[outRow][t], sigBlocks[t], q)
			if err != nil {
				return nil, err
			}
			for b := 0; b < tables.Blocks; b++ {
				for col := 0; col < tables.NCols; col++ {
					left1[b][col] = modAdd(left1[b][col], b1as[b][col], q)
					left2[b][col] = modAdd(left2[b][col], modMul(as[b][col], x1Blocks[b][col]%q, q), q)
				}
			}
		}
		for i := range msgBlocks {
			for b := 0; b < tables.Blocks; b++ {
				for col := 0; col < tables.NCols; col++ {
					right[b][col] = modAdd(right[b][col], modMul(tables.B0Msg[b][col], msgScalars[i], q), q)
				}
			}
		}
		for i := range rndBlocks {
			for b := 0; b < tables.Blocks; b++ {
				for col := 0; col < tables.NCols; col++ {
					right[b][col] = modAdd(right[b][col], modMul(tables.B0Rnd[b][col], rndScalars[i], q), q)
				}
			}
		}
		for b := 0; b < tables.Blocks; b++ {
			for col := 0; col < tables.NCols; col++ {
				residuals[b][col] = modAdd(residuals[b][col], modSub(modSub(left1[b][col], left2[b][col], q), right[b][col], q), q)
			}
		}
	}
	return residuals, nil
}
