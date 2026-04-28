package PIOP

import (
	"fmt"

	"vSIS-Signature/credential"
)

type IntGenISISRowComponent struct {
	Name     string `json:"name"`
	PolyRows int    `json:"ring_polynomials"`
}

type IntGenISISRowInventory struct {
	Profile           string                   `json:"profile"`
	RingDegree        int                      `json:"ring_degree"`
	PackingFactor     int                      `json:"packing_factor"`
	RowsPerRingPoly   int                      `json:"rows_per_ring_polynomial"`
	PreSignComponents []IntGenISISRowComponent `json:"presign_components"`
	ShowingComponents []IntGenISISRowComponent `json:"showing_components"`
	PreSignRingPolys  int                      `json:"presign_ring_polynomials"`
	ShowingRingPolys  int                      `json:"showing_ring_polynomials"`
	PreSignRows       int                      `json:"presign_rows"`
	ShowingNonPRFRows int                      `json:"showing_non_prf_rows"`
}

type IntGenISISPreSignRowLayout struct {
	MStart         int `json:"m_start"`
	MCount         int `json:"m_count"`
	SStart         int `json:"s_start"`
	SCount         int `json:"s_count"`
	EStart         int `json:"e_start"`
	ECount         int `json:"e_count"`
	CommitmentRows int `json:"commitment_rows"`
}

func (l *IntGenISISPreSignRowLayout) WitnessRows() int {
	if l == nil {
		return 0
	}
	end := l.MStart + l.MCount
	if sEnd := l.SStart + l.SCount; sEnd > end {
		end = sEnd
	}
	if eEnd := l.EStart + l.ECount; eEnd > end {
		end = eEnd
	}
	return end
}

type IntGenISISShowingRowLayout struct {
	UStart       int `json:"u_start"`
	UCount       int `json:"u_count"`
	MStart       int `json:"m_start"`
	MCount       int `json:"m_count"`
	SStart       int `json:"s_start"`
	SCount       int `json:"s_count"`
	EStart       int `json:"e_start"`
	ECount       int `json:"e_count"`
	MuSigStart   int `json:"mu_sig_start"`
	MuSigCount   int `json:"mu_sig_count"`
	X0Start      int `json:"x0_start"`
	X0Count      int `json:"x0_count"`
	X1Start      int `json:"x1_start"`
	X1Count      int `json:"x1_count"`
	ZStart       int `json:"z_start"`
	ZCount       int `json:"z_count"`
	CoreRowCount int `json:"core_row_count"`
}

func (l *IntGenISISShowingRowLayout) WitnessRows() int {
	if l == nil {
		return 0
	}
	if l.CoreRowCount > 0 {
		return l.CoreRowCount
	}
	end := 0
	for _, part := range []struct {
		start int
		count int
	}{
		{l.UStart, l.UCount},
		{l.MStart, l.MCount},
		{l.SStart, l.SCount},
		{l.EStart, l.ECount},
		{l.MuSigStart, l.MuSigCount},
		{l.X0Start, l.X0Count},
		{l.X1Start, l.X1Count},
		{l.ZStart, l.ZCount},
	} {
		if part.count <= 0 {
			continue
		}
		if partEnd := part.start + part.count; partEnd > end {
			end = partEnd
		}
	}
	return end
}

func BuildIntGenISISRowInventory(profileName string, packingFactor int) (IntGenISISRowInventory, error) {
	if packingFactor <= 0 {
		return IntGenISISRowInventory{}, fmt.Errorf("invalid packing factor %d", packingFactor)
	}
	profile, ok := credential.LookupIntGenISISProfile(profileName)
	if !ok {
		return IntGenISISRowInventory{}, fmt.Errorf("unsupported IntGenISIS profile %q", profileName)
	}
	if profile.N%packingFactor != 0 {
		return IntGenISISRowInventory{}, fmt.Errorf("ring degree %d not divisible by packing factor %d", profile.N, packingFactor)
	}
	presign := []IntGenISISRowComponent{
		{Name: "M", PolyRows: profile.EllM},
		{Name: "s", PolyRows: profile.KS},
		{Name: "e", PolyRows: profile.NC},
	}
	showing := []IntGenISISRowComponent{
		{Name: "u", PolyRows: profile.SignaturePreimageLen},
		{Name: "M", PolyRows: profile.EllM},
		{Name: "s", PolyRows: profile.KS},
		{Name: "e", PolyRows: profile.NC},
		{Name: "mu_sig", PolyRows: profile.EllMuSig},
		{Name: "x0", PolyRows: profile.EllX0},
		{Name: "x1", PolyRows: profile.EllX1},
		{Name: "Z", PolyRows: 1},
	}
	sum := func(parts []IntGenISISRowComponent) int {
		total := 0
		for _, part := range parts {
			total += part.PolyRows
		}
		return total
	}
	rowsPerPoly := profile.N / packingFactor
	presignPolys := sum(presign)
	showingPolys := sum(showing)
	return IntGenISISRowInventory{
		Profile:           profile.Name,
		RingDegree:        profile.N,
		PackingFactor:     packingFactor,
		RowsPerRingPoly:   rowsPerPoly,
		PreSignComponents: presign,
		ShowingComponents: showing,
		PreSignRingPolys:  presignPolys,
		ShowingRingPolys:  showingPolys,
		PreSignRows:       presignPolys * rowsPerPoly,
		ShowingNonPRFRows: showingPolys * rowsPerPoly,
	}, nil
}
