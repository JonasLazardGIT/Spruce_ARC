package PIOP

type IntGenISISPreSignRowLayout struct {
	MStart          int `json:"m_start"`
	MCount          int `json:"m_count"`
	MAttrStart      int `json:"m_attr_start"`
	MAttrCount      int `json:"m_attr_count"`
	KStart          int `json:"k_start"`
	KCount          int `json:"k_count"`
	SStart          int `json:"s_start"`
	SCount          int `json:"s_count"`
	EStart          int `json:"e_start"`
	ECount          int `json:"e_count"`
	CoreRowCount    int `json:"core_row_count,omitempty"`
	BoundViewStart  int `json:"bound_view_start,omitempty"`
	BoundViewCount  int `json:"bound_view_count,omitempty"`
	MViewStart      int `json:"m_view_start,omitempty"`
	MAttrViewStart  int `json:"m_attr_view_start,omitempty"`
	KViewStart      int `json:"k_view_start,omitempty"`
	SViewStart      int `json:"s_view_start,omitempty"`
	EViewStart      int `json:"e_view_start,omitempty"`
	ViewRowsPerPoly int `json:"view_rows_per_poly,omitempty"`
	CommitmentRows  int `json:"commitment_rows"`
}

func (l *IntGenISISPreSignRowLayout) WitnessRows() int {
	if l == nil {
		return 0
	}
	if l.BoundViewStart > 0 && l.BoundViewCount > 0 {
		return l.BoundViewStart + l.BoundViewCount
	}
	end := l.MStart + l.MCount
	if sEnd := l.SStart + l.SCount; sEnd > end {
		end = sEnd
	}
	if mAttrEnd := l.MAttrStart + l.MAttrCount; mAttrEnd > end {
		end = mAttrEnd
	}
	if kEnd := l.KStart + l.KCount; kEnd > end {
		end = kEnd
	}
	if eEnd := l.EStart + l.ECount; eEnd > end {
		end = eEnd
	}
	return end
}

func (l *IntGenISISPreSignRowLayout) ThetaRows() int {
	if l == nil {
		return 0
	}
	if l.CoreRowCount > 0 {
		return l.CoreRowCount
	}
	end := l.MStart + l.MCount
	if sEnd := l.SStart + l.SCount; sEnd > end {
		end = sEnd
	}
	if mAttrEnd := l.MAttrStart + l.MAttrCount; mAttrEnd > end {
		end = mAttrEnd
	}
	if kEnd := l.KStart + l.KCount; kEnd > end {
		end = kEnd
	}
	if eEnd := l.EStart + l.ECount; eEnd > end {
		end = eEnd
	}
	return end
}

type IntGenISISShowingRowLayout struct {
	LayoutVersion              string `json:"layout_version,omitempty"`
	ReplayProjection           string `json:"replay_projection,omitempty"`
	LinearHatSourceMode        string `json:"linear_hat_source_mode,omitempty"`
	UStart                     int    `json:"u_start"`
	UCount                     int    `json:"u_count"`
	MStart                     int    `json:"m_start"`
	MCount                     int    `json:"m_count"`
	MAttrStart                 int    `json:"m_attr_start"`
	MAttrCount                 int    `json:"m_attr_count"`
	KStart                     int    `json:"k_start"`
	KCount                     int    `json:"k_count"`
	SStart                     int    `json:"s_start"`
	SCount                     int    `json:"s_count"`
	EStart                     int    `json:"e_start"`
	ECount                     int    `json:"e_count"`
	MuSigStart                 int    `json:"mu_sig_start"`
	MuSigCount                 int    `json:"mu_sig_count"`
	X0Start                    int    `json:"x0_start"`
	X0Count                    int    `json:"x0_count"`
	X1Start                    int    `json:"x1_start"`
	X1Count                    int    `json:"x1_count"`
	ZStart                     int    `json:"z_start"`
	ZCount                     int    `json:"z_count"`
	BoundViewStart             int    `json:"bound_view_start,omitempty"`
	BoundViewCount             int    `json:"bound_view_count,omitempty"`
	MSECompressionLevel        int    `json:"mse_compression_level,omitempty"`
	MSECompressionPackWidth    int    `json:"mse_compression_pack_width,omitempty"`
	MSECompressionAlphabet     int64  `json:"mse_compression_alphabet,omitempty"`
	MSECompressionDecodeDegree int    `json:"mse_compression_decode_degree,omitempty"`
	MCarrierStart              int    `json:"m_carrier_start,omitempty"`
	MCarrierCount              int    `json:"m_carrier_count,omitempty"`
	MCompressedSourceRows      int    `json:"m_compressed_source_rows,omitempty"`
	MSeedViewStart             int    `json:"m_seed_view_start,omitempty"`
	MSeedViewCount             int    `json:"m_seed_view_count,omitempty"`
	SCarrierStart              int    `json:"s_carrier_start,omitempty"`
	SCarrierCount              int    `json:"s_carrier_count,omitempty"`
	ECarrierStart              int    `json:"e_carrier_start,omitempty"`
	ECarrierCount              int    `json:"e_carrier_count,omitempty"`
	MSECarrierCount            int    `json:"mse_carrier_count,omitempty"`
	UViewStart                 int    `json:"u_view_start,omitempty"`
	UShortnessStart            int    `json:"u_shortness_start,omitempty"`
	UShortnessGroupCount       int    `json:"u_shortness_group_count,omitempty"`
	UShortnessRowsPerGroup     int    `json:"u_shortness_rows_per_group,omitempty"`
	UShortnessRadix            int    `json:"u_shortness_radix,omitempty"`
	UShortnessDigits           int    `json:"u_shortness_digits,omitempty"`
	UShortnessSourceViewStart  int    `json:"u_shortness_source_view_start,omitempty"`
	UShortnessSourceViewRows   int    `json:"u_shortness_source_view_rows,omitempty"`
	UShortnessCapacity         int64  `json:"u_shortness_capacity,omitempty"`
	UShortnessProofMode        string `json:"u_shortness_proof_mode,omitempty"`
	MViewStart                 int    `json:"m_view_start,omitempty"`
	MAttrViewStart             int    `json:"m_attr_view_start,omitempty"`
	KViewStart                 int    `json:"k_view_start,omitempty"`
	SViewStart                 int    `json:"s_view_start,omitempty"`
	EViewStart                 int    `json:"e_view_start,omitempty"`
	YViewStart                 int    `json:"y_view_start,omitempty"`
	YViewCount                 int    `json:"y_view_count,omitempty"`
	MuSigViewStart             int    `json:"mu_sig_view_start,omitempty"`
	X0ViewStart                int    `json:"x0_view_start,omitempty"`
	X1ViewStart                int    `json:"x1_view_start,omitempty"`
	ZViewStart                 int    `json:"z_view_start,omitempty"`
	UHatStart                  int    `json:"u_hat_start,omitempty"`
	UHatCount                  int    `json:"u_hat_count,omitempty"`
	MHatStart                  int    `json:"m_hat_start,omitempty"`
	MHatCount                  int    `json:"m_hat_count,omitempty"`
	SHatStart                  int    `json:"s_hat_start,omitempty"`
	SHatCount                  int    `json:"s_hat_count,omitempty"`
	EHatStart                  int    `json:"e_hat_start,omitempty"`
	EHatCount                  int    `json:"e_hat_count,omitempty"`
	YHatStart                  int    `json:"y_hat_start,omitempty"`
	YHatCount                  int    `json:"y_hat_count,omitempty"`
	MuSigHatStart              int    `json:"mu_sig_hat_start,omitempty"`
	MuSigHatCount              int    `json:"mu_sig_hat_count,omitempty"`
	X0HatStart                 int    `json:"x0_hat_start,omitempty"`
	X0HatCount                 int    `json:"x0_hat_count,omitempty"`
	WHatStart                  int    `json:"w_hat_start,omitempty"`
	WHatCount                  int    `json:"w_hat_count,omitempty"`
	X1HatStart                 int    `json:"x1_hat_start,omitempty"`
	X1HatCount                 int    `json:"x1_hat_count,omitempty"`
	ZHatStart                  int    `json:"z_hat_start,omitempty"`
	ZHatCount                  int    `json:"z_hat_count,omitempty"`
	HatRowsPerPoly             int    `json:"hat_rows_per_poly,omitempty"`
	ViewRowsPerPoly            int    `json:"view_rows_per_poly,omitempty"`
	CoreRowCount               int    `json:"core_row_count"`
}

func (l *IntGenISISShowingRowLayout) WitnessRows() int {
	if l == nil {
		return 0
	}
	if l.CoreRowCount > 0 {
		end := l.CoreRowCount
		if l.UShortnessStart > 0 && l.UShortnessGroupCount > 0 && l.UShortnessRowsPerGroup > 0 {
			if shortEnd := l.UShortnessStart + l.UShortnessGroupCount*l.UShortnessRowsPerGroup; shortEnd > end {
				end = shortEnd
			}
		}
		if l.BoundViewStart > 0 && l.BoundViewCount > 0 {
			if boundEnd := l.BoundViewStart + l.BoundViewCount; boundEnd > end {
				end = boundEnd
			}
		}
		return end
	}
	end := 0
	for _, part := range []struct {
		start int
		count int
	}{
		{l.UStart, l.UCount},
		{l.MStart, l.MCount},
		{l.MAttrStart, l.MAttrCount},
		{l.KStart, l.KCount},
		{l.SStart, l.SCount},
		{l.EStart, l.ECount},
		{l.MuSigStart, l.MuSigCount},
		{l.X0Start, l.X0Count},
		{l.X1Start, l.X1Count},
		{l.ZStart, l.ZCount},
		{l.UViewStart, l.UCount * l.ViewRowsPerPoly},
		{l.UShortnessStart, l.UShortnessGroupCount * l.UShortnessRowsPerGroup},
		{l.BoundViewStart, l.BoundViewCount},
		{l.MCarrierStart, l.MCarrierCount},
		{l.MSeedViewStart, l.MSeedViewCount},
		{l.SCarrierStart, l.SCarrierCount},
		{l.ECarrierStart, l.ECarrierCount},
		{l.YViewStart, l.YViewCount},
		{l.MuSigViewStart, l.MuSigCount * l.ViewRowsPerPoly},
		{l.X0ViewStart, l.X0Count * l.ViewRowsPerPoly},
		{l.X1ViewStart, l.X1Count * l.ViewRowsPerPoly},
		{l.ZViewStart, l.ZCount * l.ViewRowsPerPoly},
		{l.UHatStart, l.UHatCount},
		{l.MHatStart, l.MHatCount},
		{l.SHatStart, l.SHatCount},
		{l.EHatStart, l.EHatCount},
		{l.YHatStart, l.YHatCount},
		{l.MuSigHatStart, l.MuSigHatCount},
		{l.X0HatStart, l.X0HatCount},
		{l.WHatStart, l.WHatCount},
		{l.X1HatStart, l.X1HatCount},
		{l.ZHatStart, l.ZHatCount},
	} {
		if part.start < 0 || part.count <= 0 {
			continue
		}
		if partEnd := part.start + part.count; partEnd > end {
			end = partEnd
		}
	}
	return end
}
