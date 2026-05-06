package credential

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	IntGenISISMessageLayoutProfileBV2    = "intgenisis_message_profile_b_v2"
	IntGenISISMessageLayoutProfileBV3    = "intgenisis_message_profile_b_v3"
	IntGenISISMessageLayoutRingTailKeyV1 = "intgenisis_message_ring_tail_key_v1"
	IntGenISISSamplerUniformRQV1         = "uniform_rq_v1"
	IntGenISISDomainTernaryV1            = "ternary_v1"
	IntGenISISDomainBoundedRangeV1       = "bounded_range_v1"
	IntGenISISDomainBoundedRangeB4V1     = "bounded_range_b4_v1"
	IntGenISISDegreeModePaperEq3V1       = "paper_eq3_v1"
)

type MessageSlot struct {
	Poly  int `json:"poly"`
	Coeff int `json:"coeff"`
}

type SemanticMessageLayout struct {
	Version       int           `json:"version"`
	Name          string        `json:"name"`
	Profile       string        `json:"profile"`
	RingDegree    int           `json:"ring_degree"`
	MessageRows   int           `json:"message_rows"`
	AttributeRows int           `json:"attribute_rows"`
	KeyRows       int           `json:"key_rows"`
	Attribute     []MessageSlot `json:"attribute_slots"`
	Key           []MessageSlot `json:"key_slots"`
	Bound         int64         `json:"bound"`
	MSEDomain     string        `json:"mse_domain,omitempty"`
	KeyDomain     string        `json:"key_domain,omitempty"`
	DegreeMode    string        `json:"degree_mode,omitempty"`
}

type SemanticMessage struct {
	M     [][]int64 `json:"M"`
	MAttr [][]int64 `json:"m"`
	K     [][]int64 `json:"k"`
}

func DefaultSemanticMessageLayout(profile IntGenISISProfile, lenKey int) (SemanticMessageLayout, error) {
	if _, ok := LookupIntGenISISProfile(profile.Name); !ok {
		return SemanticMessageLayout{}, fmt.Errorf("unsupported IntGenISIS profile %q", profile.Name)
	}
	if lenKey <= 0 {
		return SemanticMessageLayout{}, fmt.Errorf("invalid PRF key length %d", lenKey)
	}
	if lenKey > 8 {
		return SemanticMessageLayout{}, fmt.Errorf("IntGenISIS semantic layout has at most 8 key slots, got lenkey=%d", lenKey)
	}
	if profile.N <= lenKey {
		return SemanticMessageLayout{}, fmt.Errorf("ring degree %d too small for IntGenISIS semantic layout", profile.N)
	}
	domain := IntGenISISDomainBoundedRangeV1
	if profile.B == 1 {
		domain = IntGenISISDomainTernaryV1
	}
	keyStart := profile.N - lenKey
	attr := make([]MessageSlot, keyStart)
	for i := range attr {
		attr[i] = MessageSlot{Poly: 0, Coeff: i}
	}
	key := make([]MessageSlot, lenKey)
	for i := range key {
		key[i] = MessageSlot{Poly: 0, Coeff: keyStart + i}
	}
	return SemanticMessageLayout{
		Version:       4,
		Name:          IntGenISISMessageLayoutRingTailKeyV1,
		Profile:       profile.Name,
		RingDegree:    profile.N,
		MessageRows:   profile.EllM,
		AttributeRows: profile.EllM,
		KeyRows:       profile.EllM,
		Attribute:     attr,
		Key:           key,
		Bound:         profile.B,
		MSEDomain:     domain,
		KeyDomain:     domain,
		DegreeMode:    IntGenISISDegreeModePaperEq3V1,
	}, nil
}

func (l SemanticMessageLayout) Digest() []byte {
	h := sha256.New()
	writeString := func(s string) {
		_ = binary.Write(h, binary.LittleEndian, uint32(len(s)))
		h.Write([]byte(s))
	}
	writeInt := func(v int) {
		_ = binary.Write(h, binary.LittleEndian, int64(v))
	}
	writeString(l.Name)
	writeString(l.Profile)
	writeString(l.MSEDomain)
	writeString(l.KeyDomain)
	writeString(l.DegreeMode)
	writeInt(l.Version)
	writeInt(l.RingDegree)
	writeInt(l.MessageRows)
	writeInt(l.AttributeRows)
	writeInt(l.KeyRows)
	_ = binary.Write(h, binary.LittleEndian, l.Bound)
	for _, slot := range l.Attribute {
		writeInt(slot.Poly)
		writeInt(slot.Coeff)
	}
	for _, slot := range l.Key {
		writeInt(slot.Poly)
		writeInt(slot.Coeff)
	}
	return h.Sum(nil)
}

func EncodeSemanticMessage(layout SemanticMessageLayout, m [][]int64, key []int64) (SemanticMessage, error) {
	if err := layout.validate(); err != nil {
		return SemanticMessage{}, err
	}
	if len(key) != len(layout.Key) {
		return SemanticMessage{}, fmt.Errorf("key length=%d want %d", len(key), len(layout.Key))
	}
	mAttr := zeroRows(layout.AttributeRows, layout.RingDegree)
	if len(m) > 0 {
		if len(m) != layout.AttributeRows {
			return SemanticMessage{}, fmt.Errorf("attribute rows=%d want %d", len(m), layout.AttributeRows)
		}
		for r := range m {
			if len(m[r]) != layout.RingDegree {
				return SemanticMessage{}, fmt.Errorf("attribute row %d length=%d want %d", r, len(m[r]), layout.RingDegree)
			}
			copy(mAttr[r], m[r])
		}
	}
	kRows := zeroRows(layout.KeyRows, layout.RingDegree)
	for i, v := range key {
		if absInt64(v) > layout.Bound {
			return SemanticMessage{}, fmt.Errorf("key[%d]=%d outside [-%d,%d]", i, v, layout.Bound, layout.Bound)
		}
		if layout.KeyDomain == IntGenISISDomainTernaryV1 && !isTernaryInt64(v) {
			return SemanticMessage{}, fmt.Errorf("key[%d]=%d outside ternary domain {-1,0,1}", i, v)
		}
		slot := layout.Key[i]
		kRows[slot.Poly][slot.Coeff] = v
	}
	M := zeroRows(layout.MessageRows, layout.RingDegree)
	for _, slot := range layout.Attribute {
		v := mAttr[slot.Poly][slot.Coeff]
		if absInt64(v) > layout.Bound {
			return SemanticMessage{}, fmt.Errorf("attribute slot poly=%d coeff=%d value=%d outside [-%d,%d]", slot.Poly, slot.Coeff, v, layout.Bound, layout.Bound)
		}
		if layout.MSEDomain == IntGenISISDomainTernaryV1 && !isTernaryInt64(v) {
			return SemanticMessage{}, fmt.Errorf("attribute slot poly=%d coeff=%d value=%d outside ternary domain {-1,0,1}", slot.Poly, slot.Coeff, v)
		}
		M[slot.Poly][slot.Coeff] = v
	}
	for i, slot := range layout.Key {
		M[slot.Poly][slot.Coeff] = key[i]
	}
	msg := SemanticMessage{M: M, MAttr: mAttr, K: kRows}
	if err := ValidateSemanticMessage(layout, msg); err != nil {
		return SemanticMessage{}, err
	}
	return msg, nil
}

func DecodeSemanticMessage(layout SemanticMessageLayout, M [][]int64) (SemanticMessage, error) {
	if err := layout.validate(); err != nil {
		return SemanticMessage{}, err
	}
	if err := validateRows("M", M, layout.MessageRows, layout.RingDegree); err != nil {
		return SemanticMessage{}, err
	}
	mAttr := zeroRows(layout.AttributeRows, layout.RingDegree)
	for _, slot := range layout.Attribute {
		mAttr[slot.Poly][slot.Coeff] = M[slot.Poly][slot.Coeff]
	}
	kRows := zeroRows(layout.KeyRows, layout.RingDegree)
	for _, slot := range layout.Key {
		kRows[slot.Poly][slot.Coeff] = M[slot.Poly][slot.Coeff]
	}
	msg := SemanticMessage{M: cloneInt64Rows(M), MAttr: mAttr, K: kRows}
	if err := ValidateSemanticMessage(layout, msg); err != nil {
		return SemanticMessage{}, err
	}
	return msg, nil
}

func ValidateSemanticMessage(layout SemanticMessageLayout, msg SemanticMessage) error {
	if err := layout.validate(); err != nil {
		return err
	}
	if err := validateRows("M", msg.M, layout.MessageRows, layout.RingDegree); err != nil {
		return err
	}
	if err := validateRows("m", msg.MAttr, layout.AttributeRows, layout.RingDegree); err != nil {
		return err
	}
	if err := validateRows("k", msg.K, layout.KeyRows, layout.RingDegree); err != nil {
		return err
	}
	attrAllowed := slotSet(layout.Attribute)
	keyAllowed := slotSet(layout.Key)
	for r := 0; r < layout.MessageRows; r++ {
		for c := 0; c < layout.RingDegree; c++ {
			id := slotKey(r, c)
			if absInt64(msg.M[r][c]) > layout.Bound {
				return fmt.Errorf("M[%d][%d]=%d outside [-%d,%d]", r, c, msg.M[r][c], layout.Bound, layout.Bound)
			}
			if layout.MSEDomain == IntGenISISDomainTernaryV1 && !isTernaryInt64(msg.M[r][c]) {
				return fmt.Errorf("M[%d][%d]=%d outside ternary domain {-1,0,1}", r, c, msg.M[r][c])
			}
			if !attrAllowed[id] && !keyAllowed[id] && msg.M[r][c] != 0 {
				return fmt.Errorf("reserved M slot poly=%d coeff=%d is non-zero", r, c)
			}
			if !attrAllowed[id] && msg.MAttr[r][c] != 0 {
				return fmt.Errorf("reserved m slot poly=%d coeff=%d is non-zero", r, c)
			}
			if !keyAllowed[id] && msg.K[r][c] != 0 {
				return fmt.Errorf("reserved k slot poly=%d coeff=%d is non-zero", r, c)
			}
			if absInt64(msg.MAttr[r][c]) > layout.Bound {
				return fmt.Errorf("m[%d][%d]=%d outside [-%d,%d]", r, c, msg.MAttr[r][c], layout.Bound, layout.Bound)
			}
			if layout.MSEDomain == IntGenISISDomainTernaryV1 && !isTernaryInt64(msg.MAttr[r][c]) {
				return fmt.Errorf("m[%d][%d]=%d outside ternary domain {-1,0,1}", r, c, msg.MAttr[r][c])
			}
			if absInt64(msg.K[r][c]) > layout.Bound {
				return fmt.Errorf("k[%d][%d]=%d outside [-%d,%d]", r, c, msg.K[r][c], layout.Bound, layout.Bound)
			}
			if layout.KeyDomain == IntGenISISDomainTernaryV1 && !isTernaryInt64(msg.K[r][c]) {
				return fmt.Errorf("k[%d][%d]=%d outside ternary domain {-1,0,1}", r, c, msg.K[r][c])
			}
			if msg.M[r][c] != msg.MAttr[r][c]+msg.K[r][c] {
				return fmt.Errorf("M=m||k mismatch at poly=%d coeff=%d", r, c)
			}
		}
	}
	return nil
}

func PRFKeyFromSemanticMessage(layout SemanticMessageLayout, M [][]int64) ([]int64, error) {
	msg, err := DecodeSemanticMessage(layout, M)
	if err != nil {
		return nil, err
	}
	out := make([]int64, len(layout.Key))
	for i, slot := range layout.Key {
		out[i] = msg.K[slot.Poly][slot.Coeff]
	}
	return out, nil
}

func ZeroSemanticAttributes(layout SemanticMessageLayout) [][]int64 {
	return zeroRows(layout.AttributeRows, layout.RingDegree)
}

func (l SemanticMessageLayout) validate() error {
	if l.Version != 4 {
		return fmt.Errorf("unsupported semantic message layout version %d", l.Version)
	}
	if l.Name == "" || l.Profile == "" {
		return fmt.Errorf("semantic message layout missing name/profile")
	}
	if l.Name != IntGenISISMessageLayoutRingTailKeyV1 {
		return fmt.Errorf("unsupported semantic message layout %q", l.Name)
	}
	profile, ok := LookupIntGenISISProfile(l.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", l.Profile)
	}
	if l.RingDegree != profile.N || l.MessageRows != profile.EllM {
		return fmt.Errorf("semantic layout dimensions do not match profile %q", l.Profile)
	}
	if !isSupportedIntGenISISSemanticDomain(l.MSEDomain) || !isSupportedIntGenISISSemanticDomain(l.KeyDomain) {
		return fmt.Errorf("unsupported semantic domains mse=%q key=%q", l.MSEDomain, l.KeyDomain)
	}
	if l.DegreeMode != IntGenISISDegreeModePaperEq3V1 {
		return fmt.Errorf("unsupported semantic degree mode %q", l.DegreeMode)
	}
	if l.RingDegree <= 0 || l.MessageRows <= 0 || l.AttributeRows != l.MessageRows || l.KeyRows != l.MessageRows {
		return fmt.Errorf("invalid semantic message dimensions")
	}
	if l.Bound <= 0 {
		return fmt.Errorf("invalid semantic message bound %d", l.Bound)
	}
	for _, slots := range [][]MessageSlot{l.Attribute, l.Key} {
		for _, slot := range slots {
			if slot.Poly < 0 || slot.Poly >= l.MessageRows || slot.Coeff < 0 || slot.Coeff >= l.RingDegree {
				return fmt.Errorf("semantic slot out of range poly=%d coeff=%d", slot.Poly, slot.Coeff)
			}
		}
	}
	return nil
}

func validateRows(name string, rows [][]int64, wantRows, wantDegree int) error {
	if len(rows) != wantRows {
		return fmt.Errorf("%s rows=%d want %d", name, len(rows), wantRows)
	}
	for i := range rows {
		if len(rows[i]) != wantDegree {
			return fmt.Errorf("%s[%d] length=%d want %d", name, i, len(rows[i]), wantDegree)
		}
	}
	return nil
}

func zeroRows(rows, degree int) [][]int64 {
	out := make([][]int64, rows)
	for i := range out {
		out[i] = make([]int64, degree)
	}
	return out
}

func cloneInt64Rows(in [][]int64) [][]int64 {
	out := make([][]int64, len(in))
	for i := range in {
		out[i] = append([]int64(nil), in[i]...)
	}
	return out
}

func slotSet(slots []MessageSlot) map[[2]int]bool {
	out := make(map[[2]int]bool, len(slots))
	for _, slot := range slots {
		out[slotKey(slot.Poly, slot.Coeff)] = true
	}
	return out
}

func slotKey(poly, coeff int) [2]int {
	return [2]int{poly, coeff}
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func isTernaryInt64(v int64) bool {
	return v >= -1 && v <= 1
}

func isSupportedIntGenISISSemanticDomain(domain string) bool {
	switch domain {
	case IntGenISISDomainTernaryV1, IntGenISISDomainBoundedRangeV1, IntGenISISDomainBoundedRangeB4V1:
		return true
	default:
		return false
	}
}
