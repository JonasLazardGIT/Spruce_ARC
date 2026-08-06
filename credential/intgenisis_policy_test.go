package credential

import (
	"encoding/json"
	"strings"
	"testing"
)

func mEqualsPolicyForTest(t *testing.T, data any) IntGenISISPolicy {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return IntGenISISPolicy{ID: IntGenISISPolicyMEquals, Data: raw}
}

func TestValidateIntGenISISMEqualsPolicyDataCanonicalBoundary(t *testing.T) {
	layout, err := DefaultSemanticMessageLayout(Ternary1024IntGenISISProfile(), IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	valid := IntGenISISMEqualsPolicyData{MAttr: ZeroSemanticAttributes(layout)}
	valid.MAttr[0][layout.Attribute[0].Coeff] = -1
	valid.MAttr[0][layout.Attribute[1].Coeff] = 1
	decoded, err := ValidateIntGenISISMEqualsPolicyData(layout, mEqualsPolicyForTest(t, valid))
	if err != nil {
		t.Fatalf("valid signed-ternary statement rejected: %v", err)
	}
	if decoded.MAttr[0][0] != -1 || decoded.MAttr[0][1] != 1 {
		t.Fatalf("valid signed-ternary statement changed: %v", decoded.MAttr[0][:2])
	}

	q := int64(IntGenISISSharedModulusQ)
	reservedCoeff := layout.RingDegree - layout.TailReserve
	tests := []struct {
		name   string
		mutate func(*IntGenISISMEqualsPolicyData)
	}{
		{"attribute-q-minus-one", func(d *IntGenISISMEqualsPolicyData) { d.MAttr[0][0] = q - 1 }},
		{"attribute-q-plus-one", func(d *IntGenISISMEqualsPolicyData) { d.MAttr[0][0] = q + 1 }},
		{"reserved-q", func(d *IntGenISISMEqualsPolicyData) { d.MAttr[0][reservedCoeff] = q }},
		{"key-slot-nonzero", func(d *IntGenISISMEqualsPolicyData) { d.MAttr[0][layout.Key[0].Coeff] = 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := IntGenISISMEqualsPolicyData{MAttr: ZeroSemanticAttributes(layout)}
			tc.mutate(&candidate)
			if _, err := ValidateIntGenISISMEqualsPolicyData(layout, mEqualsPolicyForTest(t, candidate)); err == nil {
				t.Fatal("noncanonical public policy integer was accepted")
			}
		})
	}
}

func TestValidateIntGenISISMEqualsPolicyDataStrictJSON(t *testing.T) {
	layout, err := DefaultSemanticMessageLayout(Ternary1024IntGenISISProfile(), IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := json.Marshal(ZeroSemanticAttributes(layout))
	if err != nil {
		t.Fatal(err)
	}
	unknown := IntGenISISPolicy{
		ID:   IntGenISISPolicyMEquals,
		Data: json.RawMessage(`{"m":` + string(rows) + `,"unknown":1}`),
	}
	if _, err := ValidateIntGenISISMEqualsPolicyData(layout, unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown policy-data field was not rejected strictly: %v", err)
	}
	trailing := IntGenISISPolicy{
		ID:   IntGenISISPolicyMEquals,
		Data: append(append(json.RawMessage(nil), mEqualsPolicyForTest(t, IntGenISISMEqualsPolicyData{MAttr: ZeroSemanticAttributes(layout)}).Data...), []byte(" {}")...),
	}
	if _, err := ValidateIntGenISISMEqualsPolicyData(layout, trailing); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing policy-data JSON was not rejected: %v", err)
	}
}

func TestIntGenISISPolicyRejectsDuplicateKeysAndCanonicalizesTypedData(t *testing.T) {
	if _, err := ParseIntGenISISPolicy([]byte(`{"id":"noop","id":"noop"}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate outer policy key was accepted: %v", err)
	}
	layout, err := DefaultSemanticMessageLayout(Ternary1024IntGenISISProfile(), IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := json.Marshal(ZeroSemanticAttributes(layout))
	if err != nil {
		t.Fatal(err)
	}
	duplicateData := IntGenISISPolicy{
		ID:   IntGenISISPolicyMEquals,
		Data: json.RawMessage(`{"m":` + string(rows) + `,"m":` + string(rows) + `}`),
	}
	if _, err := ValidateIntGenISISMEqualsPolicyData(layout, duplicateData); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate nested m_eq key was accepted: %v", err)
	}
	if _, err := duplicateData.CanonicalBytes(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate nested m_eq key was canonicalized: %v", err)
	}

	typed := IntGenISISMEqualsPolicyData{MAttr: ZeroSemanticAttributes(layout)}
	compact := mEqualsPolicyForTest(t, typed)
	spaced := compact
	spaced.Data = json.RawMessage("  " + string(compact.Data) + "\n")
	compactBytes, err := compact.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	spacedBytes, err := spaced.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(compactBytes) != string(spacedBytes) {
		t.Fatal("equivalent typed m_eq data did not canonicalize identically")
	}
	if _, err := (IntGenISISPolicy{ID: IntGenISISPolicyNoop, Data: json.RawMessage(`{}`)}).CanonicalBytes(); err == nil {
		t.Fatal("noop policy payload was accepted")
	}
}
