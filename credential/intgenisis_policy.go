package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	IntGenISISPolicyNoop    = "noop"
	IntGenISISPolicyMEquals = "m_eq"
)

type IntGenISISPolicy struct {
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data,omitempty"`
}

type IntGenISISMEqualsPolicyData struct {
	MAttr [][]int64 `json:"m"`
}

func NoopIntGenISISPolicy() IntGenISISPolicy {
	return IntGenISISPolicy{ID: IntGenISISPolicyNoop}
}

func ParseIntGenISISPolicy(data []byte) (IntGenISISPolicy, error) {
	if len(data) == 0 {
		return NoopIntGenISISPolicy(), nil
	}
	var p IntGenISISPolicy
	if err := decodeStrictJSON(data, &p); err != nil {
		return IntGenISISPolicy{}, fmt.Errorf("unmarshal IntGenISIS policy: %w", err)
	}
	if p.ID == "" {
		return IntGenISISPolicy{}, fmt.Errorf("IntGenISIS policy missing id")
	}
	return p, nil
}

func (p IntGenISISPolicy) CanonicalBytes() ([]byte, error) {
	if p.ID == "" {
		p = NoopIntGenISISPolicy()
	}
	switch p.ID {
	case IntGenISISPolicyNoop:
		if len(p.Data) != 0 && string(p.Data) != "null" {
			return nil, fmt.Errorf("noop IntGenISIS policy must not carry data")
		}
		p.Data = nil
	case IntGenISISPolicyMEquals:
		var typed IntGenISISMEqualsPolicyData
		if err := decodeStrictJSON(p.Data, &typed); err != nil {
			return nil, fmt.Errorf("canonicalize m_eq policy data: %w", err)
		}
		canonicalData, err := json.Marshal(typed)
		if err != nil {
			return nil, fmt.Errorf("marshal canonical m_eq policy data: %w", err)
		}
		p.Data = canonicalData
	default:
		return nil, fmt.Errorf("unsupported IntGenISIS policy %q", p.ID)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal IntGenISIS policy: %w", err)
	}
	return data, nil
}

func (p IntGenISISPolicy) DigestHex() (string, error) {
	data, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ValidateIntGenISISMEqualsPolicyData strictly decodes and validates the
// public m_eq statement independently of any honest witness. Attribute slots
// are canonical signed ternary values and every key/reserved slot is exactly
// zero. This prevents verifier-side Fq lifting from silently identifying
// invalid integers such as q-1 with -1 or q with 0.
func ValidateIntGenISISMEqualsPolicyData(layout SemanticMessageLayout, p IntGenISISPolicy) (IntGenISISMEqualsPolicyData, error) {
	var zero IntGenISISMEqualsPolicyData
	if p.ID != IntGenISISPolicyMEquals {
		return zero, fmt.Errorf("policy id=%q want %q", p.ID, IntGenISISPolicyMEquals)
	}
	if err := layout.validate(); err != nil {
		return zero, fmt.Errorf("validate m_eq semantic layout: %w", err)
	}
	var data IntGenISISMEqualsPolicyData
	if err := decodeStrictJSON(p.Data, &data); err != nil {
		return zero, fmt.Errorf("decode m_eq policy data: %w", err)
	}
	if err := validateRows("policy.m", data.MAttr, layout.AttributeRows, layout.RingDegree); err != nil {
		return zero, err
	}
	allowed := slotSet(layout.Attribute)
	for row := range data.MAttr {
		for coefficient, value := range data.MAttr[row] {
			if allowed[slotKey(row, coefficient)] {
				if !isTernaryInt64(value) {
					return zero, fmt.Errorf("policy.m[%d][%d]=%d outside ternary domain {-1,0,1}", row, coefficient, value)
				}
				continue
			}
			if value != 0 {
				return zero, fmt.Errorf("policy.m reserved/key slot row=%d coeff=%d is non-zero", row, coefficient)
			}
		}
	}
	return data, nil
}

func ValidateIntGenISISPolicy(layout SemanticMessageLayout, p IntGenISISPolicy, msg SemanticMessage) error {
	if p.ID == "" {
		p = NoopIntGenISISPolicy()
	}
	switch p.ID {
	case IntGenISISPolicyNoop:
		return nil
	case IntGenISISPolicyMEquals:
		data, err := ValidateIntGenISISMEqualsPolicyData(layout, p)
		if err != nil {
			return err
		}
		for r := range data.MAttr {
			for c := range data.MAttr[r] {
				if msg.MAttr[r][c] != data.MAttr[r][c] {
					return fmt.Errorf("m_eq policy mismatch at row=%d coeff=%d", r, c)
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported IntGenISIS policy %q", p.ID)
	}
}
