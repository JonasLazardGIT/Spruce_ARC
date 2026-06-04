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
	if err := json.Unmarshal(data, &p); err != nil {
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

func ValidateIntGenISISPolicy(layout SemanticMessageLayout, p IntGenISISPolicy, msg SemanticMessage) error {
	if p.ID == "" {
		p = NoopIntGenISISPolicy()
	}
	switch p.ID {
	case IntGenISISPolicyNoop:
		return nil
	case IntGenISISPolicyMEquals:
		var data IntGenISISMEqualsPolicyData
		if err := json.Unmarshal(p.Data, &data); err != nil {
			return fmt.Errorf("decode m_eq policy data: %w", err)
		}
		if err := validateRows("policy.m", data.MAttr, layout.AttributeRows, layout.RingDegree); err != nil {
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
