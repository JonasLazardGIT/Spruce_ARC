package PIOP

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const canonicalPublicStatementDomainV3 = "SPRUCE/SmallWood/complete-public-statement/v3"
const canonicalRelationLayoutDomainV3 = "SPRUCE/SmallWood/reconstructed-row-layout/v3"
const canonicalPublicLayoutStatementDomainV3 = "SPRUCE/SmallWood/complete-public-and-layout-statement/v3"

// canonicalPublicInputsBytesV3 is the lossless, injectively framed encoding of
// every PublicInputs field used by strict v3 Fiat--Shamir.  In particular it
// does not pass through BuildPublicLabels: that historical helper omits zero
// values and a few legacy fields and therefore remains v2-only.
func canonicalPublicInputsBytesV3(pub PublicInputs) ([]byte, error) {
	if pub.RingDegree != 1024 {
		return nil, fmt.Errorf("canonical v3 public ring degree=%d want target degree 1024", pub.RingDegree)
	}
	out := make([]byte, 0, 4096)
	appendFrame := func(name string, payload []byte) {
		out = appendLengthPrefixedV3(out, []byte(name))
		out = appendLengthPrefixedV3(out, payload)
	}
	appendFrame("domain", []byte(canonicalPublicStatementDomainV3))

	var err error
	appendPolyVector := func(name string, polys []*ring.Poly) {
		if err != nil {
			return
		}
		var payload []byte
		payload = appendUint64V3(payload, uint64(len(polys)))
		for i, poly := range polys {
			var encoded []byte
			encoded, err = canonicalPublicPolyBytesV3(poly, pub.RingDegree, credential.IntGenISISSharedModulusQ)
			if err != nil {
				err = fmt.Errorf("canonical v3 public %s[%d]: %w", name, i, err)
				return
			}
			payload = appendLengthPrefixedV3(payload, encoded)
		}
		appendFrame(name, payload)
	}
	appendPolyMatrix := func(name string, matrix [][]*ring.Poly) {
		if err != nil {
			return
		}
		var payload []byte
		payload = appendUint64V3(payload, uint64(len(matrix)))
		for i, row := range matrix {
			rowPayload := appendUint64V3(nil, uint64(len(row)))
			for j, poly := range row {
				var encoded []byte
				encoded, err = canonicalPublicPolyBytesV3(poly, pub.RingDegree, credential.IntGenISISSharedModulusQ)
				if err != nil {
					err = fmt.Errorf("canonical v3 public %s[%d][%d]: %w", name, i, j, err)
					return
				}
				rowPayload = appendLengthPrefixedV3(rowPayload, encoded)
			}
			payload = appendLengthPrefixedV3(payload, rowPayload)
		}
		appendFrame(name, payload)
	}
	appendInt64Vector := func(name string, values []int64) {
		payload := appendUint64V3(nil, uint64(len(values)))
		for _, value := range values {
			payload = appendUint64V3(payload, uint64(value))
		}
		appendFrame(name, payload)
	}
	appendBytes := func(name string, value []byte) {
		appendFrame(name, append([]byte(nil), value...))
	}
	appendInt64 := func(name string, value int64) {
		appendFrame(name, appendUint64V3(nil, uint64(value)))
	}
	appendInt := func(name string, value int) {
		appendFrame(name, appendUint64V3(nil, uint64(int64(value))))
	}
	appendBool := func(name string, value bool) {
		b := byte(0)
		if value {
			b = 1
		}
		appendFrame(name, []byte{b})
	}

	appendPolyVector("Com", pub.Com)
	appendPolyVector("RI0", pub.RI0)
	appendPolyVector("RI1", pub.RI1)
	appendPolyMatrix("Ac", pub.Ac)
	appendPolyMatrix("CM", pub.CM)
	appendPolyMatrix("AS", pub.AS)
	appendPolyMatrix("A", pub.A)
	appendPolyVector("B", pub.B)
	appendInt64Vector("T", pub.T)
	appendInt64Vector("Tag", pub.Tag)
	appendInt64Vector("Context", pub.Context)
	appendBytes("ContextDigest", pub.ContextDigest)
	appendInt64("BoundB", pub.BoundB)
	appendInt("X0Len", pub.X0Len)
	appendInt64("X0CoeffBound", pub.X0CoeffBound)
	appendInt64("HashInputBound", pub.HashInputBound)
	appendInt("TargetDim", pub.TargetDim)
	appendInt("TargetHidingLambda", pub.TargetHidingLambda)
	appendInt("RingDegree", pub.RingDegree)
	appendBytes("HashRelation", []byte(pub.HashRelation))
	appendBool("IntGenISIS", pub.IntGenISIS)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(pub.Extras))
	for key := range pub.Extras {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	extras := appendUint64V3(nil, uint64(len(keys)))
	for _, key := range keys {
		value, ok := pub.Extras[key].([]byte)
		if !ok {
			return nil, fmt.Errorf("canonical v3 public extra %q has unsupported type %T; strict v3 accepts []byte only", key, pub.Extras[key])
		}
		extras = appendLengthPrefixedV3(extras, []byte(key))
		extras = appendLengthPrefixedV3(extras, value)
	}
	appendFrame("Extras", extras)
	if len(out) > canonicalProofMaxBytes {
		return nil, fmt.Errorf("canonical v3 public statement size %d exceeds limit", len(out))
	}
	return out, nil
}

func canonicalPublicPolyBytesV3(poly *ring.Poly, ringDegree int, q uint64) ([]byte, error) {
	if poly == nil || len(poly.Coeffs) != 1 || len(poly.Coeffs[0]) != ringDegree {
		return nil, fmt.Errorf("polynomial has noncanonical one-limb N=%d shape", ringDegree)
	}
	out := appendUint64V3(nil, 1)
	out = appendUint64V3(out, uint64(ringDegree))
	for i, coefficient := range poly.Coeffs[0] {
		if coefficient >= q {
			return nil, fmt.Errorf("coefficient %d=%d is >=q", i, coefficient)
		}
		out = appendUint64V3(out, coefficient)
	}
	return out, nil
}

func appendLengthPrefixedV3(dst, value []byte) []byte {
	dst = appendUint64V3(dst, uint64(len(value)))
	return append(dst, value...)
}

func appendUint64V3(dst []byte, value uint64) []byte {
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], value)
	return append(dst, word[:]...)
}

// canonicalPublicStatementWithLayoutBytesV3 binds the complete trusted public
// statement and the complete verifier-reconstructed row layout into the v3
// Fiat--Shamir statement.  The layout is not supplied by the proof wire.  This
// prevents a proof compiled for an older internal row inventory from sharing a
// transcript with the current, equivalently formulated relation compiler.
func canonicalPublicStatementWithLayoutBytesV3(pub PublicInputs, layout RowLayout) ([]byte, error) {
	publicBytes, err := canonicalPublicInputsBytesV3(pub)
	if err != nil {
		return nil, err
	}
	layoutBytes, err := canonicalRowLayoutBytesV3(layout)
	if err != nil {
		return nil, err
	}
	out := appendLengthPrefixedV3(nil, []byte(canonicalPublicLayoutStatementDomainV3))
	// The relation remains v3, while the canonical proof representation is a
	// separately versioned v6 codec. Bind its complete profile here so a proof
	// using the former fixed-20/Q-tail representation cannot retain the same
	// Fiat--Shamir statement under the new decoder.
	out = appendLengthPrefixedV3(out, canonicalProofCodecProfileBytesV6())
	out = appendLengthPrefixedV3(out, publicBytes)
	out = appendLengthPrefixedV3(out, layoutBytes)
	if len(out) > canonicalProofMaxBytes {
		return nil, fmt.Errorf("canonical v3 public/layout statement size %d exceeds limit", len(out))
	}
	return out, nil
}

func canonicalRowLayoutBytesV3(layout RowLayout) ([]byte, error) {
	out := appendLengthPrefixedV3(nil, []byte(canonicalRelationLayoutDomainV3))
	return appendCanonicalLayoutValueV3(out, reflect.ValueOf(layout))
}

// appendCanonicalLayoutValueV3 is an injective, field-name-framed encoder for
// the closed RowLayout type graph.  It intentionally includes zero values,
// nil/present markers, and every exported struct field; JSON omitempty tags do
// not participate in this security-critical binding.
func appendCanonicalLayoutValueV3(dst []byte, value reflect.Value) ([]byte, error) {
	if !value.IsValid() {
		return append(dst, 0), nil
	}
	switch value.Kind() {
	case reflect.Pointer:
		dst = append(dst, 'p')
		if value.IsNil() {
			return append(dst, 0), nil
		}
		dst = append(dst, 1)
		return appendCanonicalLayoutValueV3(dst, value.Elem())
	case reflect.Struct:
		dst = append(dst, 's')
		typ := value.Type()
		dst = appendLengthPrefixedV3(dst, []byte(typ.Name()))
		exported := 0
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).PkgPath == "" {
				exported++
			}
		}
		dst = appendUint64V3(dst, uint64(exported))
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			dst = appendLengthPrefixedV3(dst, []byte(field.Name))
			var err error
			dst, err = appendCanonicalLayoutValueV3(dst, value.Field(i))
			if err != nil {
				return nil, err
			}
		}
		return dst, nil
	case reflect.Slice:
		dst = append(dst, 'l')
		if value.IsNil() {
			return append(dst, 0), nil
		}
		dst = append(dst, 1)
		dst = appendUint64V3(dst, uint64(value.Len()))
		for i := 0; i < value.Len(); i++ {
			var err error
			dst, err = appendCanonicalLayoutValueV3(dst, value.Index(i))
			if err != nil {
				return nil, err
			}
		}
		return dst, nil
	case reflect.Array:
		dst = append(dst, 'a')
		dst = appendUint64V3(dst, uint64(value.Len()))
		for i := 0; i < value.Len(); i++ {
			var err error
			dst, err = appendCanonicalLayoutValueV3(dst, value.Index(i))
			if err != nil {
				return nil, err
			}
		}
		return dst, nil
	case reflect.String:
		return appendLengthPrefixedV3(append(dst, 't'), []byte(value.String())), nil
	case reflect.Bool:
		if value.Bool() {
			return append(dst, 'b', 1), nil
		}
		return append(dst, 'b', 0), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return appendUint64V3(append(dst, 'i'), uint64(value.Int())), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return appendUint64V3(append(dst, 'u'), value.Uint()), nil
	default:
		return nil, fmt.Errorf("canonical v3 row layout contains unsupported %s value", value.Kind())
	}
}
