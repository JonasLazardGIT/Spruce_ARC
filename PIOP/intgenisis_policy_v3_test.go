package PIOP

import (
	"encoding/json"
	"testing"

	"vSIS-Signature/credential"
)

func TestIntGenISISPolicyCoeffViewV3RejectsNoncanonicalPublicIntegers(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := credential.DefaultSemanticMessageLayout(credential.Ternary1024IntGenISISProfile(), intGenISISPRFKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	ctx := canonicalPreSignContextForTest(t, 7)
	omega, err := deriveRelationWitnessOmega(
		ringQ.Modulus[0], ctx.Options.NLeaves, ctx.Options.NCols,
		ctx.Options.LVCSNCols, ctx.Options.Ell, ctx.Public.HashRelation,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy := func(rows [][]int64) credential.IntGenISISPolicy {
		raw, marshalErr := json.Marshal(credential.IntGenISISMEqualsPolicyData{MAttr: rows})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return credential.IntGenISISPolicy{ID: credential.IntGenISISPolicyMEquals, Data: raw}
	}
	valid := credential.ZeroSemanticAttributes(layout)
	valid[0][0] = -1
	valid[0][1] = 1
	if _, err := intGenISISPolicyCoeffViewCoeffs(ringQ, policy(valid), layout, omega[:ctx.Options.NCols], ctx.Options.NCols); err != nil {
		t.Fatalf("valid signed-ternary verifier statement rejected: %v", err)
	}

	q := int64(ringQ.Modulus[0])
	reservedCoeff := layout.RingDegree - layout.TailReserve
	for _, tc := range []struct {
		name  string
		coeff int
		value int64
	}{
		{"attribute-q-minus-one", 0, q - 1},
		{"attribute-q-plus-one", 0, q + 1},
		{"reserved-q", reservedCoeff, q},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := credential.ZeroSemanticAttributes(layout)
			rows[0][tc.coeff] = tc.value
			if _, err := intGenISISPolicyCoeffViewCoeffs(ringQ, policy(rows), layout, omega[:ctx.Options.NCols], ctx.Options.NCols); err == nil {
				t.Fatal("verifier relation compiler accepted a noncanonical public policy integer")
			}
		})
	}
}
