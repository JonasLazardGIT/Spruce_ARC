package prf

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCanonicalTargetParamsV3BindsEveryExecutedConstant(t *testing.T) {
	for _, path := range []string{"prf_params_tag9.json", "prf_params_tag10.json", "prf_params_tag13.json"} {
		t.Run(path, func(t *testing.T) {
			params, canonical, err := LoadEmbeddedTargetParamsV3(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(canonical) == 0 {
				t.Fatal("empty canonical strict-v3 PRF profile")
			}

			// A semantically identical JSON re-encoding has the same canonical
			// profile even though its file bytes/whitespace differ.
			reencoded, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := LoadParams(bytes.NewReader(reencoded))
			if err != nil {
				t.Fatal(err)
			}
			same, err := CanonicalParamsBytesV3(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, same) {
				t.Fatal("canonical PRF profile depends on JSON formatting")
			}

			decoded.CInt[0] = (decoded.CInt[0] + 1) % decoded.Q
			mutated, err := CanonicalParamsBytesV3(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(canonical, mutated) {
				t.Fatal("canonical PRF profile did not bind a round constant")
			}
		})
	}
}
