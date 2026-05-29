package issuance

import (
	"fmt"
	"log"

	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
)

func SignTargetAndSaveWithPaths(t []int64, maxTrials int, opts ntru.SamplerOpts, paths signverify.SignPaths) (*keys.Signature, error) {
	log.Printf("[issuance] signing target (len=%d) with NTRU trapdoor", len(t))
	if maxTrials == 0 {
		maxTrials = 2048
	}
	if opts.Prec == 0 {
		opts.Prec = 256
	}
	sig, err := signTargetWithinBetaWithPaths(t, maxTrials, opts, 16, paths)
	if err != nil {
		return nil, fmt.Errorf("sign target: %w", err)
	}
	signaturePath := paths.SignaturePath
	if signaturePath == "" {
		if err := keys.Save(sig); err != nil {
			return nil, fmt.Errorf("save signature: %w", err)
		}
		signaturePath = "./ntru_keys/signature.json"
	} else if err := keys.SaveSignatureFile(signaturePath, sig); err != nil {
		return nil, fmt.Errorf("save signature: %w", err)
	}
	log.Printf("[issuance] signature saved to %s (trials_used=%d rejected=%v)", signaturePath, sig.Signature.TrialsUsed, sig.Signature.Rejected)
	return sig, nil
}

func signTargetWithinBetaWithPaths(t []int64, maxTrials int, opts ntru.SamplerOpts, attempts int, paths signverify.SignPaths) (*keys.Signature, error) {
	if attempts <= 0 {
		attempts = 1
	}
	paramsPath := paths.ParamsPath
	if paramsPath == "" {
		paramsPath = "Parameters/Parameters.json"
	}
	par, err := ntrurio.LoadParams(paramsPath, true)
	if err != nil {
		return nil, fmt.Errorf("load signature bound: %w", err)
	}
	if par.N != len(t) {
		return nil, fmt.Errorf("signature params N=%d incompatible with target length=%d", par.N, len(t))
	}
	var lastMax int64
	for attempt := 1; attempt <= attempts; attempt++ {
		sig, err := signverify.SignTargetWithPaths(t, maxTrials, opts, paths)
		if err != nil {
			return nil, err
		}
		lastMax = signatureLInf(sig)
		if uint64(lastMax) <= par.Beta {
			return sig, nil
		}
		log.Printf("[issuance] retrying target signature: max coefficient %d exceeds beta=%d (attempt %d/%d)", lastMax, par.Beta, attempt, attempts)
	}
	return nil, fmt.Errorf("signature shortness blocker after %d attempts: max coefficient %d exceeds beta=%d under q=%d", attempts, lastMax, par.Beta, par.Q)
}

func signatureLInf(sig *keys.Signature) int64 {
	if sig == nil {
		return 0
	}
	maxAbs := int64(0)
	for _, row := range [][]int64{sig.Signature.S1, sig.Signature.S2} {
		for _, v := range row {
			if v < 0 {
				v = -v
			}
			if v > maxAbs {
				maxAbs = v
			}
		}
	}
	return maxAbs
}
