package PIOP

import "testing"

func TestSigLookupShadowDefaultsToR121L2V18(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:                  true,
		CoeffNativeSigModel:         CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:               ShowingPresetInlineTargetReplayCompactResearch,
		PRFCompanionMode:            PRFCompanionModeOutputAudit,
		PRFCheckpointSamples:        8,
		UnsafeSigLookupShadowR121L2: SigLookupShadowR121L2Free,
	})
	if opts.SigShortnessRadix != sigLookupShadowR121L2Radix || opts.SigShortnessL != sigLookupShadowR121L2Digits {
		t.Fatalf("shadow shortness shape R=%d L=%d", opts.SigShortnessRadix, opts.SigShortnessL)
	}
	if !sigShortnessV18EnabledForOpts(opts) {
		t.Fatalf("shadow shortness should keep V18 optimized showing path")
	}
	if got := ResolveSignatureShortnessProfileLabelForOpts(opts); got != SigShortnessProfileCustomBalanced {
		t.Fatalf("shadow profile label=%q want %q", got, SigShortnessProfileCustomBalanced)
	}
}

func TestSigLookupShadowSameQKeepsDegree121(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:                  true,
		CoeffNativeSigModel:         CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:               ShowingPresetInlineTargetReplayCompactResearch,
		UnsafeSigLookupShadowR121L2: SigLookupShadowR121L2SameQ,
	})
	if sigLookupShadowR121L2FreeForOpts(opts) {
		t.Fatalf("same_q shadow should not use free lookup mode")
	}
	spec, err := signatureCoeffLinfSpecChecked(8380417, sigLookupShadowR121L2Radix, sigLookupShadowR121L2Digits, 1, nil)
	if err != nil {
		t.Fatalf("signature spec: %v", err)
	}
	deg, err := signatureShortnessMaxDegree(spec, opts)
	if err != nil {
		t.Fatalf("signature degree: %v", err)
	}
	if deg != sigLookupShadowR121L2TableSize {
		t.Fatalf("same_q degree=%d want %d", deg, sigLookupShadowR121L2TableSize)
	}
}

func TestR121L2PairPackingCoversR11L4Digits(t *testing.T) {
	for d0 := int64(-5); d0 <= 5; d0++ {
		for d1 := int64(-5); d1 <= 5; d1++ {
			for d2 := int64(-5); d2 <= 5; d2++ {
				for d3 := int64(-5); d3 <= 5; d3++ {
					s := d0 + 11*d1 + 121*d2 + 1331*d3
					y0 := d0 + 11*d1
					y1 := d2 + 11*d3
					if y0 < sigLookupShadowR121L2TableLo || y0 > sigLookupShadowR121L2TableHi || y1 < sigLookupShadowR121L2TableLo || y1 > sigLookupShadowR121L2TableHi {
						t.Fatalf("packed digit outside table: y0=%d y1=%d", y0, y1)
					}
					if got := y0 + 121*y1; got != s {
						t.Fatalf("recompose mismatch got=%d want=%d", got, s)
					}
				}
			}
		}
	}
}

func TestBalancedR121DigitExpandsToTwoR11Digits(t *testing.T) {
	for y := int64(sigLookupShadowR121L2TableLo); y <= int64(sigLookupShadowR121L2TableHi); y++ {
		d0 := y % 11
		if d0 > 5 {
			d0 -= 11
		}
		if d0 < -5 {
			d0 += 11
		}
		d1 := (y - d0) / 11
		if d0 < -5 || d0 > 5 || d1 < -5 || d1 > 5 {
			t.Fatalf("y=%d expands to d0=%d d1=%d outside [-5,5]", y, d0, d1)
		}
		if got := d0 + 11*d1; got != y {
			t.Fatalf("expand mismatch got=%d want=%d", got, y)
		}
	}
}
