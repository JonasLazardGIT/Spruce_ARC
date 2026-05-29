package signverify

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	mrand "math/rand"

	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
)

const betaCalibrationLabel = "spruce-beta-calibration-v1"

// BetaCalibrationReport captures deterministic production-bound calibration
// over a fixed batch of signatures on one canonical keypair.
type BetaCalibrationReport struct {
	Samples       int     `json:"samples"`
	Alpha         float64 `json:"alpha"`
	PerSample     []int64 `json:"per_sample"`
	BatchMax      int64   `json:"batch_max"`
	BatchMaxIndex int     `json:"batch_max_index"`
}

func deterministicCalibrationSeed(prefix string, idx int) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", betaCalibrationLabel, prefix, idx)))
	return sum[:]
}

func signerOptsWithTunedAlpha(pk *keys.PublicKey, sk *keys.PrivateKey, opts ntru.SamplerOpts) (ntru.Params, ntru.SamplerOpts, error) {
	par, err := paramsFromPublicKey(pk)
	if err != nil {
		return ntru.Params{}, ntru.SamplerOpts{}, err
	}
	prec := opts.Prec
	if prec == 0 {
		prec = 512
	}
	opts.Prec = prec
	sampler, err := ntru.NewSampler(sk.Fsmall, sk.Gsmall, sk.F, sk.G, par, prec)
	if err != nil {
		return ntru.Params{}, ntru.SamplerOpts{}, err
	}
	opts.UseCNormalDist = true
	opts.UseExactResidual = true
	opts.BoundShape = "cstyle"
	if par.LOG3_D {
		opts.UseLog3Cross = true
	}
	if err := autoTuneSignerAlpha(&opts, sampler); err != nil {
		return ntru.Params{}, ntru.SamplerOpts{}, err
	}
	opts.ApplyDefaults(par)
	opts.AutoTuneAlpha = false
	return par, opts, nil
}

func paramsFromPublicKey(pk *keys.PublicKey) (ntru.Params, error) {
	if pk == nil {
		return ntru.Params{}, fmt.Errorf("nil public key")
	}
	return paramsFromNQ(pk.N, pk.Q)
}

func paramsFromNQ(n int, qHex string) (ntru.Params, error) {
	Q, err := parseQHex(qHex)
	if err != nil {
		return ntru.Params{}, err
	}
	return ntru.NewParams(n, Q)
}

func parseQHex(qHex string) (*big.Int, error) {
	Q := new(big.Int)
	if _, ok := Q.SetString(qHex, 16); !ok {
		return nil, fmt.Errorf("invalid Q")
	}
	return Q, nil
}

// CalibrateMeasuredBeta signs a fixed batch of deterministic targets with the
// canonical regenerated keypair and returns the max signed-coordinate bound.
func CalibrateMeasuredBeta(paths SignPaths, samples, maxTrials int, opts ntru.SamplerOpts) (*BetaCalibrationReport, error) {
	if samples <= 0 {
		return nil, fmt.Errorf("invalid samples=%d", samples)
	}
	if maxTrials <= 0 {
		maxTrials = 2048
	}
	paramsPath := paths.ParamsPath
	if paramsPath == "" {
		paramsPath = "Parameters/Parameters.json"
	}
	bFile := paths.BFile
	if bFile == "" {
		bFile = "Parameters/Bmatrix.intgenisis_profile_b.json"
	}
	pkPath := paths.PublicKeyPath
	if pkPath == "" {
		pkPath = "ntru_keys/public.json"
	}
	skPath := paths.PrivatePath
	if skPath == "" {
		skPath = "ntru_keys/private.json"
	}
	sys, err := loadParamsFromPath(paramsPath)
	if err != nil {
		return nil, err
	}
	pk, err := keys.LoadPublicFile(pkPath)
	if err != nil {
		return nil, err
	}
	sk, err := keys.LoadPrivateFile(skPath)
	if err != nil {
		return nil, err
	}
	_, tunedOpts, err := signerOptsWithTunedAlpha(pk, sk, opts)
	if err != nil {
		return nil, err
	}
	report := &BetaCalibrationReport{
		Samples:   samples,
		Alpha:     tunedOpts.Alpha,
		PerSample: make([]int64, samples),
	}
	for i := 0; i < samples; i++ {
		mSeed := deterministicCalibrationSeed("m", i)
		x0Seed := deterministicCalibrationSeed("x0", i)
		x1Seed := deterministicCalibrationSeed("x1", i)
		tCoeffs, err := ntru.ComputeTargetFromSeeds(sys, bFile, "", mSeed, x0Seed, x1Seed)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		meta := targetMeta{
			BFile:        bFile,
			HashRelation: "",
			MSeed:        mSeed,
			X0Seed:       x0Seed,
			X1Seed:       x1Seed,
			Persist:      false,
		}
		mrand.Seed(int64(0x5a5a0000) + int64(i))
		sig, err := signWithLoadedKeys(pk, sk, tCoeffs, maxTrials, tunedOpts, meta, "")
		if err != nil {
			return nil, fmt.Errorf("sign target %d: %w", i, err)
		}
		sampleMax := maxAbsPair(sig.Signature.S1, sig.Signature.S2)
		report.PerSample[i] = sampleMax
		if sampleMax > report.BatchMax {
			report.BatchMax = sampleMax
			report.BatchMaxIndex = i
		}
	}
	return report, nil
}

func maxAbsPair(a, b []int64) int64 {
	maxAbs := func(xs []int64) int64 {
		var m int64
		for _, v := range xs {
			if v < 0 {
				v = -v
			}
			if v > m {
				m = v
			}
		}
		return m
	}
	am := maxAbs(a)
	bm := maxAbs(b)
	if bm > am {
		return bm
	}
	return am
}
