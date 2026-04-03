package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func usage() {
	fmt.Println(`usage: ntru <gen|sign|verify|calibrate-beta|bundle-sign|bundle-verify> [options]

Subcommands:
  gen            Generate an NTRU keypair and write ./ntru_keys/{public,private}.json
  sign           Sign a message and write ./ntru_keys/signature.json
  verify         Verify ./ntru_keys/signature.json against ./ntru_keys/public.json
  calibrate-beta Measure production beta on a deterministic signature batch
  bundle-sign    Sign a message against a bundle directory
  bundle-verify  Verify a bundle signature`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gen":
		runGen()
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify()
	case "calibrate-beta":
		runCalibrateBeta(os.Args[2:])
	case "bundle-sign":
		runBundleSign(os.Args[2:])
	case "bundle-verify":
		runBundleVerify(os.Args[2:])
	default:
		usage()
	}
}

func runGen() {
	flag.NewFlagSet("gen", flag.ExitOnError).Parse(os.Args[2:])

	pp, err := signverify.LoadParamsForCLI()
	if err != nil {
		log.Fatalf("load params: %v", err)
	}
	q := new(big.Int).SetUint64(pp.Q)
	par, err := ntru.NewParams(pp.N, q)
	if err != nil {
		log.Fatalf("params: %v", err)
	}
	if err := regenerateBMatrix(pp); err != nil {
		log.Fatalf("generate B matrix: %v", err)
	}
	kg := ntru.KeygenOpts{
		Prec:      512,
		MaxTrials: 10000,
		Alpha:     1.20,
	}
	if _, _, err := generateKeypairAnnulusWithRetry(par, kg, 4); err != nil {
		log.Fatalf("gen: %v", err)
	}
	fmt.Println("B matrix written to ./Parameters/Bmatrix.json")
	fmt.Println("keys written to ./ntru_keys")
}

func regenerateBMatrix(pp *ntrurio.SystemParams) error {
	if pp == nil {
		return fmt.Errorf("nil params")
	}
	ringQ, err := ring.NewRing(pp.N, []uint64{pp.Q})
	if err != nil {
		return err
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		return err
	}
	B, err := vsishash.GenerateB(ringQ, prng)
	if err != nil {
		return err
	}
	coeffs := make([][]uint64, len(B))
	for i := range B {
		coeffs[i] = make([]uint64, len(B[i].Coeffs[0]))
		copy(coeffs[i], B[i].Coeffs[0])
	}
	if err := os.MkdirAll("Parameters", 0o755); err != nil {
		return err
	}
	return ntrurio.SaveBMatrixCoeffs(filepath.Join("Parameters", "Bmatrix.json"), coeffs)
}

func generateKeypairAnnulusWithRetry(par ntru.Params, kg ntru.KeygenOpts, attempts int) (*keys.PublicKey, *keys.PrivateKey, error) {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		pk, sk, err := signverify.GenerateKeypairAnnulus(par, kg)
		if err == nil {
			return pk, sk, nil
		}
		lastErr = err
		if attempt < attempts {
			log.Printf("gen: retrying annulus keygen after attempt %d/%d failed: %v", attempt, attempts, err)
		}
	}
	return nil, nil, lastErr
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	msg := fs.String("m", "", "message string")
	fs.Parse(args)

	if *msg == "" {
		log.Fatalf("sign: -m is required")
	}
	opts := shippedSamplerOpts()

	sig, err := signverify.SignWithOpts([]byte(*msg), 2048, opts)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	fmt.Printf("sign: trials_used=%d rejected=%v max_trials=%d\n", sig.Signature.TrialsUsed, sig.Signature.Rejected, sig.Signature.MaxTrials)
	fmt.Printf("sign: l2_est=%.4g\n", sig.Signature.Norm.L2Est)

	priv, err := keys.LoadPrivate()
	if err == nil {
		qInt := new(big.Int)
		if _, ok := qInt.SetString(sig.Params.Q, 16); ok {
			if parRes, err := ntru.NewParams(sig.Params.N, qInt); err == nil {
				h, errH := ntru.PublicKeyH(ntru.Int64ToModQPoly(priv.Fsmall, parRes), ntru.Int64ToModQPoly(priv.Gsmall, parRes), parRes)
				s1Poly := ntru.Int64ToModQPoly(sig.Signature.S1, parRes)
				hs1, errConv := ntru.ConvolveRNS(s1Poly, h, parRes)
				if errH == nil && errConv == nil {
					tPoly := ntru.Int64ToModQPoly(sig.Hash.TCoeffs, parRes)
					residual := hs1.Add(tPoly)
					if centered, errC := ntru.CenterModQToInt64(residual, parRes); errC == nil {
						fmt.Printf("sign: residual_linf=%d\n", maxAbs(centered))
					}
				}
			}
		}
	}
	fmt.Println("signature written to ./ntru_keys/signature.json")
}

func runVerify() {
	sig, err := keys.Load()
	if err != nil {
		log.Fatalf("load signature: %v", err)
	}
	if err := signverify.Verify(sig); err != nil {
		log.Fatalf("verify failed: %v", err)
	}
	fmt.Println("signature verified")
}

func runCalibrateBeta(args []string) {
	fs := flag.NewFlagSet("calibrate-beta", flag.ExitOnError)
	samples := fs.Int("samples", 64, "number of deterministic targets to sign")
	maxTrials := fs.Int("max-trials", 2048, "signer max trials per target")
	paramsPath := fs.String("params", "Parameters/Parameters.json", "params JSON path")
	bFile := fs.String("bfile", "Parameters/Bmatrix.json", "B-matrix JSON path")
	publicPath := fs.String("public", "ntru_keys/public.json", "public key path")
	privatePath := fs.String("private", "ntru_keys/private.json", "private key path")
	updateParams := fs.Bool("update-params", false, "write measured beta/bound back into params JSON")
	fs.Parse(args)

	opts := shippedSamplerOpts()
	opts.AutoTuneAlpha = true
	opts.AutoTuneAlphaMargin = 1.00
	report, err := signverify.CalibrateMeasuredBeta(signverify.SignPaths{
		ParamsPath:    *paramsPath,
		BFile:         *bFile,
		PublicKeyPath: *publicPath,
		PrivatePath:   *privatePath,
	}, *samples, *maxTrials, opts)
	if err != nil {
		log.Fatalf("calibrate-beta: %v", err)
	}
	fmt.Printf("calibrate-beta: samples=%d alpha=%.6f batch_max=%d batch_max_index=%d\n", report.Samples, report.Alpha, report.BatchMax, report.BatchMaxIndex)
	fmt.Printf("calibrate-beta: per_sample=%v\n", report.PerSample)
	if *updateParams {
		if err := updateParamsBeta(*paramsPath, uint64(report.BatchMax)); err != nil {
			log.Fatalf("update params beta: %v", err)
		}
		fmt.Printf("calibrate-beta: updated %s beta=%d bound=%d\n", *paramsPath, report.BatchMax, report.BatchMax)
	}
}

func updateParamsBeta(path string, beta uint64) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	payload["beta"] = beta
	payload["bound"] = beta
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func runBundleSign(args []string) {
	fs := flag.NewFlagSet("bundle-sign", flag.ExitOnError)
	bundleDir := fs.String("bundle", "", "bundle directory containing Parameters.json, Bmatrix.json, public.json, private.json")
	msg := fs.String("m", "", "message string")
	fs.Parse(args)

	if *bundleDir == "" {
		log.Fatalf("bundle-sign: -bundle is required")
	}
	if *msg == "" {
		log.Fatalf("bundle-sign: -m is required")
	}
	paths := signverify.SignPaths{
		ParamsPath:    filepath.Join(*bundleDir, "Parameters.json"),
		BFile:         filepath.Join(*bundleDir, "Bmatrix.json"),
		PublicKeyPath: filepath.Join(*bundleDir, "public.json"),
		PrivatePath:   filepath.Join(*bundleDir, "private.json"),
		SignaturePath: filepath.Join(*bundleDir, "signature.json"),
	}
	sig, err := signverify.SignWithPaths([]byte(*msg), 2048, shippedSamplerOpts(), paths)
	if err != nil {
		log.Fatalf("bundle-sign: %v", err)
	}
	fmt.Printf("bundle-sign: trials_used=%d rejected=%v max_trials=%d\n", sig.Signature.TrialsUsed, sig.Signature.Rejected, sig.Signature.MaxTrials)
	fmt.Printf("bundle-sign: residual_linf=%d\n", sig.Signature.Norm.ResidualLinf)
	fmt.Printf("bundle-sign: l2_est=%.4g\n", sig.Signature.Norm.L2Est)
	fmt.Printf("signature written to %s\n", paths.SignaturePath)
}

func runBundleVerify(args []string) {
	fs := flag.NewFlagSet("bundle-verify", flag.ExitOnError)
	bundleDir := fs.String("bundle", "", "bundle directory containing Parameters.json and signature.json")
	fs.Parse(args)
	if *bundleDir == "" {
		log.Fatalf("bundle-verify: -bundle is required")
	}
	sigPath := filepath.Join(*bundleDir, "signature.json")
	sig, err := keys.LoadSignatureFile(sigPath)
	if err != nil {
		log.Fatalf("bundle-verify: load signature: %v", err)
	}
	paramsPath := filepath.Join(*bundleDir, "Parameters.json")
	if err := signverify.VerifyWithParamsPath(sig, paramsPath); err != nil {
		log.Fatalf("bundle-verify: verify failed: %v", err)
	}
	fmt.Printf("signature verified: %s\n", sigPath)
}

func maxAbs(vals []int64) int64 {
	var m int64
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	return m
}

func shippedSamplerOpts() ntru.SamplerOpts {
	return ntru.SamplerOpts{}
}
