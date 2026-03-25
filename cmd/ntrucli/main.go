package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
)

func usage() {
	fmt.Println(`usage: ntru <gen|sign|verify|bundle-sign|bundle-verify> [options]

Subcommands:
  gen            Generate an NTRU keypair and write ./ntru_keys/{public,private}.json
  sign           Sign a message and write ./ntru_keys/signature.json
  verify         Verify ./ntru_keys/signature.json against ./ntru_keys/public.json
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
	kg := ntru.KeygenOpts{
		Prec:      512,
		MaxTrials: 10000,
		Alpha:     1.20,
	}
	if _, _, err := generateKeypairAnnulusWithRetry(par, kg, 4); err != nil {
		log.Fatalf("gen: %v", err)
	}
	fmt.Println("keys written to ./ntru_keys")
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
