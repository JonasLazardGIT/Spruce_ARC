package signverify

import (
	"errors"
	"fmt"
	"math/big"

	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
)

// Hybrid-B defaults enforce a meaningful residual bound during sampling.
var defaultOpts = ntru.SamplerOpts{
	RSquare:          ntru.CReferenceRSquare(),
	Alpha:            1.25,
	Slack:            1.042,
	ReduceIters:      64,
	UseCNormalDist:   true,
	UseExactResidual: true,
	BoundShape:       "cstyle",
	Prec:             512,
	AutoTuneAlpha:    true,
}

func loadParams() (*ntrurio.SystemParams, error) {
	p, err := ntrurio.LoadParams("internal/source_data/Parameters.json", true)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func GenerateKeypairAnnulusToFiles(sys ntrurio.SystemParams, kg ntru.KeygenOpts, publicPath, privatePath string) (pk *keys.PublicKey, sk *keys.PrivateKey, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			pk = nil
			sk = nil
			err = fmt.Errorf("annulus keygen panic: %v", rec)
		}
	}()
	canonical, err := ntrurio.CanonicalizeParams(sys)
	if err != nil {
		return nil, nil, err
	}
	par, err := ntru.NewParams(canonical.N, new(big.Int).SetUint64(canonical.Q))
	if err != nil {
		return nil, nil, err
	}
	pk, sk, err = generateKeypairAnnulusNoRecover(canonical, par, kg)
	if err != nil {
		return nil, nil, err
	}
	if publicPath != "" {
		if err := keys.SavePublicFile(publicPath, pk); err != nil {
			return nil, nil, err
		}
	}
	if privatePath != "" {
		if err := keys.SavePrivateFile(privatePath, sk); err != nil {
			return nil, nil, err
		}
	}
	return pk, sk, nil
}

func generateKeypairAnnulusNoRecover(sys ntrurio.SystemParams, par ntru.Params, kg ntru.KeygenOpts) (*keys.PublicKey, *keys.PrivateKey, error) {
	f, g, F, G, err := ntru.Keygen(par, kg)
	if err != nil {
		return nil, nil, err
	}
	hQ, err := ntru.PublicKeyH(ntru.Int64ToModQPoly(f, par), ntru.Int64ToModQPoly(g, par), par)
	if err != nil {
		return nil, nil, err
	}
	hCoeffs, err := ntru.CenterModQToInt64(hQ, par)
	if err != nil {
		return nil, nil, err
	}
	pk := &keys.PublicKey{
		Version:      keys.KeyV2,
		ParamsDigest: sys.ParamsDigest,
		N:            par.N,
		Q:            par.Q.Text(16),
		HCoeffs:      hCoeffs,
	}
	if err := keys.BindPublicKey(pk); err != nil {
		return nil, nil, err
	}
	priv := &keys.PrivateKey{
		Version:      keys.KeyV2,
		ParamsDigest: sys.ParamsDigest,
		PublicKeyID:  pk.KeyID,
		N:            par.N,
		Q:            par.Q.Text(16),
		F:            F,
		G:            G,
		Fsmall:       f,
		Gsmall:       g,
	}
	if err := keys.ValidatePrivateKey(priv); err != nil {
		return nil, nil, err
	}
	return pk, priv, nil
}

type targetMeta struct {
	BFile        string
	HashRelation string
	MSeed        []byte
	X0Seed       []byte
	X1Seed       []byte
	Persist      bool
}

type SignPaths struct {
	ParamsPath    string
	BFile         string
	PublicKeyPath string
	PrivatePath   string
	SignaturePath string
}

func SignTargetWithPaths(tCoeffs []int64, maxTrials int, opts ntru.SamplerOpts, paths SignPaths) (*keys.Signature, error) {
	meta := targetMeta{Persist: false}
	return signWithTCoeffsAndPaths(tCoeffs, maxTrials, opts, meta, paths)
}

func loadParamsFromPath(path string) (*ntrurio.SystemParams, error) {
	if path == "" {
		return loadParams()
	}
	p, err := ntrurio.LoadParams(path, true)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func autoTuneSignerAlpha(opts *ntru.SamplerOpts, sampler *ntru.Sampler) error {
	if opts == nil || sampler == nil || !opts.AutoTuneAlpha {
		return nil
	}
	alpha, err := sampler.RecommendedAlpha(opts.AutoTuneAlphaMargin)
	if err != nil {
		return err
	}
	if alpha > 0 {
		opts.Alpha = alpha
	}
	return nil
}

func signWithTCoeffsAndPaths(tCoeffs []int64, maxTrials int, opts ntru.SamplerOpts, meta targetMeta, paths SignPaths) (*keys.Signature, error) {
	pkPath := paths.PublicKeyPath
	if pkPath == "" {
		pkPath = "ntru_keys/public.json"
	}
	skPath := paths.PrivatePath
	if skPath == "" {
		skPath = "ntru_keys/private.json"
	}
	pk, err := keys.LoadPublicFile(pkPath)
	if err != nil {
		return nil, err
	}
	sk, err := keys.LoadPrivateFile(skPath)
	if err != nil {
		return nil, err
	}
	sys, err := loadParamsFromPath(paths.ParamsPath)
	if err != nil {
		return nil, err
	}
	if pk.N != sys.N {
		return nil, fmt.Errorf("NTRU key degree %d incompatible with params degree %d", pk.N, sys.N)
	}
	keyQ := new(big.Int)
	if _, ok := keyQ.SetString(pk.Q, 16); !ok {
		return nil, errors.New("invalid NTRU public key Q")
	}
	if keyQ.Uint64() != sys.Q {
		return nil, fmt.Errorf("NTRU key modulus %s incompatible with params q=%d", pk.Q, sys.Q)
	}
	if pk.ParamsDigest != sys.ParamsDigest || sk.ParamsDigest != sys.ParamsDigest {
		return nil, fmt.Errorf("NTRU key params digest mismatch: params=%s public=%s private=%s", sys.ParamsDigest, pk.ParamsDigest, sk.ParamsDigest)
	}
	return signWithLoadedKeys(sys, pk, sk, tCoeffs, maxTrials, opts, meta, paths.SignaturePath)
}

func signWithLoadedKeys(sys *ntrurio.SystemParams, pk *keys.PublicKey, sk *keys.PrivateKey, tCoeffs []int64, maxTrials int, opts ntru.SamplerOpts, meta targetMeta, signaturePath string) (*keys.Signature, error) {
	if sys == nil {
		return nil, errors.New("nil NTRU system params")
	}
	if err := ntrurio.ValidateParams(*sys); err != nil {
		return nil, err
	}
	if pk == nil || sk == nil {
		return nil, errors.New("nil NTRU key")
	}
	if err := keys.ValidatePublicKey(pk); err != nil {
		return nil, err
	}
	if err := keys.ValidatePrivateKey(sk); err != nil {
		return nil, err
	}
	if pk.N != sk.N {
		return nil, fmt.Errorf("NTRU key degree mismatch: public N=%d private N=%d", pk.N, sk.N)
	}
	if pk.Q != sk.Q {
		return nil, fmt.Errorf("NTRU key modulus mismatch: public Q=%s private Q=%s", pk.Q, sk.Q)
	}
	if pk.ParamsDigest != sys.ParamsDigest || sk.ParamsDigest != sys.ParamsDigest {
		return nil, errors.New("NTRU key/system parameter digest mismatch")
	}
	if sk.PublicKeyID != pk.KeyID {
		return nil, errors.New("NTRU public/private key ID mismatch")
	}
	Q := new(big.Int)
	if _, ok := Q.SetString(pk.Q, 16); !ok {
		return nil, errors.New("invalid Q")
	}
	par, err := ntru.NewParams(pk.N, Q)
	if err != nil {
		return nil, err
	}
	for _, check := range []struct {
		name string
		row  []int64
	}{
		{"public h", pk.HCoeffs},
		{"private F", sk.F},
		{"private G", sk.G},
		{"private f", sk.Fsmall},
		{"private g", sk.Gsmall},
	} {
		if len(check.row) != par.N {
			return nil, fmt.Errorf("NTRU %s coefficient length=%d want N=%d", check.name, len(check.row), par.N)
		}
	}
	if !ntru.CheckNTRUIdentity(sk.Fsmall, sk.Gsmall, sk.F, sk.G, par) {
		return nil, errors.New("invalid NTRU private key identity")
	}
	derivedH, err := ntru.PublicKeyH(ntru.Int64ToModQPoly(sk.Fsmall, par), ntru.Int64ToModQPoly(sk.Gsmall, par), par)
	if err != nil {
		return nil, err
	}
	derivedHCoeffs, err := ntru.CenterModQToInt64(derivedH, par)
	if err != nil {
		return nil, err
	}
	for i := range derivedHCoeffs {
		if derivedHCoeffs[i] != pk.HCoeffs[i] {
			return nil, fmt.Errorf("NTRU public/private key mismatch at h[%d]", i)
		}
	}
	if len(tCoeffs) != par.N {
		return nil, fmt.Errorf("t size mismatch: got %d want %d", len(tCoeffs), par.N)
	}
	prec := opts.Prec
	if prec == 0 {
		prec = 512
	}
	opts.Prec = prec
	var S *ntru.Sampler
	if opts.Entropy == nil {
		S, err = ntru.NewSampler(sk.Fsmall, sk.Gsmall, sk.F, sk.G, par, prec)
	} else {
		S, err = ntru.NewSamplerWithReader(sk.Fsmall, sk.Gsmall, sk.F, sk.G, par, prec, opts.Entropy)
	}
	if err != nil {
		return nil, err
	}
	opts.UseCNormalDist = true
	opts.UseExactResidual = true
	opts.BoundShape = "cstyle"
	if par.LOG3_D {
		opts.UseLog3Cross = true
	}
	if err := autoTuneSignerAlpha(&opts, S); err != nil {
		return nil, err
	}
	opts.ApplyDefaults(par)
	S.Opts = opts
	S.Opts.UseCNormalDist = true
	S.Opts.UseExactResidual = true
	S.Opts.BoundShape = "cstyle"
	S.Opts.UseLog3Cross = opts.UseLog3Cross
	if maxTrials <= 0 {
		maxTrials = 1 << 16
	}
	S.Opts.MaxSignTrials = maxTrials
	S.Opts.ApplyDefaults(S.Par)
	tPoly := ntru.Int64ToModQPoly(tCoeffs, par)
	s0, s1, trials, err := S.SamplePreimageTargetOptionB(tPoly, maxTrials)
	if err != nil {
		return nil, err
	}
	s0i := make([]int64, par.N)
	s1i := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		s0i[i] = s0.Coeffs[i].Int64()
		s1i[i] = s1.Coeffs[i].Int64()
	}

	var hPoly ntru.ModQPoly
	var herr error
	if len(pk.HCoeffs) == par.N {
		hPoly = ntru.Int64ToModQPoly(pk.HCoeffs, par)
	} else {
		hPoly, herr = ntru.PublicKeyH(ntru.Int64ToModQPoly(sk.Fsmall, par), ntru.Int64ToModQPoly(sk.Gsmall, par), par)
		if herr != nil {
			return nil, herr
		}
	}
	c1Mod := ntru.Int64ToModQPoly(tCoeffs, par)
	hs1, err := ntru.ConvolveRNS(ntru.Int64ToModQPoly(s1i, par), hPoly, par)
	if err != nil {
		return nil, err
	}
	s2 := hs1.Add(c1Mod)
	for i := 0; i < par.N; i++ {
		s2.Coeffs[i].Mod(s2.Coeffs[i], par.Q)
	}
	s2c, err := ntru.CenterModQToInt64(s2, par)
	if err != nil {
		return nil, err
	}
	s2Vec := S.LastS2()
	if len(s2Vec) != par.N {
		s2Vec = s2c
	} else {
		for i := 0; i < par.N; i++ {
			if s2Vec[i] != s2c[i] {
				s2Vec = s2c
				break
			}
		}
	}
	passed := ntru.CheckNormC(s1i, s2Vec, par, S.Opts)

	var linf int64
	for _, v := range s2Vec {
		if v < 0 {
			v = -v
		}
		if v > linf {
			linf = v
		}
	}

	sig := keys.NewSignature()
	sig.Params.N = par.N
	sig.Params.Q = pk.Q
	sig.Params.ParamsDigest = sys.ParamsDigest
	sig.Hash.BFile = meta.BFile
	sig.Hash.HashRelation = meta.HashRelation
	if len(meta.MSeed) > 0 {
		sig.Hash.MSeed = keys.EncodeSeed(meta.MSeed)
	}
	if len(meta.X0Seed) > 0 {
		sig.Hash.X0Seed = keys.EncodeSeed(meta.X0Seed)
	}
	if len(meta.X1Seed) > 0 {
		sig.Hash.X1Seed = keys.EncodeSeed(meta.X1Seed)
	}
	sig.Hash.TCoeffs = tCoeffs
	sig.PublicKey.HCoeffs = pk.HCoeffs
	sig.PublicKey.KeyID = pk.KeyID
	sig.Signature.S0 = s0i
	sig.Signature.S1 = s1i
	normSq := ntru.CoefficientNormSquared(s1i, s2Vec, par, S.Opts)
	sig.Signature.Norm.Passed = passed
	sig.Signature.Norm.L2Est = normSq
	sig.Signature.Norm.ResidualLinf = linf
	sig.Signature.TrialsUsed = trials
	sig.Signature.Rejected = trials > 1
	sig.Signature.MaxTrials = maxTrials
	sig.Signature.S2 = s2Vec
	if err := keys.BindSignature(sig); err != nil {
		return nil, err
	}
	if err := keys.ValidateSignature(sig); err != nil {
		return nil, err
	}
	if meta.Persist {
		if signaturePath != "" {
			if err := keys.SaveSignatureFile(signaturePath, sig); err != nil {
				return nil, err
			}
		} else if err := keys.Save(sig); err != nil {
			return nil, err
		}
	}
	return sig, nil
}

func VerifyWithParamsPath(sig *keys.Signature, paramsPath string) error {
	if err := keys.ValidateSignature(sig); err != nil {
		return err
	}
	sys, err := loadParamsFromPath(paramsPath)
	if err != nil {
		return err
	}
	if sig.Params.ParamsDigest != sys.ParamsDigest {
		return fmt.Errorf("NTRU signature params digest %s does not match loaded params %s", sig.Params.ParamsDigest, sys.ParamsDigest)
	}
	if sig.Params.N != sys.N {
		return fmt.Errorf("NTRU signature degree %d does not match loaded params degree %d", sig.Params.N, sys.N)
	}
	if sig.Params.Q != new(big.Int).SetUint64(sys.Q).Text(16) {
		return fmt.Errorf("NTRU signature modulus %s does not match loaded params q=%d", sig.Params.Q, sys.Q)
	}
	Q := new(big.Int)
	if _, ok := Q.SetString(sig.Params.Q, 16); !ok {
		return errors.New("invalid Q")
	}
	par, err := ntru.NewParams(sig.Params.N, Q)
	if err != nil {
		return err
	}
	// Recompute target from seeds when available; otherwise trust stored t.
	var tCmp []int64
	if sig.Hash.MSeed != "" || sig.Hash.X0Seed != "" || sig.Hash.X1Seed != "" {
		mSeed, err := keys.DecodeSeed(sig.Hash.MSeed)
		if err != nil {
			return err
		}
		x0Seed, err := keys.DecodeSeed(sig.Hash.X0Seed)
		if err != nil {
			return err
		}
		x1Seed, err := keys.DecodeSeed(sig.Hash.X1Seed)
		if err != nil {
			return err
		}
		tCmp, err = ntru.ComputeTargetFromSeeds(sys, sig.Hash.BFile, sig.Hash.HashRelation, mSeed, x0Seed, x1Seed)
		if err != nil {
			return err
		}
	} else {
		tCmp = sig.Hash.TCoeffs
	}
	if len(tCmp) != len(sig.Hash.TCoeffs) {
		return errors.New("t size mismatch")
	}
	for i := range tCmp {
		if tCmp[i] != sig.Hash.TCoeffs[i] {
			return errors.New("target mismatch")
		}
	}
	// Congruence: h*s1 + s0 == t (mod Q)
	h := ntru.Int64ToModQPoly(sig.PublicKey.HCoeffs, par)
	s0 := ntru.Int64ToModQPoly(sig.Signature.S0, par)
	s1 := ntru.Int64ToModQPoly(sig.Signature.S1, par)
	t := ntru.Int64ToModQPoly(tCmp, par)
	hs1, err := ntru.ConvolveRNS(s1, h, par)
	if err != nil {
		return err
	}
	lhs := hs1.Add(s0)
	for i := 0; i < par.N; i++ {
		want := new(big.Int).Mod(t.Coeffs[i], par.Q)
		got := new(big.Int).Mod(lhs.Coeffs[i], par.Q)
		if want.Cmp(got) != 0 {
			return errors.New("congruence check failed")
		}
	}
	c1Mod := ntru.Int64ToModQPoly(tCmp, par)
	s2 := hs1.Add(c1Mod)
	for i := 0; i < par.N; i++ {
		s2.Coeffs[i].Mod(s2.Coeffs[i], par.Q)
	}
	s2c, err := ntru.CenterModQToInt64(s2, par)
	if err != nil {
		return err
	}
	s2Stored := sig.Signature.S2
	if len(s2Stored) == 0 {
		s2Stored = s2c
	} else {
		if len(s2Stored) != par.N {
			return errors.New("s2 length mismatch")
		}
		for i := 0; i < par.N; i++ {
			if s2Stored[i] != s2c[i] {
				return errors.New("s2 mismatch")
			}
		}
	}
	resOpts := defaultOpts
	if par.LOG3_D {
		resOpts.UseLog3Cross = true
	}
	if !ntru.CheckNormC(sig.Signature.S1, s2Stored, par, resOpts) {
		return errors.New("norm check failed (s1,s2)")
	}
	return nil
}
