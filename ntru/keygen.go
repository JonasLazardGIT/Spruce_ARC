package ntru

// KeygenOpts controls the retained annulus key generation routine.
type KeygenOpts struct {
	Prec       uint    // floating precision for embeddings (defaults to 128 bits)
	MaxTrials  int     // maximum trials for the annulus sampler (defaults to 10000)
	Alpha      float64 // annulus quality window parameter (defaults to 1.20)
	UseCRadius bool    // optional: use fixed radius instead of Alpha window
	Radius     float64 // required when UseCRadius is true
	Verbose    bool    // emit sampling diagnostics
}

// Keygen simply dispatches to the annulus/FFT path with sane defaults.
func Keygen(par Params, opts KeygenOpts) (f, g, F, G []int64, err error) {
	if opts.Prec == 0 {
		opts.Prec = 128
	}
	if opts.MaxTrials == 0 {
		opts.MaxTrials = 10000
	}
	if opts.Alpha == 0 {
		opts.Alpha = 1.20
	}
	return KeygenFFT(par, opts)
}
