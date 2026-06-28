package PIOP

import "vSIS-Signature/prf"

func loadPRFParamsForOpts(opts SimOpts) (*prf.Params, error) {
	path := opts.PRFParamsPath
	if path == "" {
		return prf.LoadLocalOrDefaultParams("prf/prf_params.json")
	}
	return prf.LoadLocalOrBundledParams(path)
}
