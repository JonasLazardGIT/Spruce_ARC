# Security Estimation Tools

This directory is retained as artifact provenance for the maintained
IntGenISIS security estimates. The scripts are not part of the public proof
runtime and should not add flags or modes to `cmd/issuance` or `cmd/showing`.

Required runtime:

- Python with Sage import support
- the vendored `lattice-estimator-main/` tree in the repository root

Run from the repository root:

```bash
python3 tools/intgenisis_commitment_estimator.py --pretty
python3 tools/intgenisis_lattice_security_estimator.py --pretty
```

The PRF parameter-computation provenance lives in `prf/`:

```bash
sage prf/sweep_rounds.sage 20 0xf8801 3 128 20 20 7
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7 nochecks
```

These files are intentionally excluded from Docker. The artifact Docker context
and scripts should remain Go-only and should not require Sage or Python.
