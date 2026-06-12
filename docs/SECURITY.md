# SPRUCE Security And Provenance

This document is the canonical security note for the maintained SPRUCE
artifact. It records estimator inputs, interpreted results, PRF parameter
provenance, and caveats. The Go/Docker artifact does not rerun these tools
during normal validation.

## Scope

The implemented artifact proves and verifies the maintained issuance/showing
relations described in [PROTOCOL.md](PROTOCOL.md). Security provenance is
outside the Docker runtime:

- `tools/intgenisis_commitment_estimator.py`
- `tools/intgenisis_lattice_security_estimator.py`
- `prf/generate_params.sage`
- `prf/sweep_rounds.sage`
- an external pinned `malb/lattice-estimator` checkout

The estimator outputs are rough estimates and model evidence, not
unconditional reductions.

## Shared Parameters

| Profile | N | q | ell_M | k_s | n_c | Ordinary M/s/e bound | PRF seed bound | ell_x0 | NTRU beta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | 512 | 1,017,857 | 1 | 2 | 1 | 1 | 4 | 2 | 6,002 |
| `intgenisis_profile_c` | 1024 | 1,017,857 | 1 | 1 | 1 | 1 | 4 | 1 | 6,142 |

The PRF seed tail contains 48 coefficients in `[-4,4]`. These are packed
base 9 into eight field lanes. Ordinary semantic message coefficients and
commitment randomness/error use the live bound `1`.

## Commitment Security

The implemented commitment is:

```text
c = C_M*M + A_s*s + e
```

with mixed bounds in `M`, ternary `s`, and ternary `e`.

| Profile | MLWE hiding bits | MLWE attack | MSIS binding bits | Mixed L2 bound | L-infinity bound | Statistical hiding | Statistical hiding slack | Statistical binding slack |
| --- | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: |
| `intgenisis_profile_b` | 131.113 | `dual_hybrid` | `inf` | 104.919 | 8 | no | -8,039.535 | 5,415.133 |
| `intgenisis_profile_c` | 131.113 | `dual_hybrid` | `inf` | 122.898 | 8 | no | -17,446.071 | 13,255.516 |

Interpretation:

- The maintained commitments are computationally MLWE hiding, not
  statistically hiding.
- Both profiles have the same rough MLWE hiding estimate because both use
  ternary `s,e`.
- Both profiles return no finite rough-estimator attack for the mixed-bound
  MSIS binding instance at the configured bound.

## NTRU/vSIS Signature Surface

The showing proof uses:

```text
A*u = T
A = (-h, 1)
u = (s1, s2)
```

The estimator model is a SIS/ISIS surrogate over `R_q^{1 x 2}`. It estimates
short-preimage hardness and does not model trapdoor leakage.

| Profile | SIS L-infinity bound | SIS L-infinity bits | C-style L2 bound | SIS L2 bits |
| --- | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | 6,002 | 103.368 | 55,506.651 | 119.428 |
| `intgenisis_profile_c` | 6,142 | 240.900 | 78,498.259 | 276.524 |

Interpretation:

- Profile B clears the maintained 96-bit engineering target under both modeled
  views, but not a 125-bit target under the L-infinity beta model.
- Profile C is well above the maintained 125+ target under both modeled views.
- The L-infinity beta model is the conservative number to track for showing,
  because the proof exposes a public coefficient bound through
  `IntGenISIS.signature_bound`.

## Rational Hash Surface

The live rational hash is:

```text
h_tran(mu_sig, x0, x1)
  = B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z
Z * (B3 - x1) = 1
```

The implementation samples `mu_sig`, `x0`, and `x1` uniformly over `R_q`, and
`Z` is the inverse of `B3 - x1`. There is no range bound on `Z`.

Because of that, the live rational-hash relation is not directly expressible as
the kind of bounded SIS/vSIS instance estimated by `lattice-estimator`. The
estimator script includes a bounded-linear surrogate for orientation only,
where deltas for `mu_sig`, `x0`, and `Z` are artificially bounded by `14`.

| Profile | Surrogate rows | Surrogate L-infinity bits | Surrogate L2 bits |
| --- | ---: | ---: | ---: |
| `intgenisis_profile_b` | 4 | 585.168 | 450.556 |
| `intgenisis_profile_c` | 3 | `inf` | `inf` |

This surrogate is not a proof of live `h_tran` security. The live rational
inverse relation is tracked as an explicit caveat.

## PRF Parameters

The shipped PRF uses the same field modulus as the proof system:

```text
q = 1,017,857
alpha = 3
security target = 128
field bits = 20
state width = 20
rounds = 20
LenKey = 8
LenTag = 7
```

Round-count provenance:

```bash
sage prf/sweep_rounds.sage 20 0xf8801 3 128 20 20 7
```

Regenerate the shipped parameter JSON:

```bash
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7 nochecks
```

The generated file is `prf/prf_params.json`. Go tests and artifact commands
load this file directly; Docker validation does not run Sage.

## Reproducing Estimator Outputs

Fetch the estimator outside the repository and pin it to the archived commit:

```bash
mkdir -p external
git clone https://github.com/malb/lattice-estimator external/lattice-estimator
git -C external/lattice-estimator checkout 4bfa63e364be9dd7fd1b2b531e2a11da8fb1c2ad
export SPRUCE_LATTICE_ESTIMATOR="$PWD/external/lattice-estimator"
```

Run these commands from the repository root in a Sage/Python environment:

```bash
python3 tools/intgenisis_commitment_estimator.py --pretty
python3 tools/intgenisis_lattice_security_estimator.py --pretty
```

Equivalently, pass `--estimator-path external/lattice-estimator` to each
script. The wrapper scripts are source provenance and must not add public flags
or modes to `cmd/issuance` or `cmd/showing`.

## Mapping To Artifact Claims

- Profile-B commitment and NTRU/vSIS estimates support the
  `n512-compact96` engineering preset.
- Profile-C commitment and NTRU/vSIS estimates support all degree-1024
  compact and query-budget presets.
- Query-budget presets carry explicit `ROQueryCaps` and DECS hash/tape widths
  in the preset registry; theorem accounting is verified by
  `gate-maintained-presets`.
- Fixed-size transcript byte claims are reproduced by `ARTIFACT.md` commands
  and are not security-estimator outputs.

## Caveats

- The commitment is computationally hiding, not statistically hiding.
- The `h_tran` rational inverse relation is documented with surrogate
  estimator evidence only.
- Estimator outputs are rough estimates and should be read as artifact
  provenance, not as full security reductions.
- NTRU key generation is randomized; validation may retry setup internally.
- Sage/Python provenance tooling and external estimator checkouts are
  intentionally excluded from Docker runtime.
