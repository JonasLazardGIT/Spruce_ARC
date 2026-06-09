# Security Estimation Workflow

This note explains how the repository computes the two non-Go security
provenance tracks:

- PRF parameter estimates and parameter generation with Sage scripts in `prf/`;
- lattice estimates with Python wrappers around the vendored
  `lattice-estimator-main/` tree in `tools/`.

The Go artifact does not rerun these tools inside Docker. Docker reproduces the
maintained issuance/showing artifacts and exact transcript byte counts. Sage and
Python estimator scripts are retained so reviewers can inspect or rerun the
parameter provenance in a Sage-capable native environment.

## Shared Inputs

All maintained artifact paths use the same prime field modulus:

```text
q = 1,017,857 = 0xf8801
```

This modulus is used by NTRU signing, the `h_tran` arithmetic, SmallWood/PACS
proof rows, and the PRF. It is prime, supports the maintained NTT degrees, and
satisfies `q congruent to 2 modulo 3`, so the cubic S-box exponent is a
permutation exponent:

```text
gcd(3, q - 1) = 1
```

The maintained lattice profiles are:

| Profile | Used by presets | N | q | ell_M | k_s | n_c | Ordinary M/s/e bound | PRF seed bound | NTRU beta |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | `n512-compact96` | 512 | 1,017,857 | 1 | 2 | 1 | 1 | 4 | 6,002 |
| `intgenisis_profile_c` | `n1024-compact96`, `n1024-compact125` | 1024 | 1,017,857 | 1 | 1 | 1 | 1 | 4 | 6,142 |

The maintained PRF parameters are:

| Field | Value |
| --- | ---: |
| `q` | 1,017,857 |
| field bits | 20 |
| S-box exponent `alpha` | 3 |
| state width `t` | 20 |
| `lenkey` | 8 |
| `lennonce` | 12 |
| `lentag` | 7 |
| target used by the Sage scripts | 128 bits |

The eight PRF key lanes are not the raw entropy source. The maintained showing
proof uses a 48-coefficient seed in `[-4,4]^48`, then packs six base-9 digits
into each PRF key lane. See `docs/prf_seed_packing.md`.

## PRF Sage Workflow

The PRF is Poseidon2-like. In Go, the tag is computed as:

```text
tag = Trunc_{lentag}(P(key || nonce) + (key || nonce))
```

where `P` applies external rounds with S-boxes on all state cells, internal
rounds with an S-box on one state cell, and MDS mixing after each round.

The Sage workflow has two scripts:

```bash
sage prf/sweep_rounds.sage 20 0xf8801 3 128 20 20 7
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7
```

For quick local regeneration of the JSON, the second command can use
`nochecks`:

```bash
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7 nochecks
```

### Round Sweep

`prf/sweep_rounds.sage` searches round counts for a fixed state width. The
maintained command sets `t_min = t_max = 20`, so it checks only the shipped
state width.

For each candidate `(R_F, R_P)`, the script applies Poseidon-style inequalities
implemented in `sat_inequiv_alpha`. These include lower bounds on full rounds,
partial rounds, interpolation-style attacks, and a Groebner-basis-style
binomial-cost check. The search then chooses the candidate with the lowest
S-box count:

```text
sboxes = t * R_F + R_P
```

The script also applies the local safety margin used by this repository:

```text
R_F += 2
R_P = ceil(1.075 * R_P)
```

For the shipped PRF profile, the sweep gives:

```text
t = 20
R_F = 8
R_P = 19
sboxes = 179
permutation heuristic bits ~= 133.05
truncation check = ok
```

The truncation check is:

```text
t - lentag > lambda / log2(q)
13 > 128 / log2(1017857)
13 > 6.413756...
```

The `sec_perm_bits` value written into `prf/prf_params.json` is:

```text
t * log2(q) / 3 = 133.047...
```

That is a permutation-capacity heuristic used by the local parameter workflow,
not a lattice estimate and not a replacement for cryptanalysis of Poseidon-like
permutations.

### Parameter Generation

`prf/generate_params.sage` repeats the round computation, then derives concrete
parameters:

- round constants from a Grain-style bit generator seeded by the field type,
  S-box type, field size, state width, and round counts;
- a Cauchy MDS matrix over `GF(q)`;
- `cExt` constants for external rounds;
- `cInt` constants for internal rounds;
- metadata fields `sec_trunc_bound` and `sec_perm_bits`.

The generated JSON is `prf/prf_params.json`. The Go code loads it through
`prf.LoadDefaultParams`, validates dimensions and round counts, and evaluates
the PRF with `prf.Tag`.

When `nochecks` is absent, the Sage script can run expensive Algorithm 1-3 MDS
trail checks in a rejection loop. For large `t`, those checks may be slow; the
artifact keeps the Cauchy construction as the normal fast path and treats the
Sage scripts as parameter-generation provenance, not Docker runtime.

### PRF Result Consumption

The PRF estimates are consumed in three places:

1. `prf/prf_params.json` fixes `q`, `alpha`, `R_F`, `R_P`, key/nonce/tag
   lengths, matrices, and round constants.
2. `prf/prf_test.go` keeps deterministic sanity tests for the shipped cubic
   profile.
3. The maintained showing proof uses `PRFCompanionMode=direct_full`, proving
   the full `tag = PRF(k, nonce)` relation inside the main proof system rather
   than relying on a legacy sampled output-audit predicate.

## Lattice Estimator Workflow

The Python scripts under `tools/` run outside Docker:

```bash
python3 tools/intgenisis_commitment_estimator.py --pretty
python3 tools/intgenisis_lattice_security_estimator.py --pretty
```

They require a Python environment that can import Sage:

```python
from sage.all import oo, sqrt
```

They also add the vendored estimator tree to `sys.path` and import:

```python
from estimator import LWE, ND, SIS
```

Both scripts call the estimator in rough mode:

```python
LWE.estimate.rough(...)
SIS.estimate.rough(...)
```

The output records the estimator path, the estimator git commit when available,
all modeled profile inputs, all attack entries returned by the rough estimator,
and the lowest finite `log2(rop)` value for each modeled surface.

The archived numbers in `docs/intgenisis_lattice_security.md` were produced
with `malb/lattice-estimator` commit:

```text
4bfa63e364be9dd7fd1b2b531e2a11da8fb1c2ad
```

### Commitment Hiding Model

The implemented commitment is:

```text
c = C_M * M + A_s * s + e
```

For hiding, the estimator models the masking part `A_s*s + e` as an MLWE
instance:

```python
LWE.Parameters(
    n = N * k_s,
    q = q,
    Xs = Uniform(-commitment_bound, commitment_bound),
    Xe = Uniform(-commitment_bound, commitment_bound),
    m = N * n_c,
)
```

`M` is a shift in the commitment output. The computational hiding claim is that
the mask distribution is hard to distinguish from random enough that the shift
does not reveal the hidden message.

The recorded rough-estimator results are:

| Profile | MLWE hiding bits | Best attack |
| --- | ---: | --- |
| `intgenisis_profile_b` | 131.113 | `dual_hybrid` |
| `intgenisis_profile_c` | 131.113 | `dual_hybrid` |

The commitment-hiding estimate is the same for both profiles because both use
the live ternary `s,e` mask distribution. Profile B is kept as a 96-bit
engineering preset because its NTRU/vSIS signature surface is the tighter
surface; profile C is used for both degree-1024 maintained presets.

### Commitment Binding Model

Two valid openings to the same commitment give:

```text
C_M * Delta_M + A_s * Delta_s + Delta_e = 0
```

The opening difference has mixed bounds. Ordinary message coefficients and
`s,e` differences are bounded by `2`; the 48 PRF seed-tail differences are
bounded by `8`; the 16 reserved tail coefficients are always zero. The scripts
model this as MSIS with vector length:

```text
bind_len = ell_M + k_s + n_c
m = N * bind_len
n = N * n_c
q = 1017857
```

They estimate two norms:

```python
L2 bound =
  sqrt((N - 64) * 2^2 + 48 * 8^2 + N * (k_s+n_c) * 2^2)
Linf bound = 8
```

The archived binding results are:

| Profile | MSIS binding bits |
| --- | ---: |
| `intgenisis_profile_b` | `inf` in rough estimator |
| `intgenisis_profile_c` | `inf` in rough estimator |

`inf` means the rough estimator did not find a finite-cost short-kernel attack
at the configured bound. It is not an unconditional proof.

The scripts also compute simple counting slacks:

```text
statistical hiding slack =
  N * (k_s + n_c) * log2(2*commitment_bound + 1)
  - N * n_c * log2(q)
  - 2 * 128

statistical binding slack =
  N * n_c * log2(q)
  - ((N*ell_M - 64) * log2(4*ordinary_message_bound + 1)
     + 48 * log2(4*prf_seed_bound + 1)
     + N * (k_s+n_c) * log2(4*commitment_bound + 1))
```

For both maintained profiles, hiding is treated as computational MLWE hiding,
not statistical hiding. Binding has large positive statistical slack in the
recorded profile table.

### NTRU/vSIS Signature Surface

The issuer signature relation used by showing is:

```text
A * u = T
A = (-h, 1)
u = (s1, s2)
```

The estimator does not model the issuer trapdoor or trapdoor leakage. It models
only the public short-preimage hardness as a SIS/ISIS surrogate:

```python
SIS.Parameters(
    n = N,
    q = q,
    m = 2 * N,
    length_bound = ntru_beta,
    norm = infinity,
)
```

The script also computes a C-style L2 orientation bound:

```text
sqrt(2 * N * c_smoothing^2 * alpha^2 * q * slack^2)
```

with:

```text
c_smoothing = 1.32
alpha = 1.25
slack = 1.042
```

The archived conservative L-infinity results are:

| Profile | NTRU/vSIS L-infinity bound | Bits |
| --- | ---: | ---: |
| `intgenisis_profile_b` | 6,002 | 103.368 |
| `intgenisis_profile_c` | 6,142 | 240.900 |

This is the key reason profile B is not promoted to the 125+ preset, while
profile C has large margin for the maintained 125+ preset.

### `h_tran` Rational-Hash Surface

The live rational hash is:

```text
h_tran(mu_sig, x0, x1)
  = B0 + B1 * mu_sig + sum_i B2[i] * x0[i] + Z
Z * (B3 - x1) = 1
```

The live sampler chooses `mu_sig`, `x0`, and `x1` uniformly over `R_q`, and the
inverse witness `Z` is not range bounded. That live relation is not directly a
bounded SIS/vSIS instance, so `lattice-estimator` cannot certify it in the same
way as the commitment or NTRU short-preimage surfaces.

For orientation only, `tools/intgenisis_lattice_security_estimator.py` also
computes a bounded-linear surrogate. It assumes deltas for `mu_sig`, `x0`, and
`Z` are bounded by:

```text
2 * LEGACY_SEED_BOUND = 14
```

and estimates SIS over:

```text
rows = ell_mu_sig + ell_x0 + 1
```

The archived surrogate results are:

| Profile | Surrogate rows | L-infinity bits | L2 bits |
| --- | ---: | ---: | ---: |
| `intgenisis_profile_b` | 4 | 585.168 | 450.556 |
| `intgenisis_profile_c` | 3 | `inf` | `inf` |

These numbers say that the bounded linearized part is not the apparent lattice
bottleneck. They do not prove security of the live rational inverse relation.
The maintained protocol therefore documents this as a caveat rather than
folding it into the main claimed lattice security margin.

## How These Estimates Map To Artifact Claims

Security estimates and proof transcript soundness are separate checks:

- Sage PRF scripts fix PRF width, rounds, truncation, and parameter JSON.
- Python lattice-estimator wrappers estimate commitment hiding, commitment
  binding, NTRU/vSIS short-preimage hardness, and an `h_tran` surrogate.
- The Go E2E benchmark computes live SmallWood/PACS theorem-bit accounting and
  exact paper transcript byte counts.

The maintained artifact gates enforce:

```text
n512-compact96       showing.paper_transcript_bytes = 21754
n1024-compact96      showing.paper_transcript_bytes = 25882
n1024-compact125     showing.paper_transcript_bytes = 34853
```

and theorem-bit lower bounds for the maintained 96-bit and 125+ targets. Those
gate numbers come from the Go proof/reporting implementation, not from Sage or
`lattice-estimator`.

## Reproducibility Checklist

Native Sage/Python provenance:

```bash
sage prf/sweep_rounds.sage 20 0xf8801 3 128 20 20 7
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7 nochecks
python3 tools/intgenisis_commitment_estimator.py --pretty
python3 tools/intgenisis_lattice_security_estimator.py --pretty
```

Go artifact validation:

```bash
./scripts/validate-artifact.sh
```

Docker artifact validation:

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact validate
```

## Caveats

- The PRF Sage workflow gives local Poseidon-style parameter checks and concrete
  constants. It is not a full independent cryptanalysis of the permutation.
- `nochecks` skips expensive MDS trail checks and should be used for quick
  regeneration, not as the strongest provenance run.
- `lattice-estimator` rough mode gives model-based attack-cost estimates. It
  does not prove lower bounds.
- `inf` in estimator output means no finite rough-estimator attack was found
  for that model and bound.
- The NTRU/vSIS model estimates short-preimage hardness of the public equation;
  it does not model trapdoor leakage.
- The live `h_tran` rational inverse relation remains documented as a separate
  caveat because its unbounded inverse witness is outside the direct bounded
  SIS/vSIS model.
