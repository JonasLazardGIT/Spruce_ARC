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

All executable configurations are experimental PoC presets. Security metadata
is informational and does not constitute a deployment claim.

The reporting invariant is:

> Benchmark reports measure executed parameters. Security profiles supply
> minimum requirements. Missing actual metadata or an actual value below its
> requirement rejects a complete-system claim.

In particular, the ledger never substitutes a desired profile tag length,
query cap, hash width, tape width, salt width, or transcript mode for the value
loaded by the proof run.

## Shared Parameters

| Profile | N | q | ell_M | k_s | n_c | Ordinary M/s/e bound | PRF seed bound | ell_x0 | NTRU beta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | 512 | 1,017,857 | 1 | 2 | 1 | 1 | 4 | 2 | 6,002 |
| `intgenisis_profile_c` | 1024 | 1,017,857 | 1 | 1 | 1 | 1 | 4 | 1 | 6,142 |

The PRF seed tail contains 48 coefficients in `[-4,4]`. These are packed
base 9 into eight field lanes. Ordinary semantic message coefficients and
commitment randomness/error use the live bound `1`.
The sampler therefore has `48*log2(9) = 152.16` bits of seed entropy.

## Security Profiles And Lifecycle

Security profiles contain requirements, not executable parameter values.
Preset lifecycle (`artifact`, `poc`, `candidate`, `research`, or `complete`) is
separate from claim scope (`proof_only` or `complete_system`).

| Profile | Mode/scope | Target | Min hash/FS | Min tape | Min salt | Min tag elements | Primitive requirement | Status |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `SC-96` | one candidate | 96 | - | - | - | 7 | 96 | proof-only |
| `SC-125` | one candidate | 125 | - | - | - | 7 | 125 | proof-only |
| `BQ10-96` | raw `[2^10]*5` CROM caps | 96 residual | 120 | 106 | 120 | 7 | 106 | proof-only |
| `BQ16-96` | raw `[2^16]*5` CROM caps | 96 residual | 136 | 112 | 136 | 7 | 112 | proof-only |
| `BQ32-96` | raw `[2^32]*5` CROM caps | 96 residual | 168 | 136 | 168 | 9 | 128 | candidate |
| `WF-128` | global CROM work factor | 128 | 264 | 128 | 256 | 13 | 128 | executable PoC candidate |

Q10 and Q16 have exact profiles and do not borrow BQ32 query metadata. The
BQ32-R96 pilot executes tag-9 and passes its parameter audit. Higher-budget and
R128 target specifications remain available to the internal tuning sweep, but
their rejected executable configurations were archived and removed from the
CLI registry.

## Ledger Structure

Every report separates proof soundness, zero knowledge, primitive security,
unlinkability/rate limiting, correctness/freshness, composition, and model
scope. Each required term records actual bits, required bits, source
(`measured`, `exact_theorem`, `estimator`, `conservative`, or `missing`), an
evidence reference, scope, accounting status, and pass/fail result.

Required `missing` or `report_only` terms reject promotion. Conservative or
theory-pending accounting also rejects promotion until reviewed for that
category. Aggregate `core_available` is informational and is not composed a
second time with its constituent primitive terms.

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

The last result is not interpreted as infinite binding security. The complete
ledger records MSIS binding as missing until a reviewed finite bound and model
are available.

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

These are currently provenance/surrogate estimates rather than an approved
complete-game lattice-signature term. The complete ledger therefore keeps the
signature term blocked pending model review instead of silently inserting the
larger profile-C number.

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

The default artifact PRF uses the same field modulus as the proof system:

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

The controlled BQ32 pilot loads `prf/prf_params_tag9.json` with `LenTag=9`.
The WF-128 PoC loads `prf/prf_params_tag13.json` with `LenTag=13`; both retain
the default permutation matrices, constants, rounds, key length, and nonce
length. The tag-13 file has SHA-256 digest
`94462038554d296342ed088fcbbecd03165a8f1705fdf64346551a4eabe6b5dd`.
The canonical preset binds both the PRF profile and exact parameter-file
digest, and runtime loading rejects a digest or tag-width mismatch. Tag-10 and
tag-14 profiles remain unregistered.

## BQ32-R96 Pilot Measurement

The candidate manifest fixes CROM, raw caps `[2^32]*5` within each proof-system
phase, at most `2^32` honest transcripts and tags per domain-separated context,
and one accepted issuance plus one accepted showing in the reported forgery
composition. Adding the two phase games gives `[2^33]*5` in that combined
report. Honest transcript volume is used for salt/tag collision accounting; it
is distinct from the adversarial random-oracle budget.

| Item | Actual | Requirement/result |
| --- | ---: | --- |
| DECS/hash and Fiat-Shamir width | 168 bits | 168 minimum |
| Tape width | 136 bits | 136 minimum; 104 bits after `2^32` guesses |
| Salt width | 168 bits | about 105 collision bits at `2^32` proofs |
| PRF tag | 9 field elements | about 116.61 collision bits at `2^32` tags/context |
| One-proof theorem result | 99.98 bits | engineering gate 99.5 |
| Current two-phase composition | 98.59 bits | above 96 residual target |
| Paper transcript | 25,844 / 36,887 bytes | issuance / showing |

The parameter audit passes. Promotion does not: simultaneous extraction remains
report-only, challenge-bias/programming terms need reviewed theorem accounting,
and MSIS binding plus the lattice-signature term are not complete-grade.

## WF-128 PoC Measurement

`system-n1024-wf128-crom-v1` executes the bare WF-128 lane with 264-bit
DECS/hash and Fiat-Shamir output, a 128-bit tape, a 256-bit salt, and tag-13.
It has no bounded-query caps: `WF-128` is a global CROM work-factor profile,
not residual security at a fixed query budget.

| Item | Actual | Requirement/result |
| --- | ---: | --- |
| DECS/hash and Fiat-Shamir width | 264 bits | 264 minimum |
| Tape width | 128 bits | 128 minimum |
| Salt width | 256 bits | 256 minimum |
| PRF tag | 13 field elements | 13 minimum |
| SmallWood geometry | block width 43, `N_DECS=524288`, `eta=46`, `theta=7`, `ell=9` | measured R11/L4 retune |
| Grinding vector | `[0,0,4,13]` | supported live path |
| Issuance/showing theorem result | 133.44 / 133.35 bits | above 128 proof target |
| Paper transcript | 26,758 / 38,092 bytes | issuance / showing; exact-byte gated |

The final geometry was selected by projection followed by measured
issuance/showing comparison. Wider committed rows alone reduced showing bytes
but increased issuance; the selected domain/block-width pair reduced the
combined transcript from 66,671 to 64,850 bytes and reproduced exactly across
three runs. The structural parameter audit passes. Primitive estimates and
unresolved full-game terms remain diagnostic, so the lifecycle is `candidate`
and `complete_system_claim=false`. The 272/136/264/tag-14 engineering lane
remains a design point without an executable preset.

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

- `poc-n512-sc96-v1` is a PoC with an SC-96 proof-only statement.
- `artifact-n1024-sc125-v1` reproduces the paper's higher single-candidate
  proof measurement; it is not a complete-system profile.
- The BQ10-R96 and BQ16-R96 artifacts preserve their exact per-phase query
  budgets and pass their structural parameter audits.
- `pilot-n1024-bq32-r96-v1` is a bounded candidate whose executed-parameter
  audit passes but whose complete ledger does not.
- `system-n1024-wf128-crom-v1` is an executable unbounded CROM work-factor PoC
  whose structural parameter audit passes; its ledger is diagnostic and it
  makes no complete-system claim.
- Query-budget presets carry explicit `ROQueryCaps` and DECS hash/tape widths
  in the preset registry; theorem accounting is recorded by each benchmark.
- Removed duplicate and rejected research measurements are preserved in
  `credential/testdata/removed_intgenisis_presets.json`; they are not
  executable presets.
- Fixed-size transcript byte claims are reproduced by `ARTIFACT.md` commands
  and are not security-estimator outputs.
- No complete-system deployment preset is currently available.

## Caveats

- The commitment is computationally hiding, not statistically hiding.
- The `h_tran` rational inverse relation is documented with surrogate
  estimator evidence only.
- Estimator outputs are rough estimates and should be read as artifact
  provenance, not as full security reductions.
- NTRU key generation is randomized; validation may retry setup internally.
- Live credential seeds, attributes, commitment randomness, and issuer-side
  BB-tran values use `crypto/rand` with unbiased integer rejection sampling.
  The current NTRU preimage sampler still uses Go's process-global
  `math/rand` source. This is a pre-existing implementation blocker, alongside
  the missing reviewed lattice-signature estimate, for any complete-system
  deployment claim.
- Sage/Python provenance tooling and external estimator checkouts are
  intentionally excluded from Docker runtime.
- The BQ128 NIZK-only preset promotes the SmallWood proof claim only. It does
  not promote PRF, MLWE, tag-collision, multi-user, or full credential-system
  security beyond the current ledger status.
- Canonical public parameters, state, verifier keys, presentations, and
  Fiat-Shamir public inputs bind the preset manifest. Legacy aliases resolve to
  the same manifest; cross-manifest use is rejected.
