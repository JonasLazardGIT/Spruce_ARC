# SPRUCE Protocol And Code Map

This document is the canonical description of the implemented SPRUCE protocol
surface. It covers the maintained IntGenISIS issuance/showing flow, preset
registry, artifact data flow, and code locations a reviewer should inspect.

## Implemented Protocol

SPRUCE implements a committed-message IntGenISIS credential flow. The holder
commits to hidden semantic message material, proves that commitment before
issuance, receives an NTRU/vSIS signature on the resulting target, and later
shows the credential without revealing the hidden message, commitment opening,
issuer rational-hash witnesses, or signature preimage.

The commitment equation is:

```text
c = C_M*M + A_s*s + e
```

The issuer samples rational-hash data:

```text
mu_sig, x0, x1
```

and signs:

```text
T = c + h_tran(mu_sig, x0, x1)
```

The rational hash is:

```text
h_tran(mu_sig, x0, x1)
  = B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z
Z * (B3 - x1) = 1
```

The showing proof proves the final relation, including:

```text
tag = PRF(k, nonce)
A*u = T
T = c + h_tran(mu_sig, x0, x1)
c = C_M*M + A_s*s + e
```

The holder message material is `M`, with hidden PRF seed material `k` packed
inside the semantic message row. `mu_sig` is issuer-sampled rational-hash input;
it is not the holder PRF key and is not the old shared-randomness `mu`.

## Algebraic Setting

All main equations live over:

```text
R_q = Z_q[X] / (X^N + 1)
q   = 1,017,857
```

The maintained profiles are:

| Profile | Used By | N | ell_M | k_s | n_c | B | ell_mu_sig | ell_x0 | ell_x1 | NTRU beta |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | `n512-compact96` | 512 | 1 | 2 | 1 | 1 | 1 | 2 | 1 | 6,002 |
| `intgenisis_profile_c` | all degree-1024 presets | 1024 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 6,142 |

Ordinary message, `s`, and `e` coefficients use the live commitment bound
`B=1`. The PRF seed tail is a separate 48-coefficient region in `[-4,4]`,
packed base 9 into eight PRF key lanes.

## Preset Taxonomy

Lifecycle describes maintenance purpose; claim scope describes security
meaning. Neither executability nor an artifact byte gate implies deployment
readiness.

Every registry entry is executable and distributed as an experimental PoC.
Security metadata is informational and does not constitute a deployment claim.

| Canonical preset | Purpose | Lifecycle | Claim | Availability |
| --- | --- | --- | --- | --- |
| `poc-n512-sc96-v1` | integration/demo | `poc` | SC-96 proof-only | available |
| `artifact-n1024-sc125-v1` | paper reproduction | `artifact` | SC-125 proof-only | available |
| `artifact-n1024-bq10-r96-historical-v1` | bounded-query reproduction | `artifact` | BQ10-R96 proof-only | available |
| `artifact-n1024-bq16-r96-historical-v1` | bounded-query reproduction | `artifact` | BQ16-R96 proof-only | available |
| `pilot-n1024-bq32-r96-v1` | controlled pilot | `candidate` | bounded complete-system candidate | available, not promoted |
| `poc-n1024-bq64-r128-v1` | bounded-query experiment | `poc` | BQ64-R128 proof-only | available |
| `poc-n1024-bq96-r128-v1` | bounded-query experiment | `poc` | BQ96-R128 proof-only | available |
| `poc-n1024-bq128-r128-v2` | bounded-query experiment | `poc` | BQ128-R128 proof-only | available |
| `system-n1024-wf128-crom-v1` | WF-128 PoC shape | `candidate` | complete-system target | available PoC; no claim |

`list-presets` prints exactly these nine unique security-target/query-budget
tuples. No complete-system deployment preset is currently available.

## Executable Preset Parameters

The executable registry accepts these selectors:

```text
n512-compact96
n1024-compact125
n1024-q10-96
n1024-q16-96
n1024-bq32-96
poc-n1024-bq64-r128-v1
poc-n1024-bq96-r128-v1
poc-n1024-bq128-r128-v2
system-n1024-wf128-crom-v1
```

Legacy selectors resolve to their canonical manifests. Removed selectors are
archived rather than redirected to different parameters.

| Preset | Profile | Proof target | `n_cols` | `N_DECS` | eta | theta | rho | ell/ell' | Showing shortness | Compression | Projection |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | --- |
| `n512-compact96` | B | 96 | 36 | 262,144 | 36 | 5 | 1 | 7/1 | R7/L5 | 0 | `project_u_digits_and_y_view_v3` |
| `n1024-compact125` | C | 125+ | 46 | 608,192 | 48 | 7 | 1 | 9/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q10-96` | C | 96 | 37 | 720,896 | 40 | 6 | 1 | 7/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q16-96` | C | 96 | 38 | 393,216 | 40 | 6 | 1 | 8/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-bq32-96` | C | 99.5 | 40 | 786,432 | 46 | 7 | 1 | 9/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `poc-n1024-bq64-r128-v1` | C | 131.54 | 43 | 917,504 | 53 | 10 | 1 | 13/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `poc-n1024-bq96-r128-v1` | C | 131.54 | 43 | 786,432 | 57 | 12 | 1 | 16/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `poc-n1024-bq128-r128-v2` | C | 131.54 | 43 | 786,432 | 60 | 13 | 1 | 18/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `system-n1024-wf128-crom-v1` | C | 128 | 43 | 524,288 | 46 | 7 | 1 | 9/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |

Issuance knobs prove the commitment opening and semantic constraints before the
issuer signs. Showing knobs prove the final credential relation and add PRF
companion rows, signature shortness rows, replay projection, compression where
selected, and the maintained SmallWood 2025 transcript mode.

## BQ32 Controlled Pilot

`pilot-n1024-bq32-r96-v1` is an executable candidate under a fixed CROM threat
manifest. Each proof-system phase has five global adversarial random-oracle caps
of `2^32`; composing one accepted issuance and one accepted showing produces
five `2^33` caps in the full-game report. Honest transcript volume is separately
bounded by `2^32` total proofs, split as at most `2^31` issuance and `2^31`
showing proofs. Tag volume is at most `2^32` per domain-separated context.

| Security profile | Hash/FS bits | Tape bits | Salt bits | Actual tag elements | `n_cols` | `N_DECS` | eta | theta | ell |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ32-R96 candidate | 168 | 136 | 168 | 9 | 40 | 786,432 | 46 | 7 | 9 |

Measured paper transcripts are 25,844 bytes for issuance and 36,887 bytes for
showing. The one-proof theorem result is 99.98 bits and the current
one-issuance/one-showing global-collision composition is 98.59 bits. These are
proof-accounting results, not a complete-system promotion.

## NIZK-Scoped R128 PoC Presets

The BQ64, BQ96, and BQ128 PoCs apply their raw query caps only to the five
SmallWood/Fiat-Shamir oracle domains. The unchanged profile-C primitive family
is assumed independently at 128 bits. Honest transcript and tag volumes are
separately bounded by `2^32` per domain-separated context.

| Preset | Raw caps per phase | Hash/FS | Tape | Salt | Tag | eta/theta/ell | Grinding | Issuance/showing bytes | Composed proof bits |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: |
| `poc-n1024-bq64-r128-v1` | `[2^64]*5` | 264 | 200 | 200 | 10 | 53/10/13 | `[13,2,8,13]` | 39,504 / 56,584 | 130.00 |
| `poc-n1024-bq96-r128-v1` | `[2^96]*5` | 328 | 232 | 200 | 10 | 57/12/16 | `[0,0,0,7]` | 52,106 / 73,456 | 130.92 |
| `poc-n1024-bq128-r128-v2` | `[2^128]*5` | 392 | 264 | 200 | 10 | 60/13/18 | `[0,3,11,12]` | 61,429 / 85,386 | 130.56 |

All three use the current raw-cap theorem, block width 43, and the measured
R7/L5 relation. BQ64 uses a `917504`-point authentication domain; BQ96 and
BQ128 use `786432`. Their structural parameter audits pass, but their claim
scope remains proof-only.

## WF-128 PoC Preset

`system-n1024-wf128-crom-v1` is an executable CROM work-factor configuration,
not a deployment claim. It uses the compiled R11/L4 relation, leaves all
bounded-query caps unset, and executes 264-bit DECS/hash and Fiat-Shamir
outputs, a 128-bit tape, a 256-bit salt, and the tag-13 PRF relation.

| Security profile | RO caps | Hash/FS bits | Tape bits | Salt bits | Actual tag elements | `n_cols` | `N_DECS` | eta | theta | ell |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| WF-128 candidate | unset | 264 | 128 | 256 | 13 | 43 | 524,288 | 46 | 7 | 9 |

The selected shape also uses grinding vector `[0,0,4,13]`. Three repeated
end-to-end measurements report 26,758 issuance bytes, 38,092 showing bytes,
and 133.44/133.35 issuance/showing theorem bits. Relative to the initial
66,671-byte combined control, this reduces the combined paper transcript by
1,821 bytes. The structural parameter audit passes. The ledger remains
diagnostic and the preset has `complete_system_claim=false`.

## Archived Research Measurements

Superseded and structurally rejected Q128, BQ64, R128, duplicate SC-96, and
historical BQ32 configurations are recorded in
`credential/testdata/removed_intgenisis_presets.json`. The corrected BQ64,
BQ96, and BQ128 PoCs above are distinct executable manifests. The archive
preserves old selectors, measurements, and rejection reasons without
redirecting them to the new parameters.

## Public Setup

Public parameters include:

```text
R_q parameters: N, q
BB-tran parameters: B0, B1, B2[], B3
commitment matrices: C_M, A_s
commitment bound: B
hash relation label: bb_tran
PRF parameters
SmallWood/PACS showing parameters
issuer NTRU public key
canonical preset ID and version
primitive and PRF profile IDs, including the exact PRF parameter-file digest
transcript mode and complete preset-manifest digest
```

The issuer holds the NTRU trapdoor/signing key. The holder does not choose
`B`, `C_M`, `A_s`, or the issuer public key.

## Issuance Flow

1. `setup-intgenisis-public` writes public IntGenISIS parameters and the
   BB-tran matrix.
2. `setup-ntru-keys` writes NTRU parameters and issuer key material for the
   selected preset profile.
3. `holder-commit` samples the semantic message/opening rows and writes
   `holder_secret.json` plus `commit_request.json`.
4. `holder-prove` builds the IntGenISIS pre-sign proof.
5. `issuer-verify-sign` verifies the pre-sign proof, samples `mu_sig`, `x0`,
   `x1`, computes `T`, signs `T`, and writes the issuer response plus verifier
   key.
6. `holder-finalize` verifies the issuer response and persists the credential
   state.

The pre-sign proof does not reveal `M`, `s`, `e`, or the PRF seed tail.

## Showing Flow

`cmd/showing` loads the finalized credential state, public params, verifier key,
and PRF parameters. It samples a public nonce, computes `tag = PRF(k, nonce)`,
builds the showing proof, verifies it locally, and optionally writes a
presentation artifact.

The showing statement proves:

- the hidden NTRU preimage is short and verifies against the signed target,
- the target is consistent with the hidden commitment and issuer rational-hash
  witnesses,
- the semantic message row contains the same hidden PRF key used for the tag,
- replay and transcript accounting match the bound canonical preset.

Standalone presentation verification requires the presentation artifact, public
parameters, verifier key, and optional persistent verifier-state path.

## Code Map

| Area | Main Paths | Purpose |
| --- | --- | --- |
| CLI workflows | `cmd/issuance`, `cmd/showing` | Operator/reviewer entrypoints |
| Presets and profiles | `credential/intgenisis_presets.go`, `credential/preset_manifest.go`, `credential/security_profiles.go` | Lifecycle, claim, threat model, requirements, aliases, and executable parameters |
| Security audit and ledger | `credential/security_parameter_audit.go`, `credential/security_ledger.go` | Required/actual checks, scoped terms, provenance, and promotion blockers |
| Public params/state | `credential/` | JSON formats, state, verifier keys, profile metadata |
| Issuance target | `issuance/intgenisis.go`, `cmd/issuance/flow_helpers.go` | Rational hash target and issuance orchestration |
| Proof system | `PIOP/` | IntGenISIS pre-sign and showing constraints, proof reports |
| Row commitments | `DECS/`, `LVCS/` | Explicit-domain row commitment and openings |
| Linear commitment | `commitment/` | Ajtai/MLWE commitment helpers |
| Signature | `ntru/` | NTRU/vSIS keygen, sampling, signing, verification |
| PRF | `prf/` | Poseidon-like PRF parameters and tag relation |
| Validation scripts | `scripts/` | Docker/native artifact commands |

Package-level READMEs provide more detailed code-navigation notes for each
subsystem.

## Persisted Artifacts

The benchmark/manual flow writes JSON artifacts for public parameters, holder
secret, commit request, proof submission, issuer response, credential state,
verifier key, presentation, verifier state, NTRU keys, and the benchmark
report. See [../ARTIFACT.md](../ARTIFACT.md) for exact filenames and
reproduction commands.

Public parameters and finalized state store the canonical ID, version,
primitive/PRF identity, transcript mode, and manifest digest. Verifier keys and
presentations carry the same identity, while the digest and canonical fields
are also Fiat-Shamir-bound as public inputs. Issuance and showing reject a
mismatch.

## Removed Surfaces

The documented historical artifact labels remain aliases. Other removed preset
labels, tuning flags, and command surfaces are invalid rather than fallback
selectors. Preset-dependent material must be generated from a registered
canonical manifest. Public accounting knobs such as query caps and DECS widths
are selected by that manifest, not by public CLI flags.
