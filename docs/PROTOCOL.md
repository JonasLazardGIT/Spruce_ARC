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

| Canonical preset | Purpose | Lifecycle | Claim | Availability |
| --- | --- | --- | --- | --- |
| `poc-n512-sc96-v1` | integration/demo | `poc` | SC-96 proof-only | available |
| `artifact-n1024-sc96-v1` | paper reproduction | `artifact` | SC-96 proof-only | available |
| `artifact-n1024-sc125-v1` | paper reproduction | `artifact` | SC-125 proof-only | available |
| `pilot-n1024-bq32-r96-v1` | controlled pilot | `candidate` | bounded complete-system candidate | available, not promoted |
| `system-n1024-wf128-crom-v1` | general deployment | `candidate` | complete system | unavailable |
| `research-n1024-bq32-r128-v1` | strong bounded-query experiment | `research` | proof-only | `-research` |
| `research-n1024-bq128-r128-v1` | extreme proof-layer experiment | `research` | proof-only | `-research` |

The CLI default list contains the first five rows and states explicitly that no
complete-system deployment preset is currently available.

## Historical Artifact Parameters

The artifact byte gate contains exactly these legacy selectors:

```text
n512-compact96
n1024-compact96
n1024-compact125
n1024-q10-128
n1024-q16-128
n1024-q32-128
n1024-q10-96
n1024-q16-96
n1024-q32-96
```

They remain aliases for reproducibility and resolve to canonical manifests.
Q10/Q16/Q32 entries carry exact query scopes; they do not inherit BQ32
metadata and are hidden from the default list.

| Preset | Profile | Proof target | `n_cols` | `N_DECS` | eta | theta | rho | ell/ell' | Showing shortness | Compression | Projection |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | --- |
| `n512-compact96` | B | 96 | 36 | 262,144 | 36 | 5 | 1 | 7/1 | R7/L5 | 0 | `project_u_digits_and_y_view_v3` |
| `n1024-compact96` | C | 96 | 43 | 230,208 | 40 | 5 | 1 | 7/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-compact125` | C | 125+ | 46 | 608,192 | 48 | 7 | 1 | 9/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q10-128` | C | 128 | 36 | 983,040 | 44 | 7 | 1 | 9/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q16-128` | C | 128 | 37 | 524,288 | 43 | 8 | 1 | 10/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q32-128` | C | 128 | 37 | 655,360 | 45 | 9 | 1 | 11/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q10-96` | C | 96 | 37 | 720,896 | 40 | 6 | 1 | 7/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q16-96` | C | 96 | 38 | 393,216 | 40 | 6 | 1 | 8/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q32-96` | C | 96 | 37 | 458,752 | 44 | 7 | 1 | 9/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |

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

## NIZK-Only Q128 Preset

The CLI-exposed SmallWood NIZK-only Q128/epsilon128 preset is:

```text
research-n1024-bq128-r128-v1
```

It is the promoted form of the internal frontier candidate
`bq128-128-raw128-residual128-theta13-lvcs48-h512`. The claim is limited to the
SmallWood NIZK proof layer: an adversary may make up to `2^128`
ROM/Fiat-Shamir queries against the proof system, and the measured proof
soundness and zero-knowledge terms remain about 128 bits.

| Preset | Profile | Claim | RO caps | Hash/FS | Tape | Salt | `n_cols` | `N_DECS` | eta | theta | ell/ell' | kappa |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `research-n1024-bq128-r128-v1` | C | NIZK-only Q128/epsilon128 | raw log `[128]*5` | 512 | 256 | 384 | 48 | 983,040 | 65 | 13 | 18/1 | `{0,0,8,5}` |

This preset uses no valid-prefix discount. Its benchmark report currently
measures `showing.paper_transcript_bytes = 89950` and
`showing.theorem_total_bits = 129.26` for the proof layer. It remains outside
the artifact preset gate because the full `BQ128-128` IntGenISIS
credential-system profile still has `complete_system_claim=false` and
`ledger_status="requires_new_primitives"` under the current primitive core.

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
