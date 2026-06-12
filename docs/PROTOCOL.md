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

## Maintained Presets

The public preset registry contains exactly:

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

The compact presets use the default maintained query budget. The `n1024-q*`
entries carry explicit random-oracle query caps and DECS hash/tape widths in
the preset registry.

| Preset | Profile | Target | LVCS cols | Leaves | eta | theta | rho | ell/ell' | Showing shortness | Compression | Projection |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | --- |
| `n512-compact96` | B | 96 | 36 | 262,144 | 36 | 5 | 1 | 7/1 | R7/L5 | 0 | `project_u_digits_and_y_view_v3` |
| `n1024-compact96` | C | 96 | 43 | 230,208 | 40 | 5 | 1 | 7/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-compact125` | C | 125+ | 46 | 608,192 | 48 | 7 | 1 | 9/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q10-128` | C | 128 | 36 | 983,040 | 44 | 7 | 1 | 9/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q16-128` | C | 128 | 37 | 524,288 | 44 | 8 | 1 | 10/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q32-128` | C | 128 | 37 | 655,360 | 48 | 9 | 1 | 11/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q10-96` | C | 96 | 37 | 720,896 | 40 | 6 | 1 | 7/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q16-96` | C | 96 | 38 | 393,216 | 40 | 6 | 1 | 8/1 | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-q32-96` | C | 96 | 37 | 458,752 | 44 | 7 | 1 | 9/1 | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |

Issuance knobs prove the commitment opening and semantic constraints before the
issuer signs. Showing knobs prove the final credential relation and add PRF
companion rows, signature shortness rows, replay projection, compression where
selected, and the maintained SmallWood 2025 transcript mode.

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
- replay and transcript accounting match the maintained preset.

Standalone presentation verification requires the presentation artifact, public
parameters, verifier key, and optional persistent verifier-state path.

## Code Map

| Area | Main Paths | Purpose |
| --- | --- | --- |
| CLI workflows | `cmd/issuance`, `cmd/showing` | Operator/reviewer entrypoints |
| Presets and profiles | `credential/intgenisis_presets.go`, `credential/intgenisis_profile.go` | Maintained public parameter registry |
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

## Removed Surfaces

Removed preset labels, tuning flags, and non-maintained command surfaces are
invalid rather than aliases. Preset-dependent material must be generated from a
maintained preset. Public accounting knobs such as query caps and DECS collision
widths are selected by the preset registry, not by public CLI flags.
