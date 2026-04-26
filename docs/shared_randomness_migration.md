# Shared-Randomness Migration Note

This branch has moved from the older commitment-derived target flow to the live
shared-randomness `h_tran` / `bb_tran` flow.

This note records the current emitted formats, compatibility boundaries, and
what has to be regenerated.

## What Changed Semantically

The live credential path now uses:

- semantic message `mu = (m || k)`
  - default/public `mu` is one full-capacity coefficient-bounded `N=1024` ring
    element with layout `full_capacity_halves_v1`; all coefficients are bounded
    by `BoundB`, coefficients `0..511` are the message half, and PRF-key
    coefficients live at `512..519`
  - the opt-in `N=512` research fork keeps the same layout over 512
    coefficients, with the PRF-key window at `256..263`; it is a research
    statement fork and requires separate artifacts
- Ajtai commitment to
  `(mu, r0H[0..X0Len-1], r1H, rbar)`
- issuer challenge rows `ri0[0..X0Len-1]`, `ri1`
- componentwise centering on the `x0` side
- direct `bb_tran` target
  - `Z = (B3 - r1)^(-1)`
  - `T = B0 + B1 * mu + sum_j B2[j] * r0[j] + Z`
- stored semantic credential witness
  `(u, mu, r0, r1, Z)`

The live code no longer uses:

- `T = B0 + Uc + Z`
- aligned commitment randomness `(S, E)`
- commitment-side witness `AsS + E`
- source-product witness rows as part of the live issuance/showing relation

## Current Emitted Versions

As of the current branch:

- public params: `version = 4`
- issuance artifacts: `version = 2`
- credential state: `version = 4`
- `benchmark-x0` JSON: `version = 2`

## Public Parameter Changes

The canonical file is `Parameters/credential_public.json`.

The live emitted surface now includes:

- `hash_relation`
- `BoundB`
- `X0Len`
- `X0CoeffBound`
- `TargetDim`
- `TargetHidingLambda`
- `X0Distribution`
- `LenMu`
- `LenR0H`
- `LenR1H`
- `LenRBar`

Current canonical defaults:

- `hash_relation = bb_tran`
- `X0Len = 6`
- `X0CoeffBound = 5`
- `TargetDim = 1`
- `TargetHidingLambda = 128`
- `X0Distribution = uniform_interval`

Compatibility:

- the loader still accepts older semantic and legacy length names when reading
  historical public-parameter files
- the emitted surface is `version = 4`
- `LenMu = 1`
- `LenR0H` must match `X0Len`

## `B` Matrix Changes

The live `bb_tran` matrix is now dimensioned for vector `x0`.

Current row order:

- `B0`
- `B1`
- `B2[0] ... B2[X0Len-1]`
- `B3`

The canonical checked-in `bb_tran` asset is:

- `Parameters/Bmatrix_bb_tran_x0len6.json`

Compatibility:

- older 4-row `B` files remain interpretable only as the scalar compatibility
  case `X0Len = 1`
- the shipped default is the vector `x0` asset, not the scalar one

## Issuance Artifact Changes

Issuance artifacts under `credential/issuance/` are now emitted as
`version = 2`.

Current files:

- `holder_secret.json`
- `commit_request.json`
- `issue_challenge.json`
- `presign_submission.json`
- `issue_response.json`

Semantic contents:

- `holder_secret.json`
  - `mu`, `r0h`, `r1h`, `rbar`
  - runtime geometry fields such as `packed_ncols`, `lvcs_ncols`, `nleaves`,
    `omega`
- `commit_request.json`
  - `com`
- `issue_challenge.json`
  - `ri0`, `ri1`
- `presign_submission.json`
  - public target `t`
  - pre-sign proof
- `issue_response.json`
  - `sig_s1`, `sig_s2`
  - public key material and signed target bundle

Compatibility:

- current issuance code expects the live artifact version
- old aligned or stale issuance artifacts should be regenerated

## Credential State Changes

The canonical holder state is `credential/keys/credential_state.json`.

Current emitted format:

- `version = 4`

Live state now stores:

- semantic witness rows:
  - `mu`
  - `r0`
  - `r1`
  - `z`
- x0 metadata:
  - `x0_len`
  - `x0_coeff_bound`
  - `target_dim`
  - `target_hiding_lambda`
- signature witness rows:
  - `sig_s1`
  - `sig_s2`
- runtime anchors
- issuance audit artifacts
- embedded public `B` and `ntru_public`

The final credential state does not store `T`.

Compatibility:

- older `m`/`k`, unversioned, or aligned legacy state is rejected

## `x0` Migration

The live branch now exposes explicit `x0` parameterization:

- `legacy_scalar`
  - `X0Len = 1`
  - `X0CoeffBound = 1`
  - compatibility and benchmark control only
- `lhl_default`
  - `X0Len = 6`
  - `X0CoeffBound = 5`
  - current shipped profile
- `lhl_alt`
  - `X0Len = 5`
  - `X0CoeffBound = 8`
  - supported benchmark alternative

The current public-parameter generator defaults to `lhl_default`.

## First-Pass Transcript Reduction

The live branch now includes the first post-migration transcript reduction on
the `x0` side:

- `RU0[]`, `R0[]`, and `K0[]` use a true singleton low-alphabet carrier codec
- the old dummy `(value, 0)` pair-carrier overpayment is gone

The x0 carrier optimization changes the live proof surface and measured
transcript geometry. The serialized credential/public-format change in this
branch is the v4 full-capacity `mu` payload described above. The optimized
showing preset additionally uses showing-only `mu_pack=2` witness compression;
this does not change credential artifact formats.

## Regenerate Fresh Artifacts

From the repository root:

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance setup-demo-public -force
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

For role-separated issuance, rerun the full artifact sequence:

```bash
go run ./cmd/issuance holder-commit
go run ./cmd/issuance issuer-challenge
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
```

For profile comparisons:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1
```

For the degree-512 research fork, regenerate into separate paths instead of
overwriting the default artifacts:

```bash
go run ./cmd/issuance setup-demo-public \
  -research-ring-degree 512 \
  -out Parameters/credential_public.research_n512.json \
  -b-path Parameters/Bmatrix_bb_tran_x0len6.research_n512.json \
  -x0-profile lhl_default \
  -force

go run ./cmd/issuance setup-ntru-keys \
  -research-ring-degree 512 \
  -params-out Parameters/Parameters.research_n512.json \
  -public-out ntru_keys/public.research_n512.json \
  -private-out ntru_keys/private.research_n512.json \
  -force

go run ./cmd/issuance demo-local \
  -research-ring-degree 512 \
  -public-params Parameters/credential_public.research_n512.json \
  -artifact-dir credential/issuance/research_n512 \
  -state-out credential/keys/credential_state.research_n512.json \
  -signature-out credential/keys/signature.research_n512.json \
  -ntru-params Parameters/Parameters.research_n512.json \
  -ntru-public-key ntru_keys/public.research_n512.json \
  -ntru-private-key ntru_keys/private.research_n512.json \
  -ntru-signature-out credential/issuance/research_n512/ntru_signature.json
```
