# credential

`credential/` defines the persisted holder state and public-parameter layer used
by the live issuance and showing flows.

It is the bridge between:

- operator commands
- versioned runtime artifacts
- the proving code in `PIOP/`

## What The Public Parameter File Stores

The canonical file is `Parameters/credential_public.json`.

Current emitted format:

- `version = 4`

Live fields:

- `hash_relation = bb_tran`
- `Ac`
- `BPath`
- `BoundB`
- `X0Len`
- `X0CoeffBound`
- `TargetDim`
- `TargetHidingLambda`
- `ring_degree`
- `X0Distribution`
- `LenMu`
- `MuLayout`
- `LenR0H`
- `LenR1H`
- `LenRBar`

Meaning:

- `BoundB` governs the low-alphabet scalar side:
  - the signed `mu = m || k` payload row
  - `r1`
  - `rbar`
- `X0CoeffBound` governs the vector `x0` side:
  - `r0h`
  - `ri0`
  - `r0`
- `LenR0H` must match `X0Len`
- `TargetDim` is currently emitted as `1`

The loader still accepts older semantic and legacy length names when reading
historical public params, but the emitted and documented surface is `version 4`
with `LenMu = 1` and `MuLayout = full_capacity_halves_v1`.

## What The Credential State Stores

The canonical holder state is `credential/keys/credential_state.json`.

Current emitted format:

- `version = 4`

Live state fields:

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
- ring metadata:
  - `ring_degree`
- runtime anchors:
  - `packed_ncols`
  - `credential_public_path`
  - `hash_relation`
  - `b_path`
  - `prf_params_path`
- issuance audit artifacts:
  - `com`
  - `ri0`
  - `ri1`
- embedded public material:
  - `b`
  - `ntru_public`

The final credential state does not store `T`. `T` remains an issuance-time
artifact carried by `presign_submission.json` and `issue_response.json`.

## Versioning And Compatibility

Current behavior:

- public params are emitted as `version = 4`
- credential state is emitted as `version = 4`
- older `m`/`k` and sparse-tail `mu` credential states are rejected and must be
  regenerated

Issuance artifacts under `credential/issuance/` are now stricter than state:

- current emitted format is `version = 2`, but the holder witness payload is
  `mu`; legacy `m`/`k` fields are parse-only and not emitted
- older issuance artifacts should be regenerated

## Main Entry Points

- `LoadDefaultRing`
- `LoadPublicParams`
- `SavePublicParams`
- `LoadState`
- `SaveState`

`cmd/issuance` writes these files. `cmd/showing` reads them back to build the
post-sign proof.

## Current Invariants

- the live relation is `bb_tran`
- the stored witness is semantic, not aligned or commitment-derived
- the default/public `mu` is one full-capacity coefficient-bounded ring element
  over `N=1024` with layout `full_capacity_halves_v1`; coefficients `0..511`
  are the message half, PRF-key coefficients live at `512..519`, and all
  coefficients are bounded by `BoundB`
- the opt-in `N=512` research fork stores `ring_degree=512` and uses the same
  layout over 512 coefficients, with the PRF-key window at `256..263`; it
  requires separately generated `research_n512` public params, B matrix, NTRU
  params/key material, state, and signature artifacts
- `r0` is vector-valued with `len(r0) = X0Len`
- the state must not contain issuer trapdoor material
- the state is runtime data, not the paper specification

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/shared_randomness_migration.md](../docs/shared_randomness_migration.md)
- [../cmd/README.md](../cmd/README.md)
