# Protocol

This note is the implementation-canonical protocol description for the current
SPRUCE branch.

It documents the live shared-randomness `h_tran` / `bb_tran` credential path
only. Deprecated aligned or commitment-derived target paths are not part of the
live protocol.

## Current Shipped Baseline

The current checked-in branch should be read with these defaults:

- relation: `bb_tran`
- public params: `version = 2`
- issuance artifacts: `version = 2`
- credential state: `version = 2`
- default `x0` profile: `lhl_default`
  - `X0Len = 6`
  - `X0CoeffBound = 5`
- `TargetDim = 1`
- `TargetHidingLambda = 128`
- showing preset: `soundness_balanced`
- replay mode: `reduced`
- PRF companion mode: `output_audit`

The theorem-clean full replay control remains a research surface, not the
maintained engineering baseline on the current canonical artifacts.

## Source Of Truth

Use this precedence:

1. paper semantics and claimed security properties
2. live code and tracked runtime assets
3. measured command outputs and tests
4. repo prose

Primary code anchors:

- [../cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go)
- [../issuance/flow.go](../issuance/flow.go)
- [../cmd/showing/main.go](../cmd/showing/main.go)
- [../credential/public_params.go](../credential/public_params.go)
- [../credential/state.go](../credential/state.go)
- [../PIOP/credential_rows.go](../PIOP/credential_rows.go)
- [../PIOP/credential_constraints.go](../PIOP/credential_constraints.go)
- [../PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [../PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go)
- [../PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go)

## Semantic Protocol

The live semantic relations are:

```text
mu = (m || k)

com = ACom [m || k || r0H[0] || ... || r0H[X0Len-1] || r1H || rbar]^T

r0[j] = center(r0H[j] + r0I[j])    for j in [0..X0Len-1]
r1    = center(r1H + r1I)

Z = (B3 - r1)^(-1)
T = B0 + B1 * mu + sum_j B2[j] * r0[j] + Z

A u = T
tag = F(k, nonce)
```

The live implementation does not use:

- `T = B0 + Uc + Z`
- aligned commitment randomness `(S, E)`
- commitment-side witness `AsS + E`
- live source-product witness rows for issuance or showing

## Public Parameters

The canonical public parameter file is `Parameters/credential_public.json`.

Current emitted format:

- `version = 2`

Live fields:

- `hash_relation`
- `Ac`
- `BPath`
- `BoundB`
- `X0Len`
- `X0CoeffBound`
- `TargetDim`
- `TargetHidingLambda`
- `X0Distribution`
- `LenM`
- `LenK`
- `LenR0H`
- `LenR1H`
- `LenRBar`

Current canonical values:

- `hash_relation = bb_tran`
- `BoundB = 1`
- `X0Len = 6`
- `X0CoeffBound = 5`
- `TargetDim = 1`
- `TargetHidingLambda = 128`
- `X0Distribution = uniform_interval`
- `LenM = 1`
- `LenK = 1`
- `LenR0H = 6`
- `LenR1H = 1`
- `LenRBar = 1`
- `BPath = Parameters/Bmatrix_bb_tran_x0len6.json`

Interpretation:

- `Ac` block order is semantic:
  `[A_m | A_k | A_r0h | A_r1h | A_rbar]`
- `LenR0H` must equal `X0Len`
- `BoundB` governs the scalar low-alphabet side
- `X0CoeffBound` governs the vector `x0` side

For `bb_tran`, the live `B` row order is:

- `B0`
- `B1`
- `B2[0] ... B2[X0Len-1]`
- `B3`

## Issuance

Issuance is a role-separated shared-randomness pre-sign protocol.

### Holder secret witness

The holder samples:

- `m`
- `k`
- `r0H[0..X0Len-1]`
- `r1H`
- `rbar`

and forms `mu = (m || k)`.

### Commitment step

`holder-commit` computes:

```text
com = ACom [m || k || r0H || r1H || rbar]^T
```

and writes:

- `credential/issuance/holder_secret.json`
- `credential/issuance/commit_request.json`

Current emitted format:

- `version = 2`

`holder_secret.json` stores:

- `m`
- `k`
- `r0h`
- `r1h`
- `rbar`
- runtime geometry fields such as `packed_ncols`, `lvcs_ncols`, `nleaves`,
  and `omega`

`commit_request.json` stores:

- `com`
- public/runtime anchors needed by the next role

### Issuer challenge step

`issuer-challenge` samples bounded public rows:

- `ri0[0..X0Len-1]`
- `ri1`

and writes `credential/issuance/issue_challenge.json`.

### Holder pre-sign proof step

`holder-prove` computes:

- componentwise centered `r0`
- scalar centered `r1`
- internal carry rows `k0[]`, `k1`
- `Z = (B3 - r1)^(-1)`
- `T = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z`

and proves knowledge of a witness satisfying:

- the Ajtai commitment opening
- the componentwise centering equations
- the inverse-witness equation
  `(B3 - r1) ⊙ Z = 1`
- the target equation
  `T = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z`
- the required boundedness checks

Public pre-sign statement:

- `com`
- `ri0`
- `ri1`
- `T`
- `Ac`
- `B`

This step writes `credential/issuance/presign_submission.json`.

### Issuer signing step

`issuer-verify-sign` verifies the pre-sign proof and signs the public target by
sampling `u` such that:

```text
A u = T
```

It writes `credential/issuance/issue_response.json`.

### Finalization step

`holder-finalize` verifies `A u = T` and persists the final credential state
used by showing.

## Stored Credential State

The canonical holder state is `credential/keys/credential_state.json`.

Current emitted format:

- `version = 2`

Live fields:

- semantic witness rows:
  - `m`
  - `k`
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

`T` is not stored in the final credential state.

## Showing

Showing uses the stored credential witness:

- `u` reconstructed from `sig_s1` / `sig_s2`
- `m`
- `k`
- `r0[0..X0Len-1]`
- `r1`
- `Z`

and a public nonce.

The tag relation is:

```text
tag = F(k, nonce)
```

The showing proof establishes knowledge of a witness satisfying:

```text
(B3 - r1) ⊙ Z = 1
A u = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z
tag = F(k, nonce)
```

The public transcript does not reveal `u`, `m`, `k`, `r0`, `r1`, or `Z`.

### Showing surfaces

Shipped engineering surface:

- `go run ./cmd/showing`
- reduced replay
- `soundness_balanced`
- `output_audit`

Research control:

- `go run ./cmd/showing -showing-preset compact_l1_research -full`

Treat the second surface as research-only on the current canonical artifacts.

## `x0` Profiles

Supported public-parameter profiles:

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

## Testing And Benchmarking

Main end-to-end checks:

```bash
go test ./issuance ./cmd/issuance ./credential ./PIOP ./cmd/showing
go test ./...
```

Regenerate a fresh credential:

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

Compare `x0` profiles and transcript geometry:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1
```

## Compatibility Note

Older aligned credentials and aligned issuance artifacts are not part of the
live format. The state loader can upgrade compatible `version = 1`
shared-randomness state, but issuance artifacts should be regenerated on the
current branch.

See [shared_randomness_migration.md](shared_randomness_migration.md) for the
full migration rules.
