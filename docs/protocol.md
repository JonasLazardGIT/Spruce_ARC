# Protocol

This note is the implementation-canonical protocol description for the current
SPRUCE branch.

It documents the live shared-randomness `h_tran` / `bb_tran` flow only.
Deprecated aligned or commitment-derived target paths are not part of the live
protocol.

## Commands

Run all commands from the repository root.

### Issuance

```bash
go run ./cmd/issuance demo-local -seed 21
```

### Reduced showing

```bash
go run ./cmd/showing
```

### Theorem-clean full replay showing

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

## Source Of Truth

- protocol semantics and claims: the paper sources under `docs/arc_spruce_revised/`
- live behavior: current code and tracked runtime assets
- operator workflow and compatibility rules: this note plus
  [shared_randomness_migration.md](shared_randomness_migration.md)

Primary runtime anchors:

- [cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go)
- [issuance/flow.go](../issuance/flow.go)
- [cmd/showing/main.go](../cmd/showing/main.go)
- [credential/state.go](../credential/state.go)
- [credential/public_params.go](../credential/public_params.go)
- [PIOP/credential_rows.go](../PIOP/credential_rows.go)
- [PIOP/credential_constraints.go](../PIOP/credential_constraints.go)
- [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go)
- [PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go)

## Live Protocol Summary

The live credential relation is `bb_tran`.

At the semantic level:

```text
mu = (m || k)
c  = ACom [mu || r0H || r1H || rbar]^T

r0 = center(r0H + r0I)
r1 = center(r1H + r1I)

Z = (B3 - r1)^(-1)
T = B0 + B1 * mu + B2 * r0 + Z

A u = T
tag = F(k, nonce)
```

The live implementation does **not** use:

- `T = B0 + Uc + Z`
- aligned commitment randomness `(S, E)`
- commitment-side witness `AsS + E`
- source-product witness rows as part of the active showing relation

## Public Parameters

The canonical credential public parameters live in
`Parameters/credential_public.json`.

The live fields are:

- `version = 1`
- `hash_relation = bb_tran`
- `Ac`
- `BPath`
- `BoundB`
- `LenM`
- `LenK`
- `LenR0H`
- `LenR1H`
- `LenRBar`

`Ac` is interpreted in block order:

```text
[A_m | A_k | A_r0h | A_r1h | A_rbar]
```

The current shipped asset uses one row for each logical block:

- `LenM = 1`
- `LenK = 1`
- `LenR0H = 1`
- `LenR1H = 1`
- `LenRBar = 1`

The loader still accepts the older `LenM1`, `LenM2`, `LenRU0`, `LenRU1`,
`LenR` names when reading historical parameter files, but the live code and all
documentation use the semantic names above.

## Issuance

Issuance is the shared-randomness pre-sign protocol.

### Holder secret witness

The holder samples:

- `m`
- `k`
- `r0H`
- `r1H`
- `rbar`

and forms `mu = (m || k)`.

### Commitment step

`holder-commit` computes:

```text
c = ACom [m || k || r0H || r1H || rbar]^T
```

and writes:

- `credential/issuance/holder_secret.json`
- `credential/issuance/commit_request.json`

### Issuer challenge step

`issuer-challenge` samples bounded public rows:

- `r0I`
- `r1I`

and writes `credential/issuance/issue_challenge.json`.

### Holder pre-sign proof step

`holder-prove` computes:

- `r0 = center(r0H + r0I)`
- `r1 = center(r1H + r1I)`
- carry rows used internally by the centering gadget
- `Z = (B3 - r1)^(-1)`
- `T = B0 + B1 * (m || k) + B2 * r0 + Z`

and proves knowledge of a witness that simultaneously satisfies:

- the Ajtai commitment opening
- the centering equations
- the inverse-witness equation `(B3 - r1) ⊙ Z = 1`
- the target equation `T = B0 + B1 * (m || k) + B2 * r0 + Z`
- the required boundedness checks

The public pre-sign statement contains:

- `com`
- `r0I`
- `r1I`
- `T`
- `Ac`
- `B`

`holder-prove` writes `credential/issuance/presign_submission.json`.

### Issuer signing step

`issuer-verify-sign` verifies the pre-sign proof, checks the public target
relation, and then samples `u` such that:

```text
A u = T
```

It writes `credential/issuance/issue_response.json`.

### Finalization step

`holder-finalize` verifies the signature equation `A u = T` and persists the
credential state used by showing.

## Stored Credential State

The persisted holder state lives at `credential/keys/credential_state.json`.

The live format is versioned and stores:

- `version`
- semantic witness rows:
  - `m`
  - `k`
  - `r0`
  - `r1`
  - `z`
- signature witness rows:
  - `sig_s1`
  - `sig_s2`
- packing and parameter anchors:
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

The final credential state does **not** store `T`. `T` remains an issuance-time
artifact carried by `presign_submission.json` and `issue_response.json`.

## Showing

Showing uses the stored credential witness:

- `u` from `sig_s1` / `sig_s2`
- `m`
- `k`
- `r0`
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
A u = B0 + B1 * (m || k) + B2 * r0 + Z
tag = F(k, nonce)
```

The public transcript does not reveal `u`, `m`, `k`, `r0`, `r1`, or `Z`.

### Showing surfaces

- default shipped path: reduced replay, `soundness_balanced`
- theorem-clean control path: full replay via
  `-showing-preset compact_l1_research -full`

Both surfaces use the same semantic credential witness and PRF/tag relation.
The difference is replay geometry and transcript shape, not the credential
semantics.

## Testing

The main end-to-end checks are:

```bash
go test ./issuance ./cmd/issuance ./credential ./PIOP ./cmd/showing
go test ./...
```

To regenerate a fresh credential with the live issuance flow:

```bash
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

## Compatibility Note

Old aligned credentials and old issuance artifacts are not part of the live
format. See [shared_randomness_migration.md](shared_randomness_migration.md)
before reusing persisted files across branches.
