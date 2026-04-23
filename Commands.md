# Command Guide

This is the operator-facing command guide for the live SPRUCE branch.

Run all commands from the repository root.

## Prerequisites

- Go with module support
- tracked runtime assets present:
  - `Parameters/Parameters.json`
  - `Parameters/credential_public.json`
  - `Parameters/Bmatrix_bb_tran_x0len6.json`
  - `prf/prf_params.json`

Most workflows also read or write:

- `ntru_keys/`
- `credential/issuance/`
- `credential/keys/`

Current emitted formats:

- public params: `version = 2`
- issuance artifacts: `version = 2`
- credential state: `version = 2`
- `benchmark-x0` export: `version = 2`

Compatibility notes:

- public params still load older semantic/legacy length names
- credential state loader upgrades `version = 1` shared-randomness state to the
  current `version = 2` metadata surface
- issuance artifacts are stricter and should be regenerated if they predate the
  current branch
- aligned or unversioned legacy artifacts are not part of the live surface

See [docs/shared_randomness_migration.md](docs/shared_randomness_migration.md)
for the regeneration rules.

## `cmd/ntrucli`

### Generate keys

```bash
go run ./cmd/ntrucli gen
```

Writes:

- `ntru_keys/public.json`
- `ntru_keys/private.json`

### Sign a message

```bash
go run ./cmd/ntrucli sign -m test
```

Writes `ntru_keys/signature.json`.

### Verify a signature

```bash
go run ./cmd/ntrucli verify
```

Verifies `ntru_keys/signature.json` against `ntru_keys/public.json`.

## `cmd/issuance`

`cmd/issuance` is the role-separated CLI for the live shared-randomness
issuance protocol.

Retained subcommands:

- `setup-demo-public`
- `holder-commit`
- `issuer-challenge`
- `holder-prove`
- `issuer-verify-sign`
- `holder-finalize`
- `demo-local`
- `benchmark-x0`

### Default one-machine flow

```bash
go run ./cmd/issuance demo-local
```

This runs the full holder/issuer sequence and writes:

- `credential/issuance/holder_secret.json`
- `credential/issuance/commit_request.json`
- `credential/issuance/issue_challenge.json`
- `credential/issuance/presign_submission.json`
- `credential/issuance/issue_response.json`
- `credential/keys/credential_state.json`
- `credential/keys/signature.json`

### Role-separated flow

```bash
go run ./cmd/issuance holder-commit
go run ./cmd/issuance issuer-challenge
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
```

Protocol meaning:

- `holder-commit`
  - samples `m`, `k`, `r0h[0..X0Len-1]`, `r1h`, `rbar`
  - computes `com = ACom [m || k || r0h || r1h || rbar]^T`
- `issuer-challenge`
  - samples issuer rows `ri0[0..X0Len-1]` and `ri1`
- `holder-prove`
  - centers `r0[j] = center(r0h[j] + ri0[j])`
  - centers `r1 = center(r1h + ri1)`
  - computes `Z` and public target `T`
  - emits the pre-sign proof
- `issuer-verify-sign`
  - verifies the pre-sign proof and signs `T`
- `holder-finalize`
  - verifies `A u = T`
  - persists the final semantic credential state

### `setup-demo-public`

This command generates the canonical credential public parameters and the
matching `B` matrix.

Default profile:

```bash
go run ./cmd/issuance setup-demo-public -force
```

Current default:

- `x0-profile=lhl_default`
- `X0Len = 6`
- `X0CoeffBound = 5`
- `TargetDim = 1`
- `TargetHidingLambda = 128`

Supported profiles:

- `legacy_scalar`
- `lhl_default`
- `lhl_alt`

You can also override with:

- `-x0-len`
- `-x0-bound`

The generated `B` row order for `bb_tran` is:

- `B0`
- `B1`
- `B2[0] ... B2[X0Len-1]`
- `B3`

### `benchmark-x0`

Use this to compare transcript and proof size across `x0` profiles:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1
```

Optional JSON export:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1 -json-out /tmp/benchmark.json
```

The current JSON export includes, per run:

- proof bytes
- paper transcript bytes
- paper transcript bucket breakdowns
- transcript-focus geometry
- witness/replay row counts
- LHL slack

## `cmd/showing`

`cmd/showing` reads the persisted credential state and builds a post-sign proof
for the live `bb_tran` relation.

Default shipped command:

```bash
go run ./cmd/showing
```

Current live semantics:

- witness `(u, m, k, r0[0..X0Len-1], r1, Z)`
- public `tag = F(k, nonce)`
- direct showing equation
  - `A u = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z`
- reduced replay under the `soundness_balanced` preset
- `output_audit` PRF companion route

### Research control

The intended theorem-clean control is:

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

Treat that as research-only on the checked-in canonical artifacts. The shipped
engineering path is the reduced default.

### Common knobs

- `-showing-preset`
- `-full`
- `-sig-shortness-profile`
- `-prf-companion-mode`

## Typical End-to-End Sequence

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

For protocol semantics, read [docs/protocol.md](docs/protocol.md). For
compatibility and regeneration rules, read
[docs/shared_randomness_migration.md](docs/shared_randomness_migration.md).
