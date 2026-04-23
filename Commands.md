# Command Guide

This file is the operator-facing guide for the retained command surface:
`cmd/ntrucli`, `cmd/issuance`, and `cmd/showing`.

Run all commands from the repository root.

## Prerequisites

- Go with module support
- tracked runtime assets present in the repository:
  - `Parameters/Parameters.json`
  - `Parameters/Bmatrix_bb_tran.json`
  - `Parameters/credential_public.json`
  - `prf/prf_params.json`

Most workflows also read or write:

- `ntru_keys/`
- `credential/issuance/`
- `credential/keys/`

If a credential state or issuance artifact predates the shared-randomness
migration, regenerate it. See
[docs/shared_randomness_migration.md](docs/shared_randomness_migration.md).

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

`cmd/issuance` is the role-separated issuance CLI for the live shared-randomness
protocol.

Faithful one-machine wrapper:

```bash
go run ./cmd/issuance demo-local
```

Retained subcommands:

- `setup-demo-public`
- `holder-commit`
- `issuer-challenge`
- `holder-prove`
- `issuer-verify-sign`
- `holder-finalize`
- `demo-local`

Default artifact flow:

- `credential/issuance/holder_secret.json`
- `credential/issuance/commit_request.json`
- `credential/issuance/issue_challenge.json`
- `credential/issuance/presign_submission.json`
- `credential/issuance/issue_response.json`
- `credential/keys/credential_state.json`

Role-separated usage:

```bash
go run ./cmd/issuance holder-commit
go run ./cmd/issuance issuer-challenge
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
```

Protocol meaning of the subcommands:

- `holder-commit`: sample `(m,k,r0h,r1h,rbar)` and publish `com`
- `issuer-challenge`: publish issuer rows `ri0`, `ri1`
- `holder-prove`: derive centered `r0`, `r1`, compute `z`, `t`, and emit the
  pre-sign proof
- `issuer-verify-sign`: verify the proof and sign the public target `t`
- `holder-finalize`: verify `A u = T` and persist the final credential state

## `cmd/showing`

`cmd/showing` builds and verifies the retained showing proof.

Default shipped command:

```bash
go run ./cmd/showing
```

Supported `-coeff-model` values:

- `literal_packed_aggregated_v3`

`cmd/showing` expects the versioned credential state prepared by
`cmd/issuance`.

Current live semantics:

- relation: `bb_tran`
- witness: `(u,m,k,r0,r1,Z)`
- tag: `F(k, nonce)`
- reduced/default surface: shipped engineering benchmark
- full `-full` surface: theorem-clean replay control

The theorem-clean full replay control is:

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

Other retained flags tune transcript geometry and reporting:

- `-showing-preset`
- `-full`
- `-sig-shortness-profile`
- `-prf-companion-mode`

## Typical End-to-End Flow

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

For protocol meaning, read [docs/protocol.md](docs/protocol.md). For
compatibility and regeneration guidance, read
[docs/shared_randomness_migration.md](docs/shared_randomness_migration.md).
