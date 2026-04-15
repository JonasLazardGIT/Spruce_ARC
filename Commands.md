# Command Guide

This file is the operator-facing guide for the retained command surface. It
matches the shipped repository as it exists now: only `cmd/ntrucli`,
`cmd/issuance`, and `cmd/showing` are supported.

Run all commands from the repository root.

## Prerequisites

- Go with module support
- tracked runtime assets present in the repository:
  `Parameters/Parameters.json`,
  `Parameters/Bmatrix.json`,
  `credential/params.json`,
  `credential/Ac.json`,
  `prf/prf_params.json`

Most workflows also read or write:

- `ntru_keys/`
- `credential/keys/`

## `cmd/ntrucli`

`cmd/ntrucli` is the shipped NTRU operator CLI.

### Generate keys

```bash
go run ./cmd/ntrucli gen
```

This writes:

- `ntru_keys/public.json`
- `ntru_keys/private.json`

### Sign a message

```bash
go run ./cmd/ntrucli sign -m test
```

Required flag:

- `-m <message>`

This writes:

- `ntru_keys/signature.json`

### Verify a signature

```bash
go run ./cmd/ntrucli verify
```

This verifies `ntru_keys/signature.json` against `ntru_keys/public.json`.

### Bundle signing

```bash
go run ./cmd/ntrucli bundle-sign -bundle ./some_bundle -m test
go run ./cmd/ntrucli bundle-verify -bundle ./some_bundle
```

Required flags:

- `bundle-sign`: `-bundle`, `-m`
- `bundle-verify`: `-bundle`

The bundle directory is expected to contain the parameter, key, and signature
files used by the bundle workflow.

## `cmd/issuance`

`cmd/issuance` runs the retained blind-issuance demo:

```bash
go run ./cmd/issuance
```

It:

- builds the commitment and pre-sign proof
- verifies that proof
- signs the target with the stored NTRU trapdoor
- updates credential state under `credential/keys/`

The command has no retained operator flags.

## `cmd/showing`

`cmd/showing` builds and verifies the retained showing proof.

Default retained layout:

```bash
go run ./cmd/showing
```

Supported `-coeff-model` values:

- `literal_packed_aggregated_v3`

`cmd/showing` expects the credential state prepared by `cmd/issuance`.

Other retained flags tune transcript geometry and reporting, for example:

- `-showing-preset`
- `-full`
- `-sig-shortness-profile`
- `-prf-companion-mode`

## Typical End-to-End Flow

```bash
go run ./cmd/ntrucli gen
go run ./cmd/ntrucli sign -m test
go run ./cmd/ntrucli verify
go run ./cmd/issuance
go run ./cmd/showing
```

For protocol meaning, read [docs/protocol.md](docs/protocol.md). For the
current modulus and packing rationale, read
[docs/modulus_choice.md](docs/modulus_choice.md). For the detailed
paper-vs-code alignment note, read
[docs/nizk_alignment_notes.md](docs/nizk_alignment_notes.md).
