# Command Packages

This directory contains the retained executables for the live shared-randomness
credential path.

Use [../Commands.md](../Commands.md) for operator usage and
[../docs/protocol.md](../docs/protocol.md) for protocol semantics.

## `cmd/ntrucli`

Operator CLI for:

- NTRU key generation
- target signing
- signature verification

This is the signer-facing wrapper around `ntru/`, `ntru/keys`, and
`ntru/signverify`.

## `cmd/issuance`

Role-separated issuance CLI for the live `bb_tran` pre-sign flow.

The command surface now assumes:

- semantic witness rows
- vector `x0` / `r0` support
- explicit `X0Len`, `X0CoeffBound`, `TargetDim`, and
  `TargetHidingLambda` in public params
- versioned issuance artifacts (`version = 2`)

Artifact flow under `credential/issuance/`:

- `holder_secret.json`
  - holder witness `(m, k, r0h[0..], r1h, rbar)` and runtime geometry
- `commit_request.json`
  - public commitment `com`
- `issue_challenge.json`
  - issuer rows `ri0[0..]`, `ri1`
- `presign_submission.json`
  - public target `t` and pre-sign proof
- `issue_response.json`
  - `sig_s1`, `sig_s2`, public key material, and signed target bundle

`demo-local` runs the same flow in one process and writes the final versioned
credential state under `credential/keys/`.

`benchmark-x0` is the main operator and study interface for comparing
`legacy_scalar`, `lhl_default`, and `lhl_alt`.

## `cmd/showing`

This command reads the persisted credential state and builds a showing proof for
the live `bb_tran` relation:

- witness `(u, m, k, r0[0..], r1, Z)`
- public tag `F(k, nonce)`
- direct signature relation
  `A u = B0 + B1(m||k) + sum_j B2[j] * r0[j] + Z`

Important surfaces:

- shipped default: `go run ./cmd/showing`
  - reduced replay
  - `soundness_balanced`
  - `output_audit`
- research control:
  `go run ./cmd/showing -showing-preset compact_l1_research -full`
  - intended theorem-clean full replay path
  - not the maintained engineering baseline on the current canonical artifacts
