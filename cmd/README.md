# Command Packages

This directory contains the retained executables for the live shared-randomness
credential path.

Use [../Commands.md](../Commands.md) for operator usage and
[../docs/protocol.md](../docs/protocol.md) for protocol context.

## `cmd/ntrucli`

This is the NTRU operator CLI. It covers key generation, target signing, and
signature verification.

## `cmd/issuance`

This command exposes the role-separated issuance surface for the live
shared-randomness flow.

Artifact flow under `credential/issuance/`:

- `holder_secret.json`: holder witness `(m,k,r0h,r1h,rbar)` plus runtime
  metadata
- `commit_request.json`: public commitment `com`
- `issue_challenge.json`: issuer rows `ri0`, `ri1`
- `presign_submission.json`: public target `t` plus pre-sign proof
- `issue_response.json`: signed target witness `sig_s1`, `sig_s2`

`demo-local` runs the same flow in one process and writes the final
versioned credential state under `credential/keys/`.

## `cmd/showing`

This command reads the persisted credential state and builds a showing proof for
the live `bb_tran` relation:

- witness `(u,m,k,r0,r1,Z)`
- public tag `F(k, nonce)`
- direct signature equation `A u = B0 + B1(m||k) + B2r0 + Z`

There are two important operator surfaces:

- shipped default: `go run ./cmd/showing`
  runs reduced replay under the `soundness_balanced` preset
- theorem-clean control: `go run ./cmd/showing -showing-preset compact_l1_research -full`
  runs the full replay statement used by
  [../docs/full_baseline_proof_study.md](../docs/full_baseline_proof_study.md)
