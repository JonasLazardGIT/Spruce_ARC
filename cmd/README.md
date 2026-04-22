# Command Packages

This directory contains the retained executables for the shipped credential
path.

Use [../Commands.md](../Commands.md) for operator usage and
[../docs/protocol.md](../docs/protocol.md) for protocol context.

## `cmd/ntrucli`

This is the NTRU operator CLI. It covers key generation, message signing,
signature verification, and the bundle-oriented variants of signing and
verification. It is the only retained command for direct NTRU operations.

## `cmd/issuance`

This command now exposes the role-separated issuance surface. The holder and
issuer exchange JSON artifacts under `credential/issuance/`, and `demo-local`
is the faithful one-process wrapper over the same production steps. The final
credential state is written under `credential/keys/`.

## `cmd/showing`

This command runs the retained post-sign showing flow. It reads the persisted
credential state and builds a showing proof on the retained coeff-native `v3`
path with the PRF companion `output_audit` route and hidden
`SigShortnessV6`.

There are two important operator surfaces:

- shipped default: `go run ./cmd/showing`
  runs reduced replay under the `soundness_balanced` preset
  (`Theta=3`, `Eta=43`, `EllPrime=2`, `Rho=2`, `LVCSNCols=89`,
  `NLeaves=4096`, `Kappa={0,0,0,5}`)
- theorem-clean baseline: `go run ./cmd/showing -showing-preset compact_l1_research -full`
  runs the full replay control used by
  [../docs/full_baseline_proof_study.md](../docs/full_baseline_proof_study.md)
