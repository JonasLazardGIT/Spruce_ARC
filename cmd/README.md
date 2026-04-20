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
path with the PRF companion route and `SigShortness` V4. The shipped default is
the reduced replay path under the `soundness_balanced` preset
(`LVCSNCols=96`).
