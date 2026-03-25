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

This command runs the blind-issuance / pre-sign flow. It builds and verifies
the issuance proof, signs the derived target, and updates the credential state
under `credential/keys/`.

## `cmd/showing`

This command runs the retained post-sign showing flow. It reads the persisted
credential state and builds a showing proof in either the default one-root `v3`
layout or the optional split-PRF `v4` layout.
