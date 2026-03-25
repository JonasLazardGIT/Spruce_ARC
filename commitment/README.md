# commitment

`commitment/` contains the linear commitment helper used in the issuance flow.

It computes the Ajtai-style commitment that binds the holder message and
issuance randomness before the pre-sign proof is produced.

## Main Responsibility

- compute `com = A_c · vec` over ring polynomials

## Main Entry Point

- `Commit`

The package intentionally stays small. Higher-level proof logic lives in
`issuance/` and `PIOP/`.

## Current Invariants

- inputs must live in a consistent ring/domain
- matrix dimensions must match the committed vector

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../issuance/flow.go](../issuance/flow.go)
