# commitment

`commitment/` contains the linear commitment helper used by issuance.

It computes the Ajtai-style commitment for the live witness vector:

```text
[m || k || r0H || r1H || rbar]
```

so the public commitment is:

```text
com = ACom [m || k || r0H || r1H || rbar]^T
```

## Main Responsibility

- compute `com = Ac · vec` over ring polynomials

## Main Entry Point

- `Commit`

The package intentionally stays small. Higher-level proof logic lives in
`issuance/` and `PIOP/`.

## Current Invariants

- inputs must live in a consistent ring/domain
- matrix dimensions must match the committed vector
- the live column order is semantic, not legacy-aligned randomness

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../issuance/flow.go](../issuance/flow.go)
