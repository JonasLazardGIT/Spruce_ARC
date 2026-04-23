# commitment

`commitment/` contains the Ajtai-style linear commitment helper used by
issuance.

The live committed witness is semantic and vector-aware:

```text
[m || k || r0H[0] || ... || r0H[X0Len-1] || r1H || rbar]
```

so the public commitment is:

```text
com = ACom [m || k || r0H || r1H || rbar]^T
```

where:

- `m` is the hidden attribute/message part
- `k` is the hidden PRF key later used for `tag = F(k, nonce)`
- `r0H` is the holder `x0` randomness block of length `X0Len`
- `r1H` is the scalar denominator-side randomness
- `rbar` is the remaining bounded commitment randomness

## Main Responsibility

- compute `com = Ac · vec` over ring polynomials

## Main Entry Point

- `Commit`

## Current Invariants

- inputs must live in one consistent ring/domain
- matrix dimensions must match the semantic committed vector
- the live block order is semantic:
  `[A_m | A_k | A_r0h | A_r1h | A_rbar]`
- `LenR0H` must equal `X0Len`
- no aligned-randomness `(S, E)` commitment path remains live

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../issuance/flow.go](../issuance/flow.go)
