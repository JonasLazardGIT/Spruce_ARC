# prf

`prf/` implements the Poseidon2-like PRF used by showing proofs.

The hidden key portion of the signed message is reused as the PRF key. A public
nonce produces:

```text
tag = PRF(key, nonce)
```

The showing proof binds that tag to the same signed witness used by the NTRU
target relation.

## Package Role

- Load and validate PRF parameters.
- Evaluate the PRF over the shared field `F_q`.
- Expose grouped S-box checkpoint traces for the PRF companion route used by
  the showing proof.
- Keep the tag relation bound to the signed `k` witness.

## Main Entry Points

- `Tag`
- `LoadParamsFromFile`
- `LoadLocalOrDefaultParams`
- `ShouldCheckpointRound`
- `SBoxOutputCountGrouped`

## Current Invariants

- The PRF uses the same modulus as the rest of the protocol.
- The shipped parameter file uses the cubic S-box over `q = 1017857`.
- The showing proof uses grouped nonlinear checkpoints with
  `PRFGroupRounds = 2`.
- Maintained compact presets use `PRFCompanionMode=direct_full`.
- The PRF key comes from the stored signed message field `k`.
- `prf_params.json` is the source parameter file used by Go tests and
  commands.
- Sage parameter scripts are retained as source-tree provenance, excluded from
  Docker, and documented in `docs/SECURITY.md`.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [Security](../docs/SECURITY.md)
