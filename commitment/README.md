# commitment

`commitment/` contains the ring-linear commitment helpers used by IntGenISIS
issuance.

The live public commitment equation is:

```text
c = C_M*M + A_s*s + e
```

where `M` is the semantic message polynomial vector, `s` is commitment
randomness, and `e` is bounded error.

## Package Role

- Generate and load coefficient matrices for commitment parameters.
- Sample bounded commitment randomness.
- Evaluate the public commitment equation over the shared ring.
- Keep matrix shape checks close to the arithmetic helpers.

## Main Entry Points

- `GenerateUniformCoeffMatrix`
- `MatrixFromCoeff`
- `SampleCommitmentRandomness`
- `CommitMessage`

## Current Invariants

- Inputs must live in one consistent ring and modulus domain.
- Matrix dimensions must match the IntGenISIS public parameters.
- `M`, `s`, and `e` are bounded by the active profile/preset configuration.
- The package only evaluates the commitment equation; protocol binding to
  NTRU targets, PRF keys, and proof rows happens above this layer.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [Security](../docs/SECURITY.md)
