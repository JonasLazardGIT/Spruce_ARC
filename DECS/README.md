# DECS

`DECS/` is the degree-enforcing commitment layer used by the retained proof
stack. It authenticates row evaluations and checks that opened values come from
low-degree polynomials rather than arbitrary vectors.

## Package Role

- Commit rows over an explicit evaluation domain.
- Derive verifier-side masking coefficients.
- Open selected points with Merkle authentication.
- Verify low-degree masked relations at opened points.

## Main Entry Points

- `NewProverWithParamsAndPointsFormalChecked`
- `(*Prover).CommitInitWithOptions`
- `(*Prover).CommitStep2Formal`
- `(*Prover).EvalOpen`
- `BuildMerkleTreeFromLeafHashBytes`
- `VerifyPathHash`

Verifier-side DECS checks are consumed through LVCS and PIOP.

## Current Invariants

- Explicit-domain semantics are mandatory.
- Low-degree checks run over the shared base field.
- Formal coefficient rows are supported where degree-sensitive proof paths need
  them.
- On the maintained path, DECS authenticates row openings for the carrier and
  PRF-companion replay families.
- The vector-`x0` path changes row-degree geometry without changing DECS
  semantics.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [LVCS](../LVCS/README.md)
- [PIOP](../PIOP/README.md)
