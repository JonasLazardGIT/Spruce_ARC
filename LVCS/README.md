# LVCS

`LVCS/` lifts DECS into a row-oracle commitment that supports the linear
openings used by issuance and showing proofs.

## Package Role

- Commit packed witness rows.
- Keep witness and mask regions in one oracle layout.
- Answer linear opening queries.
- Verify openings against the DECS commitment.

## Main Entry Points

- `CommitInitWithParamsAndPointsV2`
- `EvalInitManyChecked`
- `EvalFinishV2`
- `MergeOpeningsV2`
- `NewVerifierWithParamsAndPointsV2`
- `(*VerifierState).EvalStep2`
- `(*VerifierState).EvalStep2SmallField2025`

These v2 entry points propagate the same DECS `CommitmentContext` through the
prover and verifier and use only the full-width `RootHash`. Context-free entry
points have been removed.

## Row Model

The retained row model accepts packed row heads and tails, direct ring-backed
row polynomials, and direct formal row coefficients when degree-sensitive paths
need them.

## Current Invariants

- Explicit-domain points are mandatory.
- Prover and verifier must interpret the same oracle layout.
- V2 split and merged openings preserve one tape per logical leaf index and
  reject conflicting tapes for a repeated index.
- LVCS is the authenticated row source for issuance and showing replay.
- The maintained replay selector is reduced to carrier and PRF-companion
  families.
- The vector-`x0` path increases logical witness structure while keeping LVCS
  as the single authenticated row oracle.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [DECS](../DECS/README.md)
- [PIOP](../PIOP/README.md)
