# DECS

`DECS/` is the degree-enforcing commitment layer used by the retained proof
stack.

Its role is to authenticate row evaluations and enforce that the opened values
come from low-degree polynomials rather than arbitrary vectors.

## Main Responsibilities

- commit rows over an explicit evaluation domain
- derive and use verifier-side masking coefficients
- open selected points with Merkle authentication
- verify low-degree masked relations at opened points

## Main Entry Points

- `NewProverWithParamsAndPointsFormalChecked`
- `(*Prover).CommitInit`
- `(*Prover).CommitStep2Formal`
- `(*Prover).EvalOpen`
- `BuildMerkleTree`
- `VerifyPath`

Verifier-side DECS checks are consumed through the LVCS and PIOP layers.

## Current Invariants

- explicit-domain semantics only
- low-degree checks over the shared base field
- support for formal coefficient rows where needed by the proof path
- on the shipped maintained path, DECS underlies the authenticated row
  openings for the carrier and PRF-companion replay families
- the current vector-`x0` path uses singleton low-alphabet carrier support on
  the `x0` side, but that changes row degree geometry rather than DECS
  semantics

## Read Next

- [../LVCS/README.md](../LVCS/README.md)
- [../PIOP/README.md](../PIOP/README.md)
