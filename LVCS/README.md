# LVCS

`LVCS/` lifts DECS into a row-oracle commitment that supports the linear
openings used by the retained proof system.

It is the layer that lets the verifier request and authenticate linear forms of
committed witness rows.

## Main Responsibilities

- commit packed witness rows
- keep witness and mask regions in one oracle layout
- answer linear opening queries
- verify those openings against the DECS commitment

## Main Entry Points

- `CommitInitWithParamsAndPoints`
- `(*ProverKey).CommitFinish`
- `(*ProverKey).EvalInitMany`
- `(*ProverKey).EvalFinish`
- `NewVerifierWithParamsAndPoints`
- `(*VerifierState).EvalStep2`

## Row Model

The retained row model accepts:

- packed row heads and tails
- direct ring-backed row polynomials
- direct formal row coefficients when degree-sensitive paths need them

## Current Invariants

- explicit-domain points are mandatory
- prover and verifier must interpret the same oracle layout
- LVCS is the authenticated row source for issuance and showing replay
- on the shipped baseline, the active replay selector is reduced to carrier and
  PRF-companion families
- the live vector-`x0` path increases logical witness structure without
  changing the fact that LVCS is the single authenticated row oracle used by
  issuance and showing

## Read Next

- [../DECS/README.md](../DECS/README.md)
- [../PIOP/README.md](../PIOP/README.md)
