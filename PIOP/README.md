# PIOP

`PIOP/` contains the proving and verifying core for the current SPRUCE branch.

Its job is to compile the live issuance and showing relations into the retained
SmallWood-style DECS/LVCS proof flow.

## Live Statements

### Issuance / pre-sign

The live pre-sign statement binds:

- Ajtai commitment opening to
  `(m, k, r0H[0..X0Len-1], r1H, rbar)`
- componentwise centering for the vector `x0` side
  - `r0[j] = center(r0H[j] + r0I[j])`
- scalar centering for `r1`
  - `r1 = center(r1H + r1I)`
- inverse witness
  - `(B3 - r1) ⊙ Z = 1`
- target equation
  - `T = B0 + B1(m||k) + sum_j B2[j] * r0[j] + Z`

### Showing

The live showing statement binds:

- signature witness `u`
- semantic credential rows `(m, k, r0[0..], r1, Z)`
- PRF/tag relation `tag = F(k, nonce)`

The showing relation is:

- `(B3 - r1) ⊙ Z = 1`
- `A u = B0 + B1(m||k) + sum_j B2[j] * r0[j] + Z`
- `tag = F(k, nonce)`

## Current Witness Surface

The live branch is now vector-aware on the `x0` side.

Important consequence:

- `RU0[]`, `R0[]`, and `K0[]` are true x0 blocks
- those x0 carrier rows now use a true singleton low-alphabet codec
- scalar rows `RU1`, `RBar`, `R1`, `K1` still use the existing scalar pair path

This is the first-pass transcript reduction already reflected in the live code
and in `benchmark-x0`.

## Main Responsibilities

- build issuance and showing witness rows
- compile active constraint families
- drive DECS/LVCS commitments and openings
- run Fiat-Shamir
- replay verifier checks from opened rows and public inputs
- produce proof reports, paper transcript reports, and replay audits

## Main Entry Points

- `NewCredentialBuilder`
- `BuildWithConstraints`
- `VerifyWithConstraints`
- `BuildShowingCombined`
- `BuildCredentialRowsShowing`
- `BuildProofReport`
- `BuildReplayFamilyAuditReport`

## Current Invariants

- explicit-domain DECS/LVCS semantics
- canonical live relation `bb_tran`
- semantic witness rows only
- no live `Uc` / source-product / aligned-commitment path
- shipped showing surface:
  - reduced replay
  - `soundness_balanced`
  - `output_audit`
- theorem-clean full replay remains research-only on the checked-in canonical
  artifacts

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/nizk_alignment_notes.md](../docs/nizk_alignment_notes.md)
- [../docs/transcript_reduction_analysis.md](../docs/transcript_reduction_analysis.md)
- [../docs/full_baseline_proof_study.md](../docs/full_baseline_proof_study.md)
- [../DECS/README.md](../DECS/README.md)
- [../LVCS/README.md](../LVCS/README.md)
