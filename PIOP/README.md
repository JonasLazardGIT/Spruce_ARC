# PIOP

`PIOP/` contains the proving and verifying core for the current SPRUCE branch.

Its main job is to compile the live issuance and showing statements into the
retained SmallWood-style proof flow:

- issuance / pre-sign proving with public `T`
- showing with two explicit modes:
  - `reduced_engineering_replay`
  - `theorem_clean_full_replay`
- hidden `SigShortnessV6` binding for showing

## Main Responsibilities

- build issuance and showing witness rows
- compile the active constraint families
- drive DECS/LVCS commitments and openings
- run the Fiat-Shamir flow
- replay verifier checks from opened rows and public inputs
- produce proof reports and factual replay audits for the certified statement
  surface

## Main Entry Points

- `NewCredentialBuilder`
- `BuildWithConstraints`
- `VerifyWithConstraints`
- `BuildShowingCombined`
- `BuildCredentialRowsShowing`
- `BuildProofReport`
- `BuildProofPackingAudit`

## Current Invariants

- explicit-domain DECS/LVCS semantics
- canonical concrete relation `bb_tran`
- hidden `SigShortnessV6` for live showing proofs
- reduced replay kept only as a narrower engineering benchmark
- full replay available as the theorem-clean paper-aligned showing path
- PRF companion route retained on the live showing path

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/nizk_alignment_notes.md](../docs/nizk_alignment_notes.md)
- [../docs/full_baseline_proof_study.md](../docs/full_baseline_proof_study.md)
  for the retained manual full-baseline study/handoff note
- [../DECS/README.md](../DECS/README.md)
- [../LVCS/README.md](../LVCS/README.md)
