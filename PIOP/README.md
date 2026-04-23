# PIOP

`PIOP/` contains the proving and verifying core for the current SPRUCE branch.

Its main job is to compile the live issuance and showing relations into the
retained SmallWood-style proof flow.

## Live Statements

Issuance / pre-sign proving compiles a witness that binds:

- Ajtai commitment opening to `(m,k,r0H,r1H,rbar)`
- centering relations for `(r0,r1)`
- inverse witness `(B3 - r1) ⊙ Z = 1`
- target equation `T = B0 + B1(m||k) + B2r0 + Z`

Showing compiles a witness that binds:

- signature witness `u`
- semantic credential rows `(m,k,r0,r1,Z)`
- PRF/tag relation `tag = F(k, nonce)`

## Main Responsibilities

- build issuance and showing witness rows
- compile the active constraint families
- drive DECS/LVCS commitments and openings
- run the Fiat-Shamir flow
- replay verifier checks from opened rows and public inputs
- produce proof reports and replay audits for the certified statement surface

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
- direct inverse-witness and target relations on semantic witness rows
- no live `Uc` / source-product / aligned-commitment path
- reduced replay kept as an engineering benchmark
- full replay available as the theorem-clean showing control
- PRF companion route retained on the live showing path

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/nizk_alignment_notes.md](../docs/nizk_alignment_notes.md)
- [../docs/full_baseline_proof_study.md](../docs/full_baseline_proof_study.md)
- [../DECS/README.md](../DECS/README.md)
- [../LVCS/README.md](../LVCS/README.md)
