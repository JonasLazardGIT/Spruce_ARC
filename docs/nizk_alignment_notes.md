# NIZK Alignment Notes

This note records paper-to-code alignment for the current SPRUCE checkout after
the shared-randomness `h_tran` migration.

## Reading Rule

Use this precedence:

1. paper semantics and claimed properties
2. live implementation behavior
3. measured commands and tests
4. repo prose

Keep these categories separate:

- paper-stated fact
- code-backed fact
- measured fact
- inference

## Current Bottom Line

- issuance now matches the shared-randomness `h_tran` structure: Ajtai
  commitment, issuer randomness, centering, direct inverse witness `Z`, and
  direct public target `T`
- showing now proves the direct `bb_tran` relation from stored semantic witness
  rows `(u,m,k,r0,r1,Z)`
- reduced replay is still an engineering benchmark surface
- `compact_l1_research -full` remains the theorem-clean full replay control

## Claim Matrix

| Property | Paper | Code / Measurement | Status | Notes |
| --- | --- | --- | --- | --- |
| issuance commitment surface | Paper fact: the holder commits to `(\mu, r0H, r1H, rbar)`. | Code fact: [cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go) persists `m`, `k`, `r0h`, `r1h`, `rbar`; [issuance/flow.go](../issuance/flow.go) commits those rows through `PrepareCommit`. | aligned | The live commitment is Ajtai-style and semantic. |
| shared issuer randomness | Paper fact: issuer sends `r0I`, `r1I` and the holder centers the sums. | Code fact: [issuance/flow.go](../issuance/flow.go) samples `RI0` / `RI1` and derives centered `R0` / `R1` with explicit carry rows. | aligned | Centering is part of the pre-sign statement, not an external convention. |
| public target relation | Paper fact: `Z=(B3-r1)^(-1)` and `T=B0+B1\mu+B2r0+Z`. | Code fact: [credential/helpers.go](../credential/helpers.go) and [issuance/flow.go](../issuance/flow.go) compute `Z` and `T` directly from `(m,k,r0,r1)`; [PIOP/credential_constraints.go](../PIOP/credential_constraints.go) enforces the inverse and target equations. | aligned | No live `Uc` path remains. |
| issuer signing step | Paper fact: issuer samples `u` such that `A u = T`. | Code fact: `issuer-verify-sign` verifies the pre-sign proof and signs the public `T`; `holder-finalize` checks `A u = T` before storing state. | aligned | Trapdoor signing remains unchanged apart from target plumbing. |
| stored credential witness | Paper fact: stored witness is conceptually `(u,m,k,r0,r1)` and may cache `Z`. | Code fact: [credential/state.go](../credential/state.go) stores `m`, `k`, `r0`, `r1`, `z`, `sig_s1`, `sig_s2`, plus audit artifacts `com`, `ri0`, `ri1`. | aligned | `T` is no longer persisted in the final credential state. |
| showing relation | Paper fact: showing proves `(B3-r1)⊙Z=1`, `A u = B0 + B1(m||k) + B2r0 + Z`, and `tag = F(k, nonce)`. | Code fact: [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go), [PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go), and [PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go) compile that direct witness shape. | aligned | The live showing path no longer depends on `MSigmaR1`, `R0R1`, or a source-product bridge. |
| PRF correctness | Paper fact: showing proves the PRF/tag relation on the signed hidden key. | Code fact: [cmd/showing/main.go](../cmd/showing/main.go) derives the PRF key from stored `k`, and the live showing proof binds `tag = F(k, nonce)`. | aligned | The tag key no longer comes from an aligned-commitment witness split. |
| theorem-clean replay geometry | Paper fact: the strongest theorem-facing statement uses the full replay image. | Code fact: `go run ./cmd/showing -showing-preset compact_l1_research -full` remains the full replay control; reduced replay is still shipped separately. | aligned for `-full` | Reduced replay stays narrower by design. |
| rate limiting service | Paper conditional claim: rate limiting depends on application state outside the proof. | Code fact: `cmd/showing` constructs and verifies proofs locally; it does not maintain a spent-tag database. | unproven | The algebraic tag relation is implemented, but application policy is external. |
| blindness / one-more unforgeability | Paper-explicit non-claim or conditional claim. | Code fact: this branch does not add new proofs beyond the paper. | unchanged | Do not describe the implementation as proving more than the paper does. |

## Practical Reading

- Use [protocol.md](protocol.md) for the live issuance and showing equations.
- Use [shared_randomness_migration.md](shared_randomness_migration.md) for
  artifact-format compatibility.
- Use [full_baseline_proof_study.md](full_baseline_proof_study.md) when working
  on the theorem-clean full replay path.
