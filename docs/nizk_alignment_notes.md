# NIZK Alignment Notes

This note records paper-to-code alignment for the current SPRUCE checkout after:

- the shared-randomness `h_tran` migration
- the vector-`x0` parameterization pass
- the first-pass singleton-`x0` transcript reduction

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

- issuance matches the shared-randomness `h_tran` structure:
  - Ajtai commitment
  - issuer randomness
  - componentwise centering on the `x0` side
  - direct inverse witness `Z`
  - direct public target `T`
- showing proves the direct `bb_tran` relation from stored semantic witness
  rows `(u, mu, r0, r1, Z)`, where `mu = m || k` is one
  coefficient-bounded ring element
- the optimized V18 showing represents full-capacity `mu` with private
  `mu_pack=2` carrier rows; default, full, and aggregate V6 controls keep the
  singleton carrier
- the live `x0` side is vector-aware and parameterized by `X0Len` and
  `X0CoeffBound`
- the live `x0` carrier surface now uses a real singleton low-alphabet codec
  for `RU0[]`, `R0[]`, and `K0[]`
- reduced replay remains the default engineering surface
- the optimized V18 preset is the maintained full-replay, theorem-clean
  research profile over the default `N=1024` artifacts
- the opt-in `N=512` path is a research statement fork requiring separate
  artifacts and separate security review

## Claim Matrix

| Property | Paper | Code / Measurement | Status | Notes |
| --- | --- | --- | --- | --- |
| issuance commitment surface | Paper fact: the holder commits to `(\mu, r0H, r1H, rbar)`. | Code fact: [../cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go) persists `mu`, `r0h`, `r1h`, `rbar`; [../issuance/flow.go](../issuance/flow.go) commits those rows through `PrepareCommit`. | aligned | `r0H` is vector-valued in the live branch. |
| shared issuer randomness | Paper fact: issuer sends `r0I`, `r1I` and the holder centers the sums. | Code fact: [../issuance/flow.go](../issuance/flow.go) samples `RI0[]` / `RI1` and derives centered `R0[]` / `R1` with explicit carry rows. | aligned | Centering is part of the pre-sign statement, not an external convention. |
| public target relation | Paper fact: `Z=(B3-r1)^(-1)` and `T=B0+B1\mu+B2r0+Z`. | Code fact: [../credential/helpers.go](../credential/helpers.go) and [../issuance/flow.go](../issuance/flow.go) compute `Z` and `T` directly from `(mu,r0,r1)`; [../PIOP/credential_constraints.go](../PIOP/credential_constraints.go) enforces the inverse and target equations. | aligned | `B2 * r0` is vector accumulation in the live branch. |
| issuer signing step | Paper fact: issuer samples `u` such that `A u = T`. | Code fact: `issuer-verify-sign` verifies the pre-sign proof and signs the public `T`; `holder-finalize` checks `A u = T` before storing state. | aligned | Trapdoor signing remains unchanged apart from target plumbing. |
| stored credential witness | Paper fact: stored witness is conceptually `(u,mu,r0,r1)` and may cache `Z`. | Code fact: [../credential/state.go](../credential/state.go) stores `mu`, `r0`, `r1`, `z`, `sig_s1`, `sig_s2`, plus audit artifacts `com`, `ri0`, `ri1`. | aligned | `T` is not persisted in the final credential state. |
| showing relation | Paper fact: showing proves `(B3-r1)⊙Z=1`, `A u = B0 + B1(m||k) + B2r0 + Z`, and `tag = F(k, nonce)`. | Code fact: [../PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go), [../PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go), and [../PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go) compile that direct witness shape. | aligned | The live showing path no longer depends on `MSigmaR1`, `R0R1`, or source-product witness rows. |
| PRF correctness | Paper fact: showing proves the PRF/tag relation on the signed hidden key. | Code fact: [../cmd/showing/main.go](../cmd/showing/main.go) derives the PRF key from full-capacity `mu` coefficients `512..519` for default `N=1024`, or `256..263` for the explicit `N=512` research fork, and the live showing proof binds `tag = F(k, nonce)`. | aligned | The PRF key no longer comes from an aligned commitment split. |
| packed full-`mu` witness representation | Paper inference: low-alphabet private witness material can be represented by a packed private carrier when membership and decode are constrained. | Code fact: the optimized V18 preset reports `mu_pack=2`, `mu_rows=32`, `mu_blocks=64`; [../PIOP/carrier_codec.go](../PIOP/carrier_codec.go), [../PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go), and [../PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go) enforce ternary membership and decode before target/PRF use. | aligned | This is a witness representation change only; it does not make `mu` public or change the direct `bb_tran` statement. |
| degree-512 research fork | Paper inference: changing ring degree changes lattice assumptions and semantic payload capacity. | Code fact: `-research-ring-degree 512` is accepted only for the optimized V18 preset; issuance and showing validate `ring_degree` and coefficient lengths, and proof/layout digests bind the selected degree. | research-only | The measured theorem bits are reported by code, but production validity remains blocked on degree-512 security review. |
| x0 parameterization | Paper fact: the target-hiding term is the `x0` / `r0` side. | Code fact: [../credential/public_params.go](../credential/public_params.go) and [../cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go) expose `X0Len`, `X0CoeffBound`, `TargetDim`, and `TargetHidingLambda`. | aligned | Current shipped profile is `lhl_default`. |
| low-alphabet x0 carrier compression | Paper inference: low-alphabet rows should be encoded with support matching the actual witness alphabet. | Code fact: [../PIOP/carrier_codec.go](../PIOP/carrier_codec.go) now uses a singleton carrier codec for `RU0[]`, `R0[]`, and `K0[]`; [../docs/transcript_reduction_analysis.md](transcript_reduction_analysis.md) records the measured impact. | aligned | This is a code-backed optimization, not a new protocol claim. |
| theorem-clean replay geometry | Paper fact: the strongest theorem-facing statement uses the full replay image. | Code fact: `go run ./cmd/showing -full` is maintained on the checked-in canonical vector-`x0` artifacts and keeps the direct `bb_tran` replay image. | aligned | The default command remains the smaller reduced engineering path. |
| rate limiting service | Paper conditional claim: rate limiting depends on application state outside the proof. | Code fact: `cmd/showing` constructs and verifies proofs locally; it does not maintain a spent-tag database. | unproven | The algebraic tag relation is implemented; application policy is external. |
| blindness / one-more unforgeability | Paper-explicit non-claim or conditional claim. | Code fact: this branch does not add new proofs beyond the paper. | unchanged | Do not describe the implementation as proving more than the paper does. |

## Practical Reading

- Use [protocol.md](protocol.md) for the live issuance and showing equations.
- Use [shared_randomness_migration.md](shared_randomness_migration.md) for
  artifact-format compatibility and regeneration rules.
- Use [transcript_reduction_analysis.md](transcript_reduction_analysis.md) for
  the measured packed full-`mu` transcript regime.
- Use [full_baseline_proof_study.md](full_baseline_proof_study.md) when working
  on the theorem-clean full replay control.
