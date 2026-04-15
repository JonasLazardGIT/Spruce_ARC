# NIZK Alignment Notes

This note records how the live SPRUCE branch aligns with, compresses, or
deviates from the current ARC-SPRUCE paper source. It is not a protocol spec;
that role belongs to [protocol.md](protocol.md). This file is the detailed
paper-vs-code reconciliation log.

## Reading Rule

Interpret the tables below with the following precedence:

1. the current codebase and tracked runtime assets define live behavior
2. the paper source defines the comparison target
3. older repo prose is subordinate to both and may be stale

## Comparison Method

Paper anchors used here:

- `docs/ARC_Spruce/sections/03_blind_signature.tex`
- `docs/ARC_Spruce/sections/04_arc_construction.tex`
- `docs/ARC_Spruce/sections/05_smallwood_model.tex`
- `docs/ARC_Spruce/appendix/C_smallwood_details.tex`

Primary code anchors used here:

- `issuance/flow.go`
- `cmd/issuance/*.go`
- `cmd/showing/main.go`
- `credential/state.go`
- `PIOP/credential_rows.go`
- `PIOP/credential_constraints.go`
- `PIOP/showing_builder.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/showing_transform_bridge_constraints.go`
- `PIOP/prf_companion_bridge.go`
- `PIOP/generic_builder.go`
- `PIOP/run.go`

## At A Glance

- The live branch still follows the paper's compiled-story split: public-`T`
  issuance plus post-sign showing with PRF-tag constraints.
- The implementation compresses more of the semantic witness than the paper
  presentation suggests, especially on the showing path.
- The live showing runtime supports only coeff-native
  `literal_packed_aggregated_v3`.
- Reduced replay is the default live mode; full replay is optional.
- The paper's top-level rational-hash inverse witness `Z` does not exist as a
  separate committed showing source row on the retained live path.

## Core Alignment Matrix

| Paper term / claim | Live implementation | Status | Code anchor | Paper anchor |
| --- | --- | --- | --- | --- |
| Pre-sign carry surface is written as `C^J`, `J_0`, `J_1` | The same semantic carry surface is named `C^K`, `K0`, `K1` in code and in persisted state | Equivalent with renamed notation | `PIOP/carrier_codec.go`, `issuance/flow.go`, `credential/state.go` | `sections/05_smallwood_model.tex` (issuance compiled relation), `appendix/C_smallwood_details.tex` (issuance witness surface) |
| Issuance compiled relation keeps `T` public | The pre-sign proof takes `T` as a public input and stores it in state before signing | Equivalent | `issuance/flow.go` (`ApplyChallenge`, `ProvePreSign`, `VerifyPreSign`) | `sections/05_smallwood_model.tex` (issuance compiled relation) |
| Issuance semantic witness groups are carrier rows, decoded rows, and replay aliases | The live pre-sign row builder commits 5 carriers, 9 decoded aliases, and 4 transform aliases | Equivalent at compiled level, but code is more explicit about the concrete row inventory | `PIOP/credential_rows.go`, `PIOP/credential_constraints.go` | `sections/05_smallwood_model.tex` and `appendix/C_smallwood_details.tex` (issuance witness surface) |
| Message/key rows in issuance are written as `M`, `K` | The code carries the signed message split as `M1`, `M2`; `M2` is the part later decoded as the PRF-key carrier | Equivalent with different concrete row naming | `credential/state.go`, `cmd/showing/main.go`, `PIOP/credential_rows.go` | `sections/04_arc_construction.tex`, `sections/05_smallwood_model.tex` |
| Showing semantic groups include cert-side signature surface, compressed non-sign data, source rows `T, M, K, R0, R1, Z`, replay-image blocks, and PRF companion rows | The live retained layout commits carrier rows `C^M`, `C^ctr`, explicit `T` source blocks, replay rows for `hat(T)`, `hat(M1+M2)`, `hat(R0)`, `hat(R1)`, packed signature limb rows, and PRF companion rows | Partially aligned; live code compresses or omits several paper-semantic source rows | `PIOP/showing_coeff_native_literal_packed_runtime.go`, `PIOP/showing_transform_bridge_constraints.go` | `sections/05_smallwood_model.tex` and `appendix/C_smallwood_details.tex` (showing compiled relation / witness surface) |
| Showing source rows `M`, `K`, `R0`, `R1` are described as explicit committed source rows | On the live path, `M/K/R0/R1` are not committed as separate top-level source rows; they are recovered from carrier rows by public decode maps | Compressed in code relative to the paper's semantic presentation | `PIOP/showing_coeff_native_literal_packed_runtime.go`, `PIOP/showing_transform_bridge_constraints.go` | `sections/05_smallwood_model.tex` (showing committed rows) |
| Showing replay family is written as full block families `hat(T)_b`, `hat(m)_b`, `hat(R0)_b`, `hat(R1)_b` | The code supports full replay, but the default runtime path uses `ShowingReplayModeReduced`, i.e. one replay block | Partially aligned; full family exists, default runtime is reduced | `PIOP/run.go`, `cmd/showing/main.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go` | `sections/05_smallwood_model.tex` and `appendix/C_smallwood_details.tex` (full replay-image block families) |
| Paper writes the replay message family as `hat(m)_b = F_rep,b(M+K)` | The live code commits a combined replay row family for `M1+M2`, named `hat(M sigma)` in the row layout | Equivalent after concrete message split | `PIOP/showing_coeff_native_literal_packed_runtime.go`, `PIOP/showing_transform_bridge_constraints.go` | `sections/05_smallwood_model.tex` (source-to-replay bridges) |
| Paper includes a source-side inverse witness `Z` satisfying `(B3 - R1) Had Z = 1` | No separate rational-hash inverse source row `Z` is committed on the retained live showing path | Diverged / not realized verbatim on the retained runtime | absence in `PIOP/showing_coeff_native_literal_packed_runtime.go` row layout; no rational-hash `IdxZ` or analogous committed source row | `sections/05_smallwood_model.tex` (inverse-witness constraint), `appendix/C_smallwood_details.tex` |
| PRF companion constraints bind the public tag to the signed hidden key | The live showing builder forces the PRF companion route and rejects the legacy PRF layout | Equivalent at semantic level, stricter at runtime | `PIOP/showing_builder.go`, `PIOP/prf_companion_bridge.go`, `PIOP/generic_builder.go` | `sections/05_smallwood_model.tex` (PRF companion constraints) |
| The signed hidden key is denoted `K` in the showing relation | The live command computes the public tag by extracting key lanes from signed `M2`, while the proof re-binds those lanes through the message carrier row | Equivalent with a different concrete data path | `cmd/showing/main.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go` | `sections/04_arc_construction.tex`, `sections/05_smallwood_model.tex` |
| The verifier checks replay-space constraints against one coherent witness assignment | The live replay verifier composes post-sign transform constraints, signature shortness, and PRF companion checks against one committed row set under one root | Equivalent | `PIOP/generic_builder.go`, `PIOP/constraint_eval.go`, `PIOP/prf_companion_bridge.go` | `appendix/C_smallwood_details.tex` (what DECS/LVCS/PCS bind) |

## Important Divergences And Compression Choices

### 1. Pre-sign carry naming changed, semantics did not

The paper now writes the centering carry surface as:

- `C^J`
- `J_0`
- `J_1`

The live code still uses:

- `C^K`
- `K0`
- `K1`

This is a naming mismatch, not a different constraint. The carry rows still
mean "the wrap count needed to express centered randomness as
`RU + RI = R + (2 * BoundB + 1) * carry`".

### 2. The live pre-sign surface is not carrier-only

Older prose in this repo sometimes said that issuance commits only carrier
rows. That is false for the current branch.

The live pre-sign witness surface includes:

- 5 carrier rows
- 9 decoded alias rows
- 4 transform/replay aliases

That row inventory is enforced by the live builder and verifier path in
`PIOP/credential_rows.go` and `PIOP/credential_constraints.go`.

### 3. Showing is more compressed than the paper-semantic description

The paper's SmallWood model describes semantic groups that include explicit
source rows `M`, `K`, `R0`, `R1`, and `Z`. The retained live runtime instead
compresses the non-sign portion as follows:

- `M` and `K` are carried through one message carrier row, then decoded
  virtually
- `R0` and `R1` are carried through one centering carrier row, then decoded
  virtually
- only `T` is committed as an explicit top-level source-row family
- the replay message family is committed directly as the combined message row
  `M1 + M2`

This is the single most important paper-vs-code distinction on the live
showing path.

### 4. Reduced replay is the default runtime, not the full paper family

The paper's compiled showing relation is written against the full replay-image
block family. The live code can still commit that family, but only when
`ShowingReplayModeFull` is selected.

The default runtime path is:

- `ShowingReplayModeReduced`
- one replay block for `hat(T)`
- one replay block for `hat(M1+M2)`
- one replay block for `hat(R0)`
- one replay block for `hat(R1)`

This is why the current code should be described as "paper-aligned in shape,
reduced by default in runtime geometry".

### 5. The paper's rational-hash inverse witness `Z` is not present verbatim

Be careful not to confuse two different uses of the letter `Z`:

- the paper's rational-hash inverse witness `Z`
- the live PRF companion checkpoint openings named `Z`, which are S-box-side
  audit values

The retained code does have PRF checkpoint openings named `Z`, but those are
not the paper's rational-hash inverse witness. The live retained showing layout
does not commit a separate source row for the paper's rational-hash `Z`.

## Supported-Mode Matrix

| Paper / repo expectation | Live branch status | Status | Code anchor | Note |
| --- | --- | --- | --- | --- |
| Multiple showing layouts remain supported | Only coeff-native `literal_packed_aggregated_v3` is supported by the proving core | Diverged from stale repo prose | `PIOP/run.go`, `PIOP/showing_builder.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go`, `PIOP/generic_builder.go` | `literal_packed_aggregated_v4_split_prf` is stale documentation, not a live mode |
| Legacy PRF replay layout may still exist | The showing builder rejects the legacy PRF layout and requires the PRF companion route | Stricter in code | `PIOP/showing_builder.go`, `PIOP/generic_builder.go` | Live showing is the PRF companion route |
| Full verifier-side ARC policy is part of the shown flow | The shipped CLI only builds/verifies proofs locally; it does not store or reject spent tags | Not implemented in command surface | `cmd/showing/main.go` | Application-layer state must be added outside the current CLI |

## Stale Repo Claims Fixed By This Rewrite

The rewrite of the surrounding docs corrects the following stale repo-level
claims.

| Stale repo claim | Live value / behavior | Status | Code / asset anchor | Where it was stale |
| --- | --- | --- | --- | --- |
| `literal_packed_aggregated_v4_split_prf` is a supported showing layout | Only `literal_packed_aggregated_v3` is supported on the retained path | Stale repo prose | `PIOP/run.go`, `PIOP/showing_builder.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go` | old `README.md`, `Commands.md`, `cmd/README.md` |
| `beta = 745` | `beta = 6142` | Stale numeric claim | `Parameters/Parameters.json`, `cmd/showing/main.go` (signature bound check) | old `docs/modulus_choice.md`, old `docs/protocol.md` |
| `BoundB = 8` | `BoundB = 1` in the current tracked credential public parameters and issuance flow | Stale numeric claim | `Parameters/credential_public.json`, `cmd/issuance/*.go` | old `docs/modulus_choice.md`, old `docs/protocol.md` |
| Showing defaults use the old `Theta=5` / `Eta=63` style profile | The default showing CLI resolves to `Theta=3`, `Eta=43`, `EllPrime=2`, `Rho=2`, `LVCSNCols=96`, `NLeaves=4096`, `Kappa={0,0,0,5}` under `soundness_balanced` | Stale numeric claim | `cmd/showing/main.go`, `PIOP/run.go` | old `docs/protocol.md` |
| Issuance commits only carriers | Live pre-sign commits carriers, decoded aliases, and transform aliases | Stale structural claim | `PIOP/credential_rows.go`, `PIOP/credential_constraints.go` | old `docs/nizk_alignment_notes.txt`, old `docs/protocol.md` |

## What To Trust When Descriptions Disagree

When you encounter disagreement between the paper, the code, and repo prose on
this branch, use this rule:

- trust the code and tracked runtime assets for live behavior
- trust the paper for the intended semantic model and theorem statements
- use this file to map one to the other

If a future branch restores explicit source rows for the paper-semantic showing
surface, restores a second coeff-native layout, or reintroduces a distinct
rational-hash inverse row, this note should be updated before the protocol doc
is changed again.
