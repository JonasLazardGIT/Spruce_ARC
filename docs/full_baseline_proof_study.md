# Full Baseline Proof Study

This note is the retained current-state study for the live theorem-clean full
showing baseline only.

The live commands are:

- reduced engineering control:
  `go run ./cmd/showing -showing-preset compact_l1_research`
- theorem-clean full replay:
  `go run ./cmd/showing -showing-preset compact_l1_research -full`

The purpose of this note is to hand a new research/implementation agent the
actual state of the repo after the shipped outer `THat` relayout and after the
failed first `source_product` bridge activation attempt.

This note is not an optimization patch. It is decision prep plus handoff
context.

## Executive State

Three facts are now settled.

1. The outer same-root `THat` opening was the right next lever and has already
   been harvested.
   - The live full transcript dropped from about `66.2 KB` to about `57.3 KB`.
   - The outer `THat` opening dropped from about `14.4 KB` to about `5.45 KB`.
   - The outer shortness surface is now `6` support slots and `11` opened
     blocks on the compact full preset.

2. The first-pass `source_product` bridge plan is blocked under current
   authenticated surfaces.
   - A same-root opening over the current physical rows `2/3` does not
     round-trip the exact committed `MSigmaR1` / `R0R1` witness object.
   - The derived K-evaluations from that opening do not match the committed
     source-product rows at verifier points either.
   - So the naive plan "build a bridge directly on current rows `2/3` and move
     source-product checks out of Q" is not sound.

3. The next credible research target is still `source_product`, but no longer
   as a direct activation of the current bridge scaffolding.
   - The next viable path is a new same-root extraction shape, most likely a
     projected / alias stripe under the existing main root.
   - The first realistic cut is to move only
     `bb_tran_source_product_source_to_hat_bridge` out of Q.
   - The `bb_tran_source_product_source_residual` family should stay in Q in a
     first shipped pass unless carrier authentication is strengthened enough to
     remove it soundly.

## Current Live Commands

Re-run these first in any new research pass:

```bash
go run ./cmd/showing -showing-preset compact_l1_research
go run ./cmd/showing -showing-preset compact_l1_research -full
go test ./PIOP -run 'TestSourceProductBridge.*|TestTransformBridge.*|TestSigShortness.*|TestReplayFamilyAudit.*|TestReporting.*' -count=1
go test ./cmd/showing -run 'TestShowingV3CompactL1ResearchFullReplayPreset|TestShowingFullBaselineStudy.*|TestShowingReplayFamilyAuditShippedDefault|TestShowingReplaySubfamilyAuditShippedDefault|TestShowingRowOpeningReconstructsOmittedMvals' -count=1
```

These are the minimum sanity controls for the current state.

## Current Measurements

All measurements below were re-run locally on `2026-04-22`.

### Reduced control

Command:

```bash
go run ./cmd/showing -showing-preset compact_l1_research
```

Measured facts from the latest run:

- statement class: `reduced_engineering_replay`
- optimized transcript: `26493` bytes
- buckets:
  - `SigShortness=9452`
  - `Pdecs=6627`
  - `Q=4622`
  - `VTargets=766`
  - `BarSets=436`
- outer shortness surface:
  - `slots=1`
  - `blocks=1`
  - `opening=464`
- replay selector:
  - `16/22` rows
  - `2/2` active blocks

### Full theorem-clean replay

Command:

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

Measured facts across repeated runs:

- statement class: `theorem_clean_full_replay`
- optimized transcript: observed in the `57200..57360` byte range
- stable buckets:
  - `Pdecs=18130`
  - `VTargets=9838`
  - `BarSets=5539`
  - `Q=4622`
- shortness bucket:
  - observed in the `14466..14539` byte range
- outer shortness surface:
  - `slots=6`
  - `blocks=11`
  - opening observed in the `5445..5465` byte range
- replay selector:
  - `16/400` rows
  - `3/22` active blocks
- replay family state:
  - `source_product` still selected `2/2`
  - `carrier` still selected `2/2`
  - `t_source` selected `0/0`
  - `replay_image` selected `0/64`

Measurement note:

- There is small run-to-run jitter in `SigShortness`, `Auth`, and total
  optimized bytes.
- Treat the current full control as a range, not a single frozen exact byte
  count.
- The stable control gates already encoded in tests are:
  - full optimized bytes in `57000..57600`
  - full outer shortness opening in `5400..5500`
  - `Q=4622`
  - outer shortness support slots remain `6`

## Current Test Status

These suites were rerun after the latest source-product bridge attempt was
turned back off:

- `go test ./PIOP -run 'TestSourceProductBridge.*|TestTransformBridge.*|TestSigShortness.*|TestReplayFamilyAudit.*|TestReporting.*' -count=1`
- `go test ./cmd/showing -run 'TestShowingV3CompactL1ResearchFullReplayPreset|TestShowingFullBaselineStudy.*|TestShowingReplayFamilyAuditShippedDefault|TestShowingReplaySubfamilyAuditShippedDefault|TestShowingRowOpeningReconstructsOmittedMvals' -count=1`

Both passed in the current tree.

## What Was Achieved Since The Older Study

The following older conclusions are now obsolete:

- the outer `THat` opening is no longer the next implementation target
- the old full baseline around `66 KB` is no longer the live control
- the old outer `THat` opening around `14.4 KB` is no longer the live surface
- the old ranking "hidden geometry first, outer `THat` second, `source_product`
  later" is stale

The current shipped state is:

- `THat` replay-window relayout is done
- full theorem-clean replay keeps committed `T` source rows out of the witness
- hidden shortness still binds only to authenticated outer `THat`
- `source_product` remains the next bridge-required lever
- but the first local bridge activation attempt failed structurally

One important repo-level caveat:

- some reporting helpers are currently coarser than the real feasibility state
- in particular, replay-family audit output can still describe
  `source_product` as `derivable_after_local_refactor`
- the generated `BuildFullProofStudyReport` ranking in
  [PIOP/full_proof_study.go](../PIOP/full_proof_study.go) also still reflects
  the older pre-`THat` ranking
- that string is not authoritative for the next cycle
- the blocker tests in [PIOP/source_product_bridge_test.go](../PIOP/source_product_bridge_test.go)
  and the gating in [PIOP/source_product_bridge.go](../PIOP/source_product_bridge.go)
  are the stronger source of truth for current feasibility

## Current Full Witness Families

The live full baseline still uses these witness families:

| Family | Committed Rows | Selected Rows | Current State |
| --- | ---: | ---: | --- |
| `carrier_m` | 1 | 1 | Still live and directly consumed by replay decoding. |
| `carrier_ctr` | 1 | 1 | Still live and directly consumed by replay decoding. |
| `t_source` | 0 | 0 | Already derived away in theorem-clean full replay. |
| `mhat_sigma` | 64 | 0 | Replay-image rows, committed under main PCS only. |
| `rhat0` | 64 | 0 | Replay-image rows, committed under main PCS only. |
| `rhat1` | 64 | 0 | Replay-image rows, committed under main PCS only. |
| `msigmar1_source` | 1 | 1 | Still live. This is one of the blocked extraction targets. |
| `r0r1_source` | 1 | 1 | Still live. This is one of the blocked extraction targets. |
| `msigmar1_hat` | 64 | 0 | Replay-image source-product hats over all replay blocks. |
| `r0r1_hat` | 64 | 0 | Replay-image source-product hats over all replay blocks. |
| `t_hat` | 64 | 0 | Replay-image `THat` rows, now placed so the outer opening hits only `6` slots. |
| `prf_key` | 1 | 1 | Still live in the baseline `output_audit` path. |
| `prf_checkpoint` | 10 | 10 | Still live in the baseline `Q`-bridge. |
| `prf_final_tag` | 2 | 2 | Still live in the baseline `Q`-bridge. |
| `prf_helper` | 1 | 1 | Still live in the baseline `Q`-bridge. |

The most important current fact is:

- the only post-`THat` replay rows still selected in the full theorem-clean
  path are:
  - carrier rows `0/1`
  - source-product rows `2/3`
  - PRF companion rows `388..399`

## Current Constraint Families That Matter For The Next Step

These are the exact live families to reason about for `source_product`.

| Constraint Family | Layer | Role |
| --- | --- | --- |
| `bb_tran_source_product_source_residual` | `Fpar` | Checks that committed `MSigmaR1` / `R0R1` source rows equal the `Ω_s`-interpolated products reconstructed from carriers. |
| `bb_tran_source_product_source_to_hat_bridge` | `Fagg` | Bridges the committed source-product rows to the committed replay hats over all replay blocks. |
| `transform_hash_residual_all_blocks` | `Fpar` | Consumes the replay hats `MSigmaR1Hat` / `R0R1Hat` as part of the exact replay image. |

Important current interpretation:

- `source_product` is split between:
  - a source residual against carrier-derived interpolants
  - a source-to-hat bridge over the full replay image
- a first shipped same-root redesign only needs to replace the second one to
  be useful
- it does not need to solve carrier extraction at the same time

## Current Authenticated Surface Reality

The current live authenticated objects are enough to verify the theorem-clean
full proof, but they are not enough to justify the naive source-product bridge.

What is true now:

- the main PCS opening authenticates the committed witness rows under the main
  root
- the outer hidden shortness opening authenticates exact `THat` under the same
  root
- the current PRF scalar payload authenticates scalar outputs, not packed
  witness rows on `Ω_s`

What is not true now:

- the current main opening does not expose an exact, shipped, same-root
  `Ω_s`-witness object for `MSigmaR1` / `R0R1`
- a direct same-root opening over current physical rows `2/3` does not
  round-trip the committed source-product witness object

## Source-Product Bridge Attempt: Exact Blocker

This was the most important research result after the `THat` win.

The current bridge scaffolding remains in the tree, but activation is disabled
in:

- [PIOP/source_product_bridge.go](../PIOP/source_product_bridge.go)

The blocking probes live in:

- [PIOP/source_product_bridge_test.go](../PIOP/source_product_bridge_test.go)

Those tests now establish two negative facts:

1. `TestSourceProductBridgeCurrentPhysicalRowsDoNotRoundTripThroughSameRootOpening`
   - opening the current physical rows `2/3` under the main root does not
     reconstruct the exact committed `MSigmaR1` / `R0R1` `Ω_s` heads

2. `TestSourceProductBridgeCurrentPhysicalRowsDoNotMatchCommittedKValues`
   - even after taking the `Ω_{s+1}` limbs into account, the values derived
     from that same-root opening do not match the committed source-product rows
     at verifier K-points

This is the exact reason the previous activation attempt was turned back off.

The current gating comment in code is the authoritative short version:

- the retained bridge scaffolding stays disabled until there is a same-root
  extraction shape that actually round-trips the exact `MSigmaR1` / `R0R1`
  rows

## Why The Naive Plan Failed

The failed plan was:

- build `SourceProductBridge` directly over current physical rows `2/3`
- use that same-root opening as the shipped source-product witness surface
- move both source-product families out of Q

It failed because the current physical rows are in the main packed witness
geometry, not in a projection that is guaranteed to reconstruct the exact
`Ω_s` object the verifier needs for source-product extraction.

The practical consequence is:

- "same root" alone is not enough
- "same physical rows" is the broken assumption

## Viable Redesign Direction

The next credible path is a projected / alias stripe under the same main root.

The repo already contains the same general design pattern for PRF stripe work
in:

- [PIOP/prf_bridge_stripe.go](../PIOP/prf_bridge_stripe.go)

That file is research-only control work, but it proves the repo already has
the right conceptual tool:

- copy a source witness family into a compact physical stripe
- authenticate the stripe under the existing main root
- bind source rows to stripe rows with equality constraints
- then open the stripe rather than the original packed geometry

For `source_product`, the viable v1 redesign should be:

1. add alias rows for `MSigmaR1` and `R0R1`
2. place them in a compact stripe whose same-root opening actually round-trips
   exact `Ω_s` heads
3. enforce equality between source rows and alias rows
4. build `SourceProductBridge` over the alias stripe, not rows `2/3`
5. use the bridge to replace only
   `bb_tran_source_product_source_to_hat_bridge`
6. keep `bb_tran_source_product_source_residual` in Q in the first shipped cut

Why this is the right first cut:

- it avoids the current blocker on carrier extraction
- it should let the verifier authenticate exact source-product values without
  changing the theorem-clean full statement
- it attacks the bridge-heavy part of `source_product` first

## Expected Byte Economics

The current post-`THat` source-product opportunity is no longer a `THat`-class
win.

Expected economics for the alias-stripe redesign:

- likely net gain: about `1.5 KB` to `3 KB`
- best case: somewhat above that if the bridge opening packs unusually well
- why the gain is capped:
  - source-product rows share the first active selector block with the carrier
    rows, so removing them does not shrink active-block count by itself
  - some bytes move from `Q` into a new same-root bridge opening

The key expectation is:

- `source_product` is still worth doing next
- but only as a medium-sized same-root bridge win, not as another `8-9 KB`
  event

## No-Go Routes

The next agent should not spend time re-proving these.

### Not viable now

- flip `sourceProductBridgeEnabled(...)` back on for current rows `2/3`
- try to justify the current bridge scaffolding as already sound
- derive source-product values only locally from carrier values at challenge
  `x`

Why:

- current rows `2/3` do not round-trip the exact committed source-product
  object
- local derivation at `x` is not equivalent to authenticating the committed
  `Ω_s`-interpolated source-product polynomials

### Not the next step

- second SmallWood instance for source-product
- separate root / master-root architecture for source-product
- another `THat`-only layout pass

Why:

- source-product still has a plausible same-root redesign path
- `THat` already gave the large layout-based win
- the next `THat` upside would require a new projected same-root shape, which
  is now a smaller payoff than fixing source-product first

## PRF Context

The PRF same-root aux / stripe work remains research-only control work.

Current conclusion:

- same-root PRF stripe work is sound
- it is not economically better than the live baseline
- so it should remain a design reference, not the next optimization target

Why it still matters here:

- it is the closest existing in-repo template for a projected same-root alias
  stripe under the main root

## Ranked Recommendation Now

The current ranking after the shipped `THat` relayout is:

1. `source_product` via a projected / alias same-root stripe under the current
   main root
2. projected same-root `THat` bridge if source-product does not pay enough
3. PRF master-root / multi-oracle architecture only after same-root levers are
   exhausted

## Concrete Handoff For The Next Agent

The next agent should start with these files:

- [PIOP/source_product_bridge.go](../PIOP/source_product_bridge.go)
- [PIOP/source_product_bridge_test.go](../PIOP/source_product_bridge_test.go)
- [PIOP/prf_bridge_stripe.go](../PIOP/prf_bridge_stripe.go)
- [PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go)
- [PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go)
- [PIOP/replay_selector.go](../PIOP/replay_selector.go)
- [PIOP/full_proof_study.go](../PIOP/full_proof_study.go)
- [docs/protocol.md](./protocol.md)
- [docs/nizk_alignment_notes.md](./nizk_alignment_notes.md)

The next agent should answer these exact design questions before coding:

1. What alias-row layout guarantees exact round-trip of `MSigmaR1` / `R0R1`
   under a same-root opening?
2. What equality constraints bind source rows to alias rows with minimal byte
   cost?
3. Can the first pass move only
   `bb_tran_source_product_source_to_hat_bridge` out of Q while leaving the
   source residual in Q?
4. What is the smallest support-slot geometry that keeps the alias stripe
   economical?
5. What is the measured net win after counting both removed Q families and the
   new bridge opening?

The next agent should not claim success unless all of these are true:

- theorem-clean full replay still verifies
- hidden shortness is unchanged
- no second unrelated root is introduced
- the bridge authenticates an exact source-product object, not a local proxy
- the source-product bridge test suite proves round-trip on the new alias rows
- the full compact baseline drops materially below the current `57.2-57.4 KB`
  range

## Measurement Log Used For This Note

Commands rerun for this update:

```bash
go run ./cmd/showing -showing-preset compact_l1_research
go run ./cmd/showing -showing-preset compact_l1_research -full
go test ./PIOP -run 'TestSourceProductBridge.*|TestTransformBridge.*|TestSigShortness.*|TestReplayFamilyAudit.*|TestReporting.*' -count=1
go test ./cmd/showing -run 'TestShowingV3CompactL1ResearchFullReplayPreset|TestShowingFullBaselineStudy.*|TestShowingReplayFamilyAuditShippedDefault|TestShowingReplaySubfamilyAuditShippedDefault|TestShowingRowOpeningReconstructsOmittedMvals' -count=1
```

Latest observed reduced run:

- optimized bytes: `26493`
- shortness opening: `464`
- selector: `16/22`

Latest observed full runs:

- optimized bytes: `57202`, `57309`, `57356`
- shortness opening: `5445`, `5465`
- shortness bucket: `14466`, `14502`, `14539`
- `Q=4622` on every run
- selector: `16/400` on every run

## Bottom Line

The state of the research is now clean:

- the outer `THat` win is shipped
- the full theorem-clean baseline is about `57.3 KB`
- the naive source-product bridge is proven blocked
- the next serious step is a projected / alias same-root source-product stripe
  under the current main root
- the correct first target is the source-to-hat bridge family, not immediate
  full source-product removal from Q
