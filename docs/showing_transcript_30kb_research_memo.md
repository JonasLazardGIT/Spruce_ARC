# Showing Transcript Memo: Path Below 30 KB

This memo tracks the current SmallWood-style showing path in this repository and
focuses on one question: after the current compact preset pass, what can still
drive the paper transcript below `30 KB`?

The source-of-truth order for this note is:

1. current code
2. direct measurements from this checkout
3. `docs/2025-1085.pdf`

If this memo disagrees with older notes, this memo wins only when it is backed
by current code and fresh local measurements.

## Reading Guide

This memo labels claims explicitly:

- `Measured`: taken from fresh local runs on this checkout
- `Code-backed`: derived directly from the implementation
- `Inference`: engineering conclusion from the first two

## Current Live Presets

Measured with:

```bash
go run ./cmd/showing -showing-preset soundness_balanced
go run ./cmd/showing -showing-preset compact_l3
go run ./cmd/showing -showing-preset compact_l2
go run ./cmd/showing -showing-preset compact_l1_research
```

Measured on this checkout on 2026-04-20:

| Preset | Tuple | Paper Transcript | Theorem Total | Key Geometry |
| --- | --- | ---: | ---: | --- |
| `soundness_balanced` | `lvcs=89, eta=43, nLeaves=4096, R/L=11/4` | `76,480 B` | `101.60` | `witness=534`, `rowsBlock=6`, `maskChunks=4` |
| `compact_l3` | `lvcs=68, eta=36, nLeaves=4096, R/L=24/3` | `63,229 B` | `103.44` | `witness=406`, `rowsBlock=6`, `maskChunks=5` |
| `compact_l2` | `lvcs=70, eta=36, nLeaves=4096, R/L=111/2` | `52,294 B` | `103.21` | `witness=278`, `rowsBlock=4`, `maskChunks=5` |
| `compact_l1_research` | `lvcs=50, eta=31, nLeaves=4096, R/L=12285/1` | `39,261 B` | `103.48` | `witness=150`, `rowsBlock=3`, `maskChunks=7` |

Two immediate conclusions follow.

- `Measured`: the compact presets did improve again, but the live winners are
  not the deterministic-state sweep points. The shipped compact presets now
  want lower `eta`, while keeping the old live block-threshold widths
  `lvcs=68` and `lvcs=70`.
- `Inference`: parameter retuning is now close to exhausted. The best current
  live path is still about `9.3 KB` above `30 KB`.

## Important Measurement Caveat

An earlier optimization sweep in `cmd/showing/optimization_test.go` used
`tryBuildDeterministicCredentialStateForPackedNCols`, which is useful for
structural exploration but is not authoritative for shipped preset selection.

- `Code-backed`: the optimization sweep does not read
  `credential/keys/credential_state.json`; it constructs a deterministic state.
- `Measured`: that sweep suggested `compact_l3 -> (67,35,4096)` and
  `compact_l2 -> (55,35,3072)`.
- `Measured`: when re-run on the live showing path through `cmd/showing`, those
  points are worse than the current live threshold widths.

So the preset updates in this repository are based on the live credential state,
not on the deterministic sweep.

## What Actually Dominates Today

### `SigShortness` is still the largest bucket

Measured live buckets:

- `soundness_balanced`
  - `SigShortness=39,681`
  - `R=9,572`
  - `Pdecs=9,678`
  - `VTargets=8,421`
  - `Q=4,637`
- `compact_l1_research`
  - `SigShortness=17,239`
  - `Pdecs=7,676`
  - `Q=4,637`
  - `R=3,877`
  - `VTargets=2,373`
  - `Auth=2,341`

- `Inference`: even after the compact preset pass, the route below `30 KB`
  still runs through the shortness object first.

### `Q` is not the main blocker, but it is now too large to ignore

- `Code-backed`: `dQ=312` is still driven by the carrier system, not by
  signature shortness. The shortness radix changes do not feed the main `Q`
  constraint family.
- `Measured`: the `Q` bucket stays fixed at `4,637 B` across the current live
  compact presets.
- `Inference`: `Q` is not the first lever, but once the proof is already
  `~39 KB`, a fixed `4.6 KB` bucket is too large to dismiss.

### `NCols` is not the next frontier in the current code

The paper treats `ncols` as a free parameter. That is true in principle, but
the current implementation does not benefit from widening it on the live path.

- `Code-backed`: the paper's small-field variant explicitly treats `ncols` as a
  free PCS/LVCS packing parameter.
- `Measured`: on the actual live showing path, the best compact presets still
  sit at `NCols=16`.
- `Inference`: this codebase does not currently realize the paper's hoped-for
  `ncols` win, because wider packing inflates other proof objects and hits
  implementation limits before it wins overall.

The current failure modes are concrete:

- `Measured`: widening the packing regime eventually hits
  `R polynomial 0 too large to materialize`.
- `Measured`: more aggressive widening also hits
  `alias row 2 degree=1785 exceeds ring dimension 1024`.
- `Inference`: any serious `NCols` push first requires refactoring shortness
  materialization and alias-degree budgeting. It is not a preset-only change.

## What The Code Already Uses From 2025-1085

The paper's proof-size improvements are not absent from this repository. Many of
them are already present in the main PCS opening path.

### Already realized

- `Code-backed`: main row openings compress `P` columns through
  `maybeCompressRowOpeningPvals`.
- `Code-backed`: main row openings omit all `M` values through
  `omitAllRowOpeningMvals`.
- `Code-backed`: `Q` openings also have dedicated compression helpers in
  `run.go` and verifier-side reconstruction in `VerifyNIZK.go`.
- `Code-backed`: the transcript accounting in `canonical_transcript.go` already
  counts paper-style optimized buckets such as `Pdecs`, `VTargets`, `BarSets`,
  and `Q`.
- `Code-backed`: packed `VTargets`, packed `BarSets`, and row-opening
  reconstruction are already live.

### Only partially realized

- `Code-backed`: the main PCS path supports compressed `P` reconstruction, but
  `SigShortness` does not.
- `Code-backed`: `prepareSigShortnessOpeningForVerify` rejects
  `FormatVersion == 1` with `sig shortness P compression is not supported`.
- `Code-backed`: `buildSigShortnessProofBase` omits all `M` values on the
  shortness opening, but does not apply the same `P` compression used by the
  main PCS opening.

### Not realized in the relevant place

- `Code-backed`: `restoreExplicitMerklePaths` restores explicit Merkle paths on
  the shortness opening because sparse frontier round-tripping is still not
  stable.
- `Inference`: this means the current shortness path is still paying an
  avoidable authentication-format penalty even before any structural redesign.

## Why Parameter Retuning Alone Will Not Reach 30 KB

The live trajectory is now:

- `76.5 KB` at `soundness_balanced`
- `63.2 KB` at `compact_l3`
- `52.3 KB` at `compact_l2`
- `39.3 KB` at `compact_l1_research`

- `Measured`: the compact retunes already exploit the only big structural lever
  available without changing the statement shape: fewer shortness digits.
- `Measured`: `compact_l1_research` already uses the smallest current live
  shortness row count.
- `Inference`: the remaining `~9.3 KB` gap to `30 KB` will not come from more
  preset tuning alone. It requires at least one new proof-object redesign.

## Realistic Routes Below 30 KB

The credible routes are below, in descending order of impact.

### 1. Add `SigShortness` P-column compression and stop restoring explicit paths

This is the smallest code-local improvement that is clearly missing today.

- `Code-backed`: shortness openings already omit `M`, but reject compressed
  `P`.
- `Code-backed`: shortness openings also fall back to explicit Merkle paths via
  `restoreExplicitMerklePaths`.
- `Inference`: this is the first compression/refactor that should land before a
  larger protocol redesign.

What to change:

- teach `prepareSigShortnessOpeningForVerify` to reconstruct compressed
  `P` values exactly as the main row-opening verifier does
- apply `maybeCompressRowOpeningPvals` inside `buildSigShortnessProofBase`
- make sparse frontier/path round-tripping stable so `restoreExplicitMerklePaths`
  can go away

Likely files:

- `PIOP/sig_shortness_replay.go`
- `PIOP/run.go`
- `PIOP/VerifyNIZK.go`
- `PIOP/canonical_transcript.go`
- `PIOP/proof_report.go`

Expected effect:

- `Inference`: low single-digit kilobyte savings
- `Inference`: mostly from `SigShortness` and `Auth`

This change alone is not enough for `<30 KB`, but it is the cleanest missing
encoding win.

### 2. Apply the paper's lattice-witness compression to shortness rows

This is the most relevant paper technique that is still absent from the live
shortness object.

The paper introduces a compression technique for small-alphabet lattice witness
values:

- pack `p` values into one compressed field element
- enforce compressed membership with one higher-degree polynomial
- enforce decompression with univariate polynomials of degree at most
  `alpha^p - 1`

That is directly relevant here because the shortness witness is exactly a
small-alphabet digit witness.

- `Inference`: instead of authenticating one raw shortness digit/head surface
  entry per row, the repository could authenticate compressed shortness cells
  and reconstruct the visible digits or heads from them.
- `Inference`: this is the paper-backed way to keep shrinking the `SigShortness`
  surface after the radix/digit presets have bottomed out.

Concrete adaptation targets:

- packed signature digit rows
- shortness support values opened by `SigShortness` V4
- possibly the `THat` support reconstruction path if the compressed witness is
  defined to decode directly into the expected support heads

Likely files:

- `PIOP/signature_shortness_packed.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/sig_shortness_replay.go`
- `PIOP/row_layout_coeff_native.go`
- `PIOP/signature_shortness_modes.go`

Expected effect:

- `Inference`: this is the highest-confidence structural route to save the next
  several kilobytes from `SigShortness`
- `Inference`: it can also reduce `Pdecs`, `VTargets`, and `BarSets` if the new
  packed shortness witness removes enough committed rows to cross block
  thresholds

Main proof obligation:

- new compressed membership/decompression soundness for the shortness witness

### 3. Replace the current same-root `SigShortness` opening with a smaller shortness object

Today `SigShortness` V4 is still a same-root subset opening over all shortness
support slots.

- `Code-backed`: `buildSigShortnessSupportSlotsForVersion` still determines a
  support-slot set spanning the shortness rows, and the proof carries a DECS
  opening for that support.
- `Measured`: even after all live preset retunes, this object is still
  `17.2 KB` on `compact_l1_research`.
- `Inference`: if the target is below `30 KB`, this object probably has to
  change structurally, not just encode the same thing slightly better.

Credible redesign direction:

- authenticate a compressed shortness witness surface rather than the current
  raw support-slot surface
- keep verifier-side reconstruction of `digits -> sigHat -> THat`
- avoid opening all current support slots on the same DECS subset object

This is still a SmallWood-consistent change. It is not "replace the whole proof
system"; it is replacing the heaviest current authenticated subobject.

Likely files:

- `PIOP/sig_shortness_replay.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/row_layout_coeff_native.go`
- `PIOP/proof_report.go`
- `PIOP/canonical_transcript.go`

Expected effect:

- `Inference`: this is the most credible route for a `4-8 KB` class reduction
  from the current `39.3 KB` floor

### 4. Reduce `dQ` by redesigning the carrier encoding

This is a real lever, but it is not the first one.

- `Code-backed`: `dQ=312` comes from the carrier system and its effective
  degree-`9` membership path.
- `Measured`: the `Q` bucket is flat at `4,637 B` across the live compact
  presets.
- `Inference`: if the shortness object is reduced first, `Q` becomes the next
  fixed bucket worth attacking.

Likely direction:

- lower the carrier alphabet degree
- split carrier constraints so the main membership polynomial is lower degree
- avoid paying the current degree-`9` expansion inside the PACS `Q` system

Likely files:

- `PIOP/carrier_codec.go`
- `PIOP/showing_transform_bridge_constraints.go`
- `PIOP/constraint_eval.go`

Expected effect:

- `Inference`: roughly `1-3 KB`

This is useful, but not sufficient by itself.

### 5. Only then revisit PRF/source-product replay cleanup

Older notes over-focused on PRF replay cleanup as the next blocker. That is no
longer the right priority for proof size.

- `Measured`: on the current live compact presets, the dominant remaining
  buckets are `SigShortness`, `Pdecs`, `Q`, `R`, and `Auth`.
- `Inference`: PRF/source-product replay cleanup is still good engineering, but
  it is not the first-order route below `30 KB`.

That said, after a smaller shortness object lands, replay cleanup could matter
again if it changes the committed witness enough to cross another PCS block
threshold.

### 6. If local refactors stall, the paper's extension-field variant is the major redesign path

The paper's small-field variant is the most serious protocol-level redesign
still on the table.

- `Code-backed`: the paper describes a version where witness and masking
  polynomials live over an extension field `K`, enabling `rho=1` and `ell'=1`
  while still committing through a small-field LVCS.
- `Inference`: this is the cleanest paper-grounded route if the repository
  cannot get below `30 KB` with shortness-object and `Q` refactors alone.

Why it matters:

- the current repository is still paying `rho=2`, `ell'=2`, and a fairly large
  small-field masking geometry
- the paper's extension-field route changes that geometry at the protocol level

Likely files:

- `PIOP/masking_fs.go`
- `PIOP/masking_fs_helper.go`
- `PIOP/params_helpers.go`
- `PIOP/constraint_eval.go`
- `PIOP/VerifyNIZK.go`
- `PIOP/canonical_transcript.go`

This is not a preset retune. It is a new PCS/PIOP geometry.

## Recommended Order Of Work

If the goal is specifically `<30 KB`, the recommended sequence is:

1. Land the live preset retunes already verified in this checkout:
   - `compact_l3 -> lvcs=68, eta=36, nLeaves=4096`
   - `compact_l2 -> lvcs=70, eta=36, nLeaves=4096`
2. Add shortness `P` compression and frontier/path packing.
3. Prototype lattice-witness compression for shortness rows.
4. If that is not enough, replace the current V4 shortness opening with a
   smaller shortness-specific authenticated object.
5. Then reduce `dQ`.
6. Only if those still stall above target, evaluate the extension-field
   SmallWood variant from the paper.

## What This Means In Practice

- `Measured`: the repository can now reach about `39.3 KB` on the live path
  with `compact_l1_research`.
- `Inference`: getting below `30 KB` is realistic, but not with more preset
  sweeps alone.
- `Inference`: the next pass should be a shortness-object pass, not another
  global `NCols` retune.

That is the current engineering answer from this checkout.
