# Full Baseline Proof Study

This note tracks the theorem-facing full-replay control for the current
shared-randomness ARC-SPRUCE branch.

It is a study note, not the shipped operator runbook. The live engineering
baseline is the optimized V18 `bb_tran` showing family documented in
[protocol.md](protocol.md), [current_showing_defaults.md](current_showing_defaults.md),
and [transcript_reduction_analysis.md](transcript_reduction_analysis.md).

## Scope

This study is about one question only:

- what the theorem-clean showing statement should look like for the current
  semantic credential witness
- how that full-replay statement differs from the shipped reduced-replay
  engineering surface
- what still blocks the full-replay control on the canonical vector-`x0`
  artifacts

This note is not about the deprecated target-from-commitment path.

## Current semantic statement

The full baseline studies the same credential semantics as the shipped branch.
The hidden witness is:

- `u`
- `m`
- `k`
- `r0`
- `r1`
- `Z`

with public data:

- issuer / verifier matrices `A` and `B`
- nonce
- public tag

and the same live relation:

```text
(B3 - r1) ⊙ Z = 1
A u = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z
tag = F(k, nonce)
```

Important points:

- `r0` is the vector `x0` side, not a scalar legacy witness slot
- `B2` is interpreted as `[B2[0], ..., B2[X0Len-1]]`
- the full baseline does not reintroduce `Uc`, source-product rows, or
  commitment-derived targets

## Why this study still matters

The full baseline is still useful even though it is not the shipped path.

It gives a control surface for:

- theorem-clean replay coverage
- future V7-style shortness work
- measuring how much transcript is attributable to reduced-replay engineering
  choices instead of the core relation

The current repo should therefore be read as having two different layers:

- maintained showing profiles:
  the three x0_len=70 optimized V18 profiles selected by `-showing-profile`
- study notes:
  historical replay comparisons that are not maintained CLI surfaces

## Current status

### Shipped status

The optimized V18 profile family is the path that is both:

- green on the canonical x0_len=70 artifacts
- kept current as an engineering target

### Full-replay control status

The direct `bb_tran` theorem-clean full replay control is maintained on the
checked-in vector-`x0` artifacts.

The maintained command surface is:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

That means:

- the full baseline is semantically meaningful for the direct paper relation
- it is a green acceptance target for maintained full-replay measurements
- transcript or soundness numbers from older source-product experiments remain
  historical

## What changed after the protocol migration

The full baseline used to be easy to confuse with older aligned/source-product
surfaces. That is no longer correct.

The current full-baseline study assumes:

- Ajtai commitment to `(m, k, r0H[0], ..., r0H[X0Len-1], r1H, rbar)` at issuance
- shared issuer randomness `r0I[]`, `r1I`
- centered hidden randomness
  `r0 = center(r0H + r0I)` componentwise and `r1 = center(r1H + r1I)`
- direct `bb_tran` target formation
- stored credential witness `(u, m, k, r0, r1, Z)`

The full baseline does not assume:

- `T = B0 + Uc + Z`
- source-product witness rows as active proving inputs
- scalar `x0`
- aligned commitment randomness `(S, E)`

## Full replay versus reduced replay

### Shared semantics

Both branches use:

- the same `version = 2` credential state
- the same vector-`x0` public parameters
- the same `bb_tran` target relation
- the same PRF key `k` embedded in the signed message

### Different proof geometry

Historical reduced replay:

- excludes transform aliases and replay-image rows from the active selector
- keeps only carrier and PRF-companion replay families live
- is not the maintained public showing surface

Optimized V18 replay:

- is intended to authenticate a theorem-cleaner replay image
- uses inlined target-hiding shortness in the maintained profile family
- is current on canonical x0_len=70 artifacts

The difference is therefore proof geometry, not credential semantics.

## Where to read the current code

If you need to reason about the full-baseline study from code, start here:

- [../cmd/showing/main.go](../cmd/showing/main.go)
- [../PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [../PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go)
- [../PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go)
- [../PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go)
- [../PIOP/replay_family_audit.go](../PIOP/replay_family_audit.go)

Use [current_showing_defaults.md](current_showing_defaults.md) and
[transcript_reduction_analysis.md](transcript_reduction_analysis.md) for measured
profile defaults and the current optimization roadmap.

## How to refresh this study

When this study is being refreshed, use this order:

1. Regenerate current canonical artifacts.
2. Verify the maintained optimized V18 profiles still work.
3. Record the current transcript reports.
4. Record only measurements produced on fresh vector-`x0` artifacts.

Commands:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
go test ./PIOP ./cmd/showing
```

## Reading rule

When this note discusses "full baseline", read it as:

- a current semantic study of the theorem-clean replay surface for the live
  `bb_tran` protocol
- not a claim that historical replay-control CLI flags are maintained
- not an archival description of the deprecated aligned/source-product design
