# Transcript Reduction Analysis for ARC-SPRUCE / SmallWood

This note analyzes the current ARC-SPRUCE transcript surface after the
shared-randomness `bb_tran` migration and the vector-`x0` update.

Update status as of `2026-04-23`:

- the first-pass singleton `x0` carrier refactor has landed
- `RU0[]`, `R0[]`, and `K0[]` now use a true singleton low-alphabet codec
- `benchmark-x0` JSON export is now version `2` and includes per-run paper
  bucket and transcript-focus geometry data
- the `bb_tran` witness support and explicit-domain prefix are now stable
  across `NLeaves`, so `NLeaves` sweeps no longer silently change the witness
  embedding
- the large pre-fix square-alphabet transcript blow-up is no longer the live
  baseline

The target is the current implementation, not the paper idealization:

- live protocol: shared-randomness `bb_tran`
- live baseline: `lhl_default`, reduced replay, `soundness_balanced`,
  `PRFCompanionMode=output_audit`, hidden shortness `v6`
- primary objective: paper transcript size
- secondary objectives: prover time, verifier time, engineering risk

This note uses the repository's own accounting as ground truth:

- `PIOP.BuildProofReport`
- `PIOP.BuildPaperTranscriptReport`
- `PIOP.TranscriptOptimizationReport`
- `PIOP.BuildReplayFamilyAuditReport`
- `go run ./cmd/showing`
- `go run ./cmd/issuance benchmark-x0`

External context comes from the SmallWood paper and follow-on material:

- local copy: `docs/2025-1085.pdf`
- ePrint abstract: <https://eprint.iacr.org/2025/1085>
- CAPSS note: <https://eprint.iacr.org/2025/061>

## 1. Current design map

### 1.1 Shipped baseline

This is the only configuration that is both live and currently maintained as an
engineering target:

- hash relation: `bb_tran`
- `x0` profile: `lhl_default` (`X0Len=6`, `X0CoeffBound=5`)
- showing preset: `soundness_balanced`
- replay mode: `reduced`
- PRF companion mode: `output_audit`
- signature shortness mode: `sig_shortness_v6_hidden`

What it proves:

- signature equation
- `bb_tran` inverse and target relation
- PRF tag correctness
- reduced replay authenticity for the committed witness surface

Why it exists:

- this is the current best working balance between transcript size, runtime, and
  implementation stability on the vector-`x0` credential path

Status:

- shipped
- measured
- green in the current repo

### 1.2 Reduced-replay preset family

These are all reduced-replay, one-root showing statements on the live witness
surface:

- `soundness_balanced`
- `compact_l3`
- `compact_l2`
- `compact_l1_research`

What changes between them:

- `LVCSNCols`
- `NLeaves`
- `eta`
- `ell'`
- `kappa`
- hidden shortness radix/digit profile

What does *not* materially change on the live reduced path:

- the fact that only carrier and PRF-companion families remain in the active
  replay selector

What changed after the singleton-`x0` pass:

- `Q` is no longer the dominant shipped bucket
- the remaining transcript floor is now mostly `R` plus hidden shortness
- `Q` and `Pdecs` remain the main variable buckets when the `x0` profile
  changes

Status:

- runnable on the current canonical `lhl_default` artifacts
- measured below

### 1.3 Full-replay theorem control

Historical intended control:

- `go run ./cmd/showing -showing-preset compact_l1_research -full`

Historical intended meaning:

- theorem-clean full replay-image statement
- V7 inlined target-hiding shortness path
- no dedicated shortness opening on the intended full-V7 branch

Current repo status:

- V7 and the compact-full candidate harness are no longer live
- `go run ./cmd/showing -full` is the maintained V6 full control
- `aggregate_v11_direct_target_research` is the forward private optimization target

Historical code facts before cleanup:

- `go run ./cmd/showing -full -showing-preset compact_l1_research` now
  verifies again on the canonical `lhl_default` artifacts
- the removed compact-full benchmark subcommand ran an internal benchmark-only
  candidate family that kept the public preset label fixed at
  `compact_l1_research`
- first-wave candidates keep:
  - `HashRelation = bb_tran`
  - `ShowingReplayMode = full`
  - `PRFCompanionMode = output_audit`
  - `NCols = 16`
  - `Ell = 18`
  - `Theta = 3`
  - `Rho = 2`
  - `Kappa = {0,0,0,0}`
  - `NLeaves = 4096`

Interpretation:

- full replay is now a usable theorem-clean control again
- the blocker is no longer correctness
- the blocker is that first-wave compact-full geometry changes lose too much
  theorem soundness before they beat the current compact-full baseline

### 1.4 PRF companion family

The current code exposes three PRF companion modes:

- `output_audit`
- `direct_auth`
- `aux_instance`

Status:

- `output_audit` is live
- `direct_auth` is explicitly marked research-only by the CLI and still keeps
  the PRF bridge inside the main `Q` path
- `aux_instance` is research-only and moves the PRF bridge into a separate
  auxiliary proof

The unified sweep harness now exposes two dedicated PRF-side control tracks:

- `prf_controls_reduced`
- `prf_controls_full96`

Those tracks sweep:

- `PRFCompanionMode ∈ {output_audit, direct_auth, aux_instance}`
- `PRFCheckpointSamples ∈ {4, 8, 12}` for `output_audit` / `direct_auth`
- `PRFGroupRounds = 2`

They are intentionally non-promotable control tracks. Their job is to tell us
whether PRF-side geometry is worth further optimization work before we spend
time on deeper non-signature PACS compression.

`PRFGroupRounds` is reported in the benchmark output, but it is not currently a
safe sweep axis on the canonical packed showing path. The first attempt to run
`PRFGroupRounds = 1` failed during witness construction, so the current sweep
keeps the proven grouped setting fixed at `2`.

### 1.5 Signature-shortness family

The current codebase still carries multiple shortness surfaces, but only two
matter for this note:

- shipped path: V6 hidden shortness
- research theorem-control path: V7 inlined target hiding

Status:

- V6 is live and measured
- V7 is now live on the compact-full theorem-clean branch
- however, V7 remains a control/measurement surface rather than the default
  reduced path because the first compact-full candidate sweep did not find a
  smaller `>=118`-bit winner

### 1.6 `x0` profile family

The current implementation exposes three `x0` profiles:

- `legacy_scalar`
- `lhl_default`
- `lhl_alt`

Status:

- all three are supported by setup and issuance/showing benchmarks
- only `lhl_default` is the live shipped profile
- `legacy_scalar` is a compatibility and benchmark control only because it
  fails the LHL hiding target

## 2. Measured bottlenecks

### 2.1 Shipped baseline: current bucket order

Measured with:

```bash
go run ./cmd/showing
```

Current shipped baseline (`lhl_default`, reduced replay, `soundness_balanced`,
`output_audit`):

- proof bytes: `66916`
- paper transcript bytes: `31622`
- prover time: about `957ms`
- verifier time: about `97ms`
- selected replay rows: `20/40`
- active replay blocks: `3/3`
- committed rows: `19`
- geometry: `pcs_ncols=84`, `nleaves=4096`, `dQ=378`, `theta=3`, `rho=2`

Bucket ranking:

| bucket | bytes | share |
| --- | ---: | ---: |
| `SigShortness` | 9397 | 29.7% |
| `R` | 8404 | 26.6% |
| `Q` | 5628 | 17.8% |
| `Pdecs` | 4073 | 12.9% |
| `Auth` | 2291 | 7.2% |
| `VTargets` | 1270 | 4.0% |
| `BarSets` | 294 | 0.9% |

This confirms the ranking that should drive optimization work:

1. `SigShortness` and `R` as the fixed floor
2. `Q` as the main variable bucket
3. `Pdecs`
4. `Auth`, `VTargets`, `BarSets`

The direct `go run ./cmd/showing` output and the `benchmark-x0` matrix are both
useful, but they are not byte-for-byte identical accounting surfaces. The
benchmark harness measures issuance plus showing in a temp workspace and may
report slightly different totals from the standalone showing command. Use one
surface consistently inside a single comparison table.

The new unified sweep harness is:

```bash
go run ./cmd/showing benchmark-transcript-sweep -runs 1 -json-out <tmp>.json
```

The latest integrated sweep did two different things:

- it **reconfirmed** the shipped reduced `soundness_balanced` tuple instead of
  promoting a new reduced winner
- it **did** promote the full V6 control tuple to the best eligible
  near-`100`-bit point

Reduced track:

- current shipped tuple remains:
  - `lvcs_ncols = 84`
  - `nleaves = 4096`
  - `eta = 40`
  - `ell' = 2`
  - `theta = 3`
  - `rho = 2`
  - `kappa = {0,0,0,5}`
  - `sig = r11_l4_production`
- current sweep winner:
  - `a1_w84_n4096_e40_ep2_sig_r11_l4_production_th3_r2_k0-0-0-5`
  - paper transcript: `31580` bytes
  - theorem total: `102.15` bits

Full V6 control track:

- promoted winner:
  - `b2_w96_n4096_e43_ep2_sig_r24_l3_compact_th3_r2_k0-0-0-5`
  - sweep transcript: `56849` bytes
  - theorem total: `100.03` bits
- current shipped `go run ./cmd/showing -full` now uses:
  - `lvcs_ncols = 96`
  - `nleaves = 4096`
  - `eta = 43`
  - `ell' = 2`
  - `theta = 3`
  - `rho = 2`
  - `kappa = {0,0,0,5}`
  - `sig = r24_l3_compact`

Compact-full V7 remains benchmark/control-only. The compact-full branch is now
correctness-ready and measurable, but it still has no promotable winner.

### 2.2 Root causes, not just symptoms

#### The singleton `x0` pass removed the worst artificial degree inflation

Before this pass, each `x0` carrier paid the pair alphabet
`(2*bound+1)^2` even though the second coordinate was always zero. The live
code now uses the true singleton alphabet `2*bound+1` for `RU0[]`, `R0[]`, and
`K0[]`.

That changed the shipped baseline from roughly:

- showing proof `504 KB` -> `71 KB`
- showing transcript `111 KB` -> `32 KB`
- `dQ = 4008` -> `378`

So the old "Q dominates because x0 carriers are square-alphabet" diagnosis is
historical, not current.

#### `Q` is still the main variable bucket because degree geometry still matters

The current paper transcript accounting still uses:

- `Q ~ rho * dQ * theta * log2(q)`

On the shipped baseline:

- `dQ = 378`
- `rho = 2`
- `theta = 3`

That is why `Q` is still a first-order optimization target even though it is no
longer the dominant shipped bucket.

#### `R` and hidden shortness are now the main fixed floor

On the shipped baseline:

- `R = 9572` bytes
- `SigShortness = 9433` bytes

These buckets did not collapse with the singleton `x0` refactor because they
are driven by the reduced-replay opening geometry and the hidden shortness
subsystem, not by the `x0` carrier alphabet.

#### `Pdecs` is still the main opening-geometry bottleneck

On the shipped baseline:

- `nrows = 49`
- `m = 6`
- `pcols = 43`
- `omitP = 6`

`Pdecs` is no longer catastrophic, but it is still the main non-shortness
opening bucket.

#### Replay trimming already removed the easy families

The current replay-family audit says the active selector only includes:

- `carrier`
- `prf_companion`

It does **not** currently pay active selector cost for:

- `t_source`
- `source_product`
- `transform_alias`
- `replay_image`

So replay trimming is still worth doing, but the easy reductions are already
gone. The remaining replay cost is concentrated in:

- 8 carrier rows
- 12 PRF-companion rows

That matters for `Pdecs` and `Auth`, but it does not explain the remaining
`R/SigShortness/Q` floor.

### 2.3 Reduced preset family: historical pre-singleton comparison

These measurements were taken before the singleton-`x0` codec landed. Keep
them only as historical context for how badly the old pair-coded x0 surface
behaved. Re-run them before using them for current engineering decisions.

| variant | proof bytes | transcript bytes | `Q` | `Pdecs` | `R` | `Sig` | `Auth` | `VTargets` | `BarSets` | `pcs_ncols` | `dQ` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `soundness_balanced` | 504248 | 111367 | 60101 | 27321 | 9572 | 10020 | 2477 | 1345 | 294 | 89 | 4008 |
| `compact_l3` | 436723 | 115214 | 60101 | 34692 | 6123 | 10219 | 2443 | 1081 | 294 | 68 | 4008 |
| `compact_l2` | 436373 | 114859 | 60101 | 34125 | 6303 | 10287 | 2375 | 1113 | 294 | 70 | 4008 |
| `compact_l1_research` | 371013 | 151932 | 60086 | 73354 | 2081 | 11401 | 2375 | 1522 | 861 | 32 | 4008 |

Interpretation:

- `soundness_balanced` is still the best current transcript preset on the live
  reduced-replay vector-`x0` path.
- `compact_l3` and `compact_l2` reduce verifier payload but **increase** paper
  transcript because `Q` stays fixed while `Pdecs` rises by about `7 KB`.
- `compact_l1_research` is even worse for transcript size because `Pdecs`
  explodes to `73 KB`.

The current reduced-preset lesson is simple:

- shrinking `LVCSNCols` is not the same thing as shrinking the paper transcript
- on this witness surface, `LVCSNCols` reduction mostly trades verifier payload
  against worse `Pdecs`

### 2.4 PRF companion family: historical pre-singleton comparison

These measurements were also taken on the pre-singleton baseline and are kept
mainly to show that PRF-mode churn was not the main issue even before the x0
codec fix.

| PRF mode | proof bytes | transcript bytes | `Q` | `Pdecs` | `R` | `Sig` | `Auth` | `VTargets` | `BarSets` | selected rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `output_audit` | 504248 | 111367 | 60101 | 27321 | 9572 | 10020 | 2477 | 1345 | 294 | `20/40` |
| `direct_auth` | 504187 | 111334 | 60101 | 27321 | 9572 | 10089 | 2358 | 1345 | 280 | `20/40` |
| `aux_instance` | 536676 | 131662 | 60213 | 35951 | 11353 | 10235 | 5118 | 5828 | 1244 | `9/271` |

Interpretation:

- `direct_auth` is not a credible transcript-reduction path in the current
  implementation. It is almost identical to `output_audit`.
- `aux_instance` proves that it is possible to move PRF rows out of the main
  replay selector, but the total transcript gets much worse:
  - witness rows jump from `40` to `271`
  - `Pdecs`, `R`, `Auth`, `VTargets`, and `BarSets` all worsen

### 2.5 Compact-full V7 candidate sweep

Current compact-full V7 baseline:

- command:
  `go run ./cmd/showing -full -showing-preset compact_l1_research`
- measured result on the canonical `lhl_default` artifacts:
  - transcript: about `96,410` bytes
  - proof: about `122,286` bytes
  - soundness: about `119.05` theorem bits
  - buckets:
    - `Q = 5,613`
    - `Pdecs = 42,376`
    - `VTargets = 27,982`
    - `BarSets = 15,745`
    - `R = 2,081`
    - `SigShortness = 3`

Control measurements from the same benchmark harness:

- `soundness_balanced + full`
  - transcript: about `57,260` bytes
  - proof: about `110,615` bytes
  - soundness: about `100.03` theorem bits
- `compact_l1_research + reduced`
  - transcript: about `30,819` bytes
  - proof: about `56,539` bytes
  - soundness: about `128.11` theorem bits

First-wave compact-full V7 candidates were:

- `current`
- `w40`
- `w48`
- `w64`
- `w48_e24`
- `w48_e20`
- `w48_ep2`
- `w48_e24_ep2`
- `w48_e24_ep2_l3`
- `w48_e24_ep2_l2`

Sweep result:

- only `current` cleared the `>=118`-bit theorem floor
- every more aggressive first-wave candidate stayed on V7 but failed the
  soundness floor:
  - `w40`: about `79.05` bits
  - `w48`: about `31.13` bits
  - `w64`: effectively `0` bits
  - `w48_e24`: effectively `0` bits
  - `w48_e20`: effectively `0` bits
  - `w48_ep2`: about `31.13` bits
  - `w48_e24_ep2`: effectively `0` bits
  - `w48_e24_ep2_l3`: effectively `0` bits
  - `w48_e24_ep2_l2`: effectively `0` bits

Interpretation:

- the first compact-full V7 sweep is not transcript-limited
- it is soundness-limited
- under the current `bb_tran` explicit-domain derivation, widening LVCS or
  lowering `eta` / `ell'` without changing the rest of the theorem-control
  tuple collapses the theorem floor before it buys a promotable transcript win
- the compact-full preset therefore stays on the current baseline geometry for
  now
- the PRF bridge is therefore not the current first-order transcript bottleneck

Checkpoint-sample sensitivity also confirms this:

- `prf-checkpoint-samples=4` -> transcript `111385`
- default `8` -> transcript `111398`
- `12` -> transcript `111497`

This is a sub-`0.2 KB` effect. It is not where the big wins are.

### 2.5 Full replay near the `100`-bit frontier after `NLeaves` decoupling

The first post-decoupling question was whether full replay can improve further
once we accept about `100` theorem bits.

The integrated full-V6 sweep promoted the old `lvcs=96` control point into the
actual shipped `-full` default, and it also selected a smaller shortness
profile on that same geometry:

- promoted full default:
  - `soundness_balanced + full`
  - `lvcs_ncols = 96`
  - `nleaves = 4096`
  - `eta = 43`
  - `ell' = 2`
  - `theta = 3`
  - `rho = 2`
  - `kappa = {0,0,0,5}`
  - `sig = r24_l3_compact`
- sweep winner:
  - transcript: `56849` bytes
  - theorem total: `100.03` bits

Direct post-promotion control measurements are consistent with that sweep
result:

- `go run ./cmd/showing -full`
  - transcript: about `57,073` bytes after the direct-full alignment cleanup
  - theorem total: `100.03` bits
- `go run ./cmd/showing -full -aggregate-r0-replay`
  - transcript: about `50,547` bytes on the same parameter tuple
  - theorem total: `100.03` bits
  - row surface: `RHat0=0`, `R0B2Hat=64`, `ZHat=64`, `THat=64`
- old retired full default (`lvcs=89`, `sig=r11_l4_production`)
  - sweep transcript: about `59,468` bytes
  - theorem total: about `101.42` bits

So the new shipped full default is about `2.3 KB` smaller than the retired
full tuple while staying on the intended near-`100`-bit line. The aggregate
`R0` replay control removes about `320` committed replay rows and another
`6.5 KB` from the paper transcript, but it is intentionally opt-in because the
V6 hidden-shortness opening grows on this geometry and still needs a dedicated
retune.

Once `NLeaves` was actually decoupled from witness `Ω`, the first honest sweep
was:

- `nleaves = 2048`
  - transcript: `56,722` bytes
  - theorem total: `82.19` bits
- `nleaves = 4096`
  - transcript: `57,104` bytes
  - theorem total: `100.03` bits
- `nleaves = 8192`
  - transcript: `57,560` bytes
  - theorem total: `0.00` bits
  - `eps1` goes negative and is clamped to `0`
- `nleaves = 16384`
  - transcript: `57,880` bytes
  - theorem total: `0.00` bits
  - `eps1` again goes negative and is clamped to `0`

Interpretation:

- decoupling `NLeaves` was still the right structural fix
- but on the current full/V6 theorem-control tuple, `NLeaves` is **not** the
  next easy transcript win
- smaller `NLeaves` helps bytes but loses too much theorem soundness
- larger `NLeaves` barely changes bytes and currently destroys the first
  theorem term

The main gain from the decoupling patch is therefore not a new preset. It is
that the repo can now sweep `NLeaves` without changing the low-alphabet
embedding, which makes future geometry measurements trustworthy.

### 2.6 `x0` profiles: measured comparison after the singleton pass

Measured with:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1
```

| profile | `x0` | LHL slack | issuance proof | issuance transcript | showing proof | showing transcript | committed rows | logical replay rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `legacy_scalar` | `(1, 1)` | `-19121.63` bits | 49121 | 15995 | 62803 | 31526 | 19 | 19 |
| `lhl_default` | `(6, 5)` | `+510.12` bits | 62405 | 19576 | 70482 | 32931 | 19 | 29 |
| `lhl_alt` | `(5, 8)` | `+183.18` bits | 70328 | 19937 | 94245 | 37212 | 19 | 27 |

Current post-promotion showing-side controls on the shipped reduced tuple and
the shipped full default tell the same story:

- reduced:
  - `legacy_scalar`: `30155` bytes
  - `lhl_default`: `31642` bytes
  - `lhl_alt`: `35957` bytes
- full default (`lvcs=96`, `sig=r24_l3_compact`):
  - `legacy_scalar`: `49695` bytes
  - `lhl_default`: `57256` bytes
  - `lhl_alt`: `62453` bytes and only about `99.80` theorem bits

Interpretation:

- `legacy_scalar` is still the transcript floor control, but remains
  cryptographically ineligible because it fails the LHL target
- `lhl_default` remains the smallest eligible live `x0` profile on both the
  reduced and full default surfaces
- `lhl_alt` is still not a promotion candidate because it loses on bytes and
  misses the `100`-bit full-floor by a small margin

Key observation:

- `lhl_alt` has **fewer** logical replay rows than `lhl_default` (`27` vs
  `29`) but is now only about **1.12x** larger in showing transcript
- the singleton pass removed the old blow-up almost entirely:
  - `lhl_default` showing transcript: `111328 -> 32931`
  - `lhl_alt` showing transcript: `230875 -> 37212`

The remaining problem is no longer a wasted square alphabet. It is the real
tradeoff between:

- fewer `x0` rows
- larger singleton alphabet
- larger `dQ`
- larger `Pdecs`

### 2.7 Why `lhl_alt` is still worse despite fewer `x0` rows

This is now a healthier diagnosis than the pre-fix one.

The live code now uses a real singleton alphabet on the `x0` side.

Concrete consequence:

- `lhl_default` (`beta=5`) pays singleton alphabet size `11`
- `lhl_alt` (`beta=8`) pays singleton alphabet size `17`

That is only a `1.55x` alphabet increase now, not the old `2.39x` square-code
increase. The measured impact matches that:

- `lhl_default`: `dQ = 378`, `pcols = 43`, showing transcript `32931`
- `lhl_alt`: `dQ = 576`, `pcols = 55`, showing transcript `37212`

So the remaining `lhl_alt` penalty is now the expected one:

- row count went down a little
- but the true singleton alphabet is still larger
- and that larger alphabet still pushes both `Q` and `Pdecs` upward

The important outcome is that the code is no longer wasting degree on an unused
second carrier slot.

## 3. Upsides and downsides of each current design

### 3.1 Reduced replay vs full replay

#### Reduced replay

Upsides:

- works on the current vector-`x0` shipped path
- selector already excludes `t_source`, `source_product`, transform aliases,
  and replay-image rows
- practical prover and verifier times

Downsides:

- still pays for carrier rows and PRF companion rows in the selector
- keeps the engineering replay surface rather than the theorem-clean one
- `Q` and `Pdecs` are still large

#### Full replay / V7

Upsides:

- theorem-clean control surface
- V7 branch now verifies again on the canonical vector-`x0` artifacts
- benchmark-only candidate family makes compact-full geometry measurable
- intended V7 branch removes the dedicated shortness opening

Downsides:

- runtime-heavy
- current first-wave geometry candidates fail the theorem floor badly
- current compact-full baseline is still much larger than the full
  `soundness_balanced` control

Recommendation:

- keep it as a research/control branch
- use it for measured theorem-clean experiments only
- do not promote compact-full defaults again until either:
  - the theorem tuple is retuned jointly with geometry, or
  - the post-decoupling `NLeaves` sweep is folded into the compact-full search

### 3.2 `output_audit` vs `direct_auth` vs `aux_instance`

#### `output_audit`

Upsides:

- smallest currently live PRF companion mode
- stable
- already integrated into the shipped baseline

Downsides:

- PRF bridge still contributes replay/authentication overhead

#### `direct_auth`

Upsides:

- conceptually cleaner research direction

Downsides:

- essentially no measured transcript win today
- current implementation still keeps the PRF bridge inside the main `Q` path

Recommendation:

- do not spend optimization time here yet

#### `aux_instance`

Upsides:

- useful experiment for moving PRF work into a separate proof
- sharply reduces selected replay rows in the main selector

Downsides:

- total transcript gets worse
- proof bytes get worse
- witness geometry gets much worse
- this is geometry churn, not size reduction

Recommendation:

- keep as research instrumentation only
- current control sweeps confirm that:
  - reduced replay still prefers `output_audit` at `g2,s8`
  - the promoted full default also keeps `output_audit`; on the current
    `lvcs=96 / r24_l3_compact` surface, `output_audit g2,s4` came out smallest
    at about `56,926` bytes, with `direct_auth` slightly behind

### 3.3 V6 shortness vs V7 shortness

#### V6

Upsides:

- live
- stable
- dedicated hidden-shortness payload is only about `9%` of the shipped baseline

Downsides:

- still costs about `10 KB`
- is not the first-order bottleneck

#### V7

Upsides:

- intended to inline target hiding into the full-replay statement
- removes the dedicated shortness opening on the repaired compact-full path
- now has a real benchmark surface

Downsides:

- current first-wave compact-full sweep has no promotable winner
- the main compact-full cost is still non-shortness:
  - `Pdecs`
  - `VTargets`
  - `BarSets`
- the present V7 branch is correctness-ready, but still not transcript-ready

Recommendation:

- treat V7 as a theorem-clean tuning branch, not the live engineering default
- next V7 work should retune theorem-control geometry, not just squeeze width

### 3.4 `x0` profiles

#### `legacy_scalar`

Upsides:

- very small transcript
- useful compatibility and benchmark floor

Downsides:

- fails the LHL hiding target by a huge margin
- not cryptographically acceptable for the live protocol

#### `lhl_default`

Upsides:

- satisfies the LHL target with comfortable slack
- smallest working transcript among the LHL-satisfying shipped profiles

Downsides:

- still pays the fixed reduced-replay and hidden-shortness floor
- still carries a larger transcript than the non-hiding `legacy_scalar` control

#### `lhl_alt`

Upsides:

- satisfies the LHL target
- slightly fewer logical replay rows

Downsides:

- far worse transcript and proof size
- less LHL slack than `lhl_default`
- current carrier encoding makes the larger bound much more expensive than the
  shorter vector helps

Recommendation:

- keep `lhl_default` as the shipped profile
- do not switch to `lhl_alt` under the current carrier architecture

## 4. What SmallWood 2025/1085 implies for ARC-SPRUCE

The SmallWood paper is useful here for one very specific reason: it treats
proof size as a consequence of **extended witness design**, not only of PCS
parameters.

The points from `2025/1085` that matter most for ARC-SPRUCE are:

- SmallWood is optimized for "relatively small instances", which is exactly the
  regime ARC-SPRUCE lives in after the vector-`x0` migration.
- SmallWood's advantage comes from combining a DECS-based PCS with a better
  arithmetization layer (`PACS`) and Brakedown-style ideas for full-domain
  openings.
- In the lattice section, the paper explicitly introduces a compression method
  for low-infinity-norm witnesses: pack several small-alphabet values into one
  field element, enforce membership in a carefully chosen set `S`, then recover
  the unpacked values with low-degree univariate decompression polynomials.

That mapped directly to the first post-migration bottleneck:

- ARC-SPRUCE's current vector `x0` path already pays a high-degree univariate
  membership cost
- but it does so for a **wasted alphabet**, because each `x0` carrier uses the
  pair codec with the second coordinate fixed to zero

SmallWood also makes a second point that matters here: once the alphabet is
small enough, directly using a higher-degree low-alphabet constraint can be
better than decomposing into larger auxiliary witnesses. That is exactly the
current ARC-SPRUCE situation for `x0`:

- `beta=5` means natural singleton alphabet size `11`
- `beta=8` means natural singleton alphabet size `17`

Those are still small enough that direct univariate membership is reasonable.
The first-pass ARC-SPRUCE fix did exactly what SmallWood suggests here:

- first make the `x0` alphabet match the actual witness support
- then re-measure before attempting denser packing

That first step is now complete. The next SmallWood-inspired question is no
longer "stop wasting the second slot"; it is "should the saved degree budget be
spent on lower transcript directly, or on packing more *useful* low-alphabet
values per committed row?"

## 5. Optimization roadmap

### 5.1 Immediate engineering work

#### 1. Keep the singleton `x0` codec and optimize from the new baseline

Target buckets:

- protect the `Q`/`Pdecs` win already achieved
- use the new lower-degree baseline to optimize the remaining floor

Status:

- completed
- landed in the live code
- validated by `benchmark-x0`

Measured effect:

- `lhl_default` showing transcript: `111328 -> 32931`
- `lhl_alt` showing transcript: `230875 -> 37212`
- the live bottleneck order changed from `Q/Pdecs` dominance to a much flatter
  regime with `R`, `SigShortness`, `Q`, and `Pdecs` all relevant

#### 2. Keep `soundness_balanced` as default and retune around it, not around the compact presets

Target buckets:

- `Q`
- `Pdecs`
- maybe `R`

Why:

- the integrated sweep shows the best shipped reduced point is still on the
  `soundness_balanced` branch
- the compact presets are useful controls, but they are not the right default
  engineering branch for the live reduced path

Concrete approach:

- shipped reduced `soundness_balanced` is now:
  - `lvcs_ncols = 84`
  - `nleaves = 4096`
  - `eta = 40`
  - `ell' = 2`
  - `theta = 3`
  - `rho = 2`
  - `kappa = {0,0,0,5}`
  - `sig = r11_l4_production`
- use `benchmark-transcript-sweep` as the authoritative sweep surface for
  future reduced-track tuning
- sweep `LVCSNCols` in a narrow band around the current shipped value (`84`)
- keep `theta=3`, `rho=2` fixed at first
- accept only changes that reduce paper transcript, not merely proof payload
- use `lvcs_ncols = 96, nleaves = 4096` as the current near-`100`-bit full
  comparison point, not as a new shipped preset default

#### 3. Use the new `benchmark-x0` bucket export as the main profiling surface

Target:

- analysis quality

Status:

- completed
- the benchmark now exports per-run paper buckets and transcript-focus geometry
- this should now be the default way to compare `x0` profiles and future
  preset sweeps

#### 4. Do not spend early effort on PRF checkpoint micro-tuning

Why:

- measured effect is negligible
- current transcript is not PRF-checkpoint bound

#### 5. `NLeaves` is now a real geometry knob, but not yet a winning one

Status:

- completed structurally
- `bb_tran` witness support no longer changes when `NLeaves` changes
- `cmd/showing` and `cmd/issuance` now use the same relation-aware witness-Ω
  helper as the proving path

Measured conclusion:

- the honest first scan does **not** promote a new `NLeaves`
- `4096` remains the only viable `lvcs=96` point near `100` theorem bits

What this changes:

- future `NLeaves` sweeps are now meaningful PCS/DECS experiments instead of
  accidental witness-embedding changes
- future tuning can safely ask whether `NLeaves` helps only in combination
  with other theorem-control changes such as `eta`, `ell'`, or grinding

### 5.2 Medium-risk SmallWood-compatible changes

#### 1. Rework the non-signature witness to be PACS-minimal, not engineering-convenient

Target buckets:

- `Pdecs`
- `Q`
- `Auth`

Current suspicion:

- the repo still pays for convenience rows that are good for implementation but
  not minimal for transcript size

Main places to attack:

- carrier rows
- alias rows
- replay hats
- transform-bridge convenience rows

#### 2. Consider true useful low-alphabet packing, not dummy-slot packing

The dummy-slot waste is gone. That makes the next packing question much cleaner:

- safer path: keep singleton codecs and optimize the rest of the witness
- riskier path: actually pack two useful bounded values per carrier and use a
  decompression gadget in the spirit of SmallWood's lattice compression

Recommendation:

- benchmark the singleton baseline first
- only then test whether useful `p=2` packing beats it in transcript, not just
  in row count
- focus first on the non-signature rows that dominate `Pdecs`, `VTargets`, and
  replay-authenticated width:
  - `K0[]`
  - `R0[]`
  - then `R1` / `K1` / `RBar`

#### 3. Rework `B2 * r0` accumulation so fewer rows stay individually authenticated

Target buckets:

- `Pdecs`
- `Auth`
- maybe replay-selector width

The current `x0` surface keeps each `R0[j]` as a first-class replay-authenticated
row. If a sound PACS decomposition can aggregate more of this earlier without
breaking hiding or verification clarity, it is worth exploring.

#### 4. Delay PRF-companion redesign until the non-signature witness shrinks

Measured data already says:

- `direct_auth` does not help
- `aux_instance` moves bytes around and loses badly

So PRF redesign should stay behind non-signature witness compression.

### 5.3 Aggressive research directions

#### 1. Keep the repaired theorem-clean full-replay V7 branch as a control, then retune soundness geometry jointly

Why:

- V7 is promising
- it is now correct again on the canonical vector-`x0` artifacts
- but the first candidate sweep shows that width / `eta` / `ell'` changes alone
  collapse theorem soundness
- the next compact-full pass has to co-tune theorem parameters instead of only
  shrinking transcript geometry

#### 2. Revisit replay/authentication splitting

Only after the live witness is PACS-minimal:

- if a smaller witness still leaves replay/authentication dominant
- then a more radical replay split may make sense

#### 3. Consider decoupling shortness only if it remains material after `Q`/`Pdecs` reductions

Current baseline says:

- shortness is about `29%`

That is now large enough to matter, but it is still safer to finish the
post-singleton preset / geometry sweep before redesigning the shortness layer.

## 6. Decision recommendation

### Optimize first

1. Keep the singleton `x0` codec and treat the new `33-37 KB` regime as the
   real baseline.
2. Re-sweep `soundness_balanced` around its current LVCS / DECS geometry using
   the new `benchmark-x0` bucket export.
3. Treat compact-full V7 as measurement-ready but **not** promotable after the
   first wave; keep the current `current` geometry as the benchmark baseline.
4. Optimize the main remaining variable buckets in order: `Q`, then `Pdecs`.
5. Use the decoupled `NLeaves` path to run honest full sweeps, but do not
   expect `NLeaves` alone to win on the current theorem tuple.
6. After that, revisit hidden shortness and broader PACS witness compression on
   the non-signature side.

### Do not optimize first

- `direct_auth`
- `aux_instance`
- PRF checkpoint sample count
- `compact_l3` / `compact_l2` / `compact_l1_research` as transcript-first
  defaults
- blind compact-full width sweeps that do not co-tune theorem soundness
- blind `NLeaves` sweeps without checking the first theorem term (`eps1`) and
  the total theorem budget

### What should stay research-only for now

- `compact_l1_research -full` on the current vector-`x0` artifacts
- `transcript_first`
- `production_balance`
- PRF auxiliary-instance transcript experiments

## 6.4 Aggregate V6 retune and T-hat opening compression

The aggregate full V6 pass now has an explicit opt-in preset:

```bash
go run ./cmd/showing -showing-preset aggregate_v6_research
```

Current measured tuple:

- replay: full direct `bb_tran`
- aggregate replay: enabled (`RHat0[j]` rows replaced by one block-local
  `B2*r0` replay contribution)
- LVCS/DECS tuple: `lvcs=76`, `eta=38`, `ell'=2`, `theta=3`, `rho=2`,
  `nleaves=4096`, `kappa={2,0,0,5}`
- paper transcript: about `45.4 KB`
- verifier payload: about `74.0 KB`
- theorem bits: about `102.7`
- shortness: about `14.5 KB`, with `13` T-hat support slots and about
  `5.5 KB` T-hat opening bytes

The implementation keeps the paper relation unchanged. The size reduction comes
from three serialization/layout changes:

- aggregate replay removes the six per-component `RHat0[j]` replay rows per
  block from the committed surface;
- the full replay T-hat planner now selects the densest PCS support slots
  instead of a consecutive tail stripe;
- V5/V6 T-hat openings now use the existing compressed P suffix and
  reconstructed M-value encoding for multi-slot full replay openings.

This does not implement the deeper constraint-bound T-hat-head profile. The
remaining dominant blocker is still the V6 hidden shortness proof plus its
main-root T-hat binding surface.

## 6.5 Historical V8/V9/V10 Experiments

These profiles were useful measurements but are no longer live resolver or CLI
surfaces. They remain here only to explain why the implementation focus moved
to V11.

V8 was the first constraint-bound T-hat-head profile.

It keeps the direct `bb_tran` relation and aggregate `B2*r0` replay surface
unchanged. The difference is only the shortness binding surface:

- V6 keeps a root-authenticated DECS opening of committed `THat` rows;
- V8 carries packed `THat` heads inside `SigShortness`;
- the hidden shortness proof uses those packed heads as public input;
- the main proof adds one interpolant equality per replay block to bind the
  public head vector to the committed `THat` row.

It was versioned as `sig_shortness_v8_constraint_bound`, not a silent change to
`sig_shortness_v6_hidden`, but it revealed private `THatHeads` and was removed
from the live surface.

Current measurement:

- paper transcript: about `42.7 KB`
- verifier payload: about `71.2 KB`
- shortness: about `11.7 KB`, with `0` opening bytes and packed-head binding
  bytes instead of a V6 `THat` opening
- theorem bits: about `102.7`

V9 kept the direct aggregate `bb_tran` relation but did not reveal
`THatHeads`. Instead, the main proof and hidden shortness proof both prove
private openings of one public Ajtai-style commitment to their `THat` head
vectors. This makes V9 a privacy-correctness control for the V8 idea, not a
size win in the measured implementation.

Current measurement:

- paper transcript: about `200.5 KB`
- verifier payload: about `237.4 KB`
- shortness: about `172.0 KB`, with `0` DECS `THat` opening bytes
- theorem bits: about `102.1`

V10 kept aggregate `B2*r0` full replay and V7-style private inlined
target-hiding shortness. It carries no public `THatHeads`, no V6
`THatOpening`, and no V9 Ajtai commitment payload.

The requested grouped target was `ncols=32`, `group_size=2`, with either
`R=11,L=4` for 256 shortness rows or `R=111,L=2` for 128 shortness rows. The
current tree intentionally does not promote that geometry. The non-sign
carriers are issued and bounded on the existing 16-point coefficient-native
domain; evaluating the same message/randomness polynomials on a widened
32-point domain produces out-of-bound carrier values, so the main relation
fails before shortness constraints are reached. True 32-column grouping
therefore needs a carrier-domain split or reissued/repacked carrier surface,
not just a wider `-ncols` flag.

Last measured safe V10 control before removal:

- paper transcript: about `54.0 KB`
- verifier payload: about `117.9 KB`
- shortness rows: `384` (`2 * 64 * 3`, group size `1`, block width `16`)
- no V6 opening bytes and no public/private cross-root head bridge payload
- theorem bits: about `100.7`

This was smaller than aggregate private V7 with aggregate replay, but it was
not the planned 256-row or 128-row grouped design.

## 6.6 Aggregate V11 direct-target private shortness

The direct-target aggregate control is:

```bash
go run ./cmd/showing -showing-preset aggregate_v11_direct_target_research
```

V11 keeps private inlined shortness and the direct `bb_tran`
relation, but removes committed `THat` rows. The main proof carries one
`TargetMR0Hat` row per replay block for `B1*MHatSigma + sum_i B2_i*r0_i`, plus
the existing `RHat1` and `ZHat` rows. The shortness bridge then checks the
decoded private signature digits directly against `B0 + TargetMR0Hat + ZHat`.

Current direct-target control:

- paper transcript: about `48.7 KB`
- verifier payload: about `112.7 KB`
- replay rows: `TargetMR0Hat=64`, `RHat1=64`, `ZHat=64`, `THat=0`
- shortness rows: `384` (`2 * 64 * 3`, group size `1`, block width `16`)
- statement class: `theorem_clean_direct_target_full_replay`

The rejected V12 two-oracle/multi-domain prototype moved digit rows to a
separate signature oracle, but duplicated sidecar openings made the paper
transcript roughly `82 KB` and the first theta setting had weak effective
soundness. That path is no longer live. The next intended optimization is
single-root digit-pair packing plus lookup/range digit membership inside the
V11 direct-target family.

## 7. Reproduction commands

Baseline and preset measurements:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-preset compact_l3
go run ./cmd/showing -showing-preset compact_l2
go run ./cmd/showing -showing-preset compact_l1_research
go run ./cmd/showing -prf-companion-mode direct_auth
go run ./cmd/showing -prf-companion-mode aux_instance
```

Live full controls:

```bash
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_v11_direct_target_research
```

Full replay near the `100`-bit frontier:

```bash
go run ./cmd/showing -full
go run ./cmd/showing -full -showing-preset soundness_balanced -lvcs-ncols 96
go run ./cmd/showing -full -showing-preset soundness_balanced -lvcs-ncols 96 -nleaves 2048
go run ./cmd/showing -full -showing-preset soundness_balanced -lvcs-ncols 96 -nleaves 8192
```

`x0` profile matrix:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1
```

Reduced-replay research presets on the current vector-`x0` canonical artifacts:

```bash
go run ./cmd/showing -showing-preset transcript_first
go run ./cmd/showing -showing-preset production_balance
```
