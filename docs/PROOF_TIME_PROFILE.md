# BQ128/WF128 strict-v3 proof-time profile and candidate outcome

Date: 2026-08-05

Status: baseline profiling, implementation, and three-run unpaired performance
measurement complete. Promotion is blocked by the separate seven-seed paired/
allocation record and a BQ functional-gate engineering-high-watermark mismatch,
as described below.

## Executive conclusion

The predecessor profile concentrated cost in two deterministic regions and one
counter-dependent implementation artifact:

1. LVCS/DECS commitment construction takes about 35--46% of wall time. Its
   dominant work is dense formal-polynomial evaluation followed by SHAKE-256
   leaf hashing over every configured leaf.
2. Semantic-Q construction takes about 28--39%. Showing is especially
   allocation-heavy: the current extension-field evaluator constructs millions
   of short-lived limb slices while replaying the same relation at every Q
   interpolation point.
3. Fiat--Shamir rounds 3 and 4 rebuild, copy, and reabsorb the complete framed
   round transcript on every grinding counter. The configured grinding is not
   excessive and must remain frozen; the repeated prefix work is excessive.

The implemented pass is transcript-preserving:

- it preabsorbs the exact Fiat--Shamir prefix and clones the SHAKE state per
  sequential counter;
- it stops regenerating and revalidating the same explicit domain;
- it replaces allocating extension-field arithmetic in semantic-Q with
  worker-local `Into` operations and scratch storage;
- it caches the immutable showing replay plan and structural semantic metadata
  under the prepared context and builds each interpolation basis once; and
- it keeps the established combined DECS evaluator in production, retains the
  measured row-major candidate behind an explicit internal test constructor,
  and compacts the exact-`N` Merkle pipeline without changing hashes or
  topology.

The profiles do **not** support lowering `NLeaves`, changing kappa, shortening
hash inputs, reusing randomness, changing the relation, or changing transcript
bytes. Those would leave the implementation-only optimization boundary.

## Implemented outcome

The opt-in phase recorder now attaches before issuance proof construction,
uses proof-kind-specific labels, reports all four counters, and splits domain,
semantic-Q, Fiat--Shamir, opening, encoding, proving, verification, and DECS
hashing work without adding disabled-path clocks or formatting. The production
strict-v3 path reuses the exact Fiat--Shamir prefix by cloning the built-in
SHAKE state for each sequential counter, while retaining the generic-XOF
fallback. It prepares and binds the explicit domain once, authenticates trusted
row-head provenance, defers unused NTT materialization, and shares the
verifier's formal-degree validation helper. Semantic-Q uses pre-sized `Into`
arithmetic, cached immutable replay plans and structural semantic metadata,
immutable interpolation plans, and worker-local limb arenas. DECS uses a
fused leaf wrapper and an implicit-preorder exact-`N` hash arena. Its production
formal evaluator remains the established degree-major combined fallback. The
modulus/shape-safe row-major candidate is provisional R&D and is exposed only
through an explicit internal test constructor pending the paired adoption gate.

The R&D selector requires a fully dense, dot-safe plan with degree at most 64.
At `q<2^32`, plans with at most 200 rows use the `uint32` layout; plans with at
least 512 rows use the `uint64` layout. Intermediate, sparse, higher-degree, or
overflow-unsafe plans use the degree-major combined evaluator. The rule
contains no preset-ID branch, but production `newFormalEvalPlan` does not
activate either row-major backend without a future paired adoption decision.

No preset identifier, manifest, relation, theorem term, kappa vector,
`NLeaves`, query cap, width, randomness rule, transcript frame, codec, row
geometry, or paper-accounted byte total changed. Under fixed entropy the
optimized path is required to reproduce the predecessor's domain, rows,
hashes, roots/openings, four challenges and counters, `R`, `QPayload`, proof,
and presentation byte-for-byte.

Three fresh end-to-end runs per target on Go 1.23.12, Darwin/arm64,
`GOMAXPROCS=15`, give these independent scalar medians:

| Target/phase | Predecessor prove | Fresh candidate prove | Nominal unpaired change | Fresh MAD | Fresh verify |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ issuance | 1,706.772 ms | 1,349.588 ms | -20.93% | 36.483 ms | 499.882 ms |
| BQ showing | 3,692.639 ms | 2,902.833 ms | -21.39% | 97.182 ms | 273.419 ms |
| WF issuance | 729.139 ms | 521.758 ms | -28.44% | 4.210 ms | 241.098 ms |
| WF showing | 1,421.167 ms | 1,256.464 ms | -11.59% | 8.127 ms | 148.445 ms |

| Target | Predecessor peak RSS | Fresh candidate peak RSS | Nominal unpaired change |
| --- | ---: | ---: | ---: |
| BQ128 | 601,784,320 B | 369,393,664 B | -38.62% |
| WF128 | 326,336,512 B | 194,871,296 B | -40.29% |

One final-source allocation diagnostic (not the formal seven-pair evidence)
recorded:

| Path | Baseline approximate bytes / objects | Fresh diagnostic bytes / objects |
| --- | ---: | ---: |
| BQ issuance | 739 MB / 3.31 million | 278,032,584 B / 2,656,899 |
| BQ showing | 3.52 GB / 24.12 million | 748,198,984 B / 3,516,872 |
| WF issuance | 321 MB / 1.87 million | 129,744,768 B / 1,632,468 |
| WF showing | 1.75 GB / 18.78 million | 461,072,928 B / 2,308,581 |

These single-run allocation figures suggest the intended direction, especially
for showing, but are non-authoritative and entropy/counter-dependent. The
predecessor values were sampled approximations, and the required paired
allocation records remain to be collected.

The four nominal predecessor/candidate timing differences are each numerically
greater than 3%, but the three-run result does not clear the formal performance/
adoption gate. The samples use independent entropy and accepted Fiat--Shamir
counters; counter variability can materially affect top-level proving time.
Runtime direction remains unestablished until seven fixed-entropy alternating
pairs are measured. The six fresh runs are under
`artifacts/smallwood-v3/time-optimization-v1/{bq128,wf128}/run-{1,2,3}`.
They bind source-input digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.
Their persistent states remain 4,926 B and 4,894 B, and their fixed paper
issuance/showing totals remain 57,271/90,494 B and 23,790/39,837 B.

Fresh canonical proof and presentation lengths are not expected to be
identical across independent entropy samples: both the challenge-dependent
exact Merkle frontier node count and minimal-LEB128 Fiat--Shamir counter widths
vary. That expected sample variation does not change the canonical format or
the fixed paper accounting. Fixed-entropy predecessor/candidate equality is
the authoritative transcript-preservation test.

The existing tiled DECS evaluators remain rejected because the original exact-
shape measurements made them 1.76--2.17 times slower. Fixed DECS frame
templates were also rejected: pure leaf framing was 59--107% slower, and the
exact-`N` whole-hash template had no stable cross-target improvement of at
least 3%. Its clean WF leaf result was 3.4% faster, but only four of seven pairs
agreed in the longer repeat. DECS SHAKE-prefix cloning added 448 B and one
allocation per hash and was generally slower. All prototypes passed exact
frame/hash equality before rejection. Raw results and reproduction details are
in
`tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/RESULTS.md`.
This is distinct from the accepted Fiat--Shamir prefix clone, which amortizes
a long invariant round prefix across sequential counters.

Machine-readable promotion evidence has two blockers. The seven fixed-entropy
alternating baseline/candidate end-to-end pairs, including their allocation
records, have not yet been generated, so formal runtime direction remains
unestablished. Separately, the all-nine functional gate
does not pass its BQ showing engineering high-watermark: issuance/showing
algebraic totals are 131.548362/131.511683 bits, versus the manifest-bound
131.540568-bit target, a 0.028885-bit showing shortfall.

The required 128-bit per-phase security audit itself passes, with BQ showing
3.511683 bits of slack; the BQ proof, parameter audit, and replay checks pass as
well. The target, manifest, geometry, and accounting remain frozen and are not
changed to force the engineering check green. The fresh three-run medians above
are valid unpaired measurements, but they neither establish runtime direction,
substitute for the paired record, nor make `gate-functional-presets` pass. The
security scope remains
`claim_scope=proof_only`; no full-game or QROM claim follows from this work.

Unless a later section explicitly says “optimized,” the call graph, allocation
figures, and kernel tables below describe the accepted predecessor that guided
the implementation.

## Scope and source identity

Only the two strict-v3 targets were profiled:

- BQ128: `poc-n1024-bq128-r128-v3`;
- WF128: `system-n1024-wf128-crom-v2`.

The accepted benchmark inputs came from
`artifacts/smallwood-v3/final-size-optimization-v2/{bq128,wf128}/run-1`.
Their manifest digests are respectively
`ed2ef5aebe3fe38c07fd85f02b15cd2f0f9ee56c3be4ca49cd1fe83cc802a193`
and
`4063d1422055d5753355781160188abdb98dd683f5e42978abcb3d273e89e4c7`.

The repository base HEAD was
`f8973f05473c9110081324a0f2671fa410fb12f3`. The shared worktree already
contained extensive uncommitted strict-v3 work, so the profiling executable,
not the base commit alone, is the most precise identity for this run. The main
profile executable SHA-256 was
`c48f4d14f1f645c42606f540e425c9fe8a592b6e636d2a34a675bc66476b8caf`.

The paper repository was inspected read-only. Its HEAD was
`d19818571f04c8c12425e2e7c10ceb41f7a1762d` and it was clean. No paper file
was modified.

## Method

An overlay-only internal test under `tmp/profiling-v3` reconstructed the real
dense public parameters and witness from the accepted artifacts, called the
actual strict-v3 proof builders, and retained all generated data below the
repository. It did not add a test or profiling branch to production code.

Measurements used:

- Go 1.23.12 on Darwin/arm64;
- `GOMAXPROCS=15`, matching the 15 logical CPUs, except for the explicit worker
  sweep;
- three BQ and five WF repetitions for CPU profiles;
- one proof for each sampled allocation profile;
- two independent three-run, isolated phase-timing sequences;
- one isolated BQ showing execution trace; and
- one BQ showing run with `GODEBUG=gctrace=1`.

CPU samples are summed over concurrently running goroutines and can exceed wall
time. Allocation-space values are cumulative bytes allocated, not peak RSS.
The one-proof pprof runs include a small amount of artifact reconstruction, but
all reported dominant stacks are inside the builders. Separate timing probes
confirmed that harness setup was normally about 3--6 ms.

The accepted artifact reports remain the end-to-end baseline. The overlay runs
are diagnostic and do not replace the accepted evidence.

## Accepted end-to-end baseline

| Preset | Issuance prove median | Showing prove median | Accepted peak-RSS median |
| --- | ---: | ---: | ---: |
| BQ128 | 1,706.772 ms | 3,692.639 ms | 601,784,320 B |
| WF128 | 729.139 ms | 1,421.167 ms | 326,336,512 B |

The accepted showing reports already contain useful internal timers:

| Showing region | BQ128 median | Share of accepted median | WF128 median | Share of accepted median |
| --- | ---: | ---: | ---: | ---: |
| LVCS/DECS commit | 1,580.123 ms | 42.8% | 547.612 ms | 38.5% |
| DECS evaluation + leaf hash | 1,383.979 ms | 37.5% | 465.891 ms | 32.8% |
| Exact-N Merkle construction | 113.867 ms | 3.1% | 42.940 ms | 3.0% |
| Semantic Q + masks | 1,176.538 ms | 31.9% | 553.817 ms | 39.0% |
| Semantic relation metadata | 98.040 ms | 2.7% | 98.974 ms | 7.0% |
| Round 3 | 118.853 ms | 3.2% | 2.310 ms | 0.2% |
| Round 4 | 303.280 ms | 8.2% | 16.610 ms | 1.2% |

Commitment plus semantic-Q accounts for 74.7% of BQ showing and 77.5% of WF
showing. Rows, shortness digits, carrier construction, and row NTTs are already
too small to be first-order targets.

Issuance's accepted reports attach their phase recorder after proof
construction, so they contain verification/report phases but no issuance
builder breakdown. The isolated overlay measurements supply the missing view.
Across six isolated invocations, the medians were:

| Builder region | BQ128 issuance | WF128 issuance | BQ128 showing | WF128 showing |
| --- | ---: | ---: | ---: | ---: |
| Direct builder/harness wall | about 1,588 ms | about 664 ms | about 3,509 ms | about 1,504 ms |
| LVCS/DECS commit | 741.6 ms | 244.9 ms | 1,549.5 ms | 539.4 ms |
| Semantic Q + masks | 434.9 ms | 219.7 ms | 1,172.6 ms | 575.4 ms |

The last table deliberately excludes a single median for the Fiat--Shamir tail:
its value is governed by the fresh accepted counter and is not stable across
six proofs.

## Executed geometry and unavoidable call counts

| Phase | Formal P rows | DECS mask rows | Row degree | eta | Leaves | Tape/hash bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ issuance | 246 | 59 | 60 | 59 | 688,128 | 33 / 49 |
| BQ showing | 645 | 59 | 60 | 59 | 688,128 | 33 / 49 |
| WF issuance | 155 | 43 | 50 | 43 | 327,680 | 16 / 33 |
| WF showing | 520 | 43 | 49 | 43 | 327,680 | 16 / 33 |

### DECS commitment

For every leaf, the production combined evaluator computes powers, evaluates
the complete formal `P || M` plan, encodes the leaf, and hashes it. Strict v3
then hashes each encoded leaf into the exact-N positional Merkle tree and hashes
`NLeaves-1` internal nodes. Consequently, one proof performs approximately:

- BQ: `3 * 688128 - 1 = 2,064,383` SHAKE leaf/tree operations;
- WF: `3 * 327680 - 1 = 983,039` SHAKE leaf/tree operations.

These calls are not accidental duplicates: the first hash commits the DECS
leaf encoding, while the positional leaf and internal hashes commit the exact-N
tree topology. Merging or omitting them would change roots and transcript
semantics.

### Semantic Q

`buildSemanticQKV3` evaluates Equation (4) at `dQ+1` fixed base-field points
and once more at the independent audit point:

| Phase | dQ | Complete semantic evaluator calls |
| --- | ---: | ---: |
| BQ issuance | 472 | 474 |
| BQ showing | 570 | 572 |
| WF issuance | 391 | 393 |
| WF showing | 471 | 473 |

The Q-point count and independent audit are relation/security work and must not
be removed. The implementation of each evaluation, however, currently creates
far more temporary extension-field elements than necessary.

### Fiat--Shamir

The frozen vectors are BQ `[5,6,12,13]` and WF `[1,0,2,13]`. Expected attempts
are therefore 12,384 and 8,199 per proof respectively. This is the configured
security work. The implementation currently adds full-prefix framing, copying,
and SHAKE absorption to every one of those attempts.

Measured round time was close to linear in the accepted zero-based counter:

| Path | Approximate marginal cost per rejected counter |
| --- | ---: |
| BQ issuance round 4 | 11.3 microseconds |
| BQ showing round 3 | 29 microseconds |
| BQ showing round 4 | 35--37 microseconds |
| WF issuance round 4 | 5.8 microseconds |
| WF showing round 4 | 18--19 microseconds |

For example, isolated BQ showing round-4 runs ranged from about 21 ms at
counter 438 to 193 ms at counter 5,101; another valid run took 636 ms at
counter 17,700. This variance is expected from counter sampling, but the cost
per attempt is an implementation problem.

## CPU profile

### Issuance

The isolated multi-run issuance profiles show the same ordering on both
targets:

| Flat CPU function | BQ128 | WF128 | Assessment |
| --- | ---: | ---: | --- |
| `sha3.keccakF1600` | 32.7% | 37.2% | Dominant hash permutation work |
| `formalEvalPlan.evalDenseLowDegreeUint64Into` | 30.7% | 31.1% | Dominant field-evaluation work |
| `runtime.memmove` | 16.2% | 1.8% | BQ data movement/heap pressure |
| `addGammaScaledBasePolyV3` cumulative | 3.4% | 6.1% | Issuance aggregate-dot Q work |

The complete BQ commitment range accounts for 75.4% cumulative CPU. BQ leaf
hashing alone accounts for 42.9% cumulative CPU. WF has the same qualitative
shape.

### Showing

| Flat/cumulative CPU function | BQ128 | WF128 | Assessment |
| --- | ---: | ---: | --- |
| `sha3.keccakF1600` flat | 24.1% | 26.0% | Commitment and FS hashing |
| Dense DECS evaluator flat | 17.3% | 18.0% | Formal row evaluation |
| `formalEvalPlan.evalIntoPowers` cumulative | 31.3% | 25.2% | Complete evaluator path |
| `runtime.memmove` flat | 7.1% | 1.4% | BQ copying/heap traffic |
| `kfield.mulReduced` flat | 5.4% | 5.7% | Semantic-Q extension arithmetic |
| `kfield.AddMulBaseInto` cumulative | 11.5% | 12.5% | Projected-signature aggregation |
| `evalProjectedSignatureK` cumulative | 13.0% | about 13% | Main showing-Q subrelation |
| `CoreKEvaluator` cumulative | 16.5% | 19.3% | Complete showing relation replay |

The profile does not show excessive time in row layout validation, carrier
decoding, shortness digit generation, or row NTT conversion.

## Allocation and scheduler profile

The one-proof sampled allocation profiles recorded:

| Path | Cumulative allocation | Allocated objects |
| --- | ---: | ---: |
| BQ issuance | about 739 MB | about 3.31 million |
| WF issuance | about 321 MB | about 1.87 million |
| BQ showing | about 3.52 GB | about 24.12 million |
| WF showing | about 1.75 GB | about 18.78 million |

The issuance totals include small input-loading allocations; the dominant
entries below are inside proof construction. Sampling was set to 65,536 bytes,
so byte/object figures are approximate rather than exact counters.

### Showing allocation source

`internal/kfield.(*Field).Zero` alone allocated:

- BQ: 2.153 GB in 20.15 million calls, 61.2% of bytes and 83.6% of objects;
- WF: 1.015 GB in 16.63 million calls, 58.1% of bytes and 88.6% of objects.

The method is only `make([]uint64, theta)`. It is individually simple but is
used in inner arithmetic loops as though field elements were value-sized. The
slice-backed representation turns every `Zero`, and therefore many `Add`,
`Sub`, `Mul`, `EmbedF`, and polynomial-evaluation results, into heap traffic.

Other major showing allocations were:

| Source | BQ128 | WF128 |
| --- | ---: | ---: |
| FS length-prefixed transcript copies | 358.5 MB | 124.9 MB |
| Exact-N Merkle storage | 220.5 MB | 92.7 MB |
| Domain generation/validation families | about 188 MB | about 87 MB |
| PRF expression clone + scale | 69.4 MB | 67.8 MB |
| Semantic mask evaluation | 38.6 MB | 14.9 MB |

In one BQ showing GC trace, semantic-Q kept the live heap near 249--250 MB and
the proof triggered 35 collections. Individual stop-the-world pauses were
small, so GC is not the sole cause of long round tails. The execution trace
nevertheless attributed 62.6% of summed scheduler delay to allocation-triggered
`gcStart`, predominantly below `CoreKEvaluator`, `evalProjectedSignatureK`, and
`make([]uint64, theta)`. This is summed goroutine delay, not 62.6% of wall time.

## Which repeated functions are actually overcalled?

| Function/path | Frequency | Current quality | Decision |
| --- | --- | --- | --- |
| Dense DECS evaluator | Once per leaf | Four-way unrolled, delayed reduction, combined `P || M` scan | Necessary frequency; optimize kernel only after exact benchmarks |
| DECS leaf hash | Once per leaf | Reuses SHAKE state and scratch per worker; permutation dominates | Necessary frequency; batched/SIMD SHAKE is a later candidate |
| Exact-N Merkle leaf/internal hash | `2*NLeaves-1` | Correct positional topology; large flat arena | Necessary hashes; storage/layout can improve without changing bytes |
| `FS.roundInputV3` + `XOF.Expand` | Once per counter | Rebuilds/copies/reabsorbs an invariant prefix | Definitely overworked; preabsorb and clone |
| `kfield.Field.Zero` and allocating arithmetic | Tens of millions in showing | Slice allocation in hot loops | Definitely overcalled; use worker-local `Into` arithmetic |
| Explicit domain derivation | Repeated before and inside the prepared builder | Later result overwrites earlier work | Definitely duplicated |
| Domain distinctness validation | Repeated in domain, LVCS, and DECS layers | Allocates large `map[uint64]struct{}` each time | Duplicated on the trusted prepared path |
| Showing replay-config/PRF IR construction | Twice per proof | Rebuilds immutable public matrices, bases, and relation IR | Duplicate; share one bound immutable instance |
| `Interpolate` over Omega | Once per logical witness row | Recomputes basis data for identical x-coordinates | Duplicate basis work |
| Final Q interpolation | Once per extension-field limb | Recomputes the same x-basis 13 times for BQ, 7 for WF | Duplicate basis work |
| Semantic mask evaluation | Every Q point/column/limb | Allocates a coefficient slice merely to run Horner | Avoidable allocation |
| Prover-side LVCS verifier construction | Once per proof | Copies/validates the full domain to perform an R-degree check | Excessive; use an equivalent local degree check |
| `EvalOracle` at Omega after commitment | Once in masking flow | Reevaluates rows whose normalized Omega heads are retained | Avoidable with exact-order fast path |
| Strict issuance NTT export | Every formal/mask row | Produced even where source-only issuance never consumes it | Candidate for lazy/omitted internal export |

## Detailed assessment of the two main kernels

### DECS is expensive, but not obviously poorly implemented

`DECS/decs_prover.go` already uses a low-degree dense plan, unrolls four row
accumulators, and delays modular reduction until after the degree scan. The
production path selects `FormalEvalCombined`; it does not use the older scalar
P/M double scan. The disabled q20 `uint32` path and historical synthetic tiled
benchmarks are not evidence of a win on the current shapes.

An additional exact-shape, full-domain benchmark then compared the production
combined kernel with the existing tiled implementation. It used dense
degree-exact rows, all configured leaves, 15 contiguous worker ranges, three
repetitions, reversed mode order, and an elementwise equivalence check on 257
points:

| Geometry | Combined ns/leaf | Tile 2 | Tile 4 | Tile 8 | Tile 16 | Best tiled slowdown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ issuance, 305 rows, degree 60 | 545.8 | 1,103 | 1,050 | 962 | 984.4 | 1.76x |
| BQ showing, 704 rows, degree 60 | 1,352 | 2,754 | 2,554 | 2,401 | 2,406 | 1.78x |
| WF issuance, 198 rows, degree 50 | 336.8 | 688.6 | 634.1 | 618.8 | 602.7 | 1.79x |
| WF showing, 563 rows, degree 49 | 876.6 | 1,900 | 1,741 | 1,656 | 1,680 | 1.89x |

The existing tiled evaluator is therefore decisively worse: its best result is
76--89% slower, and it requires larger tile scratch. It must not replace the
combined path. Any future tiled work needs a new data layout/kernel, not a
configuration change.

The worker sweep also rejects a lower static worker cap:

| BQ GOMAXPROCS | Issuance commit | Showing commit | Issuance Q | Showing Q |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 6,987.6 ms | 14,566.3 ms | 723.0 ms | 6,972.1 ms |
| 2 | 3,651.5 ms | 7,401.4 ms | 563.5 ms | 3,703.3 ms |
| 4 | 1,908.6 ms | 3,839.4 ms | 476.3 ms | 1,972.6 ms |
| 8 | 1,145.1 ms | 2,672.9 ms | 426.4 ms | 1,177.4 ms |
| 15 | 756.8 ms | 1,527.9 ms | 431.2 ms | 1,178.1 ms |

| WF GOMAXPROCS | Issuance commit | Showing commit | Issuance Q | Showing Q |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 577.8 ms | 1,410.8 ms | 238.0 ms | 949.0 ms |
| 8 | 378.9 ms | 866.9 ms | 219.2 ms | 573.1 ms |
| 15 | 258.7 ms | 544.9 ms | 222.3 ms | 567.2 ms |

These are single-run directional measurements; random FS phases are excluded.
DECS continues scaling from 8 to 15 workers. Q stops scaling at 8 because its
worker pool is intentionally capped at eight. Raising that cap before removing
allocation pressure is not justified.

The credible later DECS work is a cache-tiled dense kernel and independent-lane
batched SHAKE. Both must reproduce identical leaf hashes, roots, and openings
under fixed rows, masks, tapes, salt, context, and domain. Merely switching to
an existing mode without exact-shape evidence is not acceptable.

### Semantic-Q is both expensive and allocation-inefficient

All production interpolation points are embedded base-field points. Yet the
showing evaluator repeatedly creates general extension-field temporaries while
materializing projected-signature and source-transform residuals. The largest
concrete source is `evalProjectedSignatureK`'s inner `transformLane` closure.

The safe implementation shape is:

- add `EvalFPolyAtKInto` and base-embedding into an existing element;
- change `transformLane` to `transformLaneInto(dst, scratch, ...)`;
- reuse fixed-size limb arenas per Q worker;
- use `AddMulBaseInto` for embedded points and retain the generic K path for the
  independent extension-field audit;
- reconstruct shortness with `AddMulBaseInto` instead of
  `EmbedF -> Mul -> Add` temporaries; and
- evaluate mask columns directly from `MaskColumnByDegree` without allocating
  temporary coefficient slices.

This does not change a field operation. It changes ownership and storage. The
main risks are aliasing and cross-worker scratch races, so every scratch arena
must be worker-local and differential tests must compare every residual, not
only final verification.

## Original ranked implementation plan

This section preserves the pre-implementation reasoning and review sequence.
The actual retained batches and measurements are summarized in “Implemented
outcome” above and reported in detail in
[PROOF_TIME_OPTIMIZATION.md](PROOF_TIME_OPTIMIZATION.md).

### 0. Correct permanent profiling instrumentation

Before declaring a speedup:

- attach the issuance phase recorder before `BuildIntGenISISPreSign`;
- stop labelling issuance commitment time as `showing.lvcs_commit_total`;
- record domain preparation, replay-config construction, Q plan/evaluation/
  interpolation/audit, FS prefix framing, counter loop, opening, and
  compression separately; and
- keep per-leaf timers opt-in because timing every leaf can distort the kernel.

This changes no proof data and prevents later work from being optimized against
misattributed timings.

### 1. Exact SHAKE-state cloning for grinding

Frame the v3 round input through, but excluding, the final eight-byte
big-endian counter. For the built-in SHAKE-256 implementation, absorb
`label || exact_framed_prefix` once, clone that state for each sequential
counter, append the same counter bytes, and squeeze the same digest width.
Retain the generic XOF fallback.

Required tests:

- old/new digest equality over fixed transcripts and boundary counters;
- identical lowest accepted counter and challenge for all four rounds;
- identical proof and canonical bytes under fixed entropy; and
- no parallel selection of a nonminimal counter.

This does not reduce grinding. It makes each configured attempt cheaper.

### 2. Remove redundant domain work

The unexported prepared context should own one immutable, validated domain.
Consume it before the generic builder derives any replacement. Public and
unprepared APIs must continue full validation.

For q=1,017,857, duplicate detection can use a roughly 125 KiB bitset instead
of large maps, with the map retained as a fallback for unsuitable moduli. A
trusted validation token must bind q, ordered points, `NLeaves`, widths, ell,
relation version, profile, and manifest identity. It must never be accepted
from a proof.

Also replace the temporary prover-side LVCS verifier used only for an R-degree
check with a local helper proven equivalent to the verifier's coefficient
check.

### 3. Make semantic-Q arithmetic allocation-free

Implement worker-local scratch and `Into` variants in small reviewable slices:

1. polynomial evaluation and embedding;
2. projected-signature transform lanes;
3. membership/inversion/shortness arithmetic;
4. direct mask Horner evaluation; and
5. flat destination arenas for residual vectors.

Each slice should land with exhaustive differential tests before the next one.
The target is not merely lower allocation: final Q coefficients and the
independent audit evaluation must remain exactly equal.

### 4. Share immutable replay and interpolation plans

Build one showing replay configuration/PRF IR and use it for semantic metadata
and the Q evaluator. Cache only public, immutable material under the complete
manifest/public/layout/domain identity.

Build one interpolation plan for Omega and apply it to every logical row. Build
one plan for the Q x-points and apply it to all theta limbs. Preserve the
independent Q audit point.

### 5. Remove smaller duplicate issuance work

- return retained normalized row heads when `EvalOracle` is requested at the
  exact ordered Omega prefix;
- make unused strict source-only issuance NTT exports lazy;
- reuse precomputed static range/membership data; and
- avoid immediate deep copies of newly constructed openings where ownership is
  already unique.

### 6. Reprofile before changing the DECS kernel

Once transcript copying and semantic-Q allocation are removed, rerun CPU,
allocation, trace, wall, and peak-RSS measurements. Only then evaluate:

- an exact-shape dense tile kernel;
- compact Merkle storage with identical positional hashes;
- direct canonical frontier construction; and
- vetted batched/SIMD SHAKE-256.

The current profiles cannot tell how much DECS becomes dominant after the
low-risk work; Amdahl's law makes that reprofile mandatory.

## Changes explicitly deferred

The following may be interesting research or larger rewrites, but they are not
authorized by this profile:

- lowering `NLeaves` or any cryptographic width;
- changing kappa or trying to obtain smaller counters;
- hashing a digest of the public transcript instead of the exact transcript;
- changing DECS leaf encodings or merging commitment/Merkle domains;
- deriving independent tapes from a master seed;
- reusing masks, witness randomizers, salts, or tapes;
- changing domain order;
- removing the semantic-Q audit point;
- replacing the showing relation by an aggregate-dot formulation without a new
  relation-equivalence/extractability audit; or
- architecture-specific arithmetic whose equality is not checked against the
  canonical implementation.

## Security and acceptance gate for every optimization

The target remains `claim_scope=proof_only`. A time optimization is acceptable
only when, under fixed entropy, the old and new implementations produce
byte-identical:

- domains and ordered support;
- randomized witness/mask rows;
- DECS leaf payloads, leaf hashes, roots, and openings;
- all four Fiat--Shamir digests, minimal counters, and challenges;
- R, Q payloads, VTargets, BarSets, and canonical openings; and
- complete canonical proof and presentation bytes.

In addition:

- compare every semantic residual and Q coefficient before relying on final
  verification;
- run race tests for worker-local scratch and shared immutable caches;
- test malformed/untrusted prepared contexts still fail closed;
- retain fixed kappa, `NLeaves`, query caps, salts, tapes, hash widths, relation
  versions, degree bounds, and independent randomizers;
- run at least three isolated BQ/WF issuance and showing proofs, recording wall,
  CPU, cumulative allocation, peak RSS, counters, and phase timings; and
- run the existing strict-v3 proof, replay, codec, security-gate, and full Go
  test suites.

Passing these tests supports the narrow statement that the implementation is
faster without a known change to the BQ/WF per-proof SmallWood transcript. It
does not supply full-game credential security, QROM security, or certainty
about all system-level composition assumptions.

## Profile artifacts

Temporary binaries, CPU profiles, allocation profiles, traces, GC output, and
worker-sweep outputs are under `tmp/profiling-v3`. The exact-shape evaluator
benchmark and raw output are under
`tmp/profiling-v3/time-optimization/_decs-exact-kernel-bench`. They are
diagnostic work products, not accepted benchmark evidence. Representative
profile SHA-256 values are:

| Artifact | SHA-256 |
| --- | --- |
| BQ issuance CPU | `9607dbe4447802abed284d340e5e3076fa7533ec3b7fb7f4fc769be7cc1cd517` |
| WF issuance CPU | `c660f774d8cf681ca315f8ccdc91f51b281e8e36695cde5356f47d51e3bb9265` |
| BQ showing CPU | `35d51fbd5e7423edf38c42b880c727027d9a16fcbb70ee50494ece1bfdf4aa09` |
| WF showing CPU | `0040d8d9d38b31fba2fbb6b3e43d7c816cd23ce9e2f20b961a7f8f428948b4bb` |
| BQ showing allocation | `e6e33e23f2d6ccdce2947d33031df229cebe171f847216b8cfa99bcf78e3d695` |
| WF showing allocation | `f0e559f3384dda2a062c47b5c975d579ad40b2679a989a3838929332a0309a4e` |
