# BQ128/WF128 strict-v3 proof-time optimization

Date: 2026-08-05

Status: the three-run fresh production medians are numerically 11.59--28.44%
below the predecessor medians for the four target proof paths. They do **not**
pass the cumulative runtime adoption gate, because that gate requires seven
fixed-entropy alternating baseline/candidate pairs. The checked
time-optimization evidence remains deliberately `pending` for two independent
reasons:

1. the seven fixed-entropy paired end-to-end runs with allocation counters
   have not yet been generated; and
2. the frozen BQ128 executable-preset engineering gate is not satisfied.
   Its measured `algebraic_total_bits` values are 131.548362 for issuance and
   131.511683 for showing, while the manifest-bound
   `TargetTheoremBits=131.540568`. Showing is therefore 0.028885 bits below
   that engineering target. The required 128-bit phase gate still passes with
   3.511683 bits of showing slack.

Thus the fresh-run comparison is measured but remains an unpaired indication,
not an adopted speed result. The second blocker is recorded rather than hidden
or repaired by changing the frozen preset, manifest, theorem accounting, or
production gate.

## Result boundary

This cycle targets only:

- BQ128: `poc-n1024-bq128-r128-v3`;
- WF128: `system-n1024-wf128-crom-v2`.

The allowed result is an implementation-only speedup. Under the same entropy,
the ordered domain, committed rows, DECS leaf frames and hashes, Merkle
root/opening, four Fiat--Shamir digests and counters, `R`, `QPayload`, complete
canonical proof, and presentation must be byte-identical. The relation,
theorem accounting, kappa, `NLeaves`, query caps, widths, random values,
transcript framing, schema 3, codec 6, manifests, geometry, and paper sizes are
frozen.

The security claim remains `claim_scope=proof_only`. This work makes no
full-game, QROM, or unconditional-security claim. The sibling paper repository
was clean at
`d19818571f04c8c12425e2e7c10ceb41f7a1762d` before work began and is a
read-only input.

## Accepted predecessor

The immutable predecessor is
`evidence/focused-v3-final-size-optimization.json`, SHA-256
`430ea6d8cfc30136009d69af6fabe1b0fc943d708938164b1528090292abd102`.
Its proving medians are the historical before-values, not substitutes for the
new seven-pair fixed-entropy comparison.

| Target | Issuance | Showing | Peak RSS |
| --- | ---: | ---: | ---: |
| BQ128 | 1,706.772 ms | 3,692.639 ms | 601,784,320 B |
| WF128 | 729.139 ms | 1,421.167 ms | 326,336,512 B |

The profile found that LVCS/DECS commitment and semantic-Q construction account
for about 75--78% of showing time. The detailed call graph, allocation profile,
and original kernel experiments are in
[PROOF_TIME_PROFILE.md](PROOF_TIME_PROFILE.md).

## Frozen output accounting

No accepted batch may change these paper sizes or row geometries. Fresh proof
and presentation wire lengths can differ between entropy samples because the
exact frontier and minimally encoded counter values differ; that is not a
codec change.

| Target/phase | Logical / mask / replay / physical rows | Layers | `(d,d',dQ)` | Queries / opening columns | Paper bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ issuance | 49 / 156 / 90 / 246 | 2 | 9 / 8 / 472 | 39 / 207 | 57,271 |
| BQ showing | 423 / 195 / 450 / 645 | 10 | 11 / 8 / 570 | 143 / 502 | 90,494 |
| WF issuance | 49 / 77 / 78 / 155 | 2 | 9 / 8 / 391 | 21 / 134 | 23,790 |
| WF showing | 423 / 91 / 429 / 520 | 11 | 11 / 8 / 471 | 84 / 436 | 39,837 |

The prior canonical medians remain:

| Target | State | Issuance proof | Showing proof | Presentation |
| --- | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 51,895 B | 84,717 B | 84,750 B |
| WF128 | 4,894 B | 21,720 B | 37,936 B | 37,977 B |

These are distinct from paper-accounted transcript bytes. The evidence records
each fresh proof's actual codec-6 component audit and the paper component audit
separately.

## Implementation batches and decision state

The implementation sequence is intentionally incremental. The current source
contains the cumulative candidate so it can be measured end to end. A batch is
adoptable only after exact-output differential tests and its paired adoption
measurement; the entries below are not promoted merely because they are
present in the candidate source.

| Batch | Intended reduction | Current adoption state |
| --- | --- | --- |
| Permanent instrumentation | Correct phase attribution; expose domain, commitment, semantic-Q, FS prefix/counter loop, opening, encoding, prove, and verify time | Present in all six authenticated reports; exempt from the 3% threshold |
| Exact FS prefix reuse | Absorb the invariant strict-v3 SHAKE prefix once and clone only the built-in SHAKE state per sequential counter | Included in the fresh cumulative result; paired attribution pending |
| Prepared explicit domain | Generate, validate, and bind one immutable domain per strict prepared context | Included in the fresh cumulative result; paired attribution pending |
| Duplicate LVCS work removal | Shared formal-degree validation, exact-Omega retained heads, trusted strict-row provenance, lazy unused NTTs | Included in the fresh cumulative result; paired attribution pending |
| Semantic-Q scratch/plan reuse | Remove extension-field allocation churn without changing operation or output order | Included in the fresh cumulative result; paired allocation gate pending |
| Prepared replay/PRF plan | Cache the immutable replay configuration and input-trace PRF IR once per prepared context; derive semantic metadata shape structurally instead of invoking a dummy evaluator | Retained in the final fresh cumulative result; paired allocation attribution pending |
| Portable DECS/Merkle storage | Compact implicit exact-N hash storage and identical fused framing | Included in the cumulative candidate; fixed-entropy paired adoption pending |
| Dense row-major DECS evaluation | Structural uint64/uint32 selection when dot-safe | Kept out of production; explicit R&D constructor only until the paired adoption gate passes |

Pending paired attribution is not an acceptance decision for an individual
batch. A failed production candidate must be removed and listed below with its
measured reason.

## Rejected candidates

The pre-existing tiled DECS evaluator is rejected. Exact-shape full-domain
benchmarks found its best mode 1.76x to 2.17x slower than the combined
degree-major implementation, while using additional scratch allocation. Those
results are recorded in
`tmp/profiling-v3/time-optimization/_decs-exact-kernel-bench/RESULTS.md` and
summarized in [PROOF_TIME_PROFILE.md](PROOF_TIME_PROFILE.md). A new row-major
candidate is not accepted merely because a directional microbenchmark is
promising; one structural selection rule must pass all four exact geometries.

No batch may lower `NLeaves`, change kappa, search for unusually small
counters, weaken verification, share independent tapes, introduce a master
seed, change randomness, or alter a proof/security parameter.

### Row-major DECS candidate

An isolated seven-pair exact-kernel experiment produced these medians. Values
are nanoseconds per leaf; they are not end-to-end proving results.

| Geometry | Combined | Selected row-major result | Change | Faster pairs | Microbenchmark decision |
| --- | ---: | ---: | ---: | ---: | --- |
| BQ issuance | 472.593 | uint64 460.946 | -2.46% | 5/7 | reject; use combined fallback |
| BQ showing | 1,191.652 | uint64 1,136.352 | -4.64% | 7/7 | candidate |
| WF issuance | 306.378 | uint32 295.200 | -3.65% | 6/7 | candidate |
| WF showing | 833.708 | uint64 797.720 | -4.32% | 6/7 | candidate |

The candidate rule is structural rather than preset-dispatched: require dense,
dot-safe rows with degree at most 64; use uint64 row-major for at least 512
rows, uint32 row-major for at most 200 rows when `q < 2^32`, and retain the
combined evaluator for middle sizes or unsupported shapes. BQ issuance is the
important negative control: it missed 3%, so the rule deliberately falls back.
The alternate BQ-showing and WF-showing uint32 medians were 1,112.799 and
827.770 ns/leaf. BQ alone was faster with uint32, but one large-shape uint32
rule would miss the gate on WF showing; the cross-geometry structural rule
therefore selects uint64 for both large row sets.

This rule remains a candidate until the fixed-entropy paired proof-equality and
allocation gates pass. The microbenchmark and fresh medians alone cannot adopt
it.

### DECS frame-template and SHAKE-clone prototypes

The portable framing prototypes were rejected after isolated byte- and
hash-equivalence tests:

- fixed canonical leaf-frame templates made pure framing 59--107% slower;
- exact-N whole-hash templates did not produce a stable improvement of at
  least 3% across both targets; and
- cloning a prefixed SHAKE state for each DECS hash added 448 B and one
  allocation per hash and was generally slower.

All prototype frames and hashes matched the existing encoders, so the decision
is performance-only. None of these paths entered production. The benchmark,
correctness overlay, and complete results are retained under
`tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/`.

## Measurement protocol

Each retained cumulative build is measured as follows:

1. Use Go 1.23.12, Darwin/arm64, 15 logical CPUs, and `GOMAXPROCS=15`.
2. Exclude one warm-up.
3. Run seven alternating baseline/candidate pairs using seven fixed test-only
   entropy seeds. Each pair must produce identical proof and presentation
   SHA-256 digests and identical four-counter vectors.
4. Report median and median absolute deviation (MAD), allocated bytes,
   allocation count, peak RSS, verification time, counters, and digest.
5. Require at least five of seven paired times to agree with the claimed
   direction.
6. Require every one of the four top-level proving medians to improve by at
   least 3% in the final cumulative build. Verification may not regress by more
   than 2%, and peak RSS remains below the 2x hard limit.
7. Generate exactly three fresh production runs under the fixed artifact paths
   after all functional and security gates pass.

Allocation-only adoption can justify an intermediate batch when total phase
allocation falls by at least 10%, but it does not waive the final four-way 3%
proving-time requirement.

## Required phase accounting

Instrumentation is opt-in and must do no clock read, formatting, or allocation
when disabled. Accepted fresh reports bind the complete ordered phase-timing
array and four counters for both proof kinds. The intended buckets are:

- strict domain preparation and row construction;
- replay preparation;
- LVCS and DECS commitment;
- semantic-Q plan, evaluation, interpolation, and independent audit;
- each FS round's invariant prefix and sequential counter loop;
- formal DECS evaluation, leaf framing, leaf SHAKE, exact-leaf wrapping,
  internal hashing, and tree storage in benchmark-only detail;
- opening, canonical encoding, proving total, and verification total.

The validator projects these values directly from `report.json`; it does not
infer missing timings or counters.

## Exact-output evidence

The checked record is
`evidence/focused-v3-time-optimization.json`, SHA-256
`6804756ed1f29b4e01b585b77ee9c5efb78faf26030f10a06957ac5751a259e5`.
It binds the current 204-file issuance build-input snapshot with digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.
Its schema distinguishes:

- seven paired fixed-entropy trials per target, containing baseline/candidate
  proof and presentation digests, counters, time, allocations, and RSS. Each
  pair also binds an internal-trace digest framing the complete ordered domain,
  committed rows, leaf frames/hashes, roots/openings, FS digests, `R`, and
  `QPayload`; and
- three fresh optimized runs per target, containing report/resource and core
  artifact digests, phase timings, counters, verification/replay status,
  theorem vectors, canonical proof-wire components, paper components, and RSS.

For fixed entropy, digest equality and counter equality are authoritative. A
verification success alone cannot adopt a changed transcript. For fresh
entropy, a change in the sum of minimally encoded LEB128 counter bytes must be
marked `minimal_uleb128_value_dependent_width_v1`; otherwise the validator
fails. That explanation is forbidden when no such width variation exists.

The pending record now authenticates all six fresh runs, including their
report/resource and nested proof/presentation digests, exact component audits,
timings, counters, theorem vectors, verification, ZK eligibility, parameter
audit, and replay rejection. Those per-run audits demonstrate the required
128-bit phase condition; they do not override the separate BQ128
manifest-bound engineering-target mismatch described above. The record
contains no paired-run or allocation claim. Normal validation therefore still
rejects it. It can only be inspected explicitly with:

```sh
go run ./cmd/spruce-evidence focused-v3-time \
  --spruce-dir . \
  --allow-pending
```

Remove `--allow-pending` for final validation only after both pending blockers
are resolved. An accepted record additionally
recomputes the current issuance-build-input digest, checks every fixed artifact
path and digest, and requires the unchanged clean paper checkpoint.

## Fresh-run results

The following are independent scalar medians of exactly three authenticated
fresh production runs. MAD is the median absolute deviation of proving time.
The comparison uses the immutable final-size predecessor medians.

| Target | Issuance median / MAD | Change | Showing median / MAD | Change | Verification median, issue / show | Peak RSS median | RSS change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 1,349.588 / 36.483 ms | -20.93% | 2,902.833 / 97.182 ms | -21.39% | 499.882 / 273.419 ms | 369,393,664 B | -38.62% |
| WF128 | 521.758 / 4.210 ms | -28.44% | 1,256.464 / 8.127 ms | -11.59% | 241.098 / 148.445 ms | 194,871,296 B | -40.29% |

All four fresh proving medians are more than 3% below the predecessor medians.
Because the samples do not share entropy or counter vectors, this does not pass
the cumulative runtime gate. The seven-pair experiment is needed to separate
implementation cost from grinding-counter variation and to evaluate the 2%
per-phase regression rule.

The showing recorder existed in both epochs, so its unpaired component medians
also illustrate why the formal paired gate is essential. These values are
diagnostic only; in particular, round-four time is dominated by different
accepted counter samples.

| Showing component | BQ predecessor | BQ candidate | WF predecessor | WF candidate |
| --- | ---: | ---: | ---: | ---: |
| Row construction | 7.687 ms | 7.319 ms | 7.658 ms | 8.884 ms |
| Constraint/replay preparation | 98.072 ms | 80.768 ms | 99.006 ms | 83.441 ms |
| LVCS/DECS commitment | 1,580.123 ms | 1,586.056 ms | 547.612 ms | 574.101 ms |
| `BuildQAndMasks` | 1,176.538 ms | 1,155.468 ms | 553.817 ms | 546.709 ms |
| Round-four tail/opening | 303.280 ms | 7.945 ms | 16.610 ms | 4.973 ms |

The predecessor issuance recorder was attached after proof construction, so no
source-bound before/after issuance component table can be manufactured from
that evidence. Corrected issuance phase data is present in all three candidate
runs; the missing paired baseline is deliberately left as a blocker.

| Target/run | State | Issuance proof | Showing proof | Presentation | Issuance / showing paper | Issuance counters | Showing counters |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| BQ run 1 | 4,926 B | 51,748 B | 84,962 B | 84,995 B | 57,271 / 90,494 B | 21 / 10 / 655 / 6,997 | 40 / 39 / 2,860 / 10,986 |
| BQ run 2 | 4,926 B | 52,042 B | 84,718 B | 84,751 B | 57,271 / 90,494 B | 24 / 26 / 2,913 / 1,287 | 14 / 180 / 4,994 / 5,786 |
| BQ run 3 | 4,926 B | 51,503 B | 85,256 B | 85,289 B | 57,271 / 90,494 B | 9 / 25 / 632 / 773 | 19 / 70 / 5,231 / 7,081 |
| WF run 1 | 4,894 B | 21,984 B | 37,772 B | 37,813 B | 23,790 / 39,837 B | 0 / 0 / 5 / 14,065 | 3 / 0 / 1 / 21,299 |
| WF run 2 | 4,894 B | 21,752 B | 37,771 B | 37,812 B | 23,790 / 39,837 B | 3 / 0 / 6 / 52 | 0 / 0 / 2 / 4,242 |
| WF run 3 | 4,894 B | 21,456 B | 37,837 B | 37,878 B | 23,790 / 39,837 B | 0 / 0 / 5 / 10,760 | 1 / 0 / 6 / 8,610 |

Every run passed proof verification, its report-local 128-bit parameter audit,
ZK eligibility, and replay rejection. The aggregate
`gate-functional-presets` command nevertheless rejects BQ128 because showing
does not reach the distinct manifest-bound engineering target stated above.
State and paper-accounted transcript sizes are invariant.
Physical proof sizes vary because fresh Fiat--Shamir tails produce different
exact positional Merkle frontier node counts. BQ also has value-dependent
minimal-LEB128 counter-width variation; all three WF runs use five counter
bytes per phase. The evidence records both components and emits the explicit
counter-width explanation only for BQ. Neither is a codec, geometry, or
theorem change.

### Indicative one-run allocation profile

An overlay harness also captured one post-optimization allocation profile per
path with `GOMAXPROCS=15`, using the final production source and accepted
final-size run-1 artifacts. Random counters still vary between invocations.
These values are diagnostic only: they are not alternating, not seven-pair
medians, and therefore do not satisfy the formal allocation adoption gate.

| Path | Allocated bytes | Mallocs | Approximate prior allocation / mallocs | Indicative reduction |
| --- | ---: | ---: | ---: | ---: |
| BQ issuance | 278,032,584 B | 2,656,899 | ~739 MB / 3.31 M | 62.4% bytes / 19.7% mallocs |
| BQ showing | 748,198,984 B | 3,516,872 | ~3.52 GB / 24.12 M | 78.7% bytes / 85.4% mallocs |
| WF issuance | 129,744,768 B | 1,632,468 | ~321 MB / 1.87 M | 59.6% bytes / 12.7% mallocs |
| WF showing | 461,072,928 B | 2,308,581 | ~1.75 GB / 18.78 M | 73.7% bytes / 87.7% mallocs |

The magnitude is consistent with the intended semantic-Q and domain/LVCS
allocation reductions, but the evidence status remains pending until the
required paired allocation measurements replace this diagnostic snapshot and
the frozen BQ128 engineering-gate mismatch is resolved without weakening the
gate or changing the accepted security geometry.

## Remaining limitations

Even after an accepted speed result, the claim is narrow: no known output or
per-proof SmallWood-flow change under the tested strict-v3 contexts. Timing
equivalence does not prove complete credential-system security. Full-game
accounting remains deferred, the presets remain custom theorem
instantiations, and portable microarchitectural performance can vary on other
machines.
