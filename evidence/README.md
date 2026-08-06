# SPRUCE evidence

Evidence is intentionally split by epoch. `spruce-evidence` freezes the seven
non-target v2 preset manifests and their three-run
`benchmark-intgenisis-e2e` baselines into the deterministic
`spruce.paper-artifact-lock.v2` lock. BQ128 and WF128 have a separate checked
strict-v3 foundation record at
[focused-v3-size-optimization.json](focused-v3-size-optimization.json) and a
structural-reduction record at
[focused-v3-transcript-reduction.json](focused-v3-transcript-reduction.json).
The preceding non-research optimization record is
[focused-v3-nonresearch-optimization.json](focused-v3-nonresearch-optimization.json).
No evidence path rewrites or reinterprets results from another epoch.

## Publication-v4 exact-five evidence

The BQ96-32, BQ96-96, WF128, BQ128-64, and BQ128-128 family has a separate
fail-closed validator in `publication_v4.go`. A final batch is accepted only
with one content-addressed, boundary-expanded candidate lock; exactly 12
screening runs, two additional confirmation runs for each analytic top-three
candidate, and seven fresh final runs per preset (125 reports total). Median
and MAD summaries are recomputed only from the 35 final runs.

`ValidatePublicationV4BenchmarkArtifacts` strictly decodes the lock, batch,
and raw reports; rehashes every report, resource sidecar, candidate binding,
and all 15 regular artifact files; and checks replay/tamper gates, the actual
four Fiat--Shamir output widths in both phases, aggregate-Q versus WF128
accounting, canonical size projectors, geometry identities, allocations, peak
RSS, source/build/machine equality, cyclic order, and live-manifest adoption.
It does not add these five presets to either the historical-v2 lock or the two
focused-v3 records.

The current record is
[focused-v3-final-size-optimization.json](focused-v3-final-size-optimization.json).
It binds three codec-6 runs per target, the exact unpadded Merkle frontier,
BQ128 R11/L4 compiler geometry, manifest digests, report/resource digests,
security gates, and the 2× accepted codec-5 resource limits.

The next, proof-time-only epoch is scaffolded at
[focused-v3-time-optimization.json](focused-v3-time-optimization.json). It is
currently `pending` and therefore makes no final accepted speed claim. It now
authenticates exactly three fresh optimized production runs per target, whose
proving medians pass the four-way 3% cumulative runtime gate. Final adoption
is blocked independently by (1) the missing seven alternating fixed-entropy
baseline/candidate pairs per target with allocation counters and (2) the
frozen BQ128 executable-preset engineering gate. BQ128 measures
`algebraic_total_bits=131.548362` for issuance and `131.511683` for showing;
the showing value is 0.028885 bits below the manifest-bound
`TargetTheoremBits=131.540568`. The required 128-bit phase gate still passes
with 3.511683 bits of showing slack, so this is a stricter engineering-target
mismatch, not a failure of the stated 128-bit phase requirement. No preset,
manifest, theorem accounting, or production gate is changed here.

Fixed-entropy proofs, presentations, all four counters, and the internal
transcript trace must be identical. The fresh runs bind source inputs, phase
timings, component sizes, theorem terms, report/resource and
proof/presentation digests, verification, ZK eligibility, and replay
rejection. See
[PROOF_TIME_OPTIMIZATION.md](../docs/PROOF_TIME_OPTIMIZATION.md).

Inspect the fail-closed partial evidence explicitly with:

```sh
go run ./cmd/spruce-evidence focused-v3-time \
  --spruce-dir . \
  --allow-pending
```

The command also checks that the adjacent paper checkout is still clean at the
recorded HEAD; use `--paper-dir` only when that checkout is elsewhere.

Final validation omits `--allow-pending`; it rejects the checked record until
both blockers above are resolved. The six fresh directories are under
`artifacts/smallwood-v3/time-optimization-v1/{bq128,wf128}/run-{1,2,3}`.
Regenerate their pending projection with
`--refresh-pending-fresh-runs --allow-pending`. Fresh minimal-LEB128
counter-width variation must carry the schema's explicit
value-dependent-width explanation and is never treated as a proof-format
change. Exact Merkle frontier sizes can also vary with fresh challenges and
are independently component-audited.

| Target | Fresh issuance / showing proving median | Change from predecessor | Fresh peak RSS median |
| --- | ---: | ---: | ---: |
| BQ128 | 1,349.588 / 2,902.833 ms | -20.93% / -21.39% | 369,393,664 B |
| WF128 | 521.758 / 1,256.464 ms | -28.44% / -11.59% | 194,871,296 B |

| Target | State | Issuance proof | Showing proof | Presentation | Issuance/showing paper |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128, R11/L4 | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B |
| WF128 | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B |

Raw reports are under
`artifacts/smallwood-v3/final-size-optimization-v2/{bq128,wf128}/run-{1,2,3}`.
Validate the checked summary and, when installed, every report/resource digest
with:

```sh
go test ./evidence -run '^TestFocusedV3FinalSizeOptimizationEvidence$' -count=1
```

## Previous codec-5 BQ128/WF128 evidence

`poc-n1024-bq128-r128-v3` and `system-n1024-wf128-crom-v2` use strict
manifest/transcript v3 and are excluded from the historical-v2 lock. WF128's
`-v2` suffix is part of its canonical identifier, not its active proof epoch.
Existing v2 reports for these two presets remain historical data and are never
matched against the current manifests or silently migrated.

The table reports independent scalar medians of three accepted codec-5 runs.
BQ wires were fixed. Minimal LEB128 counters made WF run 1 one byte larger
than runs 2 and 3; both states and paper accounting were fixed.

| Target | Persistent canonical state | Issuance canonical proof wire | Showing canonical proof wire | Canonical presentation wire | Paper transcript, issuance / showing |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 52,385 B | 86,801 B | 86,834 B | 57,271 / 91,756 B |
| WF128 (`LVCSNCols=41` showing) | 4,894 B | 22,050 B | 38,068 B | 38,109 B | 23,790 / 39,837 B |

These are four separate metric families: persistent credential-state bytes,
actual presentation-wire bytes, actual proof-wire bytes per phase, and
paper-accounted transcript bytes per phase. The baseline fields named
`modeled_*_verifier_message_bytes` are estimates only and are not wire sizes.

The current checked record contains three report and resource digests per
target, frozen κ, source-only issuance and adopted showing geometry, codec-5
wire identities, theorem bits, verification/replay and zero-knowledge flags,
and runtime/peak-memory medians. For every run it also fixes the exact ordered
15-file role/path set—public parameters, B matrix, holder secret, commitment
request, pre-sign submission, issue response, state, verifier key,
presentation, holder usage state, verifier state, and all four NTRU files—and
verifies each regular file's byte length and SHA-256 digest. Report/resource
digests and the nested issuance/showing proof digests are checked separately;
changing any of them therefore invalidates the local evidence bundle. All six
reports also bind the same 202-file Go build-input snapshot (including embedded
PRF parameters) with digest
`2b963f0ddebfa6c7ec80154a6c5b353c0dcbd94cbff3e929f3b4bf61830b6e16`;
the validator recomputes it from `go list`. The checked evidence JSON has
SHA-256
`eeade3fe96a1fdcaff89016f964a3b34d12eb78692308752c5325c2141c04d59`.
Its validator requires both targets to match the live manifests, every run to
pass, and each proving time and peak-memory measurement to remain within 2×
the accepted transcript-reduction median:

```sh
go test ./evidence -run '^TestFocusedV3NonResearch' -count=1
```

Raw reproduction reports and resource sidecars use these exact paths:

```text
artifacts/smallwood-v3/nonresearch-optimization/bq128/run-{1,2,3}/report.json
artifacts/smallwood-v3/nonresearch-optimization/bq128/run-{1,2,3}/resource.txt
artifacts/smallwood-v3/nonresearch-optimization/wf128/run-{1,2,3}/report.json
artifacts/smallwood-v3/nonresearch-optimization/wf128/run-{1,2,3}/resource.txt
```

Each run directory directly contains the fail-closed
`credential_state.intgenisis.v8`, issuance-v4 `presign_submission.json`,
`presentation.intgenisis.v3`, and usage-v3 `holder_usage_state.json`. The proof
objects retain schema 3 while their only accepted binary representation is
codec 5 (`SPRUCEP5`, grouped radix-`q`, pre-challenge constant-only Q kernel,
exact-`N` Merkle frontier). Target loaders reject codecs 3 and 4, legacy or
mixed-version files,
and retired PRF-companion metadata instead of migrating, normalizing, or
falling back to v2/debug verification. Exact reproduction commands are in
[ARTIFACT.md](../ARTIFACT.md).

The target evidence records `claim_scope=proof_only`. It supports the narrow
per-proof result; full-game accounting remains deferred.

Both preceding strict-v3 records are intentionally retained as before-data.
The current comparison baseline is the accepted transcript-reduction median:
BQ state/issuance/showing/presentation 4,926/60,426/87,091/87,124 B and
corrected paper 65,091/91,756 B; WF 4,894/25,935/38,199/38,240 B and corrected
paper 27,575/39,837 B.
The raw predecessor JSON retains 65,058/91,723 B and 27,558/39,820 B as
historical undercounts; it is not rewritten or accepted as current accounting.

Before and after this implementation, the sibling paper repository was clean
at `d19818571f04c8c12425e2e7c10ceb41f7a1762d`. The implementation and evidence
workflow writes no paper-repository file.

Regenerate the checked projection from the six fixed raw directories while
auditing the paper tree read-only with:

```sh
go run ./cmd/spruce-evidence focused-v3-nonresearch \
  --spruce-dir . \
  --paper-dir ../Better-Lattice-based-Blind-Signatures \
  --measured-on 2026-08-04
```

## Seven-preset historical-v2 paper lock

The historical lock also renders the paper's tracked
`generated/v2_macros.tex` and `generated/v2_tables.tex` inputs. It has no
wall-clock export timestamp and contains no absolute checkout paths.

For every canonical preset, run the benchmark three times and preserve its
reports at exactly:

```text
artifacts/smallwood-salted-v2/<canonical-id>/runs/run-01.json
artifacts/smallwood-salted-v2/<canonical-id>/runs/run-02.json
artifacts/smallwood-salted-v2/<canonical-id>/runs/run-03.json
```

No fourth JSON report is accepted in `runs/`. Aggregate all seven historical
v2 presets with:

```sh
go run ./cmd/spruce-evidence baseline --spruce-dir .
```

During incremental measurement, add
`--preset <exact-canonical-v2-preset-id>` to process one preset. The operation
strictly validates each report against its preset and requires identical byte,
geometry/relation, security, and environment projections. It then writes:

```text
artifacts/smallwood-salted-v2/<canonical-id>/benchmark-intgenisis-e2e.json
artifacts/smallwood-salted-v2/<canonical-id>/benchmark-intgenisis-e2e-baseline.json
```

The canonical report is a byte-for-byte copy of run 02; it is never rewritten
to look like a synthetic benchmark execution. The sidecar binds the SHA-256
digest and timestamp of every run and records independent scalar medians for
all six setup timings plus issuance/showing proving and verification timings.

Generate final evidence only after those canonical reports and sidecars exist:

```sh
go run ./cmd/spruce-evidence export \
  --spruce-dir . \
  --paper-generated-dir ../Better-Lattice-based-Blind-Signatures/generated
```

Final export revalidates each sidecar from its three run files, requires the
canonical report to still equal run 02, and binds all 21 run SHA-256 digests.
The lock records `run_count=3`, the
`independent_scalar_median_of_three_v2` aggregation identity, the sidecar
digests, and an independently domain-separated digest of the 21-run set.

For initial wiring only, `--allow-pending` emits a lock whose status is
explicitly `pending` and whose missing preset entries carry a reason. Final
validation rejects that lock unless the same bootstrap flag is supplied.

Validate the source tree, reports, lock digest, and tracked TeX with:

```sh
go run ./cmd/spruce-evidence validate \
  --spruce-dir . \
  --paper-generated-dir ../Better-Lattice-based-Blind-Signatures/generated
```

`--spruce-dir` may be omitted when `SPRUCE_DIR` is set. A non-default report
root can be selected with `--reports-dir`; relative report roots are resolved
below the SPRUCE checkout. No repository location is compiled into the tool.

JSON readers reject unknown fields, trailing values, non-v2 identities,
manifest mismatches, and report/preset transcript mismatches. The source-tree
digest covers protocol source, tests, scripts, parameter JSON, and repository
documentation while deliberately excluding `.git`, ignored `artifacts/`, and
the user-owned `TODO.md` and `results.md` notes.

Final report ingestion also requires exact independent-selective tape
accounting (`tape_bytes`, count and width), leaf-encoding version 2, full root
width, and a live zero-knowledge-eligibility result. Those values are copied
into the lock rather than inferred from a preset.
