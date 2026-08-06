# Preset Results

## Evidence Set

The seven non-target rows below are historical hard-v2 measurements generated
on 2026-08-04 from the working tree based on Git commit
`f8973f05473c9110081324a0f2671fa410fb12f3`. The working tree also contained
the local DECS hashing/Merkle buffering optimization; that optimization does
not change proof bytes, relation geometry, manifests, or theorem inputs.

Each of the nine presets was originally executed three times with
`benchmark-intgenisis-e2e`. The repository's evidence tool validated those
historical runs and generated:

```text
artifacts/smallwood-salted-v2/<canonical-id>/benchmark-intgenisis-e2e.json
artifacts/smallwood-salted-v2/<canonical-id>/benchmark-intgenisis-e2e-baseline.json
```

The canonical historical report is run 2. Historical timings below are
independent scalar medians of the three runs. For every preset, the evidence
tool reported stable bytes, geometry, security fields, and environment. The
runs used Go 1.23.12 on Darwin/arm64 with 15 logical CPUs and
`GOMAXPROCS=15`.

The historical-v2 lock now covers only the seven non-target presets. BQ128 and
WF128 retain their old rows below as baselines, but their executable manifests
select strict v3 and their current evidence is under `artifacts/smallwood-v3`.
Every preset still has `claim_scope=proof_only`; these measurements are
artifact results, not a complete-system security claim.

## Proof Sizes And Relation Rows

For historical v2, `proof_size_bytes` is a modeled verifier-message estimate;
it is not a serialized proof length. `Paper` is the optimized paper-transcript
accounting. The seven non-target values remain unchanged.

| Canonical preset | Issuance rows | Issuance modeled | Issuance paper | Showing rows | Showing modeled | Showing paper | Combined paper |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `poc-n512-sc96-v2` | 102 | 16,221 B | 15,283 B | 375 | 26,482 B | 23,963 B | 39,246 B |
| `artifact-n1024-sc125-v2` | 165 | 25,294 B | 23,926 B | 536 | 43,102 B | 40,150 B | 64,076 B |
| `artifact-n1024-bq10-r96-v2` | 165 | 20,127 B | 19,113 B | 600 | 36,983 B | 34,388 B | 53,501 B |
| `artifact-n1024-bq16-r96-v2` | 165 | 21,702 B | 20,592 B | 536 | 37,693 B | 35,000 B | 55,592 B |
| `pilot-n1024-bq32-r96-v2` | 165 | 26,341 B | 24,859 B | 600 | 44,222 B | 41,159 B | 66,018 B |
| `poc-n1024-bq64-r128-v2` | 165 | 42,239 B | 39,950 B | 600 | 68,220 B | 64,350 B | 104,300 B |
| `poc-n1024-bq96-r128-v2` | 165 | 55,305 B | 52,472 B | 600 | 87,386 B | 82,972 B | 135,444 B |
| `poc-n1024-bq128-r128-v3` | 165 | 65,353 B | 62,029 B | 600 | 101,159 B | 96,254 B | 158,283 B |
| `system-n1024-wf128-crom-v2` | 165 | 27,952 B | 26,515 B | 536 | 45,760 B | 42,739 B | 69,254 B |

The BQ128 and WF128 rows in that table are retained only as their v2 baselines.
They are not current serialized results and cannot be verified under the v3
target manifests.

## Current BQ128/WF128 Strict-v3 Sizes

Persistent state, both proof-wire columns, and presentation wire below are
actual canonical binary lengths. Paper bytes are separate mathematical
transcript accounting and are not described as serialized bytes. Values are
medians of three accepted end-to-end runs.

| Target | Persistent state | Issuance proof wire | Showing proof wire | Presentation wire | Issuance paper | Showing paper | Combined paper | Issuance / showing rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ128, `L=43`, R11/L4 | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 B | 90,494 B | 147,765 B | 49 / 423 |
| WF128, showing `L=41` | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 B | 39,837 B | 63,627 B | 49 / 423 |

The BQ artifact-gate expectations now use the accepted 90,494/147,765 B
showing/combined paper values. The previous 91,756/149,027 B constants were a
stale predecessor expectation; correcting them changes no security policy,
manifest, geometry, or transcript accounting.

The like-for-like baseline for this final-size epoch is the accepted codec-5
non-research epoch:

| Target | Prior state | Prior issuance proof | Prior showing proof | Prior presentation | Prior issuance / showing paper |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 52,385 B | 86,801 B | 86,834 B | 57,271 / 91,756 B |
| WF128 | 4,894 B | 22,050 B | 38,068 B | 38,109 B | 23,790 / 39,837 B |

Thus BQ128 saves 490 B on issuance proof wire and 2,084 B on both showing and
presentation wire. WF128 saves 330 B on issuance and 132 B on
showing/presentation. Persistent state is unchanged. BQ paper-accounted
showing saves 1,262 B through R11/L4; Merkle unpadding does not change paper
accounting. WF paper accounting is unchanged.

The first measured strict-v3 structural implementation is retained as an older
historical comparison. Its first published paper totals were optimistic
because they mixed trimmed `R` with omitted `M`; the corrected paper columns
below charge full `R`, omit `M`, and use the correct `Q` dimension.

| Target | Prior state | Prior issuance proof | Prior showing proof | Prior presentation | Corrected prior issuance/showing paper | Prior showing rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 60,688 B | 91,490 B | 91,523 B | 65,296 / 96,098 B | 551 |
| WF128 | 4,894 B | 26,039 B | 40,319 B | 40,360 B | 27,655 / 41,933 B | 487 |

That earlier structural pass saved 262 B / 4,399 B on the BQ issuance/showing
proof wires and 104 B / 2,120 B on the WF wires. It remains a historical epoch,
not the current result. Its reduction came from eliminating 64 public-linear
showing rows, one then-derivable `Q` coefficient per extension-field limb, and
trusted-zero `VTargets` suffixes.

The frozen target baselines were:

| Target | Compact-JSON state | Issuance paper | Showing paper | Showing rows |
| --- | ---: | ---: | ---: | ---: |
| BQ128 | 37,084 B | 62,029 B | 96,254 B | 600 |
| WF128 | 37,074 B | 26,515 B | 42,739 B | 536 |

Against the older v2 table, the current combined paper totals are lower by
9,256 B for BQ128 and 5,627 B for WF128. That remains an epoch comparison, not
the primary optimization delta: strict v3 also corrected the undersized mask
matrix and the full-`R`/omitted-`M` accounting. The immediately preceding
strict-v3 table above is the appropriate current before/after comparison.

The old compact JSON presentation medians were 6,756,367 B and 5,431,063 B,
respectively; those envelope sizes are historical diagnostics, not proof-wire
baselines. Component accounting and exact run records are in
[`docs/CREDENTIAL_SIZE_OPTIMIZATION.md`](docs/CREDENTIAL_SIZE_OPTIMIZATION.md).

WF128 showing `LVCSNCols=41` was adopted in the preceding strict-v3 pass. The
showing relations are now 423 rows for both targets. The current source-only
issuance relation replaces 165 core/view rows by 49 rows in both targets: 15 paired
ordinary-message carriers, two raw reserved/seed-tail rows, 16 paired `S`
carriers, and 16 paired `E` carriers. All 1,024 commitment coordinates remain
constrained. No parameter search or grinding trade was made: BQ128 κ remains
`[5,6,12,13]`, WF128 κ remains `[1,0,2,13]`, and neither target changed
`NLeaves`, query caps, salt/tape/hash widths, or nonce/seed sizes.

## Proof Timings

These timings cover proof construction and proof verification only. They
exclude public-parameter setup, NTRU key generation, holder/issuer file I/O,
and other end-to-end setup stages. They are medians of three runs on the
machine described above and should not be treated as portable performance
guarantees.

| Canonical preset | Issuance prove | Issuance verify | Showing prove | Showing verify |
| --- | ---: | ---: | ---: | ---: |
| `poc-n512-sc96-v2` | 231.2 ms | 42.1 ms | 655.4 ms | 117.3 ms |
| `artifact-n1024-sc125-v2` | 485.5 ms | 81.6 ms | 1,762.6 ms | 362.3 ms |
| `artifact-n1024-bq10-r96-v2` | 579.3 ms | 120.2 ms | 1,955.0 ms | 367.4 ms |
| `artifact-n1024-bq16-r96-v2` | 363.8 ms | 67.2 ms | 1,913.8 ms | 304.0 ms |
| `pilot-n1024-bq32-r96-v2` | 658.9 ms | 147.4 ms | 2,108.6 ms | 455.4 ms |
| `poc-n1024-bq64-r128-v2` | 1,379.9 ms | 392.7 ms | 3,842.6 ms | 921.1 ms |
| `poc-n1024-bq96-r128-v2` | 1,266.6 ms | 226.4 ms | 3,144.4 ms | 929.3 ms |

Independent scalar medians need not all come from the same run. The sidecar
for each historical preset records all run timestamps and SHA-256 digests.
The seven rows above are preserved historical-v2 results.

The current strict-v3 proof-time pass compares against the immutable accepted
final-size predecessor medians:

| Target/phase | Predecessor prove | Fresh candidate prove | Nominal unpaired change | Fresh MAD | Fresh verify |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128 issuance | 1,706.772 ms | 1,349.588 ms | -20.93% | 36.483 ms | 499.882 ms |
| BQ128 showing | 3,692.639 ms | 2,902.833 ms | -21.39% | 97.182 ms | 273.419 ms |
| WF128 issuance | 729.139 ms | 521.758 ms | -28.44% | 4.210 ms | 241.098 ms |
| WF128 showing | 1,421.167 ms | 1,256.464 ms | -11.59% | 8.127 ms | 148.445 ms |

Peak-RSS medians nominally fell from 601,784,320 B to 369,393,664 B (-38.62%)
for BQ and from 326,336,512 B to 194,871,296 B (-40.29%) for WF. All four
unpaired timing comparisons are numerically greater than 3%, but this does not
pass the formal performance/adoption gate. The predecessor and candidate runs
use independent entropy and counters; accepted Fiat--Shamir counter variability
can materially affect top-level proving time. Runtime direction remains
unestablished until seven fixed-entropy alternating predecessor/candidate pairs
are measured. The three fresh runs per target were:

| Target/run | Issuance prove | Showing prove | Peak RSS | Verification/replay |
| --- | ---: | ---: | ---: | --- |
| BQ128/1 | 1,313.105 ms | 2,785.502 ms | 369,557,504 B | pass |
| BQ128/2 | 1,349.588 ms | 2,902.833 ms | 369,393,664 B | pass |
| BQ128/3 | 1,432.924 ms | 3,000.015 ms | 368,394,240 B | pass |
| WF128/1 | 521.758 ms | 1,233.894 ms | 194,871,296 B | pass |
| WF128/2 | 517.548 ms | 1,256.464 ms | 196,788,224 B | pass |
| WF128/3 | 549.270 ms | 1,264.591 ms | 194,772,992 B | pass |

The retained implementation batches are exact Fiat--Shamir prefix reuse,
prepared-domain/provenance and lazy-NTT reuse, a shared formal-degree helper,
semantic-Q `Into` operations and worker-local arenas, cached replay plans and
structural semantic metadata, and fused implicit-preorder exact-`N` Merkle
storage. Production DECS uses the established combined evaluator. The
structurally selected portable row-major candidate is provisional R&D exposed
only by an explicit internal test constructor; it is not adopted without the
missing paired gate. Existing tiled DECS modes, fixed DECS frame templates, and
DECS-frame SHAKE-prefix cloning were rejected by measurement. Pure template
framing was 59--107% slower; whole-hash templating had no stable cross-target
3% win; SHAKE cloning added 448 B and one allocation per hash and was generally
slower. Exact byte/hash equivalence passed. The R&D record is
`tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/RESULTS.md`.
No κ, `NLeaves`, corrected projected work, `NDECS*eta`, relation, width,
query-cap, randomness, or tape/salt/seed knob was changed.

Fresh proof/presentation wires varied within 51,503--52,042 / 84,718--85,256 /
84,751--85,289 B for BQ issuance/showing/presentation and 21,456--21,984 /
37,771--37,837 / 37,812--37,878 B for WF. This is expected: independent
entropy changes both the exact Merkle-frontier node count and minimal-LEB128
counter widths. It is not a format or geometry change. Persistent state and
paper issuance/showing values remain fixed at 4,926 B and 57,271/90,494 B for
BQ, and 4,894 B and 23,790/39,837 B for WF.

The raw runs are in
`artifacts/smallwood-v3/time-optimization-v1/{bq128,wf128}/run-{1,2,3}`.
All six reports bind source-input digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.
Machine-readable time-optimization evidence has two blockers. The seven fixed-
entropy alternating baseline/candidate end-to-end pairs and allocation records
have not yet been generated, so formal runtime direction is unestablished.
Separately, the all-nine functional gate reports
BQ issuance/showing algebraic totals of 131.548362/131.511683 bits against the
manifest-bound 131.540568-bit engineering high-watermark, so showing misses by
0.028885 bits. The actual required 128-bit per-phase audit passes—BQ showing
has 3.511683 bits of slack—and its proof, parameter audit, and replay checks
pass. Fixed-entropy byte equality remains authoritative for transcript
preservation. No preset, manifest, geometry, or accounting term is changed.
The result remains `claim_scope=proof_only`; it is neither a full-game nor a
QROM claim.

## Theorem Accounting

The phase columns are the executed SmallWood one-proof theorem totals. The
`One issuance + one showing` column is the report's conservative current-
theorem composition of exactly one accepted issuance and one accepted showing,
including the global random-oracle collision term. It remains report-only
because the repository does not yet have a reviewed simultaneous-extraction
and complete-system theorem.

| Canonical preset | RO scope per domain | Issuance theorem | Showing theorem | One issuance + one showing | Ledger status |
| --- | --- | ---: | ---: | ---: | --- |
| `poc-n512-sc96-v2` | `Q_i = 1` | 96.010 bits | 96.010 bits | 95.010 bits | `proof_only` |
| `artifact-n1024-sc125-v2` | `Q_i = 1` | 125.023 bits | 125.019 bits | 124.021 bits | `proof_only` |
| `artifact-n1024-bq10-r96-v2` | `Q_i <= 2^10` | 96.091 bits | 96.091 bits | 95.089 bits | `proof_only` |
| `artifact-n1024-bq16-r96-v2` | `Q_i <= 2^16` | 96.028 bits | 96.020 bits | 94.996 bits | `proof_only` |
| `pilot-n1024-bq32-r96-v2` | `Q_i <= 2^32` | 99.228 bits | 99.228 bits | 97.986 bits | `candidate` |
| `poc-n1024-bq64-r128-v2` | `Q_i <= 2^64` | 131.248 bits | 131.248 bits | 130.003 bits | `proof_only` |
| `poc-n1024-bq96-r128-v2` | `Q_i <= 2^96` | 131.261 bits | 131.261 bits | 130.013 bits | `proof_only` |

The seven rows above are the unchanged historical-v2 values. Current strict-v3
target accounting is:

| Target | Issuance theorem | Showing theorem | Claim scope |
| --- | ---: | ---: | --- |
| BQ128 | 131.251460 bits | 131.251460 bits | `proof_only` |
| WF128 | 128.060024 bits | 128.421260 bits | `proof_only` |

These are applicable per-proof SmallWood terms. Full-game credential
composition remains deferred; this is neither a QROM nor a deployment claim.

`Q_0` counts DECS/Merkle random-oracle queries and `Q_1` through `Q_4`
count the four Fiat-Shamir domains. A bounded-query label is a theorem resource
assumption, not an enforceable online request limit. The WF profile targets a
classical random-oracle work factor instead of a fixed bounded-query residual;
its generated ledger remains candidate/proof-only.

The historical `candidate` ledger status for BQ32 does not change its
`claim_scope`: all nine presets are proof-only. Current blockers include the
report-only multi-proof composition and missing reviewed complete-system game,
MSIS-binding, and lattice-signature accounting.

## Transcript Widths

| Canonical preset | DECS/Merkle hash | Independent leaf tape | Global salt | Collision width | Query-cap log2 |
| --- | ---: | ---: | ---: | ---: | --- |
| `poc-n512-sc96-v2` | 144 bits | 144 bits | 512 bits | 144 bits | `0/0/0/0/0` |
| `artifact-n1024-sc125-v2` | 144 bits | 144 bits | 512 bits | 144 bits | `0/0/0/0/0` |
| `artifact-n1024-bq10-r96-v2` | 128 bits | 128 bits | 512 bits | 128 bits | `10/10/10/10/10` |
| `artifact-n1024-bq16-r96-v2` | 136 bits | 136 bits | 512 bits | 136 bits | `16/16/16/16/16` |
| `pilot-n1024-bq32-r96-v2` | 168 bits | 136 bits | 168 bits | 168 bits | `32/32/32/32/32` |
| `poc-n1024-bq64-r128-v2` | 264 bits | 200 bits | 200 bits | 264 bits | `64/64/64/64/64` |
| `poc-n1024-bq96-r128-v2` | 328 bits | 232 bits | 200 bits | 328 bits | `96/96/96/96/96` |
| `poc-n1024-bq128-r128-v3` | 392 bits | 264 bits | 200 bits | 392 bits | `128/128/128/128/128` |
| `system-n1024-wf128-crom-v2` | 264 bits | 128 bits | 256 bits | 264 bits | `0/0/0/0/0` |

The seven historical-v2 presets and both strict-v3 targets sample an
independent tape for every DECS leaf and disclose only tapes belonging to
opened leaves. They serialize no master tape seed. The proof-global salt,
transcript version, and commitment role are bound into every leaf, internal
node, and relevant challenge domain. Historical v2 retains its padded tree.
Strict v3 commits an exact-`N` largest-lower-power tree, binds `NLeaves` and
each interval/split, and transmits exactly the tail-derived positional
frontier without padding. The
strict-v3 target manifests bind their full public statement, field profile,
codec-6 profile, and exact-`N` topology at the configured widths above.

## Reproduction

The complete in-repository measurement workflow is documented in
[`evidence/README.md`](evidence/README.md). The current promoted
machine-readable projection still covers the six final-size BQ128/WF128 runs;
regenerate and validate it with:

```bash
go run ./cmd/spruce-evidence focused-v3-nonresearch \
  --spruce-dir . \
  --paper-dir ../Better-Lattice-based-Blind-Signatures \
  --measured-on 2026-08-04
go test ./evidence -run '^TestFocusedV3NonResearch' -count=1
go run ./cmd/issuance gate-artifact-presets \
  -artifact-dir artifacts/exact-byte-gate
```

Use `go run ./cmd/spruce-evidence baseline --spruce-dir .` only when
validating the seven historical-v2 three-run sets.

Those six promoted reports and resource sidecars are under:

```text
artifacts/smallwood-v3/nonresearch-optimization/bq128/run-{1,2,3}/
artifacts/smallwood-v3/nonresearch-optimization/wf128/run-{1,2,3}/
```

Their checked manifest/size/gate record is
[`evidence/focused-v3-nonresearch-optimization.json`](evidence/focused-v3-nonresearch-optimization.json).
The transcript-reduction and first size-optimization records remain frozen and
are not overwritten.

The fresh time-optimization reports and resource sidecars are under:

```text
artifacts/smallwood-v3/time-optimization-v1/bq128/run-{1,2,3}/
artifacts/smallwood-v3/time-optimization-v1/wf128/run-{1,2,3}/
```

Their exact build-and-run loop is in [`ARTIFACT.md`](ARTIFACT.md). They are
measured results, but their machine-readable successor must remain pending
until the seven fixed-entropy paired end-to-end/allocation records exist and
the BQ showing engineering high-watermark mismatch no longer prevents the
all-nine functional gate from passing.

The current record has SHA-256
`eeade3fe96a1fdcaff89016f964a3b34d12eb78692308752c5325c2141c04d59`.
Every raw report and the validator bind the same 202-file production build
snapshot,
`2b963f0ddebfa6c7ec80154a6c5b353c0dcbd94cbff3e929f3b4bf61830b6e16`,
so the measured dirty tree is identified independently of its base HEAD.

The evidence export command intentionally is not part of this local results
record because it writes generated material into a separate paper repository.
