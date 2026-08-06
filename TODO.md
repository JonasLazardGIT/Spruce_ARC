# Current Work

## Hard-v2 Transcript Alignment: Complete

The earlier DECS alignment work is implemented in the current hard-v2 epoch.
The maintained transcript now:

- samples an independent random tape for every DECS leaf;
- serializes only tapes belonging to opened leaves and no master tape seed;
- samples the global proof salt before the DECS commitments;
- binds the salt, transcript version, and commitment role into leaf, internal-
  node, padding-node, and challenge encodings;
- uses full-width Merkle roots and indices wider than 16 bits;
- rejects legacy or mixed tape/seed representations; and
- reports the measured tape count, tape width, disclosure mode, leaf encoding,
  and zero-knowledge eligibility.

The corresponding unit and integration tests cover salt/tape tampering,
indices 65,535 and 65,536, opening merges, serialization, full-width roots,
and end-to-end replay rejection.

## BQ128/WF128 Strict-v3 Final Size Optimization: Complete

The focused strict-v3 path is implemented for
`poc-n1024-bq128-r128-v3` and `system-n1024-wf128-crom-v2`. It includes:

- exact SHAKE-256 rejection sampling and direct full-statement transcript
  binding;
- trusted field profiles, corrected Eq. (2) mask geometry, randomized witness
  extra-point values, and one shared semantic relation evaluator;
- the input-trace Poseidon relation and proved base-9 packing of the bounded
  `mu_sig`, `x0`, and `x1` sources;
- direct substitution of the public-linear `mu_sig` and `x0` transforms into
  the signature aggregate, while retaining the nonlinear `x1`/`Z` chain;
- a 49-row source-only issuance relation with paired `M`, `S`, and `E`
  carriers, a raw reserved/seed tail, and all 1,024 full-ring commitment
  residuals;
- a challenge-bound aggregate evaluator that is coefficient-for-coefficient
  identical to complete `Q` from the independent 1,024-residual formal oracle,
  but does not materialize those residual polynomials in production;
- a schema-3/codec-6 proof boundary with grouped radix-`q` encoding and one
  derivable `Q` coordinate per extension-field limb: its constant coefficient
  is fixed before the evaluation challenge by the support-sum identity;
- exact-`N` largest-lower-power Merkle commitments, with the exact positional
  frontier derived from the Fiat–Shamir tail and no transmitted padding;
- BQ128 R11/L4 shortness, accepted only after compiler-derived degree,
  mask/query/opening, theorem, ZK, time, and memory gates passed;
- trusted ragged `VTargets`, reconstructed to the original dense transcript;
- complete verifier-reconstructed `RowLayout` binding in the v3 public
  statement;
- fail-closed schema-3 proof/presentation semantics, proof codec 6, and the
  state-v8 codec; retired PRF-companion metadata and codec-3/codec-4 target
  artifacts are rejected;
- an exact `go list` build-input digest in every raw report and the checked
  evidence, covering untracked production sources and embedded PRF parameters
  rather than identifying a dirty tree by its base HEAD alone; and
- three accepted issuance/showing runs per target, including canonical bytes,
  paper accounting, theorem terms, wall time, peak RSS, verification, and
  replay rejection.

Final measured medians are:

| Target | State | Issuance proof | Showing proof | Presentation | Issuance/showing paper | Issuance/showing rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B | 49 / 423 |
| WF128 | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B | 49 / 423 |

Relative to the accepted codec-5 medians, this pass removes 490 B / 2,084 B
from BQ issuance/showing proof wire and 330 B / 132 B from WF. Presentation
savings equal showing-proof savings. BQ showing paper falls by 1,262 B; other
paper totals and persistent state are unchanged. The old
epochs, including the corrected full-`R`/omitted-`M` accounting, remain frozen
as historical evidence rather than being rewritten.

WF128 showing adopted `LVCSNCols=41`; BQ128 retained `LVCSNCols=43` because
the frozen search found no strictly eligible measured improvement. This work
did not trade size for grinding: the target κ arrays, `NLeaves`, query caps,
corrected projected work, `NDECS*eta`, cryptographic widths, salt/tape widths,
and nonce/seed sizes did not increase. The seven non-target presets and all of
their historical-v2 results remain unchanged.

## BQ128/WF128 Proof-Time Optimization: Implemented, Promotion Blocked

The strict-v3 issuance/showing optimization is implemented. Retained work
includes corrected permanent phase instrumentation, exact Fiat--Shamir prefix
cloning with a generic-XOF fallback, one immutable bound prepared domain,
trusted strict-row provenance, lazy NTT materialization, a shared formal-degree
validator, semantic-Q `Into` arithmetic and worker-local arenas, structural
semantic metadata and cached replay plans, and fused implicit-preorder exact-
`N` Merkle storage. Production DECS keeps the established combined evaluator.
The structurally selected row-major candidate remains available only through
an explicit internal test constructor and is not adopted pending the paired
gate. Existing tiled DECS modes, fixed frame templates, and DECS-frame SHAKE-
prefix cloning were measured and rejected. The template R&D preserved exact
bytes/hashes, but pure framing was 59--107% slower, whole-hash templating had no
stable cross-target 3% win, and SHAKE cloning added 448 B plus one allocation
per hash. Its record is at
`tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/RESULTS.md`.

The fresh three-run medians are:

| Target | Issuance prove | Showing prove | Proving MADs | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| BQ128 | 1,349.588 ms (-20.93%) | 2,902.833 ms (-21.39%) | 36.483 / 97.182 ms | 369,393,664 B (-38.62%) |
| WF128 | 521.758 ms (-28.44%) | 1,256.464 ms (-11.59%) | 4.210 / 8.127 ms | 194,871,296 B (-40.29%) |

Verification medians are 499.882/273.419 ms for BQ issuance/showing and
241.098/148.445 ms for WF. Relative to the predecessor medians, all four fresh
unpaired comparisons are nominally greater than 3%; this does not pass the
performance/adoption gate. Independent entropy produces different accepted
Fiat--Shamir counters, whose variability can materially affect top-level
proving time. Runtime direction remains unestablished until the seven fixed-
entropy alternating pairs are measured. Kappa, geometry, paper sizes,
persistent state, randomness, and transcript rules are unchanged. Fresh proof/
presentation lengths may vary with the challenge-dependent exact frontier and
minimal-LEB128 counter widths; the fixed-entropy byte-equality tests are
authoritative.

Two promotion blockers remain:

1. Generate the seven alternating fixed-entropy baseline/candidate end-to-end
   pairs and allocation records.
2. Resolve, without changing the frozen target, manifest, geometry, or
   accounting, the all-nine functional-gate mismatch: BQ issuance/showing
   algebraic totals are 131.548362/131.511683 bits, while the manifest-bound
   engineering high-watermark is 131.540568 bits. Showing misses that
   engineering target by 0.028885 bits.

The actual required 128-bit phase audit passes: BQ showing retains 3.511683
bits of slack, and its proof, parameter audit, and replay checks pass. Thus the
three-run timings remain valid as unpaired measurements, but the runtime
direction, `gate-functional-presets`, and machine-readable promotion are not
established. Details are in
[`docs/PROOF_TIME_OPTIMIZATION.md`](docs/PROOF_TIME_OPTIMIZATION.md) and
[`docs/PROOF_TIME_PROFILE.md`](docs/PROOF_TIME_PROFILE.md).

## Current Evidence

The seven non-target canonical presets retain their accepted three-run
historical-v2 evidence under:

```text
artifacts/smallwood-salted-v2/<canonical-id>/
```

The accepted focused strict-v3 reports and resource records are under:

```text
artifacts/smallwood-v3/final-size-optimization-v2/bq128/run-{1,2,3}/
artifacts/smallwood-v3/final-size-optimization-v2/wf128/run-{1,2,3}/
```

The fresh proof-time runs are under:

```text
artifacts/smallwood-v3/time-optimization-v1/bq128/run-{1,2,3}/
artifacts/smallwood-v3/time-optimization-v1/wf128/run-{1,2,3}/
```

All six reports bind source-input digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.

Exact sizes, median timings, theorem values, transcript widths, and claim
status are summarized in [`results.md`](results.md). Focused machine-readable
metadata is in `evidence/focused-v3-nonresearch-optimization.json`; the
preceding records remain in `evidence/focused-v3-transcript-reduction.json`
and `evidence/focused-v3-size-optimization.json`. The time-optimization
machine-readable successor is intentionally still pending both the seven
paired fixed-entropy/allocation records and the BQ showing engineering
high-watermark mismatch in the all-nine functional gate.

## Deferred Security Work

Every maintained preset remains `claim_scope=proof_only`. Before promoting any
preset, the following require written, reviewed arguments and evidence:

1. Prove adaptive multi-proof/simultaneous extraction for issuance and showing
   under the actual shared random-oracle transcript.
2. Replace accepted-proof-only composition with an adversarial-attempt and
   global-query theorem for the declared user, context, proof, and tag scope.
3. Finalize challenge-bias and random-oracle programming-conflict accounting.
4. Supply reviewed MSIS-binding and lattice-signature/IntGenISIS security
   estimates with exact reduction losses and provenance.
5. Review the zero-knowledge, blindness, soundness, and unlinkability hybrids
   against the implemented bounded-source relation and context/slot policy.
6. Keep the security model explicitly CROM. A QROM claim requires a separate
   theorem.

These tasks remain intentionally deferred. Completing the strict-v3 per-proof
path does not complete the credential-system game or authorize a stronger
claim than `proof_only`.

## Optimization Boundary

For the seven historical-v2 presets, safe work without a new theorem remains
limited to implementation-only changes that preserve byte-identical
transcripts, relation geometry, manifests, and security inputs. Every such
change should be checked against the three-run baseline and exact-byte gates.

The reviewed input-trace and base-9 packing arguments apply only to the two
strict-v3 targets. Extending them to another preset requires a fresh compiled
relation audit and evidence; their presence here is not a generic license to
pack or omit witness rows.

The following are research changes and must not be enabled in a canonical
preset merely to improve a size table:

- changing the strict-v3 carrier encoding, lane decoders, fused public-linear
  substitutions, or retained `x1`/`Z` bindings without preserving the local
  implication/extractability proof;
- omitting independently necessary `VTargets` or any `BarSets` values; only
  trusted all-zero suffixes are currently absent from the wire;
- trimming executed `R` or any further `QPayload` coordinate without a
  separate derivability proof;
- PRF hole-sharing: only 16 unused source holes exist while the next showing
  row reduction needs 29, and selector-weighted nonlinear reuse would raise
  the unaccounted degree;
- two-round Poseidon folding or other degree-9 cross-lane folds, which are not
  covered by the current local input-trace lemma or compiler degree audit;
- using valid-prefix query discounts not covered by the current theorem;
- changing SmallWood degree, row, opening, or query accounting without a
  compiler-backed relation audit and updated theorem; or
- replacing independent leaf tapes with seed-derived pseudorandom tapes.

## Evidence Maintenance

After any protocol, relation, parameter, or transcript change:

1. Run the full Go tests, race checks for affected concurrent code, vet,
   static analysis, and builds.
2. Run `gate-functional-presets` for all nine canonical IDs.
3. Generate exactly three fresh reports for each affected preset using the
   layout documented in [`evidence/README.md`](evidence/README.md); do not
   replace the seven historical-v2 sets when they are unaffected.
4. For a BQ128/WF128 strict-v3 change, run `go run ./cmd/spruce-evidence
   focused-v3-nonresearch --spruce-dir . --paper-dir
   ../Better-Lattice-based-Blind-Signatures --measured-on YYYY-MM-DD`; this
   command audits the paper checkout read-only and validates the complete
   15-file bundle in each of the six fixed run directories.
   For a historical-v2 change, run
   `go run ./cmd/spruce-evidence baseline --spruce-dir .` instead.
5. Run `gate-artifact-presets` and deliberately update its expected bytes only
   when the reviewed change is supposed to alter the transcript.
6. Refresh [`results.md`](results.md), [`README.md`](README.md),
   [`ARTIFACT.md`](ARTIFACT.md), and [`docs/SECURITY.md`](docs/SECURITY.md) from
   the canonical reports rather than from estimates.

Do not run the evidence export step unless changes to the separate paper
repository are explicitly authorized.
