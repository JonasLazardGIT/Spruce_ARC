# SPRUCE targeted acceleration v1

## Outcome and boundary

The earlier broad acceleration experiment was rolled back to the exact pre-acceleration recovery snapshot before this implementation began. The rollback comparison reported no material differences, including file modes, outside `.git` and cache data. The preserved recovery bundles are:

- Pre-acceleration baseline: `/Users/jolaz/Desktop/ARC/.spruce-safety/acceleration-v1.20260806.7915928cc12e`
- Discarded broad implementation: `/Users/jolaz/Desktop/ARC/.spruce-safety/pre-targeted-acceleration.20260806.61963fea35af`

This implementation changes execution only. It does not change a publication-v4 preset, manifest digest, Fiat--Shamir width, transcript domain, proof schema, canonical wire format, relation, salt, tape, or historical artifact. The paper repository was not modified.

The accepted machine-local latency policy is 15 bounded workers, 32-leaf dynamic DECS chunks, 15 semantic workers, 15 issuance-plan workers, a warm immutable canonical context, and the generic SHAKE backend. The zero-value execution policy remains the compatibility path and preserves the historical static DECS partition and eight-worker semantic limit.

## Implemented changes

### Fixed-input evidence and controls

`benchmark-intgenisis-e2e` now accepts `-execution-profile baseline|candidate`, worker controls, `-decs-chunk-leaves`, and `-context-mode cold|warm`. Deterministic entropy is deliberately not a public CLI option. A guarded benchmark-child environment derives one SHAKE stream from a fresh 256-bit seed and records only its SHA-256 digest. Production commands retain `crypto/rand.Reader`.

The report binds the execution policy, context mode, ARM64 SHA3 capability, source tree, binary, machine, preset manifest, configured FS width, and four observed FS widths. Baseline and candidate reports in the accepted set share one source digest and build digest.

### Dynamic DECS work queue

DECS retains one long-lived goroutine and one reusable evaluator/SHAKE scratch arena per worker. With a positive chunk size, workers claim monotonically indexed leaf ranges from an atomic counter. Every result is still written to its canonical leaf index, so scheduling order cannot change a leaf, Merkle root, opening, or transcript. Zero chunks retain the old equal-range behavior.

The representative boundary sweep tested 8, 16, 32, 64, 128, and 256 leaves per chunk after the worker sweep. Thirty-two leaves was faster than both 16 and 64, so the selected point is interior to the tested interval.

### Issuance semantic plan

The challenge-dependent aggregate plan is partitioned by independent `(block, limb)` outputs plus public limbs. Each job owns disjoint destination slices. The hot loop uses the existing exact LVCS reciprocal/Barrett reducer rather than repeated `bits.Div64`. Gamma validation is serial and fail-closed before workers begin. When an in-place aggregate factory is available, semantic setup constructs that plan once rather than constructing an unused allocating duplicate.

The final same-source paired median reduction for this phase is 91.84--92.12% across the five presets.

### Showing semantic evaluation

The hard eight-worker cap is retained for compatibility policy and lifted only by an explicit execution policy. The relation wrapper now carries the existing issuance `EvalParallelInto` and `AggregateDotInto` implementations and a real showing `CoreKIntoEvaluator`. A showing worker binds its output buffers on first use and rejects scratch reuse with different backing storage. Bridge aggregate outputs write directly into worker-owned storage.

At embedded interpolation points, structurally base-field coefficients use linear `ScaleBaseInto`, `AddMulBaseInto`, and the new differentially tested `SubMulBaseInto` primitive instead of full quadratic extension-field multiplication. The generic full-
`K` path remains authoritative for the non-embedded audit point. The paired median showing semantic reduction is 39.85--41.27%.

### Prepared canonical context

`PreparedExecutionContext` owns a deep copy of public inputs and validated canonical/replay geometry. Its binding digest includes the proof kind, codec, modulus, leaf count, canonical public statement, domain, relation/layout data, preset extras, field profile, PRF binding, and FS policy reached through the trusted context. Execution policy, phase recorder, and mutation hooks are excluded because they are operational rather than cryptographic.

Prepared marshal and unmarshal entry points preserve the wire exactly. The benchmark prepares once and reuses the context for issuance and showing encode/decode; cold mode remains available. All five preset context digests are distinct, and changing only the worker policy leaves a digest unchanged. One fixed-input cold/warm pair per preset showed total preparation-plus-encode-plus-decode savings of 20.5--33.4 ms for issuance and 30.3--85.4 ms for showing.

This is public deterministic precomputation. It contains no credential, witness, salt, tape, mask, or proof randomness. No request-independent showing commitment was added: presentation context, slot, and fresh proof randomness remain request-dependent.

## Same-source paired results

The table reports medians of seven fixed-input baseline/candidate pairs. “Gain” is the median of the seven paired percentage changes, not a percentage recomputed from unrelated historical medians.

| Preset | Issuance baseline | Issuance candidate | Issuance gain | Showing baseline | Showing candidate | Showing gain |
|---|---:|---:|---:|---:|---:|---:|
| BQ96-32 | 874.3 ms | 674.9 ms | 15.53% | 2433.1 ms | 2183.1 ms | 9.86% |
| BQ96-96 | 790.8 ms | 636.8 ms | 22.20% | 2526.0 ms | 2152.9 ms | 14.92% |
| WF128 | 904.7 ms | 761.2 ms | 14.25% | 2368.5 ms | 2115.8 ms | 10.87% |
| BQ128-64 | 833.3 ms | 653.8 ms | 21.27% | 2510.1 ms | 2135.2 ms | 15.07% |
| BQ128-128 | 965.8 ms | 744.6 ms | 23.24% | 3264.8 ms | 2749.9 ms | 17.43% |

Every showing pair and 34 of 35 issuance pairs were faster. Median total allocation changes were only +0.039% to +0.069%. Verifier timing moved within noise: no median paired regression exceeded 1.27%, and the execution policy does not alter verifier arithmetic.

The broader change relative to the previously accepted publication executable is larger, but that comparison crosses source digests and is therefore historical context rather than promotion evidence. The accepted evidence above deliberately compares baseline and candidate from the same final source and binary.

## Correctness and security evidence

For every preset, seven secure seeds produced a baseline/candidate pair. All 35 pairs had byte-identical complete canonical pre-sign submissions and byte-identical binary presentations. Each report passed issue, show, verification, canonical reconstruction, artifact hash, replay rejection, and tamper rejection. The four observed FS outputs were exactly 168, 296, 256, 264, and 392 bits for the respective five presets. All frozen publication-v4 manifest digests are unchanged.

Targeted race tests passed for DECS dynamic scheduling, semantic workers, parallel aggregate construction, prepared contexts, and guarded entropy. `go test ./...` passed every package except the three restored, pre-existing focused-v3 evidence gates: two reject the intentionally dirty paper checkout, and one rejects the stale focused-v3 timing fixture for a missing `showing.replay_preparation` field. No validation was weakened to hide those failures.

## Architecture-specific and throughput decisions

The M5 Pro advertises ARM SHA3 instructions, but the repository has no audited ARM64 SHAKE implementation. `arm64` backend selection therefore fails closed and the accepted profile records `generic`. No NEON formal evaluator was added: after portable changes, it still requires a separately reviewed assembly implementation and new profiling. Neither speculative gain is included in the result table.

A separate three-run diagnostic launched two independent BQ128-128 flows with 7+8 workers. Median aggregate wall time fell from 18.560 s sequential to 10.915 s concurrent, a 41.19% throughput gain. However, per-flow showing latency increased by about 16.6--18.3%, exceeding the 15% guard. The split is therefore not promoted as a default; it remains an explicit service-throughput experiment.

## Reproduction

Build once, then run an ordinary warm candidate measurement:

```text
go build -o ./issuance ./cmd/issuance
./issuance benchmark-intgenisis-e2e \
  -preset publication-n1024-bq-r128-q128-v4 \
  -execution-profile candidate \
  -workers 15 \
  -decs-chunk-leaves 32 \
  -context-mode warm \
  -artifact-dir <unique-directory> \
  -json-out <report.json>
```

Use `-execution-profile baseline -context-mode cold` for the compatibility comparison. The fixed-input child environment is intentionally undocumented as a user-facing production control; its guarded implementation and tests are retained solely for the evidence harness.

Raw reports, exactness copies, cold/warm artifacts, and throughput reports are under [`artifacts/publication-v4/targeted-acceleration-v1/72ddb2893e8c452f`](../artifacts/publication-v4/targeted-acceleration-v1/72ddb2893e8c452f). The machine-readable summary is `evidence-summary.json` in that directory.
