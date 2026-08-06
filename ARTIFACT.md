# SPRUCE Artifact Guide

This is the reviewer guide for SPRUCE's seven historical-v2 presets and the
strict-v3 BQ128/WF128 targets. The supported surface is `cmd/issuance`,
`cmd/showing`, the canonical preset registry, the Go test suite, functional
gates, and generated benchmark reports.

Every preset is experimental and has the proof-only claim scope. A successful
run demonstrates execution and verification of the encoded relations under
the selected manifest; it does not establish deployment security.

## Supported Presets

Only these canonical identifiers are accepted:

```text
poc-n512-sc96-v2
artifact-n1024-sc125-v2
artifact-n1024-bq10-r96-v2
artifact-n1024-bq16-r96-v2
pilot-n1024-bq32-r96-v2
poc-n1024-bq64-r128-v2
poc-n1024-bq96-r128-v2
poc-n1024-bq128-r128-v3
system-n1024-wf128-crom-v2
```

List the executable registry directly:

```bash
go run ./cmd/issuance list-presets
```

The canonical ID, preset version, manifest digest, primitive and PRF profile,
transcript tuple, rate-limit policy, and executable tuning are one identity.
Earlier selectors and persisted artifacts are not aliases and are not
migrated. Recreate the entire setup, issuance, credential, and showing state
for this epoch.

This is intentionally a mixed-epoch registry: the first seven identifiers use
their historical v2 manifests and results, while BQ128 and WF128 use strict-v3
manifests and transcripts. WF128's canonical identifier still ends in `-v2`;
that suffix is historical and does not select its active proof epoch.

## Build And Validate

Native build and functional validation:

```bash
go test ./...
go vet ./...
go build ./cmd/issuance ./cmd/showing
go run ./cmd/issuance gate-functional-presets
```

Run the repository validation script:

```bash
./scripts/validate-artifact.sh
```

Preserve reports and generated artifacts with:

```bash
ARTIFACT_ROOT="$(pwd)/artifacts" ./scripts/validate-artifact.sh
```

Build and run the Go-only Docker artifact:

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact list
docker run --rm --user "$(id -u):$(id -g)" \
  spruce-artifact bench artifact-n1024-sc125-v2
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact gate
```

Retain Docker validation output on the host:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/artifacts:/artifacts" \
  spruce-artifact validate
```

## Benchmark Reports And Evidence Status

Run one preset and write its report:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset artifact-n1024-sc125-v2 \
  -artifact-dir artifacts/sc125-v2 \
  -json-out artifacts/sc125-v2/benchmark-intgenisis-e2e.json \
  -force
```

The JSON report, not prose in this guide, is the source of truth for:

- the canonical preset and manifest actually executed;
- proof geometry and transcript component accounting;
- actual canonical wire metrics where available, historical modeled
  verifier-message estimates where labeled, and paper-transcript accounting;
- theorem/accounting diagnostics and executed-parameter audits;
- phase timings and runtime/build metadata;
- artifact paths, local verification, and replay rejection checks.

The seven non-target presets retain their 2026-08-04 historical-v2 results.
BQ128 and WF128 now use strict v3 and must not be compared through the old v2
`proof_size_bytes` field as if it were actual wire output. Their actual binary
state, proof, presentation, paper accounting, and three-run resource evidence
are recorded separately in [results.md](results.md),
[docs/CREDENTIAL_SIZE_OPTIMIZATION.md](docs/CREDENTIAL_SIZE_OPTIMIZATION.md),
and [evidence/focused-v3-final-size-optimization.json](evidence/focused-v3-final-size-optimization.json).
The preceding [transcript-reduction](evidence/focused-v3-transcript-reduction.json)
and [first size-optimization](evidence/focused-v3-size-optimization.json)
records remain frozen as historical before-data.

The table reports independent scalar medians from three codec-6 runs. Exact
Merkle-frontier node counts and minimal-LEB128 counter widths can vary by run;
state and paper accounting were identical in all three runs.

| Target | Persistent canonical state | Issuance canonical proof wire | Showing canonical proof wire | Canonical presentation wire | Paper transcript, issuance / showing |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128, R11/L4 showing | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B |
| WF128 (`LVCSNCols=41` showing) | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B |

Keep these as four distinct metric families:

1. persistent canonical credential-state bytes;
2. actual canonical presentation-wire bytes;
3. actual canonical proof-wire bytes, separately for issuance and showing;
4. paper-accounted transcript bytes, separately for issuance and showing.

The modeled verifier-message estimate is a separate historical/accounting
field and is never an actual wire measurement. Every one of the three runs per
target passes proof verification, replay rejection, theorem and zero-knowledge
eligibility, and the 2× baseline-median proving-time and peak-memory gates. The
evidence is limited to `claim_scope=proof_only`; full-game accounting remains
deferred.

Against the accepted codec-5 medians, this epoch saves 490 B on BQ issuance
and 330 B on WF issuance, plus 2,084 B and 132 B on each target's showing proof
and presentation. BQ showing paper saves 1,262 B; other paper totals and
persistent state are unchanged.

### Reproduce The Focused Strict-v3 Runs

The checked raw-run layout is:

```text
artifacts/smallwood-v3/final-size-optimization-v2/bq128/run-{1,2,3}/
artifacts/smallwood-v3/final-size-optimization-v2/wf128/run-{1,2,3}/
```

On macOS, build once and reproduce the report, generated runtime artifacts,
and resource sidecar at those paths with:

```bash
mkdir -p artifacts/smallwood-v3/_work
go build -o artifacts/smallwood-v3/_work/issuance-v3-final-size ./cmd/issuance

run_v3_target() {
  preset="$1"
  label="$2"
  run_no="$3"
  out="artifacts/smallwood-v3/final-size-optimization-v2/$label/run-$run_no"
  mkdir -p "$out"
  /usr/bin/time -l -o "$out/resource.txt" \
    artifacts/smallwood-v3/_work/issuance-v3-final-size \
    benchmark-intgenisis-e2e \
    -preset "$preset" \
    -artifact-dir "$out" \
    -json-out "$out/report.json" \
    -force
}

for run_no in 1 2 3; do
  run_v3_target poc-n1024-bq128-r128-v3 bq128 "$run_no"
  run_v3_target system-n1024-wf128-crom-v2 wf128 "$run_no"
done
```

The canonical sizes are in each report's `canonical_sizes` object. Each run's
checked projection fixes all 15 production artifacts in canonical role/path
order and verifies every regular file's byte length and SHA-256 digest, plus
the report/resource and nested issuance/showing proof digests. All six reports
must also carry the same canonical Go build-input
digest, including embedded PRF parameters. The generator recomputes that
snapshot from `go list`; a different dirty source tree is rejected even when
its base Git HEAD is unchanged. Validate the checked focused evidence against
the current target manifests and gates with:

```bash
go test ./evidence -run '^TestFocusedV3FinalSizeOptimizationEvidence$' -count=1
```

### Reproduce The Strict-v3 Time-Optimization Runs

The transcript-preserving proving implementation has three fresh runs at:

```text
artifacts/smallwood-v3/time-optimization-v1/bq128/run-{1,2,3}/
artifacts/smallwood-v3/time-optimization-v1/wf128/run-{1,2,3}/
```

The final source includes the retained replay-plan cache and structurally
derived semantic metadata, alongside the exact Fiat--Shamir prefix, prepared-
domain, semantic-Q arena, combined-DECS fallback, and implicit-tree batches
described in
[docs/PROOF_TIME_OPTIMIZATION.md](docs/PROOF_TIME_OPTIMIZATION.md). The
structurally selected row-major DECS candidate is provisional R&D, callable
only through an explicit internal test constructor, and is not active in
production pending the paired adoption gate.
Fixed DECS frame templates were not retained: exact equality passed, but pure
framing was 59--107% slower, whole-hash templating had no stable cross-target
3% win, and SHAKE prefix cloning added 448 B plus one allocation per hash. See
`tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/RESULTS.md`.

Rebuild and reproduce them on macOS with Go 1.23.12 and
`GOMAXPROCS=15`:

```bash
mkdir -p tmp/profiling-v3/time-optimization/_work
go build -o tmp/profiling-v3/time-optimization/_work/issuance-v3-time-opt \
  ./cmd/issuance

run_v3_time_target() {
  preset="$1"
  label="$2"
  run_no="$3"
  out="artifacts/smallwood-v3/time-optimization-v1/$label/run-$run_no"
  mkdir -p "$out"
  GOMAXPROCS=15 /usr/bin/time -l -o "$out/resource.txt" \
    tmp/profiling-v3/time-optimization/_work/issuance-v3-time-opt \
    benchmark-intgenisis-e2e \
    -preset "$preset" \
    -artifact-dir "$out" \
    -json-out "$out/report.json" \
    -force
}

for run_no in 1 2 3; do
  run_v3_time_target poc-n1024-bq128-r128-v3 bq128 "$run_no"
  run_v3_time_target system-n1024-wf128-crom-v2 wf128 "$run_no"
done
```

The independent scalar medians are:

| Target | Issuance prove | Showing prove | Issuance/showing verify | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| BQ128 | 1,349.588 ms | 2,902.833 ms | 499.882 / 273.419 ms | 369,393,664 B |
| WF128 | 521.758 ms | 1,256.464 ms | 241.098 / 148.445 ms | 194,871,296 B |

The proving MADs are 36.483/97.182 ms for BQ issuance/showing and
4.210/8.127 ms for WF. All six reports bind source-input digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.

The nominal unpaired comparison against the immutable predecessor is
20.93%/21.39% lower for BQ issuance/showing and 28.44%/11.59% lower for WF;
peak-RSS medians are 38.62% and 40.29% lower. These numbers do not pass the
formal performance/adoption gate. The runs use independent entropy and
counters, and accepted Fiat--Shamir counter variability can materially affect
top-level proving time. Runtime direction remains unestablished until seven
fixed-entropy alternating predecessor/candidate pairs are measured. All fixed
security inputs, the 49/423 row geometry, state sizes, and paper transcript
sizes remain unchanged. Independent fresh proofs can also have different
canonical lengths because both the exact-frontier node count and minimal-
LEB128 counter widths are challenge-dependent; compare predecessor and
candidate with identical entropy when checking byte preservation.

The three-run measurements are complete, but the focused machine-readable
time-optimization successor has two blockers. Seven alternating fixed-entropy
predecessor/candidate end-to-end pairs and their allocation records are still
missing, so the formal runtime direction is not established. In addition,
`gate-functional-presets` is not green: BQ
issuance/showing algebraic totals are 131.548362/131.511683 bits against the
manifest-bound 131.540568-bit engineering high-watermark, so showing misses by
0.028885 bits. The actual required 128-bit phase gate passes, with BQ showing
3.511683 bits above it, and the BQ proof, parameter audit, and replay checks
pass. Do not promote the fresh-run reports as a substitute for paired evidence
or describe the all-nine functional gate as passing. Do not alter the target,
manifest, geometry, or accounting to remove the mismatch. See
[docs/PROOF_TIME_OPTIMIZATION.md](docs/PROOF_TIME_OPTIMIZATION.md).

`gate-artifact-presets` and `gate-degree1024-maintained-presets` are the
exact-byte reproduction entrypoints:

```bash
go run ./cmd/issuance gate-artifact-presets \
  -artifact-dir artifacts/exact-byte-gate
go run ./cmd/issuance gate-degree1024-maintained-presets \
  -artifact-root artifacts/degree1024-exact-byte-gate
```

The checked-in byte gates match the 2026-08-04 canonical reports. Timings are
reported separately as medians of three runs and are not exact gate values.
The BQ artifact-gate paper expectations were corrected from the stale
91,756/149,027 B showing/combined values to the accepted 90,494/147,765 B
values. This aligns the gate with the existing codec-6 result; it changes no
security policy, manifest, geometry, or transcript accounting.

## Manual End-To-End Flow

The benchmark command is the shortest reviewer path. The following sequence
shows every artifact and the required showing state explicitly. It uses two
files containing identical example service context bytes to model the holder
input and the verifier's independently supplied expectation.

```bash
PRESET="artifact-n1024-sc125-v2"
RUN="$(mktemp -d)"
printf '%s' 'reviewer-service-context-v2' > "$RUN/holder-context.bin"
printf '%s' 'reviewer-service-context-v2' > "$RUN/verifier-context.bin"

go run ./cmd/issuance setup-intgenisis-public \
  -preset "$PRESET" \
  -out "$RUN/credential_public.json"

go run ./cmd/issuance setup-ntru-keys \
  -preset "$PRESET" \
  -params-out "$RUN/ntru_params.json" \
  -public-out "$RUN/ntru_public.json" \
  -private-out "$RUN/ntru_private.json"

go run ./cmd/issuance holder-commit \
  -preset "$PRESET" \
  -public-params "$RUN/credential_public.json" \
  -holder-secret "$RUN/holder_secret.json" \
  -commit-request "$RUN/commit_request.json"

go run ./cmd/issuance holder-prove \
  -preset "$PRESET" \
  -holder-secret "$RUN/holder_secret.json" \
  -presign-submission "$RUN/presign_submission.json"

go run ./cmd/issuance issuer-verify-sign \
  -preset "$PRESET" \
  -commit-request "$RUN/commit_request.json" \
  -presign-submission "$RUN/presign_submission.json" \
  -issue-response "$RUN/issue_response.json" \
  -ntru-params "$RUN/ntru_params.json" \
  -ntru-public-key "$RUN/ntru_public.json" \
  -ntru-private-key "$RUN/ntru_private.json" \
  -ntru-signature-out "$RUN/ntru_signature.json" \
  -verifier-key-out "$RUN/intgenisis_verifier_key.json"

go run ./cmd/issuance holder-finalize \
  -preset "$PRESET" \
  -holder-secret "$RUN/holder_secret.json" \
  -commit-request "$RUN/commit_request.json" \
  -issue-response "$RUN/issue_response.json" \
  -state-out "$RUN/credential_state.json" \
  -signature-out "$RUN/signature.json" \
  -ntru-params "$RUN/ntru_params.json" \
  -verifier-key "$RUN/intgenisis_verifier_key.json"

go run ./cmd/showing \
  -preset "$PRESET" \
  -state-path "$RUN/credential_state.json" \
  -verifier-key "$RUN/intgenisis_verifier_key.json" \
  -context-file "$RUN/holder-context.bin" \
  -holder-usage-state "$RUN/holder_usage_state.json" \
  -presentation-out "$RUN/presentation.json"

go run ./cmd/showing \
  -preset "$PRESET" \
  -public-params "$RUN/credential_public.json" \
  -verifier-key "$RUN/intgenisis_verifier_key.json" \
  -verify-presentation "$RUN/presentation.json" \
  -expected-context-file "$RUN/verifier-context.bin" \
  -verifier-state "$RUN/verifier_state.json"
```

`-context-file` is required only for creation;
`-expected-context-file` is required only for verification. The verifier must
obtain its context through the service protocol rather than trusting data from
the presentation.

The holder state file is created if absent and atomically updated before proof
construction. It burns one of the 16 hidden slots for the exact credential and
derived context even if later proof construction fails. The verifier state
file is created if absent and atomically records the accepted tag under the
derived context after cryptographic verification.

For algebraic verification without rate-limit acceptance, omit
`-verifier-state` and add `-proof-only`:

```bash
go run ./cmd/showing \
  -preset "$PRESET" \
  -public-params "$RUN/credential_public.json" \
  -verifier-key "$RUN/intgenisis_verifier_key.json" \
  -verify-presentation "$RUN/presentation.json" \
  -expected-context-file "$RUN/verifier-context.bin" \
  -proof-only
```

`-proof-only` cannot be used while creating a presentation and cannot be
combined with `-verifier-state`.

## Generated State And Identities

A full manual or benchmark run produces the following classes of data:

```text
credential public parameters and B matrix
NTRU parameters, public key, private key, and signature bundle
holder secret, commitment request, and pre-sign submission
issuer response and public verifier key
final credential state
holder usage state keyed by credential and context
presentation envelope
verifier replay state keyed by public parameters, verifier key, and context
benchmark report
```

The opaque context files are service inputs, not presentation outputs.
Historical-v2 envelopes carry the canonical derived digest and 11 public
lanes. Presentation-v3 carries neither: the verifier supplies the context and
its derived values through the trusted proof context, where Fiat--Shamir binds
them directly.

The enforced epoch identities include:

| Artifact or protocol component | Seven historical presets | BQ128/WF128 targets |
| --- | --- | --- |
| preset manifest | version `2` | version `3` |
| public parameters | schema version `8` | unchanged container; v3 manifest binding |
| credential state | schema version `7` | canonical binary format `8` |
| verifier key | schema version `2` | unchanged container; v3 manifest binding |
| presentation | `intgenisis_presentation_v2` | canonical binary format `3` |
| holder usage state | version `2` | version `3` |
| issuance artifact | historical v2 envelope | version `4`, canonical proof only |
| proof | schema version `2` | schema version `3` |
| canonical proof codec | historical object/model | codec `6`, `SPRUCEP6` magic, grouped radix-`q` fields, pre-challenge constant-only `Q` reconstruction, exact unpadded frontier |
| relation/layout/transcript | version `2` | version `3` |
| DECS opening container | version `2` | version `2` with exact-`N` v3 positional authentication |
| NTRU parameters, keys, signatures | v2 identities | unchanged v2 containers, bound to v3 setup |

The numeric storage schema counters do not imply migration support. Each
loader checks the exact current value, canonical field encodings, content
digests, and cross-artifact bindings. In particular, the target state and
presentation loaders reject legacy JSON rather than migrating it or falling
back to v2/debug verification.

For each focused target run, the fail-closed lifecycle files are:

| Path below the run directory | Active target format | Boundary enforced |
| --- | --- | --- |
| `credential_state.intgenisis.v8` | canonical binary state v8 | exact magic/length, canonical packing, preset/public/key bindings; mode `0600` |
| `presign_submission.json` | issuance artifact v4 | one schema-3/codec-6 pre-sign proof; codec-3/codec-4/codec-5 bytes, legacy proof objects, and missing canonical proof rejected |
| `presentation.intgenisis.v3` | canonical binary presentation v3 | packed tag plus schema-3/codec-6 showing proof; wrong kind/version/context and trailing data rejected |
| `holder_usage_state.json` | holder usage v3 | canonical state-v8 fingerprint plus manifest/public/key bindings; old usage state rejected |

Public-parameter and verifier-key container schemas remain unchanged, but
their configured-width bindings include the target manifest. Consequently a
same-schema file from another preset or epoch still fails closed.

## What The Gates Establish

| Check | Command or observation |
| --- | --- |
| all-nine functional gate | `go run ./cmd/issuance gate-functional-presets`; currently non-green only because BQ showing misses its engineering high-watermark by 0.028885 bits, despite passing the required 128-bit phase audit |
| one exact manifest is executed | benchmark report canonical ID, version, and manifest digest |
| issuance and showing proofs verify | benchmark phase results and CLI success |
| context is independently bound | verification fails if expected context bytes differ |
| hidden-slot quota is durable | holder usage state advances monotonically and stops after 16 reservations |
| accepted tags cannot replay in one context | a second stateful verification is rejected |
| cross-artifact mixing fails | digest, schema, preset, PRF, transcript, and key checks reject |
| Go implementation health | tests, vet, static analysis, and builds in the validation script |

These are implementation and proof-artifact claims. Primitive reductions,
multi-user composition, operational recovery, and deployment assurance remain
outside this artifact claim.

## Expected Failures

The CLIs fail closed on:

- a non-canonical preset selector or an artifact from another epoch;
- missing, unknown, or non-canonical persisted fields;
- manifest, public-parameter, PRF, verifier-key, or NTRU identity mismatch;
- a missing creation context, holder usage state, or verifier key;
- a missing independently expected verification context;
- a context mismatch or a repeated `(context, tag)` acceptance;
- exhaustion of all 16 holder slots for one credential and context;
- legacy DECS opening material or a mixed commitment role/salt;
- BB-tran coefficients outside `{-1,0,1}` or an invalid inverse relation;
- unavailable entropy, malformed keys, or exhausted bounded NTRU retries.

All live randomness, including NTRU key generation and preimage sampling, is
obtained from `crypto/rand` or an explicitly injected `io.Reader`. Entropy
failure is returned as an error; the implementation does not silently fall
back to deterministic process-global randomness.
