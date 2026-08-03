# SPRUCE Artifact Guide

This is the reviewer guide for the hard v2 SPRUCE artifact. The supported
surface is `cmd/issuance`, `cmd/showing`, the canonical preset registry, the Go
test suite, functional gates, and generated benchmark reports.

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
- serialized and paper-transcript size metrics;
- theorem/accounting diagnostics and executed-parameter audits;
- phase timings and runtime/build metadata;
- artifact paths, local verification, and replay rejection checks.

The bounded BB-tran rows, public-context/hidden-slot relation, v2 artifact
envelopes, and independent salted tapes change both serialization and runtime.
Earlier byte and timing baselines are invalid for this epoch. Maintained v2
byte and timing evidence is pending freshly generated benchmark reports; no
replacement figures are asserted here.

`gate-artifact-presets` and `gate-degree1024-maintained-presets` are the
reproduction entrypoints once v2 baselines have been generated and checked in:

```bash
go run ./cmd/issuance gate-artifact-presets -artifact-dir "$(mktemp -d)"
go run ./cmd/issuance gate-degree1024-maintained-presets \
  -artifact-root "$(mktemp -d)"
```

Until those baselines are regenerated, a report marked pending is not an
exact-byte claim.

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
  -holder-secret "$RUN/holder_secret.json" \
  -presign-submission "$RUN/presign_submission.json"

go run ./cmd/issuance issuer-verify-sign \
  -commit-request "$RUN/commit_request.json" \
  -presign-submission "$RUN/presign_submission.json" \
  -issue-response "$RUN/issue_response.json" \
  -ntru-params "$RUN/ntru_params.json" \
  -ntru-public-key "$RUN/ntru_public.json" \
  -ntru-private-key "$RUN/ntru_private.json" \
  -ntru-signature-out "$RUN/ntru_signature.json" \
  -verifier-key-out "$RUN/intgenisis_verifier_key.json"

go run ./cmd/issuance holder-finalize \
  -holder-secret "$RUN/holder_secret.json" \
  -commit-request "$RUN/commit_request.json" \
  -issue-response "$RUN/issue_response.json" \
  -state-out "$RUN/credential_state.json" \
  -signature-out "$RUN/signature.json" \
  -ntru-params "$RUN/ntru_params.json"

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

The opaque context files are service inputs, not presentation outputs. Raw
context bytes are not copied into the presentation; it carries the canonical
derived digest and 11 public lanes.

The enforced hard-epoch identities include:

| Artifact or protocol component | Required identity |
| --- | --- |
| preset manifest | preset version `2` and one canonical ID above |
| public parameters | schema version `8` |
| credential state | schema version `7` |
| verifier key | schema version `2` |
| presentation and verifier state | version `2`; presentation schema `intgenisis_presentation_v2` |
| holder usage state | version `2` |
| proof | schema version `2` |
| DECS commitment/opening | version `2` |
| NTRU parameters | `ntru-params-v2` |
| NTRU keys | `ntru-key-v2` |
| NTRU signatures | `ntru-signature-v2` |

The numeric storage schema counters do not imply migration support. Each
loader checks the exact current value, canonical field encodings, content
digests, and cross-artifact bindings.

## What The Gates Establish

| Check | Command or observation |
| --- | --- |
| every registry entry executes | `go run ./cmd/issuance gate-functional-presets` |
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
