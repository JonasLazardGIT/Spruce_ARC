# SPRUCE Artifact Guide

This guide is the canonical reviewer entrypoint for reproducing the maintained
SPRUCE artifact. It covers supported commands, expected outputs, generated
files, claim mapping, limitations, and common failure modes.

## Supported Surface

The artifact supports:

- committed-message IntGenISIS issuance
- IntGenISIS showing and verification
- fixed-size paper transcript reporting
- purpose-specific preset benchmarking and gates
- Go tests and static checks used by the validation script

The command surface is limited to `cmd/issuance` and `cmd/showing`. The default
preset list is purpose-oriented:

```text
poc-n512-sc96-v1
artifact-n1024-sc96-v1
artifact-n1024-sc125-v1
pilot-n1024-bq32-r96-v1
system-n1024-wf128-crom-v1       (unavailable)
```

The exact-byte artifact gate retains these nine historical selectors:

```text
n512-compact96
n1024-compact96
n1024-compact125
n1024-q10-128
n1024-q16-128
n1024-q32-128
n1024-q10-96
n1024-q16-96
n1024-q32-96
```

These selectors remain aliases so historical commands and byte tables continue
to reproduce. They are not nine equivalent security/deployment profiles. Use
`list-presets -all` to display them and `list-presets -research` for public
proof-only research points.

## Expected Results

The canonical paper-facing size metric is
`showing.paper_transcript_bytes`. It is not the serialized JSON proof size and
not KiB.

| Preset | Role | Expected `showing.paper_transcript_bytes` |
| --- | --- | ---: |
| `n512-compact96` | PoC alias; SC-96 proof-only | 22016 |
| `n1024-compact96` | paper artifact; SC-96 proof-only | 26144 |
| `n1024-compact125` | paper artifact; SC-125 proof-only | 35223 |
| `n1024-q10-128` | hidden historical proof artifact, raw `2^10` caps | 37093 |
| `n1024-q16-128` | hidden historical proof artifact, raw `2^16` caps | 42070 |
| `n1024-q32-128` | BQ32-R128 proof-theorem research point | 48691 |
| `n1024-q10-96` | hidden historical proof artifact, raw `2^10` caps | 29653 |
| `n1024-q16-96` | hidden historical proof artifact, raw `2^16` caps | 30591 |
| `n1024-q32-96` | superseded historical BQ32-R96 proof artifact | 37257 |

The validation scripts fail if these byte counts change.

Additional measured, non-artifact points are:

| Preset | Role | Expected `showing.paper_transcript_bytes` |
| --- | --- | ---: |
| `pilot-n1024-bq32-r96-v1` | bounded CROM candidate; actual tag-9; raw `[2^32]*5` caps per phase | 36887 |
| `research-n1024-bq128-r128-v1` | proof-only SmallWood NIZK Q128/epsilon128 claim for up to `2^128` proof-system queries | 89950 |

Neither row is an artifact byte gate. The BQ32 executed-parameter audit passes,
but its complete ledger remains blocked. The BQ128 row is proof-only and the
full `BQ128-128` profile still reports `requires_new_primitives`.

## Docker Reproduction

Build the Go-only artifact image:

```bash
docker build -t spruce-artifact .
```

Run the smoke test and one benchmark:

```bash
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact test
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact bench n1024-compact125
```

Run the exact-byte artifact gate:

```bash
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact gate
```

Run the full validation path and keep artifacts on the host:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/artifacts:/artifacts" \
  spruce-artifact validate
```

Docker commands write reports under `/artifacts` when that directory is
mounted. The image intentionally excludes Sage/Python security-provenance tools.

## Native Reproduction

Run the full validation script:

```bash
./scripts/validate-artifact.sh
```

To preserve benchmark artifacts:

```bash
ARTIFACT_ROOT="$(pwd)/artifacts" ./scripts/validate-artifact.sh
```

The validation script runs:

```text
gofmt -l over Go sources
go test ./...
go vet ./...
staticcheck ./...
deadcode -test ./... with no output allowed
deadcode ./... with no output allowed
go build ./cmd/issuance ./cmd/showing
benchmark-intgenisis-e2e for all nine historical exact-byte selectors
```

If `staticcheck` is not installed, the script runs the pinned tool through
`go run`. If `deadcode` is not installed, the script installs the pinned tool
and then fails on any reported unreachable code.

## Main Commands

Benchmark one preset and write a JSON report:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-compact125 \
  -artifact-dir artifacts/n1024-compact125 \
  -json-out artifacts/n1024-compact125/benchmark-intgenisis-e2e.json \
  -force
```

Run the historical exact-byte gate:

```bash
go run ./cmd/issuance gate-artifact-presets -artifact-dir "$(mktemp -d)"
```

Run only the degree-1024 gates:

```bash
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root "$(mktemp -d)"
```

Run the separated functional, proof, and candidate gates:

```bash
go run ./cmd/issuance gate-functional-presets
go run ./cmd/issuance gate-proof-profiles
go run ./cmd/issuance gate-candidate-presets
```

`gate-maintained-presets` remains a deprecated alias for
`gate-artifact-presets`. `gate-complete-system-presets` fails while there is no
complete deployment preset; it must never pass vacuously.

Run the manual issuance/showing sequence:

```bash
go run ./cmd/issuance setup-intgenisis-public -preset n1024-compact125
go run ./cmd/issuance setup-ntru-keys -preset n1024-compact125
go run ./cmd/issuance holder-commit -preset n1024-compact125
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/showing -preset n1024-compact125
```

Preset-dependent commands require `-preset`. Tuning/accounting knobs are not
public CLI flags; query caps, DECS collision widths, replay shape, compression,
and transcript mode are selected by the preset registry.

Default terminal output is concise and reviewer-facing. Pass `-verbose` to
`benchmark-intgenisis-e2e` or `cmd/showing` for row geometry, bucket
breakdowns, phase timings, and soundness-vector diagnostics.

## Generated Files

Each benchmark directory contains:

```text
credential_public.<profile>.json
Bmatrix.<profile>.json
holder_secret.json
commit_request.json
presign_submission.json
issue_response.json
credential_state.intgenisis.json
intgenisis_verifier_key.json
presentation.intgenisis.json
verifier_state.json
ntru_params.json
ntru_public.json
ntru_private.json
ntru_signature.json
benchmark-intgenisis-e2e.json
```

The benchmark JSON report records:

- selected preset-derived issuance/showing options
- proof and paper transcript metrics
- theorem/accounting bits
- non-zero runtime timings
- replay rejection status
- canonical preset ID/version, lifecycle, claim scope, and threat model
- canonical manifest digest and executed-parameter `required`/`actual` audit
- ledger term source, evidence reference, scope, accounting status, and result
- generated artifact paths
- Go runtime and VCS build metadata when available

## Claim Map

| Claim | Reproduction command | Report field or check |
| --- | --- | --- |
| Historical artifact byte list | `go run ./cmd/issuance gate-artifact-presets` | all nine exact-byte aliases pass |
| BQ32 controlled-pilot candidate | `go run ./cmd/issuance gate-candidate-presets` | actual parameters pass their profile requirements; ledger remains explicitly blocked |
| SmallWood NIZK-only Q128/epsilon128 preset | `go run ./cmd/issuance benchmark-intgenisis-e2e -preset research-n1024-bq128-r128-v1` | `showing.theorem_total_bits >= 128`, `zero_knowledge_bits >= 128`, `security_ledger.complete_system_claim == false`, `ledger_status == "requires_new_primitives"` |
| Maintained paper transcript byte counts | `./scripts/validate-artifact.sh` | `showing.paper_transcript_bytes` equals the maintained table above |
| Public proof-profile accounting | `go run ./cmd/issuance gate-proof-profiles` | executable proof-layer targets pass |
| SmallWood 2025 transcript mode | any benchmark JSON report | `showing.transcript_security_status == "smallwood_2025_1085_live"` |
| Fixed-size transcript stability | repeat benchmark for same preset | `showing.paper_transcript_bytes` unchanged |
| Replay protection | any benchmark JSON report | `replay_rejected == true` |
| Public CLI surface | `go run ./cmd/issuance help`, `go run ./cmd/showing -h` | listed commands and flags |
| Go code health | `./scripts/validate-artifact.sh` | tests, vet, staticcheck, deadcode pass |

## Limitations

This repository is a paper artifact, not a backwards-compatible Go library
distribution. It intentionally does not support:

- removed preset labels and non-maintained tuning selectors
- old non-IntGenISIS showing builders
- old signature-shortness proof versions
- old credential state APIs
- broad parameter searches or tuning flags as public CLI features
- external Go library compatibility for removed convenience APIs
- treating executable, artifact, or candidate lifecycle as a deployment claim

Removed modes should fail closed with explicit errors instead of silently
falling back.

Public parameters, proofs, finalized state, verifier keys, and presentations
bind the canonical preset ID, version, primitive/PRF identity, transcript mode,
and complete manifest digest. Mixing artifacts from different manifests is
rejected.

The security-estimator and PRF-generation material is provenance. The wrapper
scripts and Sage sources are documented in [docs/SECURITY.md](docs/SECURITY.md)
and excluded from Docker artifact runtime; lattice-estimator itself is supplied
as an external pinned checkout.

## Runtime And Failure Modes

Runtime varies by CPU and scheduler. The `n512` preset is normally a short
smoke run. Query-budget-specific degree-1024 128-bit artifacts are the slowest
exact-byte runs.

NTRU key generation is randomized and can internally retry if the numerical
annulus sampler rejects a trial. The artifact uses a bounded retry budget and
reports a setup error if all attempts fail. Rerunning the command is acceptable
for that setup failure. The current NTRU preimage sampler uses Go's
process-global `math/rand` source, so these artifact runs are reproducibility
and proof-system measurements, not evidence for a complete-system deployment
claim.

To stress artifact NTRU key generation:

```bash
NTRU_STRESS_RUNS=20 ./scripts/stress-ntru-keygen.sh n1024-compact125
```
