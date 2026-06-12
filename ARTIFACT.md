# SPRUCE Artifact Guide

This guide is the canonical reviewer entrypoint for reproducing the maintained
SPRUCE artifact. It covers supported commands, expected outputs, generated
files, claim mapping, limitations, and common failure modes.

## Supported Surface

The artifact supports:

- committed-message IntGenISIS issuance
- IntGenISIS showing and verification
- fixed-size paper transcript reporting
- maintained preset benchmarking and gates
- Go tests and static checks used by the validation script

The public command surface is limited to `cmd/issuance`, `cmd/showing`, and the
nine maintained presets:

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

## Expected Results

The canonical paper-facing size metric is
`showing.paper_transcript_bytes`. It is not the serialized JSON proof size and
not KiB.

| Preset | Role | Expected `showing.paper_transcript_bytes` |
| --- | --- | ---: |
| `n512-compact96` | profile-B compact 96-bit engineering preset | 22008 |
| `n1024-compact96` | profile-C compact 96-bit preset | 26136 |
| `n1024-compact125` | profile-C compact 125+ preset | 35215 |
| `n1024-q10-128` | profile-C 128-bit preset for `ROQueryCaps=[2^10]*5` | 37266 |
| `n1024-q16-128` | profile-C 128-bit preset for `ROQueryCaps=[2^16]*5` | 42155 |
| `n1024-q32-128` | profile-C 128-bit preset for `ROQueryCaps=[2^32]*5` | 48960 |
| `n1024-q10-96` | profile-C 96-bit preset for `ROQueryCaps=[2^10]*5` | 29645 |
| `n1024-q16-96` | profile-C 96-bit preset for `ROQueryCaps=[2^16]*5` | 30583 |
| `n1024-q32-96` | profile-C 96-bit preset for `ROQueryCaps=[2^32]*5` | 37249 |

The validation scripts fail if these byte counts change.

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

Run the maintained gate:

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
benchmark-intgenisis-e2e for all nine maintained presets
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

Run all maintained byte/theorem gates:

```bash
go run ./cmd/issuance gate-maintained-presets -artifact-root "$(mktemp -d)"
```

Run only the degree-1024 gates:

```bash
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root "$(mktemp -d)"
```

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
- generated artifact paths
- Go runtime and VCS build metadata when available

## Claim Map

| Claim | Reproduction command | Report field or check |
| --- | --- | --- |
| Maintained preset list | `go run ./cmd/issuance benchmark-intgenisis-e2e -h` | supported `-preset` names |
| Paper transcript byte counts | `./scripts/validate-artifact.sh` | `showing.paper_transcript_bytes` equals the table above |
| Degree-1024 96-bit theorem accounting | `go run ./cmd/issuance gate-maintained-presets` | `showing.theorem_total_bits >= 96` |
| Degree-1024 125+ theorem accounting | `go run ./cmd/issuance gate-maintained-presets` | `showing.theorem_total_bits >= 125` |
| Query-budget 128-bit theorem accounting | `go run ./cmd/issuance gate-maintained-presets` | `showing.theorem_total_bits >= 128` |
| Query-budget 96-bit theorem accounting | `go run ./cmd/issuance gate-maintained-presets` | `showing.theorem_total_bits >= 96` |
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

Removed modes should fail closed with explicit errors instead of silently
falling back.

The security-estimator and PRF-generation material is provenance. The wrapper
scripts and Sage sources are documented in [docs/SECURITY.md](docs/SECURITY.md)
and excluded from Docker artifact runtime; lattice-estimator itself is supplied
as an external pinned checkout.

## Runtime And Failure Modes

Runtime varies by CPU and scheduler. The `n512` preset is normally a short
smoke run. Query-budget-specific degree-1024 128-bit presets are the slowest
maintained presets.

NTRU key generation is randomized and can internally retry if the numerical
annulus sampler rejects a trial. The artifact uses a bounded retry budget and
reports a setup error if all attempts fail. Rerunning the command is acceptable
for that setup failure.

To stress only maintained NTRU key generation:

```bash
NTRU_STRESS_RUNS=20 ./scripts/stress-ntru-keygen.sh n1024-compact125
```
