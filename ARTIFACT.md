# SPRUCE Paper Artifact

This artifact reproduces the maintained ARC-SPRUCE IntGenISIS issuance and
showing prototype. The public artifact surface is intentionally limited to the
three maintained presets:

| Preset | Role | Expected showing paper transcript bytes |
| --- | --- | ---: |
| `n512-compact96` | compact 96-bit engineering preset | 21754 |
| `n1024-compact96` | degree-1024 96-bit preset | 25882 |
| `n1024-compact125` | degree-1024 125+ preset | 34853 |

The byte counts above are the paper-facing transcript metric
`showing.paper_transcript_bytes`, not JSON proof size and not KiB.

## Docker Reproduction

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact test
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n512-compact96
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n1024-compact96
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n1024-compact125
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact gate
```

For the complete native-quality gate inside Docker:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact validate
```

Docker artifact commands are Go-only. They do not require Sage, Python, private
files, generated keys, or local absolute paths. The `--user` flag keeps mounted
artifact outputs owned by the host user.

## Native Reproduction

Run the full validation gate:

```bash
./scripts/validate-artifact.sh
```

To keep generated artifacts:

```bash
ARTIFACT_ROOT="$(pwd)/artifacts" ./scripts/validate-artifact.sh
```

The validation script runs:

```text
go test ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
go run golang.org/x/tools/cmd/deadcode@v0.36.0 -test ./...
go run golang.org/x/tools/cmd/deadcode@v0.36.0 ./...
benchmark-intgenisis-e2e for all three maintained presets
```

It fails if any showing transcript byte count differs from the expected values.

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

The JSON report records proof metrics, transcript metrics, timings, replay
rejection status, artifact paths, Go runtime metadata, and VCS build metadata
when the Go toolchain provides it.

## Expected Runtime

Runtime varies by CPU and scheduler. On a desktop-class machine, the `n512`
preset is normally a short smoke run, while `n1024-compact125` is the slowest
maintained preset. The paper-facing byte counts are fixed-size transcript
metrics and should not vary across runs.

NTRU key generation is randomized and may internally retry if the numerical
annulus sampler rejects a trial. The artifact uses a bounded retry budget and
reports a clear setup error if all attempts fail.

To stress only the maintained NTRU key-generation setup path:

```bash
NTRU_STRESS_RUNS=20 ./scripts/stress-ntru-keygen.sh n1024-compact125
```

## Security Provenance

Go artifact commands do not rerun lattice-estimator or PRF-parameter generation.
The source tree retains provenance material under `tools/`,
`lattice-estimator-main/`, and `prf/*.sage`; see
[tools/README.md](tools/README.md) and
[docs/intgenisis_lattice_security.md](docs/intgenisis_lattice_security.md).
