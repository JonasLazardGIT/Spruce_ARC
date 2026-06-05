# SPRUCE

This repository contains the maintained ARC-SPRUCE IntGenISIS prototype. The
public surface is intentionally narrow: committed-message issuance, IntGenISIS
showing, and the three promoted compact presets.

## Artifact Scope

The maintained artifact supports IntGenISIS issuance, showing, verification,
fixed-size transcript reporting, and E2E benchmark reproduction for the
maintained compact presets. Research tuning surfaces and old presets are not
public artifact interfaces.

## Maintained Presets

```text
n512-compact96
n1024-compact96
n1024-compact125
```

`n512-compact96` is the compact 96-bit engineering preset. The maintained
high-security preset is `n1024-compact125`; it is a live 125+ preset, not a
128-bit claim.

## Docker Quickstart

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact test
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact bench n512-compact96
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact bench n1024-compact96
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact bench n1024-compact125
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact gate
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact validate
```

Benchmark and gate commands write JSON artifacts under `/artifacts` inside the
container. To keep outputs on the host:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n1024-compact125
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact gate
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/artifacts:/artifacts" spruce-artifact validate
```

The Docker artifact is Go-only. Security-estimator and PRF-generation
provenance under `tools/`, `lattice-estimator-main/`, and `prf/*.sage` is kept
in the source tree but excluded from Docker.

## Native Quickstart

```bash
go run ./cmd/issuance setup-intgenisis-public -preset n1024-compact125
go run ./cmd/issuance setup-ntru-keys -preset n1024-compact125
go run ./cmd/issuance holder-commit -preset n1024-compact125
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125
go run ./cmd/issuance gate-maintained-presets
go run ./cmd/showing -preset n1024-compact125
```

Commands that create preset-dependent material require one of the maintained
IntGenISIS presets. Tuning flags and research selectors are not public
interfaces.

## Reproducing Results

```bash
./scripts/validate-artifact.sh
```

Expected showing paper transcript bytes are:

| Preset | `showing.paper_transcript_bytes` |
| --- | ---: |
| `n512-compact96` | 21754 |
| `n1024-compact96` | 25882 |
| `n1024-compact125` | 34853 |

For native security-estimation provenance, see [tools/README.md](tools/README.md).
Those commands require Sage/Python locally and are not Docker artifact
dependencies.

## Documentation

Start with [ARTIFACT.md](ARTIFACT.md), [CLAIMS.md](CLAIMS.md), and
[LIMITATIONS.md](LIMITATIONS.md) for reviewer-facing reproduction details.

See [docs/protocol.md](docs/protocol.md),
[docs/intgenisis_protocol_h_tran.md](docs/intgenisis_protocol_h_tran.md),
[docs/intgenisis_lattice_security.md](docs/intgenisis_lattice_security.md),
[docs/modulus_choice.md](docs/modulus_choice.md), and
[docs/degree1024_maintained_presets.md](docs/degree1024_maintained_presets.md)
for the canonical protocol and parameter notes. PRF seed packing is summarized
in [docs/prf_seed_packing.md](docs/prf_seed_packing.md), and release notices
are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
