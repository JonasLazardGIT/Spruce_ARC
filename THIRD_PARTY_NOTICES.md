# Third-Party Notices

This repository depends on third-party code for artifact reproduction and
provenance.

## Go Module Dependencies

The Go module dependencies are listed in [go.mod](go.mod) and [go.sum](go.sum).
They are fetched by the Go toolchain during normal native builds and during the
Docker image build.

Notable direct dependencies:

- `github.com/tuneinsight/lattigo/v4`
- `github.com/go-echarts/go-echarts/v2`
- `golang.org/x/crypto`

Before public archival, confirm whether the venue requires copying upstream
license texts for module dependencies into the artifact bundle.

## External Security Estimator

Security-estimator reproduction uses an external pinned checkout of
`malb/lattice-estimator` at commit
`4bfa63e364be9dd7fd1b2b531e2a11da8fb1c2ad`, as described in
[docs/SECURITY.md](docs/SECURITY.md). The estimator source is not vendored in
this repository or copied into the Docker image.

## Sage/Python Provenance Scripts

The scripts under `tools/` and `prf/*.sage` are provenance material. They are
not required by Docker artifact commands and are excluded from the Docker image.
