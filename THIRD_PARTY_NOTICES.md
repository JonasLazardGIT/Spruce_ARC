# Third-Party Notices

This repository vendors and depends on third-party code for artifact
reproduction and provenance.

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

## Vendored Security Estimator

The `lattice-estimator-main/` directory is retained as source-tree provenance
for the archived security-estimator runs described in
[docs/intgenisis_lattice_security.md](docs/intgenisis_lattice_security.md).
It is excluded from the Docker artifact context.

No license file is present in this vendored checkout. Before public
redistribution, either add the appropriate upstream license notice, replace the
vendored tree with a pinned source reference, or obtain explicit redistribution
clearance.

## Sage/Python Provenance Scripts

The scripts under `tools/` and `prf/*.sage` are provenance material. They are
not required by Docker artifact commands and are excluded from the Docker image.

