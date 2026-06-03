# Docker Cleanup Contract

This branch prepares a Docker-ready IntGenISIS artifact by shrinking the
repository first. Do not build Docker until the maintained Go artifact is small,
clear, and reproducible.

## Maintained Surface

The Docker-facing public surface is exactly:

- `n1024-compact96`
- `n1024-compact125`
- committed-message issuance
- showing and presentation verification
- fixed-size transcript mode
- SmallWood 2025 transcript/protocol tuple
- direct-full PRF companion proof path
- E2E benchmark and degree-1024 gate commands
- legacy verification only where tests prove it is still required

`n512-compact96`, profile-B data, old x0len profiles, N=256 research presets,
sweep candidates, and unsafe lookup-shadow controls are not Docker-facing
interfaces.

## Final Repository Shape

Keep the Go module centered on these packages and commands:

- `cmd/issuance`
- `cmd/showing`
- `credential`
- `issuance`
- `PIOP`
- `DECS`
- `LVCS`
- `commitment`
- `ntru`
- `prf`
- `internal/*`

Keep `cmd/ntrucli` only if it is clearly documented as internal tooling or if
tests require it. Otherwise delete it from the public command surface.

Keep only checked-in parameter data needed by maintained generation or
verification:

- `Parameters/Parameters.json`
- `Parameters/Bmatrix.intgenisis_profile_c.json`
- `Parameters/credential_public.intgenisis_profile_c.json`
- `prf/prf_params.json`
- legacy profile-B parameter data only until tests no longer require it

Do not commit generated runtime artifacts:

- `.gocache/`
- root binaries such as `/showing`
- `credential/issuance/*`
- `credential/keys/*.json`
- `ntru_keys/*.json`
- `_markdown_test/`
- `tools/__pycache__/`
- `poseidon_params_*.txt`
- local PDF drops under `docs/`
- vendored `lattice-estimator-main/`

Optional research tools may remain under `tools/`, but they must not assume a
vendored estimator checkout or participate in Docker validation.

## Keep

Keep code that is reachable from one of these paths:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact96 -artifact-dir "$(mktemp -d)" -force
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125 -artifact-dir "$(mktemp -d)" -force
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root "$(mktemp -d)"
go run ./cmd/showing -preset n1024-compact96
go run ./cmd/showing -preset n1024-compact125
```

Also keep tests that prove:

- maintained presets resolve to fixed-size transcripts
- `paper_transcript_bytes`, `proof_size_bytes`, and `auth_bytes` are stable
- issuance proof generation and verification still pass
- showing proof generation and verification still pass
- direct-full PRF companion verification still passes
- legacy proof verification still passes where retained

## Delete Or Hide

Delete now when no Go tests or maintained runs reference the item:

- generated caches, binaries, copied PDFs, markdown build products, pycache, and
  benchmark output directories
- stale sweep result JSON
- stale root PRF parameter-generation text dumps
- vendored third-party estimator checkout
- docs that point to removed local generated paths

Quarantine behind internal or legacy docs until tests can be updated:

- `n512-compact96`
- profile-B public parameter data
- legacy transcript verification
- `output_audit`, `direct_auth`, and `aux_instance` PRF companion modes
- baseline transcript comparison flags
- `cmd/ntrucli`
- manual tuning flags not needed by maintained presets

Delete after tests prove no dependency:

- old challenge-style issuance artifacts and commands
- N=256 paths
- old x0len showing profiles
- unsafe lookup-shadow mode
- sweep and preset-candidate generation code
- benchmark fixtures not tied to `n1024-compact96` or `n1024-compact125`

## Non-Goals For Cleanup Passes

Do not change in cleanup-only commits:

- proof equations
- transcript format
- security parameters
- Section 6 numbers
- benchmark numbers
- NTRU signing math
- SmallWood soundness accounting

Only update benchmark or Section 6 numbers after rerunning the relevant
benchmark/gate and recording the exact command.

## Validation

Every cleanup commit must pass:

```bash
gofmt -w <changed-go-files>
go test ./...
git diff --check
git status --short --branch
```

Before Docker work starts, also run:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact96 -artifact-dir "$(mktemp -d)" -force
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125 -artifact-dir "$(mktemp -d)" -force
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root "$(mktemp -d)"
```

Do not keep cleanup edits that make `go test ./...` fail.
