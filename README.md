# SPRUCE

SPRUCE is the maintained ARC-SPRUCE IntGenISIS paper artifact. It implements
the committed-message issuance flow, final IntGenISIS showing proof, verifier
path, fixed transcript reporting, and the curated maintained presets.

The maintained artifact surface is intentionally narrow:

- `cmd/issuance`
- `cmd/showing`
- the nine maintained IntGenISIS presets
- Go tests, gates, and benchmark reports for those presets

The CLI also exposes explicitly marked candidate/research measurement presets.
Those labels are not maintained byte gates unless this README and
[ARTIFACT.md](ARTIFACT.md) list them as such. Removed tuning flags, old preset
labels, and non-maintained command surfaces are not public interfaces.

## Reviewer Path

This README is the first reviewer document. Then read:

1. [ARTIFACT.md](ARTIFACT.md): build, run, validate, expected outputs, claims,
   limitations, and generated files.
2. [docs/PROTOCOL.md](docs/PROTOCOL.md): implemented protocol, preset surface,
   artifact/code map, and data flow.
3. [docs/SECURITY.md](docs/SECURITY.md): security estimates, provenance
   commands, PRF parameter generation, and caveats.

Package-level READMEs remain available for code navigation, but the files above
are the canonical reviewer-facing docs.

## Maintained Presets

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

`n512-compact96` is the profile-B engineering preset. `n1024-compact96` and
`n1024-compact125` are compact profile-C presets, where `n1024-compact125` is a
125+ live preset rather than a 128-bit claim. The `n1024-q*` presets are
query-budget-specific profile-C presets with fixed random-oracle query caps and
DECS hash/tape widths baked into the preset registry.

## NIZK-Only Q128 Preset

The promoted SmallWood NIZK-only Q128/epsilon128 preset is:

```text
n1024-bq128-128-raw128-residual128-theta13-lvcs48-h512
```

It targets proof soundness and zero knowledge of about 128 bits against an
adversary making up to `2^128` ROM/Fiat-Shamir queries against the proof
system. It uses raw log caps `[128]*5`, `h512`, 256-bit tape, 384-bit salt,
`theta=13`, `ell=18`, `LVCS=48`, and `NLeaves=983040`.

This is not a complete IntGenISIS credential-system claim: the `BQ128-128`
system profile remains `requires_new_primitives` because the current executable
primitive core is below the 256-bit core required for that full-system profile.

## Fast Docker Run

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact test
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact bench n1024-compact125
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact gate
```

To keep generated reports:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/artifacts:/artifacts" \
  spruce-artifact validate
```

The Docker artifact is Go-only. Sage/Python provenance scripts stay in the
source tree, while lattice-estimator reproduction uses an external pinned
checkout documented in [docs/SECURITY.md](docs/SECURITY.md).

## Fast Native Run

```bash
go test ./...
go build ./cmd/issuance ./cmd/showing
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125
go run ./cmd/issuance gate-maintained-presets
```

The full native validation script runs formatting, tests, vet, staticcheck,
strict deadcode, CLI builds, and all maintained preset byte gates:

```bash
./scripts/validate-artifact.sh
```

To keep validation artifacts:

```bash
ARTIFACT_ROOT="$(pwd)/artifacts" ./scripts/validate-artifact.sh
```

## Manual Flow

The end-to-end benchmark above is the main reviewer command. The individual
issuance/showing commands are also available:

```bash
go run ./cmd/issuance setup-intgenisis-public -preset n1024-compact125
go run ./cmd/issuance setup-ntru-keys -preset n1024-compact125
go run ./cmd/issuance holder-commit -preset n1024-compact125
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/showing -preset n1024-compact125
```

Commands that create preset-dependent material require `-preset`. Accounting
parameters are not exposed as public flags; they come from the maintained
preset registry.
