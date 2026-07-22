# SPRUCE

SPRUCE is the ARC-SPRUCE IntGenISIS paper artifact. It implements
the committed-message issuance flow, final IntGenISIS showing proof, verifier
path, fixed transcript reporting, and one executable preset registry.

The maintained artifact surface is intentionally narrow:

- `cmd/issuance`
- `cmd/showing`
- every preset in the executable registry
- Go tests, one all-preset functional gate, the historical artifact gate, and
  benchmark reports

All configurations are experimental PoC presets. Security metadata is
informational and does not constitute a deployment claim. Lifecycle and claim
scope remain in reports so a run can be identified precisely, but they do not
restrict execution.

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

## Executable Presets

```bash
go run ./cmd/issuance list-presets
```

The command prints every canonical registry entry. Every listed preset can be
run by `benchmark-intgenisis-e2e`; there are no visibility flags or unavailable
placeholder entries.

The old `n512-*` and `n1024-*` names remain accepted aliases for artifact
reproduction. They resolve to the same canonical manifest and do not create a
second wire identity.

`system-n1024-wf128-crom-v1` is executable, but remains a candidate with
`CompleteSystemClaim=false`. No complete-system deployment preset is currently
available.

## BQ32 Controlled Pilot

`pilot-n1024-bq32-r96-v1` is a CROM candidate, not a deployment preset. Its
immutable scope uses raw query caps `[2^32]*5` within each proof-system phase,
at most `2^32` honest proof transcripts and tags per domain-separated context,
and the actual tag-9 PRF relation. One issuance plus one showing composes to
`[2^33]*5`. It executes 168-bit DECS/hash and Fiat-Shamir outputs, 136-bit tapes,
and a 168-bit salt.

The current live measurement is 25,844 issuance bytes, 36,887 showing bytes,
99.98 one-proof theorem bits, and 98.59 bits after the current one-issuance /
one-showing global-collision composition. The executed-parameter audit passes,
but complete-system promotion remains blocked by missing or unreviewed
primitive and full-game ledger terms.

## NIZK-Only Q128 Preset

The public SmallWood NIZK-only Q128/epsilon128 research preset is:

```text
research-n1024-bq128-r128-v1
```

It targets proof soundness and zero knowledge of about 128 bits against an
adversary making up to `2^128` ROM/Fiat-Shamir queries against the proof
system. It uses raw log caps `[128]*5`, 512-bit hash/Fiat-Shamir output,
256-bit tape, 384-bit salt, `theta=13`, `ell=18`, polynomial block width
`n_cols=48`, and degree-enforcing domain size `N_DECS=983040`.

This is not a complete IntGenISIS credential-system claim: the `BQ128-128`
system profile remains `requires_new_primitives` because the current executable
primitive core is below the 256-bit core required for that full-system profile.

## WF-128 PoC Preset

`system-n1024-wf128-crom-v1` exercises the intended unbounded CROM work-factor
shape with 264-bit DECS/hash and Fiat-Shamir outputs, a 128-bit tape, a 256-bit
salt, and the bundled tag-13 PRF profile. Its bounded-query caps are unset. The
initial measured run reports 27,124 issuance bytes, 39,547 showing bytes, and
139.12/138.98 issuance/showing theorem bits. Its structural parameter audit
passes; its security ledger remains diagnostic and makes no complete-system
claim.

## Fast Docker Run

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact list
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact bench system-n1024-wf128-crom-v1
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact gate
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact artifact-gate
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
go run ./cmd/issuance list-presets
go run ./cmd/issuance benchmark-intgenisis-e2e -preset system-n1024-wf128-crom-v1
go run ./cmd/issuance gate-functional-presets
go run ./cmd/issuance gate-artifact-presets
```

The full native validation script runs formatting, tests, vet, staticcheck,
strict deadcode, CLI builds, and all historical exact-byte artifact gates:

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
go run ./cmd/issuance setup-intgenisis-public -preset artifact-n1024-sc125-v1
go run ./cmd/issuance setup-ntru-keys -preset artifact-n1024-sc125-v1
go run ./cmd/issuance holder-commit -preset artifact-n1024-sc125-v1
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/showing -preset artifact-n1024-sc125-v1
```

Commands that create preset-dependent material require `-preset`. Accounting
parameters are not exposed as public flags; they come from the canonical
preset manifest. Public parameters, credential state, verifier keys,
presentations, and Fiat-Shamir public inputs bind that manifest.
