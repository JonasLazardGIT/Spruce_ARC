# Artifact Limitations

This repository is a paper artifact for the maintained ARC-SPRUCE IntGenISIS
prototype. It is not a backwards-compatible Go library distribution.

## Supported Surface

Supported public artifact entrypoints are:

```text
cmd/issuance
cmd/showing
n512-compact96
n1024-compact96
n1024-compact125
```

Maintained Go entrypoints are the IntGenISIS issuance/showing builders,
verification path, public params, presets, `credential.IntGenISISState`, and
`PIOP.BuildProofReport`.

## Unsupported Surfaces

The artifact intentionally does not support:

- removed research presets and projection modes;
- old non-IntGenISIS showing builders;
- old signature-shortness proof versions;
- legacy credential state APIs;
- broad parameter sweeps and tuning flags as public CLI features;
- external Go library compatibility for removed convenience APIs.

Removed modes should fail closed with explicit errors rather than silently
falling back.

## Security-Estimator Scope

The Go artifact proves and verifies the implemented issuance/showing relations.
Lattice-estimator scripts are retained as provenance but are not Docker runtime
dependencies.

The `h_tran` rational inverse relation is documented separately in
[docs/intgenisis_lattice_security.md](docs/intgenisis_lattice_security.md). The
local estimator gives bounded-linear surrogate evidence for that surface; it is
not a complete reduction for uniform rational-inverse witnesses.

## Randomized Setup

NTRU key generation is randomized. The artifact uses bounded retries around the
annulus key generator because rare numerical sampler failures can occur before
proof generation. If the retry budget is exhausted, rerun the command or inspect
the reported keygen error.

