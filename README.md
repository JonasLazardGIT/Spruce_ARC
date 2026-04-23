# SPRUCE

SPRUCE is a lattice-based anonymous credential prototype with a live
shared-randomness `bb_tran` issuance path and a live post-sign showing proof.

The current implementation surface is:

- semantic message `mu = (m || k)`
- Ajtai commitment to `(m, k, r0H[0..ell0-1], r1H, rbar)`
- shared randomness with issuer challenge rows `r0I[0..ell0-1]`, `r1I`
- centered hidden rows
  - `r0[j] = center(r0H[j] + r0I[j])`
  - `r1 = center(r1H + r1I)`
- direct `bb_tran` target
  - `Z = (B3 - r1)^(-1)`
  - `T = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z`
- issuer sampling `u` such that `A u = T`
- showing tag `tag = F(k, nonce)`

The live code does not use:

- target-from-commitment `T = B0 + Uc + Z`
- aligned commitment randomness `(S, E)`
- live `Uc`, `MSigmaR1`, `R0R1`, or source-product witness rows

## Current Shipped Configuration

The checked-in canonical profile is:

- hash relation: `bb_tran`
- `x0` profile: `lhl_default`
  - `X0Len = 6`
  - `X0CoeffBound = 5`
- target dimension: `1`
- target-hiding lambda: `128`
- showing preset: `soundness_balanced`
- replay mode: `reduced`
- PRF companion mode: `output_audit`
- hidden shortness path: `v6`

The current theorem-clean full-replay control remains a research path. The
intended CLI is still:

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

but the checked-in canonical vector-`x0` artifacts should currently be treated
as reduced-replay-first engineering artifacts, not a maintained full-replay
baseline.

## Reading Order

1. [docs/protocol.md](docs/protocol.md)
   Implementation-canonical protocol description, parameter surface, artifact
   flow, and command semantics.
2. [docs/shared_randomness_migration.md](docs/shared_randomness_migration.md)
   Versioning, regeneration rules, compatibility notes, and migration summary.
3. [docs/transcript_reduction_analysis.md](docs/transcript_reduction_analysis.md)
   Measured transcript bottlenecks, profile comparisons, and optimization
   roadmap after the singleton-`x0` carrier pass.
4. [docs/nizk_alignment_notes.md](docs/nizk_alignment_notes.md)
   Paper-to-code alignment matrix for the live branch.
5. [docs/full_baseline_proof_study.md](docs/full_baseline_proof_study.md)
   Research-only note for the theorem-clean full replay control.
6. [docs/modulus_choice.md](docs/modulus_choice.md)
   Shared field rationale and the interaction between `q`, `BoundB`,
   `X0CoeffBound`, and the PRF.

Subsystem context:

- [Commands.md](Commands.md)
- [cmd/README.md](cmd/README.md)
- [credential/README.md](credential/README.md)
- [commitment/README.md](commitment/README.md)
- [PIOP/README.md](PIOP/README.md)
- [ntru/README.md](ntru/README.md)
- [prf/README.md](prf/README.md)
- [DECS/README.md](DECS/README.md)
- [LVCS/README.md](LVCS/README.md)
- [Preimage_Sampler/README.md](Preimage_Sampler/README.md)

## Quick Start

Run all commands from the repository root.

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

Meaning:

1. `cmd/ntrucli gen` creates the issuer trapdoor and public key.
2. `cmd/issuance demo-local` runs the full shared-randomness holder/issuer
   issuance flow and writes the canonical credential state.
3. `cmd/showing` builds and verifies the shipped reduced-replay showing proof.

## Runtime Assets

Tracked runtime files used by the live branch:

- `Parameters/Parameters.json`
- `Parameters/credential_public.json`
- `Parameters/Bmatrix_bb_tran_x0len6.json`
- `prf/prf_params.json`
- `ntru_keys/*.json`
- `credential/issuance/*.json`
- `credential/keys/*.json`

The emitted live formats are currently:

- public params: `version = 2`
- issuance artifacts: `version = 2`
- credential state: `version = 2`
- `benchmark-x0` JSON: `version = 2`

## Benchmarking

The first-pass singleton-`x0` transcript reduction is already in the live code.
Use the benchmark matrix to compare `legacy_scalar`, `lhl_default`, and
`lhl_alt`:

```bash
go run ./cmd/issuance benchmark-x0 -profiles legacy_scalar,lhl_default,lhl_alt -runs 1
```

This now exports per-run:

- total proof bytes
- paper transcript bytes
- paper bucket breakdowns
- transcript-focus geometry
- LHL slack

## Repository Map

- [cmd/README.md](cmd/README.md): command entrypoints and artifact flow
- [credential/README.md](credential/README.md): persisted holder state and
  versioning
- [commitment/README.md](commitment/README.md): Ajtai commitment helper and
  column order
- [PIOP/README.md](PIOP/README.md): proof construction, replay surfaces, and
  proof reporting
- [ntru/README.md](ntru/README.md): trapdoor signing layer
- [prf/README.md](prf/README.md): PRF and grouped checkpoint traces
- [DECS/README.md](DECS/README.md): degree-enforcing commitment layer
- [LVCS/README.md](LVCS/README.md): authenticated row-oracle layer
- [Preimage_Sampler/README.md](Preimage_Sampler/README.md): sampler support
