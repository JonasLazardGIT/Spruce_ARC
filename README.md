# SPRUCE

SPRUCE is a lattice-based anonymous credential prototype with two live proof
roles:

- **issuance**: the holder commits to `(mu, r0H, r1H, rbar)`, derives the
  shared-randomness `bb_tran` target, and proves the public target before the
  issuer signs it
- **showing**: the holder proves possession of a valid credential witness and a
  correctly derived PRF tag without revealing the hidden credential data

The current live credential path is the shared-randomness `h_tran` flow:

- `mu = (m || k)`
- `c = ACom [m || k || r0H || r1H || rbar]^T`
- issuer challenge rows `r0I`, `r1I`
- centered rows `r0 = center(r0H + r0I)`, `r1 = center(r1H + r1I)`
- direct `bb_tran` target
  `T = B0 + B1 * mu + B2 * r0 + (B3 - r1)^(-1)`
- issuer sampling `u` such that `A u = T`
- showing tag `tag = F(k, nonce)`

The old live path is no longer the implementation surface:

- no target-from-commitment `T = B0 + Uc + Z`
- no aligned commitment randomness `(S, E)`
- no live dependence on `Uc`, `MSigmaR1`, `R0R1`, or source-product replay rows

Two showing surfaces remain:

- shipped default: `go run ./cmd/showing`
  uses reduced replay under the `soundness_balanced` preset
- theorem-clean control: `go run ./cmd/showing -showing-preset compact_l1_research -full`
  runs the full replay statement used by the baseline study note

## Reading Order

1. [docs/protocol.md](docs/protocol.md) for the current issuance/showing model
2. [docs/shared_randomness_migration.md](docs/shared_randomness_migration.md)
   for artifact and credential-format migration notes
3. [docs/nizk_alignment_notes.md](docs/nizk_alignment_notes.md) for
   paper-to-code alignment at the current protocol surface
4. [docs/full_baseline_proof_study.md](docs/full_baseline_proof_study.md) for
   the current theorem-clean full replay workflow
5. [docs/modulus_choice.md](docs/modulus_choice.md) for modulus and packing
   rationale
6. [Commands.md](Commands.md) for operator-facing command usage
7. package READMEs for subsystem context:
   [PIOP](PIOP/README.md),
   [ntru](ntru/README.md),
   [prf](prf/README.md),
   [credential](credential/README.md),
   [DECS](DECS/README.md),
   [LVCS](LVCS/README.md),
   [Preimage_Sampler](Preimage_Sampler/README.md),
   [commitment](commitment/README.md)

## Quick Start

Run everything from the repository root.

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

Typical order:

1. `cmd/ntrucli gen` creates the issuer trapdoor and public key
2. `cmd/issuance demo-local` runs the shared-randomness holder/issuer flow and
   writes `credential/keys/credential_state.json`
3. `cmd/showing` builds and verifies a post-sign proof from that state

## Runtime Assets

The shipped commands rely on tracked runtime files:

- `Parameters/Parameters.json`
- `Parameters/Bmatrix_bb_tran.json`
- `Parameters/credential_public.json`
- `credential/issuance/*.json`
- `credential/keys/*.json`
- `prf/prf_params.json`
- `ntru_keys/*.json`

## Repository Map

- [cmd/README.md](cmd/README.md): executable entrypoints and artifact flow
- [credential/README.md](credential/README.md): persisted holder state and
  migration rules
- [ntru/README.md](ntru/README.md): trapdoor sampler and signature logic
- [prf/README.md](prf/README.md): PRF definition and grouped trace helpers
- [PIOP/README.md](PIOP/README.md): proof orchestration for issuance and showing
- [DECS/README.md](DECS/README.md): degree-enforcing commitment layer
- [LVCS/README.md](LVCS/README.md): row-oracle commitment and linear openings
- [Preimage_Sampler/README.md](Preimage_Sampler/README.md): FFT support for the
  sampler
- [commitment/README.md](commitment/README.md): Ajtai-style linear commitment
  helper used by issuance
