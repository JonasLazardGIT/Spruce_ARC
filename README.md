# SPRUCE

SPRUCE is a lattice-based anonymous credential prototype built around two proof
roles:

- **issuance**, where a holder proves that a blind-signature target was formed
  correctly before the issuer signs it;
- **showing**, where the holder proves possession of a valid credential and a
  correctly derived PRF tag without revealing the credential secret.

The current repository is the reduced, shipped codebase. It keeps only the
credential path that is still wired end to end:

- NTRU key generation, signing, and verification
- blind issuance / pre-sign proving
- showing with the retained `v3` and split-PRF `v4` layouts
- the SmallWood-style proof stack used by those flows

The protocol framing in this repo follows the current paper source in
`Spruce_Latex`, especially:

- `sections/01_intro.tex`
- `sections/04_arc_construction.tex`
- `sections/06_parameters.tex`
- `appendix/C_smallwood_details.tex`
- `appendix/D_extended_parameters.tex`
- `appendix/E_prf_and_misc.tex`

The code remains the source of truth for live defaults and supported behavior.

## Reading Order

Start here, then read:

1. [docs/protocol.md](docs/protocol.md) for the current protocol and proof
   model
2. [docs/modulus_choice.md](docs/modulus_choice.md) for the modulus and packing
   rationale
3. [Commands.md](Commands.md) for operator-facing command usage
4. package READMEs for subsystem context:
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
go run ./cmd/ntrucli sign -m test
go run ./cmd/ntrucli verify
go run ./cmd/issuance
go run ./cmd/showing
go run ./cmd/showing -coeff-model literal_packed_aggregated_v4_split_prf
```

Typical order:

1. `cmd/ntrucli gen` creates the NTRU trapdoor and public key
2. `cmd/issuance` prepares credential state under `credential/keys/`
3. `cmd/showing` builds and verifies a post-sign proof from that state

## Retained Showing Surface

Only two showing layouts remain:

- `literal_packed_aggregated_v3`
- `literal_packed_aggregated_v4_split_prf`

`v3` is the default shipped layout.

Current showing defaults from code:

- shared parameters:
  `NCols=16`, `Theta=6`, `Ell=18`, `Eta=31`, `EllPrime=2`, `Rho=2`
- one-root `v3`:
  `LVCSNCols=24`, `NLeaves=2048`
- split `v4`:
  post-sign `LVCSNCols=32`, `NLeaves=1536`
  and PRF `LVCSNCols=28`, `NLeaves=2048`

## Runtime Assets

The shipped commands rely on tracked runtime files:

- `Parameters/Parameters.json`
- `Parameters/Bmatrix.json`
- `credential/params.json`
- `credential/Ac.json`
- `credential/keys/*.json`
- `prf/prf_params.json`
- `ntru_keys/*.json`

## Repository Map

- [cmd/README.md](cmd/README.md): executable entrypoints
- [credential/README.md](credential/README.md): persisted holder state and
  showing payload
- [ntru/README.md](ntru/README.md): NTRU trapdoor, sampler, and signing logic
- [prf/README.md](prf/README.md): PRF definition and grouped trace helpers
- [PIOP/README.md](PIOP/README.md): proof orchestration for issuance and showing
- [DECS/README.md](DECS/README.md): degree-enforcing commitment layer
- [LVCS/README.md](LVCS/README.md): row-oracle commitment and linear openings
- [Preimage_Sampler/README.md](Preimage_Sampler/README.md): high-precision FFT
  and cyclotomic arithmetic used by the sampler
- [commitment/README.md](commitment/README.md): Ajtai-style linear commitment
  helper used in issuance
