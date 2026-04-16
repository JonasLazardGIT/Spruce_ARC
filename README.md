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
- showing with the retained coeff-native `v3` layout and PRF companion route
- the SmallWood-style proof stack used by those flows

The protocol framing in this repo follows the current paper source.
The code remains the source of truth for live defaults and supported behavior.

## Reading Order

Start here, then read:

1. [docs/protocol.md](docs/protocol.md) for the current protocol and proof
   model
2. [docs/nizk_alignment_notes.md](docs/nizk_alignment_notes.md) for the
   detailed paper-vs-code reconciliation
3. [docs/modulus_choice.md](docs/modulus_choice.md) for the modulus and packing
   rationale
4. [Commands.md](Commands.md) for operator-facing command usage
5. package READMEs for subsystem context:
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
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

Typical order:

1. `cmd/ntrucli gen` creates the NTRU trapdoor and public key
2. `cmd/issuance demo-local` runs the faithful one-machine holder/issuer flow
   and prepares credential state under `credential/keys/`
3. `cmd/showing` builds and verifies a post-sign proof from that state

## Retained Showing Surface

Only one showing layout remains on the retained proving path:

- `literal_packed_aggregated_v3`

Current showing defaults from code:

- shared parameters:
  `NCols=16`, `Ell=18`, `PRFGroupRounds=2`, explicit domain, replay `reduced`
- default preset `soundness_balanced` resolves to:
  `Theta=3`, `Eta=43`, `EllPrime=2`, `Rho=2`, `LVCSNCols=96`,
  `NLeaves=4096`, `Kappa={0,0,0,5}`
- PRF companion mode defaults to `output_audit`

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
