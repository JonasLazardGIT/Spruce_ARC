# Shared-Randomness Migration Note

This branch has migrated from the older commitment-derived target flow to the
shared-randomness `h_tran` flow.

## Breaking Changes

- `credential/keys/credential_state.json` is now versioned and must be
  `version = 1`
- issuance artifacts under `credential/issuance/` are now versioned and must be
  `version = 1`
- the persisted credential witness is now semantic:
  - `m`
  - `k`
  - `r0`
  - `r1`
  - `z`
  - `sig_s1`
  - `sig_s2`
- final credential state no longer stores `T`
- live public parameter names are now:
  - `LenM`
  - `LenK`
  - `LenR0H`
  - `LenR1H`
  - `LenRBar`

## Unsupported Old Data

The live code rejects:

- unversioned or legacy credential states
- old issuance artifacts written for the aligned or commitment-derived flow

The public-parameter loader still accepts the older length field names when
reading historical `credential_public.json` files, but that compatibility is
only for loading the parameter file. It does not make old credential states or
issuance transcripts valid.

## Regenerate Fresh Artifacts

Use this sequence from the repository root:

```bash
go run ./cmd/ntrucli gen
go run ./cmd/issuance demo-local
go run ./cmd/showing
```

For role-separated issuance, rerun the full artifact sequence:

```bash
go run ./cmd/issuance holder-commit
go run ./cmd/issuance issuer-challenge
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
```
