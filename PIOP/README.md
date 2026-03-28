# PIOP

`PIOP/` contains the retained proving and verifying core for SPRUCE.

Its job is to turn the shipped statements into the current SmallWood-style proof
stack:

- issuance / pre-sign proving
- showing in the one-root `v3` layout
- showing in the retained one-root coeff-native layout

## Main Responsibilities

- build witness rows for issuance and showing
- compile the active constraint families
- run the Fiat-Shamir proof flow
- drive DECS/LVCS commitments and openings
- replay verifier checks from opened row values and public inputs

## Main Entry Points

- `NewCredentialBuilder`
- `BuildWithConstraints`
- `VerifyWithConstraints`
- `BuildShowingCombined`
- `BuildCredentialRowsShowing`
- `BuildProofReport`
- `BuildProofPackingAudit`

## Current Invariants

- explicit-domain DECS/LVCS semantics
- replay-based verification
- only the retained showing layouts:
  `literal_packed_aggregated_v3`
  and the retained `literal_packed_aggregated_v3`
- coeff-native showing witness at the caller boundary
- grouped PRF checkpoints in the showing statement

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../DECS/README.md](../DECS/README.md)
- [../LVCS/README.md](../LVCS/README.md)
