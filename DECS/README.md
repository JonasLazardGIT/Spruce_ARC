# DECS

`DECS/` is the degree-enforcing commitment layer used by the retained proof
stack. It authenticates row evaluations and checks that opened values come from
low-degree polynomials rather than arbitrary vectors.

## Package Role

- Commit rows over an explicit evaluation domain.
- Derive verifier-side masking coefficients.
- Open selected points with Merkle authentication.
- Verify low-degree masked relations at opened points.

## Main Entry Points

- `NewProverWithParamsAndPointsFormalChecked`
- `(*Prover).CommitInitV2WithOptions`
- `(*Prover).CommitStep2Formal`
- `(*Prover).EvalOpenV2`
- `NewVerifierWithParamsAndPointsV2Checked`
- `BuildMerkleTreeFromLeafHashBytesV2`
- `VerifyPathHashV2`
- `MergeOpeningsV2`

The v2 API requires a `CommitmentContext` containing the exact transcript
identity `smallwood_2025_1085_salted_decs_v2`, a canonical commitment-role
label, and the proof-global salt. It returns and verifies the full
configured-width root. There is no context-free commitment or verification
entry point.

Verifier-side DECS checks are consumed through LVCS and PIOP.

## Current Invariants

- Explicit-domain semantics are mandatory.
- Low-degree checks run over the shared base field.
- Formal coefficient rows are supported where degree-sensitive proof paths need
  them.
- V2 samples one independent tape per leaf and reveals exactly the tapes for
  the distinct opened indices. No master derivation seed is represented by the
  maintained opening type.
- Leaf, padding, and internal-node hashes have separate v2 domains and bind
  full-width indices, tree positions, version, role, and salt.
- On the maintained path, DECS authenticates row openings for the carrier and
  PRF-companion replay families.
- The vector-`x0` path changes row-degree geometry without changing DECS
  semantics.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [LVCS](../LVCS/README.md)
- [PIOP](../PIOP/README.md)
