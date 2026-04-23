# credential

`credential/` defines the persisted holder state used by the live issuance and
showing flows.

It is the bridge between the operator commands and the proving code.

## What It Stores

The live state is versioned and stores:

- semantic credential witness rows:
  - `m`
  - `k`
  - `r0`
  - `r1`
  - `z`
- signature witness rows:
  - `sig_s1`
  - `sig_s2`
- shared runtime anchors:
  - `packed_ncols`
  - `credential_public_path`
  - `hash_relation`
  - `b_path`
  - `prf_params_path`
- issuance audit artifacts:
  - `com`
  - `ri0`
  - `ri1`
- embedded public material:
  - `b`
  - `ntru_public`

Showing reconstructs its coeff-native witness directly from this state. There is
no separate persisted showing blob.

The final credential state does **not** store `T`. `T` is issuance-time data
only.

## Main Entry Points

- `LoadDefaultRing`
- `LoadState`
- `SaveState`

`cmd/issuance` writes the state under `credential/keys/`, and `cmd/showing`
reads it back to build the post-sign proof.

## Current Invariants

- the live state format is `version = 1`
- old aligned or unversioned credential states are rejected
- the state stores semantic witness data, not the old split/aligned commitment
  witness
- the state must not contain issuer trapdoor material
- the state is runtime data, not the protocol specification

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/shared_randomness_migration.md](../docs/shared_randomness_migration.md)
- [../cmd/README.md](../cmd/README.md)
