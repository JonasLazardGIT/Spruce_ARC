# credential

`credential/` defines the persisted holder state used by the retained issuance
and showing flows.

It is the bridge between the operator commands and the proving code.

## What It Stores

The current state includes:

- issuance witness rows and public commitment/challenge artifacts
- `credential_public_path`, the stable credential public-parameter source
- pre-sign witness outputs such as `T`
- showing signature rows and packed-width metadata
- references to PRF parameters and issuer public key data

Showing reconstructs its coeff-native semantic witness directly from the
top-level signed state; there is no separate runtime showing blob.
Both reduced and theorem-clean full showing derive the hidden shortness witness
and committed `THat` surface from that same state at runtime.

## Main Entry Points

- `LoadDefaultRing`
- `LoadState`

`cmd/issuance` writes the state under `credential/keys/`, and `cmd/showing`
reads it back to build the post-sign proof.

## Current Invariants

- the persisted state is aligned with the current shared modulus
- showing uses the coeff-native semantic payload, not a legacy layout-specific
  witness file
- reduced showing no longer relies on a persisted packed-signature replay basis
- full showing still reconstructs the theorem-clean replay surface from the
  same signed state rather than a second persisted showing blob
- the state must not contain issuer trapdoor material
- the state is treated as command/runtime data, not as the protocol
  specification

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../cmd/README.md](../cmd/README.md)
