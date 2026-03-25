# credential

`credential/` defines the persisted holder state used by the retained issuance
and showing flows.

It is the bridge between the operator commands and the proving code.

## What It Stores

The current state includes:

- issuance-side public matrices and metadata
- pre-sign witness outputs such as `T`
- the coeff-native semantic showing payload
- references to PRF parameters and NTRU public data

The semantic showing payload is built around:

- `Sig`
- `U`
- `X0`
- `X1`
- `PRFKey`
- `NCols`

## Main Entry Points

- `LoadDefaultRing`
- `LoadState`

`cmd/issuance` writes the state under `credential/keys/`, and `cmd/showing`
reads it back to build the post-sign proof.

## Current Invariants

- the persisted state is aligned with the current shared modulus
- showing uses the coeff-native semantic payload, not a legacy layout-specific
  witness file
- the state is treated as command/runtime data, not as the protocol
  specification

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../cmd/README.md](../cmd/README.md)
