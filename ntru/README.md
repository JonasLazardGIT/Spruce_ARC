# ntru

`ntru/` contains the lattice trapdoor, sampler, and signing logic used by the
shipped credential path.

This package provides the signature primitive that issuance relies on after the
pre-sign proof has fixed the target `T`.

## Main Responsibilities

- construct NTRU parameters and public keys
- generate trapdoors with the shipped FFT-based key generation path
- run the preimage sampler used for signing
- reconstruct and verify signature targets

## Main Entry Points

- `KeygenFFT`
- `NewSampler`
- `PublicKeyH`

The CLI-facing wrappers live in:

- `ntru/signverify`
- `ntru/keys`
- `ntru/io`

The main operator entrypoints built on top of this package are:

- `signverify.GenerateKeypairAnnulus`
- `signverify.SignWithOpts`
- `signverify.SignTarget`
- `signverify.Verify`

## Current Invariants

- the shipped path uses the current tracked parameter file in
  `Parameters/Parameters.json`
- signatures are verified against the same target construction used during
  signing
- the modulus is shared with the proof system and the PRF

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/modulus_choice.md](../docs/modulus_choice.md)
- [../Preimage_Sampler/README.md](../Preimage_Sampler/README.md)
