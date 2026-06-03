# ntru

`ntru/` contains the lattice trapdoor, sampler, and signing logic used by the
shipped credential path.

This package signs the public `bb_tran` target fixed by issuance after the
holder has proven the shared-randomness relation.

## Main Responsibilities

- construct NTRU parameters and public keys
- generate trapdoors with the shipped FFT-based key generation path
- run the preimage sampler used for signing
- reconstruct and verify signature targets
- bind the sampler to the live target equation rather than a deprecated
  commitment-derived target

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

## Current protocol role

The issuer-side signing step is:

```text
sample u such that A u = T
```

where the live target is:

```text
T = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z
```

with:

```text
(B3 - r1) ⊙ Z = 1
```

The NTRU package does not derive `T` from the commitment and does not know
about the deprecated `Uc` path. It consumes the public target supplied by the
current issuance flow.

## Current Invariants

- the shipped path uses the current tracked parameter file in
  `internal/source_data/Parameters.json`
- signatures are verified against the same target construction used during
  signing
- the target shape is the direct shared-randomness `bb_tran` target
- the modulus is shared with the proof system and the PRF
- the final credential state stores the signature witness and hidden message
  material, not `T` itself

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/modulus_choice.md](../docs/modulus_choice.md)
