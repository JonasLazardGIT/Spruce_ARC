# ntru

`ntru/` contains the lattice trapdoor, sampler, key, and signature utilities
used by the credential issuer.

The issuer signs the public IntGenISIS target fixed by issuance:

```text
T = c + h_tran(mu_sig, x0, x1)
```

with preimage sampling for:

```text
A*u = T
```

## Package Role

- Construct NTRU parameters and public keys.
- Generate trapdoors with the FFT-based key-generation path.
- Run the preimage sampler used for signing.
- Reconstruct and verify signature targets.
- Persist and load signing/verification key material for CLI flows.

## Main Entry Points

- `KeygenFFT`
- `NewSampler`
- `PublicKeyH`
- `signverify.GenerateKeypairAnnulusToFiles`
- `signverify.SignTargetWithPaths`
- `signverify.VerifyWithParamsPath`

## Current Invariants

- The shipped path uses `internal/source_data/Parameters.json` unless an
  operator passes an explicit key/parameter path.
- Signatures are verified against the same target construction used during
  signing.
- The modulus is shared with the proof system, commitment layer, and PRF.
- Final credential state stores signature witness and hidden message material,
  not the public target itself.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [Security](../docs/SECURITY.md)
