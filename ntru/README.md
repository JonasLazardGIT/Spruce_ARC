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

## Entropy

Production key generation and preimage sampling read from `crypto/rand.Reader`.
There is no package-global pseudorandom generator. Tests and audited callers can
inject a deterministic or alternate `io.Reader` through `KeygenOpts.Entropy`,
`SamplerOpts.Entropy`, `NewSamplerWithReader`, or `SetEntropyReader`. Short reads
and reader failures are returned as errors wrapping `ntru.ErrEntropySource`.

## V2 Artifacts

- Parameter files have the exact identity `ntru-params-v2` and carry a
  canonical SHA-256 digest of `(N,Q,beta)`. `LoadParams` rejects legacy files,
  unknown fields, redundant `k`/`bound` mismatches, and stale digests.
- Public and private key files have the exact identity `ntru-key-v2`. Public
  keys carry a canonical key ID; private keys bind that ID and the parameter
  digest.
- Signature bundles have the exact identity `ntru-signature-v2`, bind the
  parameter digest and public-key ID, and carry a canonical content ID.
- `signverify.GenerateKeypairAnnulusToFiles` accepts `ntru/io.SystemParams` so
  generated keys bind the complete parameter identity rather than only `N/Q`.

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
