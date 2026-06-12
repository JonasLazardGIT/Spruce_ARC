# credential

`credential/` defines the persisted IntGenISIS data model: public parameters,
holder state, maintained presets, policy data, presentations, and verifier
keys.

## Package Role

- Own the public preset registry used by `cmd/issuance` and `cmd/showing`.
- Persist the public matrices, profile metadata, commitment/security
  annotations, and verifier-facing parameters.
- Persist holder state after issuance without storing issuer trapdoor material.
- Bind presentation metadata, replay state, and policy digests to verifier
  checks.

## Key Files

- `intgenisis_profile.go`: profile descriptors for the maintained `N=512` and
  `N=1024` families.
- `intgenisis_presets.go`: the preset registry and preset-derived accounting.
- `public_params.go`: shared public-parameter serialization.
- `intgenisis_public.go`: IntGenISIS public-parameter structure.
- `intgenisis_state.go`: holder state saved by issuance and consumed by
  showing.
- `intgenisis_presentation.go`: verifier-facing presentation metadata.
- `intgenisis_verifier_key.go`: verifier-key persistence.
- `intgenisis_security.go`: archived estimator metadata attached to public
  parameters.

## Current Invariants

- The public CLI parameter surface is the maintained preset registry.
- Preset-derived `ROQueryCaps` and `DECSCollisionBits` remain part of reports
  and persisted runtime artifacts.
- Holder state stores witness and signature material needed for showing; it
  must not contain issuer trapdoor material.
- Public parameters bind `Profile`, `Modulus`, `HashRelation`, `BPath`,
  commitment matrices, dimensions, `ring_degree`, and security metadata.
- The PRF seed is a bounded 48-coefficient witness region that is packed into
  the Poseidon key lanes by the protocol layer.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [Security](../docs/SECURITY.md)
- [Artifact Guide](../ARTIFACT.md)
