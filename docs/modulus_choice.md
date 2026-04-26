# Modulus Choice

This note explains the current shared-field choice for the live ARC-SPRUCE
implementation and how that modulus interacts with the post-migration witness,
the vector-`x0` parameterization, and the current transcript surface.

It is an implementation note, not a paper derivation and not a full parameter
regeneration checklist.

## Current arithmetic surface

The live branch keeps the following layers over one shared modulus `q`:

- NTRU signing and verification
- `bb_tran` target arithmetic
- the SmallWood-style proof stack
- the PRF used in showing

That is a deliberate design choice. It avoids cross-field encodings between:

- the signed witness `u`
- the hash/inverse witness `(m, k, r0, r1, Z)`
- replay-authenticated proof rows
- PRF checkpoint rows and final tag constraints

For the current implementation, one shared field is the simplest way to keep
issuance and showing in one coherent arithmetic model.

## Current live values

### Core ring and signature parameters

From `Parameters/Parameters.json`:

- ring degree `N = 1024`
- modulus `q = 1054721`
- modulus-width ceiling `k = 21`
- signature bound `beta = 6142`
- signature bound alias `bound = 6142`

The opt-in degree-512 research fork uses
`Parameters/Parameters.research_n512.json` with the same `q` and `beta` but
`n = 512`. That file is only for separately generated `research_n512`
artifacts; it is not the default public parameter set.

### Credential-side public parameters

From `Parameters/credential_public.json`:

- `BoundB = 1`
- `X0Len = 6`
- `X0CoeffBound = 5`
- `TargetDim = 1`
- `TargetHidingLambda = 128`

These are the current checked-in `lhl_default` values.

### PRF parameters

From `prf/prf_params.json`:

- `q = 1054721`
- S-box exponent `d = 3`
- `LenKey = 8`
- `LenNonce = 12`
- `LenTag = 7`
- state width `t = 20`
- `RF = 8`
- `RP = 19`

## Why `q = 1054721` is the live modulus

The current modulus is not just "big enough". It simultaneously satisfies the
constraints of the current protocol stack.

- `q` is prime, so the proof stack and PRF run over a field.
- `q ≡ 1 mod 2048`, so the default `N = 1024` power-of-two NTT structure works.
  This also satisfies the `N = 512` research fork's weaker `q ≡ 1 mod 1024`
  NTT requirement.
- `q ≡ 2 mod 3`, so the cubic PRF exponent is compatible with the field.

Those properties let the repo keep:

- the current NTRU/ring infrastructure
- explicit-domain DECS/LVCS commitments
- the cubic PRF
- the direct `bb_tran` target relation

inside one base field.

## How the modulus interacts with the live witness

The post-migration credential witness is:

- `u`
- `m`
- `k`
- `r0[0], ..., r0[X0Len-1]`
- `r1`
- `Z`

with target:

```text
T = B0 + B1 * (m || k) + sum_j B2[j] * r0[j] + Z
```

The modulus therefore affects:

- NTRU preimage sampling and verification on `A u = T`
- the inverse-witness equation `(B3 - r1) ⊙ Z = 1`
- the `B2[j] * r0[j]` accumulation on the `x0` side
- the low-degree proof arithmetic that authenticates those rows
- the PRF constraints on the signed key `k`

This is why the modulus is shared infrastructure, not an isolated signature
parameter.

## Bound separation: `beta`, `BoundB`, and `X0CoeffBound`

The live repo has three different "smallness" concepts that should not be
collapsed together.

### Signature bound

- `beta = 6142`
- used for `sig_s1` / `sig_s2` shortness checks
- lives on the NTRU side

### Credential-side small alphabet

- `BoundB = 1`
- governs:
  - packed message carriers for `(m, k)` under the current demo profile
  - scalar centering side `r1`
  - scalar carry `k1`
  - `rbar`

### `x0` side bound

- `X0CoeffBound = 5` on the shipped `lhl_default` profile
- governs:
  - holder-side `r0H[]`
  - issuer-side `r0I[]`
  - centered `r0[]`
  - `k0[]` carry rows
  - the singleton low-alphabet `x0` carrier codec

This separation matters both cryptographically and for transcript size.

## Why the vector-`x0` regime matters for arithmetic costs

The current branch is no longer scalar on the target-hiding side.

Shipped `lhl_default`:

- `X0Len = 6`
- `X0CoeffBound = 5`
- singleton `x0` alphabet size `2*5+1 = 11`

Alternative `lhl_alt`:

- `X0Len = 5`
- `X0CoeffBound = 8`
- singleton `x0` alphabet size `2*8+1 = 17`

Even though both profiles satisfy the current LHL target, the larger `x0`
alphabet of `lhl_alt` increases the degree of low-alphabet membership and
decode constraints. That, in turn, pushes:

- `dQ`
- `Pdecs`
- overall paper transcript size

The modulus does not cause that effect by itself, but the shared field fixes
the ambient arithmetic cost of every such degree increase.

## Why the PRF uses the same modulus

The PRF is part of the showing relation:

```text
tag = F(k, nonce)
```

Using the same modulus means:

- `k` can be extracted from the signed message witness directly into `F_q`
- nonce lanes already live in the same field as the rest of the statement
- grouped checkpoint constraints and final tag constraints remain native to the
  main proof system

That avoids field-translation gadgets between the signature/hash witness and
the PRF side of the statement.

## What a modulus change would force

Changing `q` is not a one-package edit. At minimum it requires revalidating:

1. `Parameters/Parameters.json`
2. `Parameters/credential_public.json`
3. `prf/prf_params.json`
4. `Parameters/Bmatrix_bb_tran_x0len*.json`
5. NTRU keys and signatures
6. the LHL report for the active `x0` profile
7. proof geometry and presets that depend on row width and degree

Changing only the ring degree is also not a runtime flag on existing
artifacts. The `N=512` fork needs its own public params, B matrix, NTRU
params/key material, issuance artifacts, credential state, and signature
files. The code validates exact coefficient lengths before converting those
artifacts to ring polynomials.

In practice it also forces regeneration of:

- credential artifacts
- credential state
- signature fixtures
- transcript benchmark baselines

## Practical reading rule

When you see transcript or proof-size changes in the current repo, do not read
them as a pure modulus story.

For the live branch, size comes from the interaction of:

- shared modulus width
- witness geometry
- low-alphabet support size
- replay opening layout
- shortness payload

The modulus is the foundation, but the current transcript gains and losses are
mostly driven by how the witness is arithmetized over that field.

## Reading next

- [protocol.md](protocol.md) for the current issuance/showing model
- [shared_randomness_migration.md](shared_randomness_migration.md) for the
  post-aligned migration history
- [transcript_reduction_analysis.md](transcript_reduction_analysis.md) for the
  current measured transcript bottlenecks
- [../PIOP/README.md](../PIOP/README.md) for the proof-system package surface
