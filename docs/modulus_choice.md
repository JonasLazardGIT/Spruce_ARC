# Modulus Choice

This note explains the current shared-field choice used by the live SPRUCE
branch. It is implementation-facing, not a paper-only rationale and not a
parameter-regeneration runbook.

## Why One Shared Field

The current branch keeps the main arithmetic layers on one modulus:

- the NTRU signature target and public verification equation
- the rational-hash relation
- the SmallWood-style proof stack
- the PRF used during showing

That avoids cross-field encodings between:

- signed witness rows
- proof-system rows and replay identities
- PRF checkpoint constraints

For the current implementation, one shared field is the simplest way to keep
issuance and showing inside one coherent arithmetic model.

## Current Live Values

### From `Parameters/Parameters.json`

- ring degree `N = 1024`
- modulus `q = 1054721`
- modulus-width ceiling `k = 21`
- signature bound `beta = 6142`
- signature bound alias `bound = 6142`

### From `credential/params.json`

- message / centering bound `BoundB = 1`

### From `prf/prf_params.json`

- the PRF also uses `q = 1054721`
- S-box exponent `d = 3`
- `LenKey = 8`
- `LenNonce = 12`
- `LenTag = 7`
- state width `t = 20`
- `RF = 8`
- `RP = 19`

## Why `q = 1054721` Works For The Current Stack

The live modulus is not just "a large enough prime". It satisfies several
branch-critical constraints at once.

- `q` is prime, so all proof/PRF arithmetic is performed in a field.
- `q ≡ 1 mod 2048`, so the current `N = 1024` power-of-two NTT structure is
  valid.
- `q ≡ 2 mod 3`, so the cubic PRF exponent is compatible with the field.

Those conditions let the branch keep:

- the current NTRU/ring infrastructure
- the explicit-domain proof machinery
- the cubic PRF used by the showing proof

inside the same base field.

## What This Means For The Proof System

Keeping one field means the proof system can express:

- the pre-sign public-target hash relation
- the post-sign matrix equation for the signature witness
- the transform-bridge replay identities
- the grouped PRF checkpoint constraints

without field translation layers.

That does not make packing free. A 21-bit modulus is wider than the older
small-field regimes sometimes referenced in stale repo prose, so any serialized
field payload that is packed bitwise will generally grow. But the live branch
chooses implementation coherence over those older narrower-field assumptions.

## How The Modulus Interacts With Current Bounds

The current repo should be read with the following pairings in mind:

- signature-side coefficient checks use `beta = 6142`
- credential-side carrier/centering checks use `BoundB = 1`

These numbers come from different runtime assets and govern different parts of
the stack:

- `beta` is the showing-time bound checked against `SigS1` / `SigS2`
- `BoundB` is the low-alphabet bound used for message packing, centering, and
  carrier decode/membership on the credential side

So a modulus change is not only a signature change. It affects:

- the signature witness range
- the carrier encoding space
- the transform-replay arithmetic
- the PRF field and checkpoint equations

## Why The PRF Uses The Same Modulus

The PRF is not an add-on subsystem in this branch. It is part of the showing
statement.

Using the same modulus means:

- key lanes are decoded directly from signed message material into `F_q`
- nonce lanes live in the same field as the signature/hash witness
- checkpoint openings and final tag constraints stay native to the proof system

For the current live code, that is the cheapest and cleanest way to ensure the
public tag is tied to the same hidden signed message that supports the
post-sign proof.

## If `q` Changes

At minimum, a modulus change requires revalidating all of the following:

1. `Parameters/Parameters.json`
2. `prf/prf_params.json`
3. NTRU keys and signatures
4. issuance output in `credential/keys/credential_state.json`
5. showing-time signature-bound checks against the new `beta`
6. proof geometry and preset defaults that depend on row width / packing width

In other words, the modulus is shared infrastructure. It is not safe to treat
it as a single-package knob.

## Reading Next

- [protocol.md](protocol.md) for the current issuance/showing model
- [nizk_alignment_notes.md](nizk_alignment_notes.md) for paper-vs-code
  reconciliation
- [../PIOP/README.md](../PIOP/README.md) for the proof-system package surface
