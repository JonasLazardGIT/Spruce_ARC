# Modulus Choice

This note explains the current modulus choice in human terms. It is not a
regeneration runbook; it is the rationale behind why the shipped code uses the
field and packing profile it does.

The paper background for this note comes mainly from:

- `sections/06_parameters.tex`
- `appendix/D_extended_parameters.tex`
- `appendix/E_prf_and_misc.tex`

The live values come from the repository itself.

## Why One Shared Field

SPRUCE keeps the core protocol on one shared modulus and base field.

That single choice ties together:

- the NTRU signature map and target construction
- the rational hash used to derive the blind-signature target
- the SmallWood proof stack, whose constraints are evaluated over `F_q`
- the PRF, which is instantiated over the same field so its constraints remain
  native to the proof system

This is the simplest coherent design for the shipped code. It avoids field
translation layers between the signature path, the proof system, and the PRF.

## Current Live Values

From `Parameters/Parameters.json`:

- ring degree `N = 1024`
- modulus `q = 1054721`
- modulus width ceiling `k = 21`
- retained signature coefficient bound `beta = 745`

From `credential/params.json`:

- issuance/showing message bound `BoundB = 8`

From `prf/prf_params.json`:

- the PRF also uses `q = 1054721`
- exponent `d = 3`
- `LenKey = 8`
- `LenNonce = 12`
- `LenTag = 7`
- `RF = 8`
- `RP = 19`

## Migration Status

The field and PRF migration is configured in code, but the end-to-end adoption
is not complete yet.

Two blockers remain on the current branch:

- regenerated NTRU signatures under `q = 1054721` no longer fit the preserved
  showing bound `beta = 745`
- issuance pre-sign proof replay is not yet verifying again under the migrated
  field

So this note describes the selected target field and why it was chosen, but not
yet a fully re-landed end-to-end proving baseline.

## Why The Wider Field Was Chosen

The new modulus is close to `2^20`, but not chosen only for width.

It was selected because:

- `q = 1054721` is prime
- `q ≡ 1 mod 2048`, so the current `N = 1024` power-of-two NTT structure stays valid
- `q ≡ 2 mod 3`, so `gcd(3, q-1) = 1` and the paper rule selects a cubic PRF

The older near-`2^20` candidate `1038337` does not satisfy the cubic PRF
condition.

## Why The Wider Field Still Hurts Packing

Moving from the old 14-bit regime to the current 21-bit regime increases the
encoded width of many packed field elements.

That matters because:

- the proof serializer packs many field-valued objects tightly
- transcript buckets such as `VTargets`, `QR`, row openings, and `Q` openings
  are sensitive to width growth
- moving to a larger modulus quickly increases encoded proof size even if the
  logical statement stays the same

The current choice therefore helps the proof system in two ways at once:

- it keeps the arithmetic native to the same field across all subsystems
- but it does not keep packed proof payloads as compact as the old 14-bit field

## How `beta` And Signature Shortness Fit Together

The retained showing path still keeps the old signature coefficient target:

- `beta = 745`

Under the new field, regenerated signatures currently exceed that retained
bound, so the migration is intentionally blocked until the signature-bound
decision is resolved. The modulus and the showing shortness gadget are therefore
still coupled design choices, not independent knobs.

## Why The PRF Shares The Same Modulus

The PRF is proved inside the showing statement, so the cheapest design is still
to keep it in the same field as the rest of the proof system.

That means:

- key lanes are represented directly over `F_q`
- checkpointed S-box outputs are replayed over the same field
- no cross-field encoding is needed before building the proof

With the new modulus, the paper rule now selects the cubic S-box, so the PRF is
not only field-aligned but also paper-aligned on exponent choice.

The PRF is therefore not a bolt-on subsystem. It is chosen so the showing proof
can express:

- signature validity
- hidden-message consistency
- tag correctness

inside one coherent field arithmetic model.

## How The Modulus Affects Proof Geometry

The modulus choice interacts with proof geometry indirectly through packing and
soundness.

For showing, the currently retained preset structure still exists, but the
field migration does not yet have a fully re-landed end-to-end baseline because
of the blockers above.

## If `q` Changes

If the modulus changes, the minimal consequences are:

1. update `Parameters/Parameters.json`
2. regenerate `prf/prf_params.json` for the same field
3. regenerate NTRU keys and signatures
4. rerun issuance so credential state and showing payloads are rebuilt under the
   new field
5. recheck the shortness gadget against the new `beta` and `q / 2`
6. rerun `cmd/showing` in both retained layouts to confirm the packing and proof
   geometry still make sense

In other words, a modulus change is never just an NTRU change. It changes the
shared arithmetic base of the signature path, the proof system, and the PRF.

## Reading Next

- [protocol.md](protocol.md) for the current issuance/showing model
- [../PIOP/README.md](../PIOP/README.md) for the proof-stack implementation
- [../prf/README.md](../prf/README.md) for the PRF and grouped checkpoint trace
