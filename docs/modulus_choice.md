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
- modulus `q = 12289`
- modulus width ceiling `k = 14`
- signature coefficient bound `beta = 745`

From `credential/params.json`:

- issuance/showing message bound `BoundB = 8`

From `prf/prf_params.json`:

- the PRF also uses `q = 12289`
- exponent `d = 5`
- `LenKey = 8`
- `LenNonce = 12`
- `LenTag = 7`
- `RF = 8`
- `RP = 18`

## Why The 14-Bit Ceiling Matters

The current modulus sits below `2^14`, so packed proof objects stay within a
14-bit field-width ceiling on the shipped path.

That matters because:

- the proof serializer packs many field-valued objects tightly
- transcript buckets such as `VTargets`, `QR`, row openings, and `Q` openings
  are sensitive to width growth
- moving to a larger modulus quickly increases encoded proof size even if the
  logical statement stays the same

The current choice therefore helps the proof system in two ways at once:

- it keeps the arithmetic native to the same field across all subsystems
- it keeps packed proof payloads compact

## How `beta` And Signature Shortness Fit Together

The shipped showing path uses a fixed signed shortness chain:

- radix `R = 13`
- length `L = 3`
- caps `[6, 6, 4]`

That gives a representable signed range of:

- `6 + 13*6 + 13^2*4 = 760`

which comfortably covers the live signature bound:

- `beta = 745`

while still remaining well below `q / 2 = 6144`.

That is the key no-wrap property the code needs:

- the shortness gadget must cover the live signature bound
- its signed decomposition must still behave cleanly modulo `q`

So the modulus and the shortness gadget are not independent knobs. The chosen
`q` is part of why the shipped `R = 13`, `L = 3`, caps `[6,6,4]` profile is
compact and safe.

## Why The PRF Shares The Same Modulus

The PRF is proved inside the showing statement, so the cheapest design is to
keep it in the same field as the rest of the proof system.

That means:

- key lanes are represented directly over `F_q`
- checkpointed S-box outputs are replayed over the same field
- no cross-field encoding is needed before building the proof

The PRF is therefore not a bolt-on subsystem. It is chosen so the showing proof
can express:

- signature validity
- hidden-message consistency
- tag correctness

inside one coherent field arithmetic model.

## How The Modulus Affects Proof Geometry

The modulus choice interacts with proof geometry indirectly through packing and
soundness.

For showing, the shipped defaults are:

- shared:
  `NCols = 16`, `Theta = 6`, `Ell = 18`, `Eta = 31`, `EllPrime = 2`, `Rho = 2`
- one-root `v3`:
  `LVCSNCols = 24`, `NLeaves = 2048`
- split `v4`:
  post-sign `32 / 1536`
  and PRF `28 / 2048`

Those geometry choices were made under the current field and packing budget.
The field width constrains how expensive packed openings become, while the
SmallWood degree and soundness terms constrain how narrow or wide the committed
row layout can be without hurting the proof.

In practice, the current modulus supports a compact packed proof profile while
still leaving enough room for:

- the signature equation
- the fixed shortness gadget
- the grouped PRF checkpoints
- the explicit-domain DECS/LVCS proof stack

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
