# Protocol

This document is the canonical protocol/context note for the shipped SPRUCE
codebase. It is written against the current repository and aligned with the
current paper source in `Spruce_Latex`.

Use this file for:

- protocol purpose and terminology
- the current issuance and showing model
- the retained showing layouts and live defaults
- how the proof stack maps into the implementation

Use [../README.md](../README.md) for the repository overview,
[modulus_choice.md](modulus_choice.md) for parameter rationale, and
[../Commands.md](../Commands.md) for command usage.

## Protocol Purpose

SPRUCE is an anonymous-credential construction built around:

- a blind issuance flow that produces a proof-friendly lattice signature
- a showing flow that proves possession of that credential
- a PRF-derived public tag used for rate limiting without revealing the
  credential secret
- a SmallWood-style proof stack that makes both proofs succinct and replayable

This framing follows the current paper story:

- `sections/01_intro.tex` gives the high-level credential and ARC motivation
- `sections/04_arc_construction.tex` gives the issuance/showing narrative
- `appendix/C_smallwood_details.tex` explains the proof stack

## Message Split And Credential Model

The signed credential message is split as:

- `m = μ || k`

where:

- `μ` is the holder attribute payload
- `k` is the secret PRF key used later during showing

The holder also carries bounded randomness used during issuance and the final
signature preimage. In showing, those values stay hidden; only the public nonce
and the derived tag are exposed.

The persisted state is described in [../credential/README.md](../credential/README.md).

## Issuance Flow

The retained issuance command implements the pre-sign proof role.

At a high level:

1. the holder commits to its message and randomness with an Ajtai-style linear
   commitment
2. the issuer contributes challenge randomness
3. the holder centers the combined randomness and derives the target `T`
4. the holder proves that `T` is well formed relative to the commitment and the
   public issuer challenge
5. the issuer signs `T` with the NTRU trapdoor
6. the resulting state is written under `credential/keys/`

In the current code, `T` is public in the issuance proof. That keeps the
pre-sign statement structurally simpler than the post-sign statement.

The implementation entrypoints are:

- `issuance.PrepareCommit`
- `issuance.ApplyChallenge`
- `issuance.ProvePreSign`
- `issuance.VerifyPreSign`

## Showing Flow

The retained showing command implements the post-sign proof role.

At a high level:

1. the holder loads the persisted credential state
2. it chooses a public nonce
3. it computes `tag = PRF(k, nonce)`
4. it proves that:
   - it knows a valid signature `u`
   - the signed message still contains the same hidden `k`
   - the public `tag` is the PRF output derived from that `k` and the chosen
     nonce

This follows the canonical ARC shape from `sections/04_arc_construction.tex`:
the PRF tag is deterministic for a fixed `(k, nonce)` pair, so reused nonces
repeat the same tag, while fresh nonces keep showings unlinkable.

The current command path is:

- `PIOP.BuildShowingCombined`
- `PIOP.VerifyWithConstraints`

## Retained Showing Layouts

Only two showing layouts remain in the shipped code:

### `literal_packed_aggregated_v3`

This is the default one-root layout.

It uses:

- a coeff-native semantic showing witness at the caller boundary
- literal-packed signature rows in the committed witness
- fixed packed signature shortness with radix `13`, `L = 3`, caps `[6,6,4]`
- grouped PRF nonlinear witness rows
- one shared SmallWood commitment/oracle for post-sign and PRF rows

### `literal_packed_aggregated_v4_split_prf`

This is the retained split-PRF prototype layout.

It keeps the same witness semantics and verifier model, but separates the
post-sign and PRF slices into distinct proof slices under one transcript. The
post-sign slice and PRF slice use different LVCS/DECS geometry while keeping
the same high-level statement.

## Current Live Defaults

### Shared ring and field

The shipped code uses:

- ring degree `N = 1024`
- modulus `q = 12289`
- exact modulus width ceiling `k = 14`

These values come from:

- `Parameters/Parameters.json`
- `prf/prf_params.json`

### Issuance defaults

The retained issuance flow uses:

- `Theta = 4`
- `Ell = 25`
- `Eta = 19`
- `EllPrime = 2`
- `Rho = 2`
- witness support width `NCols = 16`

The credential-side bound used in issuance is:

- `BoundB = 8`

from `credential/params.json`.

### Showing defaults

The retained showing flow uses:

- `Theta = 6`
- `Ell = 18`
- `Eta = 31`
- `EllPrime = 2`
- `Rho = 2`
- witness support width `NCols = 16`
- grouped PRF checkpointing with `PRFGroupRounds = 2`

Per layout:

- `v3`: `LVCSNCols = 24`, `NLeaves = 2048`
- `v4 split` post-sign: `LVCSNCols = 32`, `NLeaves = 1536`
- `v4 split` PRF: `LVCSNCols = 28`, `NLeaves = 2048`

## Proof-Stack Mapping

The proof system follows the SmallWood layering described in
`appendix/C_smallwood_details.tex`, with code-specific responsibilities split as
follows.

### Commitment

The [../commitment/README.md](../commitment/README.md) package provides the
Ajtai-style linear commitment used in issuance to bind the holder message and
randomness before the signature target is derived.

### DECS

The [../DECS/README.md](../DECS/README.md) package is the degree-enforcing
commitment layer. It authenticates row evaluations and enforces low-degree
consistency over an explicit evaluation domain.

### LVCS

The [../LVCS/README.md](../LVCS/README.md) package lifts DECS into a row-oracle
commitment that supports the linear openings needed by the proof system.

### PIOP

The [../PIOP/README.md](../PIOP/README.md) package compiles issuance and
showing statements into the retained proof machinery:

- witness row construction
- constraint-family construction
- Fiat-Shamir challenge flow
- verifier replay from committed row openings

### PRF

The [../prf/README.md](../prf/README.md) package implements the Poseidon2-like
PRF and the grouped checkpoint trace helpers used during showing.

## Replay Verifier Model

The retained verifier model is replay based.

That means the verifier checks:

- committed row openings
- public inputs
- replayed constraint residuals
- committed `Q` material
- small-field replay data when `Theta > 1`

It does **not** rely on auxiliary routed openings, legacy helper oracles, or
old layout-specific side channels.

This is the main binding invariant of the shipped stack: all constraint families
are replayed against one coherent committed witness assignment, so the same
hidden message and PRF key are used consistently across the signature, hash, and
PRF checks.

## Current Invariants

The shipped repository assumes:

- one shared base modulus `q` across the NTRU path, rational hash, SmallWood
  constraints, and PRF
- explicit-domain DECS/LVCS semantics
- replay-based proof verification
- only the retained `v3` and split `v4` showing layouts
- coeff-native showing state at the command boundary
- grouped PRF checkpoints on the retained showing surface

For the parameter rationale behind those choices, read
[modulus_choice.md](modulus_choice.md).
