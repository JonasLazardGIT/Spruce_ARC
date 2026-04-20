# Updated Protocol Note

This document is the implementation-canonical protocol note for the current
SPRUCE branch after the hidden `SigShortnessV6` redesign.

If this file disagrees with older prose, memos, or stale comments, the current
code wins. The main code anchors are:

- [PIOP/generic_builder.go](../PIOP/generic_builder.go)
- [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [PIOP/masking_fs.go](../PIOP/masking_fs.go)
- [PIOP/masking_fs_helper.go](../PIOP/masking_fs_helper.go)
- [PIOP/VerifyNIZK.go](../PIOP/VerifyNIZK.go)
- [PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go)
- [PIOP/run.go](../PIOP/run.go)
- [cmd/showing/main.go](../cmd/showing/main.go)

This file exists because [protocol.md](protocol.md) still describes the older
same-root shortness path. New literal-packed showing proofs now use:

- an outer showing proof over the main retained witness
- a nested hidden SmallWood proof for shortness
- a root-authenticated outer `THat` opening that binds the two together

## Scope

The retained branch implements two proof roles:

- issuance: a public-target pre-sign proof
- showing: a packed showing proof for possession of a valid signature plus a
  correctly derived PRF tag

The current shipped showing architecture is narrower than the full paper design
space:

- only explicit-domain proving is retained
- only coeff-native showing model
  `literal_packed_aggregated_v3` is retained
- the reduced replay path is the default outer showing path
- the packed PRF companion route is retained
- shortness for new literal-packed showing proofs is `SigShortnessV6`

## Runtime Statement Family

### Issuance

Issuance remains the public-target pre-sign proof. The holder proves that the
public target `T` was formed correctly from hidden message and randomness rows
before the issuer signs it.

Public issuance objects:

- `Com`
- `RI0`, `RI1`
- `Ac`
- `B`
- `T`
- `BoundB`

Hidden issuance objects:

- `M1`, `M2`
- `RU0`, `RU1`
- `R`
- derived centered rows `R0`, `R1`
- carry rows `K0`, `K1`

### Showing

Showing starts from the finalized holder state in
`credential/keys/credential_state.json`. The holder reconstructs:

- signature rows `SigS1`, `SigS2`
- hidden message rows `M1`, `M2`
- centered randomness rows `R0`, `R1`
- the public target `T`

The showing command also reconstructs:

- the public post-sign matrix `A`
- the public rational-hash matrix `B`
- a public nonce
- a public PRF tag derived from the hidden PRF key embedded in signed `M2`

The holder then proves that one hidden signed witness simultaneously supports:

- the signature-derived replay image
- the cleared `bb_tran` relation
- the PRF computation that produced the public tag
- a hidden shortness witness for the signature coefficients

## High-Level Architecture

The live showing proof has two layers.

### 1. Outer showing proof

The outer proof is the normal retained showing NIZK:

- it commits the main witness rows under `proof.Root`
- it proves the transform-bridge / post-sign relation
- it proves the PRF companion relation
- it carries the standard `Q` commitment and row openings

The important current change is that the outer committed witness no longer
contains raw shortness digit rows.

The outer witness still contains:

- replay-facing post-sign rows such as `sigHat`, `THat`, carrier rows, and PRF
  rows

The outer witness no longer contains:

- the old packed shortness limb rows that used to be opened directly from the
  main PCS root

That reduction is intentional. The live post-sign outer `Q` path does not need
those raw shortness rows anymore.

### 2. Nested hidden shortness proof

`SigShortnessV6` is a second proof object carried inside the outer proof. It is
not a second main-root commitment for the whole showing witness. It is a
separate, smaller SmallWood proof whose hidden witness consists only of a
compressed shortness witness for the signature.

The nested hidden proof:

- hides the shortness witness
- proves bounded signed decomposition of the packed signature blocks
- proves that those hidden digits induce the authenticated outer `THat`

The outer proof then authenticates the outer `THat` rows under `proof.Root`.

## Why `SigShortnessV6` Exists

The earlier exact-head V5 path was small, but it revealed the exact packed
signature heads. That broke signature privacy and linkability goals.

`SigShortnessV6` fixes that by changing the shortness object boundary:

- do not send exact signature blocks
- do not reopen raw digit rows from the main PCS root
- instead prove shortness inside a separate hidden SmallWood proof
- bind that hidden proof back to the main outer witness only through
  authenticated `THat`

This restores hiding while keeping the shortness object much smaller than the
old same-root shortness opening.

## `SigShortnessV6` Proof Shape

The live versioned shape in [run.go](../PIOP/run.go) is:

```go
type SigShortnessProof struct {
	Version      int
	SupportSlots []int
	Opening      *decs.DECSOpening
	V5           *SigShortnessProofV5
	V6           *SigShortnessProofV6
}

type SigShortnessProofV6 struct {
	Mode        uint8
	Radix       int
	Digits      int
	HiddenProof *Proof
	THatOpening *decs.DECSOpening
}
```

For V6:

- `Version = 6`
- legacy `SupportSlots` / `Opening` are empty
- `HiddenProof` is the nested hidden SmallWood proof
- `THatOpening` is a same-root opening of only the outer replay `THat` rows
- `Radix` / `Digits` describe the hidden shortness representation actually used

Legacy V2-V5 verification paths are still retained for old proofs, but new
literal-packed showing proofs emit V6.

## What V6 Authenticates

V6 authenticates two different things in two different ways.

### Hidden shortness witness

The hidden shortness witness is authenticated by the nested hidden proof.

Its live witness surface is:

- digit rows for each packed signature block and signature component

Its live public statement includes:

- the public post-sign matrix `A`
- the relation label
- encoded outer `THat` heads
- the outer main root
- the chosen shortness radix / digit count

### Outer `THat`

The outer showing witness is still authenticated by `proof.Root`.

V6 opens only the replay `THat` rows under that root:

- not the raw shortness digits
- not exact packed signature heads

That opening is the bridge from the hidden shortness witness back into the main
outer witness.

## V6 Binding Digest

The hidden shortness proof is also bound into Fiat-Shamir round 0 of the outer
proof.

The outer prover computes a digest over the nested hidden proof:

`H_v6 = SHA256("spruce.sig_shortness.v6/hidden_smallwood_v1" || mode || radix || digits || digest(hidden_proof))`

This digest is transient. It is:

- included in outer FS round 0 material
- recomputed by the outer verifier from the carried `SigShortnessV6`

The outer round-0 material is therefore:

- `proof.Root`
- optional `LabelsDigest`
- optional `SigShortnessBindingDigest`

This prevents the hidden shortness subproof from being swapped after the outer
FS challenges have been sampled.

## Hidden Shortness Witness Model

The nested proof uses a shortness representation chosen independently from the
main outer showing preset.

That is the key design freedom of V6:

- the outer showing proof may stay on `compact_l1_research`
- the hidden shortness proof may choose a different radix / digit profile if it
  yields a smaller hidden proof

The live implementation currently prefers a compact hidden SmallWood shortness
profile and falls back to other feasible profiles if needed.

The hidden witness consists of digit rows only. The nested proof then enforces:

1. each digit lies in the allowed signed digit set
2. the digit rows reconstruct the packed signature blocks
3. the reconstructed packed blocks induce `sigHat`
4. `sigHat` induces the public `THat` carried in the hidden statement extras

The verifier never sees the digit rows or the exact signature blocks.

## Live Hidden-Proof Tuning

The current hidden proof is intentionally tuned separately from the outer proof.
The live hidden builder in
[sig_shortness_replay.go](../PIOP/sig_shortness_replay.go) uses:

- its own shortness profile choice
- `Theta = 2`
- `Rho = 1`
- `Ell = 2`
- `EllPrime = 1`
- `Eta = 8`
- `NCols = 16`
- `PCSNCols = LVCSNCols = min(logical_hidden_witness_polys, 256)` with the
  lower bound `>= NCols`
- `NLeaves` as the smallest power of two at least `PCSNCols + 2`, with a floor
  of `512`

These are hidden-proof parameters only. They do not change the outer showing
preset.

## Prover Flow

The outer showing prover in
[generic_builder.go](../PIOP/generic_builder.go) proceeds as follows.

### Outer proof construction

1. Build the normal retained showing rows from the credential state.
2. Do not append raw shortness limb rows into the main witness.
3. Commit the outer rows to obtain:
   - outer `proof.Root`
   - outer LVCS/DECS prover key
4. Keep the outer replay `THat` rows in the main witness.

### Hidden shortness proof construction

5. Reconstruct the packed signature witness from the private signature rows.
6. Choose a hidden shortness profile / hidden proof tuple that fits the
   signature witness.
7. Build the hidden digit rows on the hidden witness domain.
8. Build the hidden constraint set:
   - shortness digit membership family in `Fpar`
   - `THat` bridge family in `Fagg`
9. Build the hidden public inputs:
   - outer public `A`
   - relation label
   - encoded `THat` heads
   - outer main root
   - hidden shortness spec metadata
10. Build the nested hidden SmallWood proof with those rows and constraints.
11. Self-verify the hidden proof immediately.

### Outer binding

12. Build the outer `THatOpening` under `proof.Root`.
13. Compute the V6 shortness binding digest from the nested hidden proof.
14. Feed that digest into outer FS round 0.
15. Run the normal outer SmallWood proving path.
16. Attach:
   - `SigShortness.Version = 6`
   - `SigShortness.V6.HiddenProof`
   - `SigShortness.V6.THatOpening`
17. Self-check the final shortness proof against the finished outer proof.

## Verifier Flow

The verifier path is split in the same way.

### Outer verification

1. Recompute the V6 shortness binding digest from the carried hidden proof.
2. Include it in outer FS round 0 verification.
3. Verify the outer retained showing proof normally.

### `SigShortnessV6` verification

4. Verify the outer `THatOpening` against `proof.Root`.
5. Extract authenticated outer `THat` heads from that opening.
6. Rebuild the hidden public inputs from:
   - outer public `A`
   - relation label
   - outer root
   - authenticated outer `THat`
   - V6 radix / digit metadata
7. Rebuild the hidden shortness replay evaluator from public data.
8. Verify the nested hidden proof under that replay.

The shortness subproof accepts only if:

- the nested hidden proof verifies
- the authenticated outer `THat` matches the hidden shortness witness through
  the bridge constraints

## Why The Binding Is Sound

The binding argument for V6 is:

1. the outer root binds the main replay witness, including outer `THat`
2. the nested hidden proof is fixed before outer FS challenges by the V6
   round-0 binding digest
3. the hidden public statement carries the outer root and the authenticated
   `THat`
4. the hidden bridge constraints force the hidden digit witness to induce that
   same `THat`
5. therefore the hidden shortness witness and the outer showing witness are
   bound together without revealing the signature itself

The important difference from the exact-head V5 path is that the bridge is now:

`hidden digits -> hidden packed blocks -> sigHat -> THat -> authenticated outer THat`

not:

`explicit exact heads -> authenticated outer THat`

## Privacy Consequence

The live V6 path restores hiding of the signature witness relative to the V5
exact-head path.

The proof no longer carries:

- exact packed signature heads
- exact signature coefficients
- raw same-root shortness digit openings

Instead it carries:

- a nested hidden proof
- an authenticated outer `THat` opening

So the verifier learns that a valid hidden shortness witness exists and is
consistent with the authenticated outer `THat`, but does not learn the exact
signature blocks.

## Current Limitations

The live branch still has deliberate limits:

- only the explicit-domain retained proving path is supported
- only literal-packed coeff-native showing is supported
- the nested hidden shortness relation is specialized to the current showing
  layout and replay image
- legacy proof versions are still verified for compatibility, but new proofs
  should use V6

## Practical Summary

The current showing protocol should be read as:

1. prove the main showing relation with the retained outer SmallWood NIZK
2. prove shortness separately with a smaller hidden SmallWood proof
3. bind the two through authenticated outer `THat` and outer FS round 0

That is the current codebase architecture.
