# Updated Protocol Note

This document is the implementation-canonical protocol note for the current
SPRUCE branch after the `SigShortnessV5` exact-head redesign.

If this file disagrees with older prose, paper summaries, or stale comments,
the current code wins. The main code anchors are:

- [PIOP/generic_builder.go](../PIOP/generic_builder.go)
- [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [PIOP/masking_fs.go](../PIOP/masking_fs.go)
- [PIOP/masking_fs_helper.go](../PIOP/masking_fs_helper.go)
- [PIOP/VerifyNIZK.go](../PIOP/VerifyNIZK.go)
- [PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go)
- [PIOP/run.go](../PIOP/run.go)
- [cmd/showing/main.go](../cmd/showing/main.go)

This file exists because [protocol.md](protocol.md) still describes the older
`SigShortness` V4 world. The live implementation now uses `SigShortness` V5
for new literal-packed showing proofs.

## Scope

The retained branch implements two proof roles:

- issuance: a public-target pre-sign proof
- showing: a packed showing proof for possession of a valid signature plus a
  correctly derived PRF tag

The current shipped showing architecture is narrower than the paper-level
design space:

- only explicit-domain proving is retained
- only coeff-native showing model
  `literal_packed_aggregated_v3` is retained
- the reduced showing replay path is the default
- the packed PRF companion route is retained
- new literal-packed showing proofs now use `SigShortness` V5

This repo ships local proof construction and local verification. It does not
ship application-level spent-tag state, transport, or policy logic.

## Source Of Truth

The live runtime depends on tracked assets plus the current code:

- `Parameters/Parameters.json`
- `Parameters/credential_public.json`
- `Parameters/Bmatrix_bb_tran.json`
- `prf/prf_params.json`
- `credential/keys/credential_state.json`
- `issuance/flow.go`
- `PIOP/showing_builder.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/showing_transform_bridge_constraints.go`
- `PIOP/prf_companion_bridge.go`
- `PIOP/sig_shortness_replay.go`
- `PIOP/generic_builder.go`
- `PIOP/masking_fs.go`
- `PIOP/masking_fs_helper.go`
- `PIOP/VerifyNIZK.go`
- `PIOP/run.go`

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

## Concrete Showing Relation

The canonical live hash relation is `bb_tran`. The target is interpreted as:

`T = B1 * (M1 + M2) + B2 * R0 + 1 / (B3 - R1)`

whenever `B3 - R1` is invertible in `Rq`.

The compiled proof uses the cleared identity:

`B3*T - T*R1 - (B3*B1)*(M1+M2) - (B3*B2)*R0 + B1*MSigmaR1 + B2*R0R1 - 1 = 0`

with auxiliary source-product rows:

- `MSigmaR1 = (M1 + M2) * R1`
- `R0R1 = R0 * R1`

The main showing proof does not directly expose the signed source rows.
Instead, it works through transform-domain replay rows and a separate PRF
companion path.

## Current Showing Architecture

### Current defaults and presets

The live CLI defaults are:

- `CoeffNativeSigModel = literal_packed_aggregated_v3`
- `NCols = 16`
- `Ell = 18`
- `PRFGroupRounds = 2`
- `ShowingPreset = soundness_balanced`
- `ShowingReplayMode = reduced`
- `PRFCompanionMode = output_audit`
- `PRFCheckpointSamples = 8`
- explicit-domain proving

Shipped preset bundles come from `PIOP/run.go`:

| Preset | Shortness profile | `Theta` | `Eta` | `EllPrime` | `Rho` | `LVCSNCols` | `NLeaves` | `Kappa` |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `soundness_balanced` | `r11_l4_production` | 3 | 43 | 2 | 2 | 89 | 4096 | `{0,0,0,5}` |
| `compact_l3` | `r24_l3_compact` | 3 | 36 | 2 | 2 | 68 | 4096 | `{0,0,0,5}` |
| `compact_l2` | `r111_l2_compact` | 3 | 36 | 2 | 2 | 70 | 4096 | `{0,0,0,5}` |
| `compact_l1_research` | `r12285_l1_research` | 3 | 31 | 2 | 2 | 50 | 4096 | `{0,0,0,5}` |
| `transcript_first` | `r11_l4_production` | 6 | 31 | 2 | 2 | 32 | 2048 | `{0,0,0,0}` |
| `production_balance` | `r11_l4_production` | 6 | 31 | 2 | 2 | 32 | 2048 | `{0,0,0,0}` |

`compact_l1_research` is currently the best transcript preset on this branch,
but the default CLI preset remains `soundness_balanced`.

### Current committed row surface

On the reduced literal-packed showing path, the committed witness rows now
contain:

- message carrier row `C^M`
- centered-randomness carrier row `C^ctr`
- source-product rows `MSigmaR1` and `R0R1`
- non-sign transform aliases:
  `hat(M1+M2)`, `hat(R0)`, `hat(R1)`, `hat(MSigmaR1)`, `hat(R0R1)`
- committed replay image rows `THat`
- packed PRF companion rows

What is no longer in the main committed witness:

- legacy signature-source replay basis rows
- hidden `T` source rows on the reduced path
- raw packed signature shortness limb rows

That last point is the important V5 change. The main witness no longer carries
the raw shortness surface just so shortness can authenticate it later.

### Row-layout invariants after V5

For literal-packed showing proofs after the V5 change:

- `RowLayout.CoeffNativeSig.PackedSigBlocks`,
  `PackedSigComponents`, and `PackedSigBlockWidth` remain populated
- `RowLayout.IdxTHatBase` and `ReplayTHatCount` remain populated
- `RowLayout.PackedSigChainBase = -1`
- `RowLayout.PackedSigChainGroupCount = 0`
- `RowLayout.PackedSigChainRowsPerGroup = 0`
- `RowLayout.SigSignedChain = false`
- `RowLayout.SigBoundSliceRows = 0`

Those invariants are intentional. V5 still needs the packed-signature layout
metadata and the replay `THat` rows, but it does not need raw shortness rows
inside the main PCS witness.

### Oracle structure

The current proof has two authenticated polynomial objects and two auxiliary
payload families:

1. Main row oracle under `proof.Root`
   - all committed showing rows
   - row-degree-check polynomials `R`
   - row opening `PCSOpening` / `RowOpening`
2. `Q` oracle under `proof.QRoot`
   - the aggregated residual family
   - Q degree-check polynomials `QR`
   - `QOpening`
3. PRF companion payload
   - bridge digest
   - authenticated checkpoint/tag/key openings
4. `SigShortness` payload
   - now V5 exact-head payload plus `THat`-only opening under `proof.Root`

So the current architecture is not "everything under one root". It is:

- one main committed row root
- one separate `Q` root
- plus auxiliary payloads that are bound into the same Fiat-Shamir transcript
  and/or back to the main root

## Current Fiat-Shamir Transcript Model

The proving core uses four Fiat-Shamir rounds indexed `0..3` in the proof.
The helper code in `PIOP/masking_fs_helper.go` labels them by the objects they
derive.

### Round 0: `Gamma`

Material:

- `proof.Root`
- optional `LabelsDigest`
- optional `SigShortnessBindingDigest`

Output:

- `Gamma`
- row degree-check polynomials `R`

This is the key V5 binding point. The exact shortness payload is fixed before
`Gamma` is sampled.

### Round 1: `GammaPrime` / `GammaAgg`

Material:

- `proof.Root`
- `Gamma`
- `R`
- optional `LabelsDigest`
- `Chi` and `Zeta` when `Theta > 1`

Output:

- `GammaPrime`
- `GammaAgg`
- optional PRF companion bridge digest and bridge families

### Round 2: eval points / `GammaQ`

Material:

- `proof.Root`
- `Gamma`
- `GammaPrime`
- `GammaAgg`
- `proof.QRoot`
- optional PRF companion coordinate digest
- optional `LabelsDigest`

Output:

- eval points or small-field `k`-points
- `CoeffMatrix`
- `BarSets`
- `VTargets`
- `GammaQ`
- `QR`

### Round 3: tail points and final openings

Material:

- prior transcript material
- `proof.QR`
- eval-point data
- `CoeffMatrix`
- `BarSets`
- `VTargets`
- optional PRF companion opening payload

Output:

- sampled tail indices
- main row opening under `proof.Root`
- `QOpening` under `proof.QRoot`

The verifier replays these four rounds exactly from the proof and public
inputs. No prover-chosen challenge is trusted.

## Prover Model

The honest showing prover knows:

- the finalized holder state
- the hidden signed message/randomness rows
- the signature rows
- the PRF secret key embedded in signed `M2`

The honest prover does not choose verifier challenges. It:

1. loads runtime assets and reconstructs the semantic witness
2. builds the committed row surface for the retained showing statement
3. commits the main row oracle and obtains `proof.Root` and the LVCS prover key
4. builds optional auxiliary payloads that must be bound before FS challenge
   generation, including `SigShortness` V5
5. runs the four-round Fiat-Shamir transcript to derive `Gamma`,
   `GammaPrime`, `GammaAgg`, eval points, tail points, and `GammaQ`
6. builds the main row opening, `QOpening`, PRF companion openings, and
   `SigShortness` payload
7. outputs one proof object that the verifier can replay deterministically

The prover is modelled as a holder proving knowledge of one witness assignment
that satisfies all compiled relations at once.

## Verifier Model

The honest verifier knows only public inputs and tracked runtime assets:

- public matrices and parameters
- public tag and nonce
- public relation label and bounds
- the proof object

The verifier:

1. loads parameters and reconstructs the explicit domain
2. replays Fiat-Shamir rounds `0..3`
3. rechecks the row-degree proof under `proof.Root`
4. verifies the `Q` degree proof under `proof.QRoot`
5. reconstructs and checks the compiled constraint replay
6. verifies PRF companion payloads if present
7. verifies `SigShortness` if present

The verifier never trusts prover-side "already checked" flags. It derives the
same challenges from transcript material and reopens the authenticated objects
it needs.

## Current Main Showing Components

The current reduced showing proof is the conjunction of four component
families.

### 1. Main transform/hash relation

This component proves:

- carrier decode and membership for hidden message/randomness
- source-product consistency for `MSigmaR1` and `R0R1`
- non-sign transform bridges
- the cleared `bb_tran` residual against committed `THat`

### 2. PRF companion route

This component proves:

- packed checkpoint/helper/final-tag rows
- key binding back to the hidden signed material
- authenticated checkpoint/tag/key audit openings

The PRF companion route is still part of the current replay bottleneck, but it
is orthogonal to the V5 shortness redesign.

### 3. `SigShortness` V5

This component proves that the packed signature heads are short and that they
agree with the replay `THat` rows committed under the main root.

This is described in detail below.

### 4. DECS/LVCS/PACS replay

This component provides:

- the main row opening on `Omega` plus sampled tail points
- `VTargets`
- `BarSets`
- formulaic `R`
- the separate `Q` opening

## `SigShortness` V5

### Why V5 exists

V4 authenticated shortness by opening raw signature digit rows from the main
PCS witness. That made shortness pay for the geometry of the wrong object.

V5 changes the object boundary:

- exact packed signature heads are carried as a hash-bound explicit payload
- only the replay `THat` rows are opened under the main root
- the verifier derives `THat` from the exact heads and compares it against the
  authenticated `THat` opening

This removes the raw shortness rows from the main committed witness while
preserving the binding needed for the NIZK.

### V5 proof shape

The live proof types are:

```go
type SigShortnessProof struct {
	Version      int
	SupportSlots []int
	Opening      *decs.DECSOpening
	V5           *SigShortnessProofV5
}

type SigShortnessProofV5 struct {
	Mode        uint8
	Radix       int
	Digits      int
	ExactHeads  SigShortnessPackedMatrix
	THatOpening *decs.DECSOpening
}

type SigShortnessPackedMatrix struct {
	Bits     []byte
	BitWidth uint8
}
```

For V5:

- `Version = 5`
- `Mode = sigShortnessV5ModeExactSigHeads`
- legacy `SupportSlots` and `Opening` must be empty
- `ExactHeads` stores the exact packed signature heads
- `THatOpening` is a same-root opening for only the replay `THat` rows

The exact-head matrix dimensions are not serialized. They are derived from:

- `rows = PackedSigComponents * PackedSigBlocks`
- `cols = PackedSigBlockWidth`

### What V5 authenticates

V5 authenticates two different things in two different ways:

1. Exact packed signature heads
   - not under a separate Merkle root
   - bound by a digest inserted into Fiat-Shamir round 0
2. Replay `THat`
   - authenticated under the main row root `proof.Root`
   - opened through `THatOpening`

V5 intentionally does not:

- commit a separate shortness root
- hash `THatOpening` into round 0
- reopen raw digit rows from the main witness

### V5 binding digest

The prover computes:

`H_v5 = SHA256("spruce.sig_shortness.v5/exact_sig_heads_v1" || metadata || ExactHeads)`

where the metadata includes:

- V5 mode
- radix
- digit count
- witness packing width
- packed-signature component/block geometry
- replay `THat` count
- packed matrix width metadata

That digest is inserted into Fiat-Shamir round 0 together with:

- `proof.Root`
- optional `LabelsDigest`

The verifier recomputes the same digest from the proof before replaying round
0. So the prover cannot change the exact-head payload after seeing `Gamma`.

### V5 prover flow

The current prover path is:

1. Build and commit the main row oracle first.
   - This produces `proof.Root` and the LVCS prover key.
2. Rebuild the exact packed signature heads from the semantic witness.
   - This uses `buildLiteralPackedPolyWitness(...).SigHeads`.
3. Pack those exact heads into `SigShortnessPackedMatrix`.
4. Resolve the active shortness profile.
   - V5 stores the concrete radix and digit count used by the verifier.
5. Build `THatOpening`.
   - The rows are exactly the replay `THat` rows.
   - The support slots are the unique residues `row % pcs_ncols`.
   - `M` payload is omitted in the same way the main row opening can omit it.
6. Assemble `SigShortnessProof{Version:5, V5:...}`.
7. Compute the V5 binding digest and feed it into round 0.
8. Finish the main proof transcript.
9. Attach V5 to the proof and self-verify it before returning.

The important sequencing point is:

- the main root exists before the V5 digest is sampled into FS round 0
- the exact-head payload is fixed before `Gamma`

### V5 verifier flow

The current verifier path is:

1. Validate the V5 shape.
   - legacy and V5 fields must not be mixed
2. Recompute the V5 binding digest from the proof.
3. Include that digest in Fiat-Shamir round 0 replay.
4. Verify the `THatOpening` as a DECS/LVCS subset opening under `proof.Root`.
5. Unpack `ExactHeads` using row-layout-derived dimensions.
6. Check exact-head boundedness directly.
   - each exact head is centered
   - `decomposeLinfDigitsSigned` is applied under the active shortness spec
7. Reconstruct `sigHat` from the exact packed signature heads.
8. Reconstruct the expected replay `THat`.
9. Compare expected `THat` against the authenticated values read from
   `THatOpening`.

If any of those steps fail, shortness fails.

### Why the V5 binding is sound in the current architecture

The binding argument for V5 is:

1. The exact-head payload is fixed before Fiat-Shamir challenge generation by
   the round-0 digest.
2. The replay `THat` rows are committed under `proof.Root`.
3. The verifier derives `THat` from the exact heads and checks equality
   against a root-authenticated opening of those `THat` rows.
4. The current live main `Q` path does not consume the deleted raw shortness
   rows.

Therefore, removing raw shortness rows from the main witness removes unused
committed surface, not an active witness relation required elsewhere in the
compiled NIZK.

This point matters. The safety of the carve-out relies on the current code
fact that the live main statement no longer needs those rows in `Q`.

### What V5 proves semantically

V5 proves:

- the exact packed signature heads satisfy the active shortness bound
- those exact heads imply the same replay `THat` that the main showing proof
  uses

The main proof then uses authenticated `THat` inside the transform/hash replay.
So the signature path is now:

`ExactHeads -> sigHat -> THat -> main replay relation`

instead of:

`main-root digit rows -> sigHat -> THat`

## Current Proof Object Summary

At a high level, the current proof contains:

- `Root`: main row root
- `R`: main row degree-check polynomials
- `Gamma`, `GammaPrime`, `GammaAgg`: Fiat-Shamir challenge families
- `QRoot`: separate root for the `Q` oracle
- `QR`: degree-check polynomials for `Q`
- `Tail`: sampled tail indices
- `CoeffMatrix`, `KPoint`, `BarSets`, `VTargets`: explicit-domain replay
  payloads
- `PCSOpening`: opening of the main row oracle
- `QOpening`: opening of the `Q` oracle
- optional `PRFCompanion`
- optional `SigShortness`

The verifier replays and checks all of these together.

## Current Shortness And Witness Consequences

After V5:

- shortness no longer inflates the main witness row count with raw digit rows
- the main reduced showing witness surface is materially smaller
- `SigShortness` is now dominated by the exact-head payload plus a tiny
  `THat`-only opening

The current compact presets show this clearly: the shortness bucket dropped
from the old V4 high-teens/40KB regime to roughly the mid-5KB range depending
on preset, because the shortness object is now authenticating the right
surface.

## What The Current CLI Does Not Prove At The Application Layer

`cmd/showing`:

- builds a public nonce
- computes a public PRF tag
- builds a proof
- verifies the proof locally

It does not:

- maintain verifier-side spent-tag state
- enforce replay/rate-limit policy across sessions
- implement a network verifier service

So the repo currently ships the cryptographic proof machinery, not the full
application protocol around acceptance and statefulness.

## Security Status And Non-Goals

The code currently claims and checks:

- local correctness of issuance proof construction and verification
- local correctness of showing proof construction and verification
- deterministic verifier replay of the compiled NIZK transcript
- shortness binding through V5 exact heads plus authenticated `THat`

The code does not by itself establish:

- application-level rate-limit security
- deployment policy for nonce generation and storage
- blindness or one-more security beyond the retained protocol design
- a full service-level ARC verifier state machine

## Practical Reading Order

For the live code path, the most useful reading order is:

1. [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
2. [PIOP/generic_builder.go](../PIOP/generic_builder.go)
3. [PIOP/masking_fs.go](../PIOP/masking_fs.go)
4. [PIOP/masking_fs_helper.go](../PIOP/masking_fs_helper.go)
5. [PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go)
6. [PIOP/VerifyNIZK.go](../PIOP/VerifyNIZK.go)
7. [cmd/showing/main.go](../cmd/showing/main.go)

That is the shortest path to the current implementation.
