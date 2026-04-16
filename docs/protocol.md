# Protocol

This document is the implementation-canonical protocol note for the current
SPRUCE branch. It is intentionally code-first: if this file disagrees with
older prose, comments, or paper-level summaries, the current implementation and
tracked runtime assets win.

Use this file for the live issuance/showing model. Use
[nizk_alignment_notes.md](nizk_alignment_notes.md) for detailed paper-vs-code
alignment notes, [modulus_choice.md](modulus_choice.md) for field rationale,
and [../Commands.md](../Commands.md) for operator-facing command usage.

## Overview

SPRUCE currently implements a proof-oriented anonymous-credential / ARC
prototype with two retained proof roles:

- pre-sign issuance, where a holder proves that a public target `T` was formed
  correctly from committed message material and centered randomness before the
  issuer signs it
- showing, where the holder proves possession of a signed hidden message and a
  correctly derived PRF tag without revealing the signed secret

At the branch level, the implementation is split between:

- reusable issuance helpers in `issuance/flow.go`
- the role-separated issuance CLI in `cmd/issuance/`
- the retained showing CLI in `cmd/showing/main.go`
- the SmallWood-style compiled proof stack in `PIOP/`

The abstract paper story is still "blind issuance plus ARC showing", but the
live repository is more specific:

- the canonical concrete hash relation is `bb_tran`; `bbs` remains only as an
  explicit transition mode selected through public params
- issuance keeps the target `T` public inside the compiled pre-sign statement
- showing uses one retained coeff-native proving path
- showing uses the PRF companion route, not the legacy PRF layout
- the shipped CLIs are local proof programs; issuance now follows a
  role-separated JSON artifact flow, but the repo still does not implement a
  networked transport or a spent-tag database

## Source Of Truth

The following sources define live behavior on this branch.

### Runtime and command sources

- `Parameters/Parameters.json`
- `Parameters/credential_public.json`
- `prf/prf_params.json`
- `credential/keys/credential_state.json`
- `cmd/issuance/*.go`
- `cmd/showing/main.go`

### Proof-system sources

- `issuance/flow.go`
- `credential/state.go`
- `PIOP/credential_rows.go`
- `PIOP/credential_constraints.go`
- `PIOP/showing_builder.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/showing_transform_bridge_constraints.go`
- `PIOP/prf_companion_bridge.go`
- `PIOP/generic_builder.go`
- `PIOP/run.go`
- `PIOP/proof_report.go`

### Paper comparison sources

These are comparison targets only; they are not the source of truth for the
current branch:

- `docs/ARC_Spruce/sections/03_blind_signature.tex`
- `docs/ARC_Spruce/sections/04_arc_construction.tex`
- `docs/ARC_Spruce/sections/05_smallwood_model.tex`
- `docs/ARC_Spruce/appendix/C_smallwood_details.tex`

## Runtime Assets

The current command path depends on tracked JSON/runtime assets.

| Asset | Role | Current live values / notes |
| --- | --- | --- |
| `Parameters/Parameters.json` | shared ring and signature parameters | `N=1024`, `q=1054721`, `k=21`, `beta=6142`, `bound=6142` |
| `Parameters/credential_public.json` | canonical credential public parameters | `hash_relation=bb_tran`, `BoundB=1`, `LenM1=1`, `LenM2=1`, `LenRU0=1`, `LenRU1=1`, `LenR=1`, tracked full-matrix `Ac`, `BPath=Parameters/Bmatrix_bb_tran.json` |
| `Parameters/credential_public_bbs.json` | transition credential public parameters | explicit `bbs` compatibility asset; not the canonical runtime default |
| `prf/prf_params.json` | PRF parameters | `q=1054721`, `d=3`, `LenKey=8`, `LenNonce=12`, `LenTag=7`, `t=20`, `RF=8`, `RP=19` |
| `Parameters/Bmatrix_bb_tran.json` | canonical rational-hash public matrix `B` | loaded by issuance and showing when `hash_relation=bb_tran` |
| `credential/issuance/*.json` | role-separated issuance artifacts | holder/issuer JSON exchange for commit, challenge, proof submission, and response |
| `credential/keys/credential_state.json` | persisted holder state | stores issuance witness material, public challenge/commitment data, signed target, `credential_public_path`, and showing-time signature rows |
| `credential/keys/signature.json` | copied signature artifact | populated by `holder-finalize` when the issuer response carries the full signature bundle |

### Persisted holder state

`credential.State` is the bridge between issuance and showing. The top-level
state carries:

- issuance rows `M1`, `M2`, `RU0`, `RU1`, `R`, `R0`, `R1`, `K0`, `K1`
- public issuance artifacts `Com`, `RI0`, `RI1`, `B`, `T`
- showing signature rows `SigS1`, `SigS2`
- `PackedNCols`, which fixes how the signed `M2` row is decoded into PRF key
  lanes
- `CredentialPublicPath`, which points at the stable credential public params
- optional embedded NTRU public coefficients

`credential.CoeffNativeShowingState` is only a compatibility shim for older
JSON. Production showing derives its semantic witness from the top-level state,
not from a separate legacy showing blob.

## Issuance Flow

### Abstract live issuance path

The reusable issuance helpers implement the following live shape.

1. The holder provides coefficient-domain rows `M1`, `M2`, `RU0`, `RU1`, and
   `R`.
2. `issuance.PrepareCommit` derives the canonical pre-sign carrier/alias
   surface on `Ω` and computes the public commitment vector `Com` from the
   logical rows `M1`, `M2`, `RU0`, `RU1`, and `R`.
3. The issuer-side challenge is represented by public rows `RI0`, `RI1`.
4. `issuance.ApplyChallenge` centers `RU0 + RI0` and `RU1 + RI1` into `R0`,
   `R1`, records carry rows `K0`, `K1`, loads `B`, and derives the public
   target `T` under the `hash_relation` selected by the credential public
   params.
5. `issuance.ProvePreSign` builds the pre-sign proof with public inputs
   `{Com, RI0, RI1, Ac, B, T, BoundB}` and witness inputs
   `{M1, M2, RU0, RU1, R, R0, R1, K0, K1}`.
6. `issuance.VerifyPreSign` replays the same statement against the committed
   row openings and public data.
7. `issuance.SignTargetAndSave` signs the public target `T` with the NTRU
   trapdoor and persists the signature.
8. `holder-finalize` serializes the holder state to
   `credential/keys/credential_state.json` for the showing CLI.

### What is public and what is hidden

On the retained issuance path:

- public: `Com`, `RI0`, `RI1`, `Ac`, `B`, `T`, `BoundB`
- hidden witness rows: `M1`, `M2`, `RU0`, `RU1`, `R`, `R0`, `R1`, `K0`, `K1`

This matches the compiled pre-sign design used in the paper's SmallWood model:
the prover certifies consistency of hidden rows with a public target `T`,
rather than hiding `T` inside the proof.

### Current `cmd/issuance` command surface

The shipped command now follows a faithful role split:

1. `holder-commit`
2. `issuer-challenge`
3. `holder-prove`
4. `issuer-verify-sign`
5. `holder-finalize`

`demo-local` is a convenience wrapper over those same steps.

Important concrete choices in the shipped command surface:

- `Ac` is loaded from tracked `Parameters/credential_public.json`; issuance no
  longer fabricates or rewrites it
- the default holder path samples nonzero hidden witness material, including a
  nonzero `M2`
- the issuer path samples nonzero public challenge rows with
  `issuance.SampleChallenge`
- intermediate artifacts are written under `credential/issuance/`
- final holder state carries `credential_public_path` and omits issuer
  trapdoor material

### Current issuance proof options

`cmd/issuance` resolves and then overrides proof options so that the live
pre-sign run uses:

- `DomainMode=explicit`
- `NCols=16`
- `Ell=18`
- `Theta=1`
- `Eta=19`
- `EllPrime=2`
- `Rho=2`
- `NLeaves=4096`
- `LVCSNCols=96`

These are issuance-harness settings. They are not the same thing as the
showing CLI's default preset.

## Showing Flow

### Abstract live showing path

The retained showing path starts from persisted holder state and proceeds as
follows.

1. `cmd/showing` loads `credential/keys/credential_state.json`.
2. `buildCoeffNativeShowingWitnessFromState` reconstructs the coeff-native
   showing witness from top-level state:
   `SigS1`, `SigS2`, `M1`, `M2`, `R0`, `R1`, and `T`.
3. The command checks that the stored signature rows satisfy the current live
   shortness bound from `Parameters/Parameters.json`.
4. `buildSignatureMatrix` reconstructs the public post-sign matrix `A` from the
   embedded or on-disk NTRU public key.
5. The command extracts PRF key lanes from the signed `M2` row, samples a
   public nonce, computes `tag = PRF(key, nonce)`, and exposes the nonce/tag as
   public lanes.
6. The command loads the credential public params from
   `state.CredentialPublicPath` and rejects any mismatch between the state's
   stored `hash_relation` and the loaded relation.
7. `PIOP.BuildShowingCombined` constructs the retained showing proof.
8. `PIOP.VerifyWithConstraints` replays the verifier logic from proof metadata,
   public inputs, and committed row openings.

### Signature relation used in showing

The current showing command reconstructs `A` from the stored NTRU public key.
For the normal two-component signature case:

- the hidden signature witness is `U = [s1, s2]`
- the public post-sign equation is `(-h) * s1 + s2 = T`

This is the matrix form consumed by the compiled showing constraints.

### PRF key and tag handling

The current branch uses the signed hidden message as the PRF-key carrier.

- at CLI time, `cmd/showing` extracts the key directly from the signed `M2`
  witness's packed upper-half source lanes to compute the public nonce/tag pair
- inside the compiled proof, the key is rebound through the committed message
  carrier row and the PRF companion layout

This means the public tag is generated outside the proof builder, but the proof
still enforces that the same signed hidden key was used.

### Current showing defaults

`cmd/showing` fixes some knobs directly and resolves the rest through
`PIOP.ResolveSimOptsDefaults`.

Direct CLI defaults:

- `CoeffNativeSigModel=literal_packed_aggregated_v3`
- `NCols=16`
- `Ell=18`
- `PRFGroupRounds=2`
- `ShowingPreset=soundness_balanced`
- `ShowingReplayMode=reduced`
- `PRFCompanionMode=output_audit`
- `PRFCheckpointSamples=8`
- explicit-domain proving

The default preset then resolves to:

- `Theta=3`
- `Eta=43`
- `EllPrime=2`
- `Rho=2`
- `LVCSNCols=96`
- `PostSignLVCSNCols=96`
- `PRFLVCSNCols=96`
- `NLeaves=4096`
- `PostSignNLeaves=4096`
- `PRFNLeaves=4096`
- `Kappa={0,0,0,5}`
- signature shortness profile `r11_l4_production`

These are the live default reporting/proving settings for `cmd/showing`, not
paper-only targets.

### What `cmd/showing` does not do

The current showing CLI:

- does build a public nonce
- does compute and prove a public tag
- does verify the proof locally

It does not:

- maintain verifier-side rate-limit state
- reject reused `(nonce, tag)` or `(message, tag)` pairs
- implement an application service around proof acceptance

So the repo currently ships the cryptographic proof path, not the full
application-layer ARC verifier state machine.

## Compiled Proof Model

### Shared stack

Both proof roles are compiled through the same SmallWood-style stack:

- explicit-domain witness rows
- DECS for degree-enforced commitment/oracle openings
- LVCS as the row-oriented linear opening layer
- PACS/Fiat-Shamir replay in `PIOP/`

The retained code supports only explicit public-domain semantics. The proof
builder normalizes non-explicit requests back to the explicit mode.

### Pre-sign compiled witness surface

The live pre-sign row builder in `PIOP/credential_rows.go` commits:

- five carrier rows:
  `C^M`, `C^preRU`, `C^preR`, `C^ctr`, `C^K`
- nine decoded alias rows:
  `M1`, `M2`, `RU0`, `RU1`, `R`, `R0`, `R1`, `K0`, `K1`
- in canonical `bb_tran` mode, two proof-only source product rows:
  `MSigmaR1 = (M1 + M2) * R1` and `R0R1 = R0 * R1`
- four transform/replay aliases:
  `hat(M1)`, `hat(M2)`, `hat(R0)`, `hat(R1)`
- in canonical `bb_tran` mode, two product transform aliases:
  `hat(MSigmaR1)` and `hat(R0R1)`

So the live committed pre-sign surface is not "carriers only". In canonical
`bb_tran` mode it is a 22-row witness surface combining:

- carrier membership rows
- decode/alias rows
- proof-only source product rows
- replay-facing transform aliases, including the product aliases

The active pre-sign constraint families cover:

- carrier membership
- decode bridges
- commitment binding against `Com`
- centering consistency using `K0`, `K1`
- the public-target hash relation with `T`
- in canonical `bb_tran` mode, source-product consistency for `MSigmaR1` and
  `R0R1`
- replay/transform bridges for the non-sign rows

### Canonical target relation

`Parameters/credential_public.json` selects `hash_relation=bb_tran`, so the
canonical live target is

`T = B1 * (M1 + M2) + B2 * R0 + 1 / (B3 - R1)`

whenever `B3 - R1` is invertible in `Rq`. The compiled issuance and showing
proofs certify the retained cleared form

`B3*T - T*R1 - (B3*B1)*(M1+M2) - (B3*B2)*R0 + B1*MSigmaR1 + B2*R0R1 - 1 = 0`

using the auxiliary product rows `MSigmaR1` and `R0R1`. The legacy `bbs`
relation remains available only behind an explicit alternate public-params
file.

### Showing compiled witness surface

The live showing builder in
`PIOP/showing_coeff_native_literal_packed_runtime.go` commits the following
families on the retained path.

- message carrier row `C^M`
- centered-randomness carrier row `C^ctr`
- explicit `T` source rows, one block per `NCols` chunk of the signed target
- replay rows for:
  `hat(M1+M2)`, `hat(R0)`, `hat(R1)`, and `hat(T)`
- in canonical `bb_tran` mode, explicit source product rows:
  `MSigmaR1` and `R0R1`
- in canonical `bb_tran` mode, replay rows for:
  `hat(MSigmaR1)` and `hat(R0R1)`
- signature shortness limb rows for the packed coeff-native signature witness
- packed PRF companion rows

Important consequences of the live layout:

- the showing path does not commit separate top-level source rows for `M`, `K`,
  `R0`, and `R1`; those are recovered from carriers by public decode maps
- the rational-hash message surface is carried as `M1`, `M2` in state, then as
  a combined replay row `hat(M1+M2)` in the transform-bridge proof
- the live layout does not commit a separate top-level rational-hash inverse
  row `Z`; canonical `bb_tran` instead uses explicit product rows
  `MSigmaR1` and `R0R1`

### Replay mode

The retained showing compiler supports two replay extents:

- `reduced` (default): only the first replay block is committed/replayed
- `full`: all replay blocks are committed/replayed

The default runtime path is therefore narrower than the paper's full semantic
block family. The proof machinery can still expand to the full replay image
when `ShowingReplayModeFull` is selected.

### PRF companion route

`PIOP.BuildShowingCombined` forces the live showing path onto the packed PRF
companion route:

- packed PRF witness rows are enabled
- PRF companion metadata is required
- the legacy PRF layout is rejected

In verifier terms, the live showing statement is:

- transform-bridge post-sign constraints
- signature shortness constraints
- PRF companion bridge/opening constraints

all replayed against one committed witness assignment.

## Current Supported Modes

### Supported proving surface

The live proving core supports exactly one coeff-native showing model:

- `literal_packed_aggregated_v3`

The code rejects unsupported alternatives at multiple layers, including:

- coeff-native model validation in
  `PIOP/showing_coeff_native_literal_packed_runtime.go`
- showing verification in `PIOP/generic_builder.go`
- showing constraint compilation in `PIOP/showing_coeff_native_constraints.go`

Older repo prose that still mentions `literal_packed_aggregated_v4_split_prf`
is stale and has been cleaned up in the surrounding docs.

### Presets versus protocol variants

The current knobs are easy to misread. They are not independent protocol
families.

- `showing-preset` chooses a coherent transcript/geometry bundle
- `-full` switches replay extent from reduced to full
- shortness-profile and raw radix/digit overrides retune the signature gadget
- `PRFCompanionMode=direct_auth` remains research scaffolding around the same
  retained showing path

So the live branch has one retained showing statement, with several reporting
and geometry knobs around it.

### Domain mode

Only explicit-domain proving is retained on the live path. The implementation
normalizes the proving mode back to explicit-domain semantics even if callers
try to request something else.

## Verifier Model

The retained verifier model is replay-based.

For both issuance and showing, the verifier:

- uses committed row openings under one PCS/LVCS root
- rebuilds the active evaluator set from proof metadata, public inputs, and
  row layout
- replays the PACS identities on those openings
- checks auxiliary proof objects such as the PRF companion bridge/openings when
  present

The verifier does not rely on older side-channel layouts or legacy helper
oracles. The key invariant is that the same committed witness assignment must
simultaneously satisfy:

- commitment and centering equations
- signature binding
- rational-hash residuals
- PRF companion/key-binding equations

That single-root binding property is the main reason the hidden message and PRF
key cannot be swapped across subsystems without breaking replay.

## Security And Theorem Status

The repository implements compiled proofs and local correctness checks. It does
not add new reductions beyond the current paper story.

What the live branch actually provides:

- executable issuance/showing proof construction and replay verification
- a compiled pre-sign statement with public `T`
- a compiled showing statement with transform-bridge replay and PRF companion
  constraints

What still lives at the paper/security-model level rather than as a code-level
claim:

- blind issuance blindness
- blind issuance one-more unforgeability
- theorem-backed transport from the compiled showing statement to the abstract
  ARC relation
- PRF security beyond correctness of the implemented computation
- verifier-side stateful rate-limit enforcement

The paper source is explicit that the non-blind signature layer and the
compiled NIZK layer are the theorem-facing pieces, while blindness/one-more
security for the blind issuance protocol remain a reduction roadmap item. The
codebase should be read the same way.

## Paper Alignment Summary

At a high level, the current code still follows the paper's compiled-story
shape:

- issuance proves consistency of hidden committed rows with a public `T`
- showing proves a signature/hash relation plus PRF-tag correctness
- both proofs are compiled through a SmallWood-style explicit-domain stack

The important branch-specific differences are:

- canonical live hashing is `bb_tran`, while `bbs` is retained only as an
  explicit transition mode
- pre-sign carry rows are named `C^K`, `K0`, `K1` in code where some paper
  passages still use `C^J`, `J_0`, `J_1`
- the live pre-sign witness surface commits carriers, alias rows, proof-only
  product rows, and transform aliases, not carriers alone
- the live showing path keeps only the retained coeff-native `v3` model
- showing defaults to reduced replay, not the paper's full semantic replay
  family
- the live showing layout compresses `M`, `K`, `R0`, and `R1` through carrier
  rows and uses explicit BB-tran product rows `MSigmaR1` and `R0R1` instead of
  a source-side inverse row `Z`
- the PRF companion route is mandatory on the live path
- the shipped showing CLI does not implement the application-layer stateful
  rate-limit check

For the detailed row-by-row and claim-by-claim comparison, read
[nizk_alignment_notes.md](nizk_alignment_notes.md).
