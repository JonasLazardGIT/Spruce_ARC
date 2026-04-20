# Protocol

This document is the implementation-canonical protocol note for the current
SPRUCE branch. It is intentionally code-first: if this file disagrees with
older prose, paper summaries, or stale README text, the current code and
tracked runtime assets win.

Use this file for the live issuance/showing model. Use
[nizk_alignment_notes.md](nizk_alignment_notes.md) for paper-vs-code deltas,
[modulus_choice.md](modulus_choice.md) for field rationale, and
[../Commands.md](../Commands.md) for operator-facing command usage.

## Overview

SPRUCE currently implements two retained proof roles:

- pre-sign issuance, where the holder proves that a public target `T` was
  formed correctly from hidden message and randomness rows before the issuer
  signs it
- showing, where the holder proves possession of a valid signature on hidden
  message material and a correctly derived PRF tag without revealing the signed
  secret

The live repository is more specific than the paper-level story:

- the canonical concrete hash relation is `bb_tran`
- issuance keeps `T` public inside the compiled statement
- showing keeps one retained coeff-native layout:
  `literal_packed_aggregated_v3`
- the showing path uses the packed PRF companion route
- the showing path uses `SigShortness` V4 by default
- the shipped CLIs are local proof programs; the repo does not implement a
  spent-tag database or a network transport

## Source Of Truth

Live behavior is defined by the current code and tracked runtime assets:

- `Parameters/Parameters.json`
- `Parameters/credential_public.json`
- `prf/prf_params.json`
- `credential/keys/credential_state.json`
- `issuance/flow.go`
- `cmd/issuance/*.go`
- `cmd/showing/main.go`
- `PIOP/showing_builder.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/showing_transform_bridge_constraints.go`
- `PIOP/prf_companion_bridge.go`
- `PIOP/sig_shortness_replay.go`
- `PIOP/generic_builder.go`
- `PIOP/run.go`
- `PIOP/proof_report.go`

The paper under `docs/ARC_Spruce/` remains a comparison target, not the source
of truth for shipped defaults.

## Runtime Assets

The retained command path depends on tracked JSON/runtime assets.

| Asset | Role | Current live values / notes |
| --- | --- | --- |
| `Parameters/Parameters.json` | shared ring and signature parameters | `N=1024`, `q=1054721`, `k=21`, `beta=6142`, `bound=6142` |
| `Parameters/credential_public.json` | canonical credential public parameters | `hash_relation=bb_tran`, `BoundB=1`, `BPath=Parameters/Bmatrix_bb_tran.json` |
| `Parameters/credential_public_bbs.json` | transition credential public parameters | explicit `bbs` compatibility asset; not the canonical runtime default |
| `prf/prf_params.json` | PRF parameters | `q=1054721`, `d=3`, `LenKey=8`, `LenNonce=12`, `LenTag=7`, `t=20`, `RF=8`, `RP=19` |
| `Parameters/Bmatrix_bb_tran.json` | canonical rational-hash public matrix `B` | loaded by issuance and showing when `hash_relation=bb_tran` |
| `credential/issuance/*.json` | role-separated issuance artifacts | holder/issuer JSON exchange for commit, challenge, proof submission, and response |
| `credential/keys/credential_state.json` | persisted holder state | stores issuance witness material, public challenge/commitment data, signed target, `credential_public_path`, and showing-time signature rows |

## Issuance Flow

The retained issuance flow is still the public-target pre-sign proof:

1. The holder chooses hidden rows `M1`, `M2`, `RU0`, `RU1`, and `R`.
2. `issuance.PrepareCommit` derives the canonical carrier/alias surface and
   computes the public commitment `Com`.
3. The issuer challenge is represented by public rows `RI0`, `RI1`.
4. `issuance.ApplyChallenge` centers the challenge-adjusted rows into `R0`,
   `R1`, records carry rows `K0`, `K1`, loads `B`, and derives the public
   target `T`.
5. `issuance.ProvePreSign` proves consistency of the hidden rows with
   `{Com, RI0, RI1, Ac, B, T, BoundB}`.
6. `issuance.VerifyPreSign` replays the same compiled statement.
7. The issuer signs the public `T`, and `holder-finalize` writes the final
   holder state to `credential/keys/credential_state.json`.

On the retained issuance path:

- public: `Com`, `RI0`, `RI1`, `Ac`, `B`, `T`, `BoundB`
- hidden: `M1`, `M2`, `RU0`, `RU1`, `R`, `R0`, `R1`, `K0`, `K1`

`cmd/issuance` exposes the role-separated flow:

1. `holder-commit`
2. `issuer-challenge`
3. `holder-prove`
4. `issuer-verify-sign`
5. `holder-finalize`

`demo-local` is a convenience wrapper over the same steps.

## Showing Flow

### Public and hidden objects

The retained showing path starts from `credential/keys/credential_state.json`
and reconstructs the semantic witness:

- signature rows `SigS1`, `SigS2`
- hidden message rows `M1`, `M2`
- centered randomness rows `R0`, `R1`
- public target `T`

The command also reconstructs the public post-sign matrix `A`, extracts the
PRF key from signed `M2`, samples a public nonce, computes the public tag, and
then proves that the same signed secret supports both the signature relation
and the PRF computation.

### Canonical relation

`Parameters/credential_public.json` selects `hash_relation=bb_tran`, so the
canonical live target is

`T = B1 * (M1 + M2) + B2 * R0 + 1 / (B3 - R1)`

whenever `B3 - R1` is invertible in `Rq`.

The compiled issuance and showing proofs certify the cleared form

`B3*T - T*R1 - (B3*B1)*(M1+M2) - (B3*B2)*R0 + B1*MSigmaR1 + B2*R0R1 - 1 = 0`

using the auxiliary products:

- `MSigmaR1 = (M1 + M2) * R1`
- `R0R1 = R0 * R1`

### Current default showing options

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

The shipped default preset then resolves to:

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

These are live proving/reporting defaults, not paper-only targets.

### Current committed showing surface

On the shipped reduced showing path, the committed witness surface is:

- message carrier row `C^M`
- centered-randomness carrier row `C^ctr`
- source-product rows `MSigmaR1` and `R0R1`
- non-sign transform aliases:
  `hat(M1+M2)`, `hat(R0)`, `hat(R1)`, `hat(MSigmaR1)`, `hat(R0R1)`
- committed replay image row `THat`
- packed PRF companion rows
- packed signature digit rows used only by `SigShortness` V4

Important consequences of the current layout:

- reduced showing no longer commits the legacy signature-source replay basis
- reduced showing no longer commits hidden `T` source rows
- the main transform bridge no longer carries signature bridge families
- signature correctness is now authenticated through shortness:
  `digits -> sigHat -> THat`
- the live layout still does not commit a separate rational-hash inverse row
  `Z`; `bb_tran` uses explicit source-product rows instead

### Current proving components

The shipped showing statement is split across four surfaces:

1. Main transform/hash relation
   - carrier decode and membership for hidden `M1`, `M2`, `R0`, `R1`
   - source-product consistency for `MSigmaR1` and `R0R1`
   - non-sign transform bridges
   - the cleared `bb_tran` residual evaluated against committed `THat`
2. PRF companion route
   - packed PRF checkpoint/helper/final-tag rows
   - key binding back to the signed hidden message
   - packed PRF bridge plus direct authenticated PRF openings
3. `SigShortness` V4
   - same-root support-slot opening over packed signature digit rows and
     committed `THat`
   - digit membership and layout checks
   - verifier-side reconstruction of packed signature heads, then `sigHat`,
     then expected `THat`
4. DECS/LVCS/PACS replay
   - the main row opening on `Omega'`
   - replay objects `VTargets` and `BarSets`
   - formulaic `R` and `Q` transcript terms

### Reduced versus full replay

The retained showing compiler still supports two replay extents:

- `reduced` (default)
- `full`

The default runtime path is therefore narrower than the paper's full semantic
replay family, but it is still the same retained relation family.

### What the current verifier enforces

For the shipped reduced path, the verifier checks that one committed witness
assignment simultaneously satisfies:

- the post-sign matrix/signature relation through committed `THat`
- the cleared `bb_tran` relation
- carrier and source-product identities
- `SigShortness` V4 consistency from digits to `THat`
- PRF companion/key-binding equations
- DECS/LVCS/PACS replay under one PCS root

The verifier does not use any legacy packed-signature replay basis on the
reduced path.

## Current Measured Default

The following numbers come from a fresh local run on this checkout on
2026-04-20:

```bash
go run ./cmd/showing -showing-preset soundness_balanced
```

Measured paper-aligned transcript:

- total: `80,630` bytes (`78.74 KB`)
- `SigShortness = 42,739`
- `R = 10,325`
- `Pdecs = 9,678`
- `VTargets = 9,082`
- `Q = 4,637`
- `Auth = 2,189`
- `BarSets = 1,711`

Measured default geometry:

- witness rows: `534`
- committed witness rows: `114`
- mask rows: `24`
- PCS blocks: `6`
- total committed rows `nrows = 138`
- replay geometry `m = 36`
- row-opening `pcols = 102`
- `SigShortness` default: `v4`, `slots=96`, `blocks=6`

Measured replay audit summary:

- selected replay rows: `16/22`
- selector reduction: `27.27%`
- active replay blocks: `2/2`
- current dominant remaining blockers:
  `prf_companion`, `source_product`, `carrier`

These are measured examples from the current checkout, not timeless constants.
The precise bytes can move as serialization details evolve.

## Transcript Interpretation

For the current shipped default:

- `SigShortness` is still the dominant paper bucket
- the packed-signature-source duplication is already gone on reduced replay
- the next blocker is the packed PRF companion bridge, not the old signature
  replay basis
- `VTargets` and `Pdecs` are now materially smaller because the witness shrank
  from the old seven-block geometry to six PCS blocks

Use [showing_transcript_30kb_research_memo.md](showing_transcript_30kb_research_memo.md)
for the current transcript-focused memo.

## Supported Modes

The live proving core supports exactly one coeff-native showing model:

- `literal_packed_aggregated_v3`

The important knobs are not separate protocol variants:

- `showing-preset` chooses a transcript/geometry bundle
- `-full` expands replay extent from reduced to full
- shortness profile overrides retune the signature gadget
- `PRFCompanionMode=direct_auth` remains an alternate audit mode around the
  same retained PRF companion statement

Only explicit-domain proving is retained on the live path.

## What `cmd/showing` Does Not Do

The current showing CLI:

- builds a public nonce
- computes and proves a public tag
- verifies the proof locally

It does not:

- maintain verifier-side rate-limit state
- reject reused `(nonce, tag)` or `(message, tag)` pairs
- implement an application service around proof acceptance

So the repo ships the cryptographic proof path, not the full application-layer
ARC verifier state machine.

## Security Status

The repository implements compiled proofs and local correctness checks. It does
not add new reductions beyond the current paper story.

What the live branch provides:

- executable issuance/showing proof construction and verification
- a compiled pre-sign statement with public `T`
- a compiled reduced/default showing statement with PRF companion and
  `SigShortness` V4

What still remains a paper/security-model claim rather than a code claim:

- blindness and one-more security for the issuance protocol
- theorem-backed transport from the compiled showing statement to the abstract
  ARC relation
- PRF security beyond correctness of the implemented computation
- stateful rate-limit enforcement
