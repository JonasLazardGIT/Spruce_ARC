# NIZK Alignment Notes

This note records how the live SPRUCE branch aligns with the current
ARC-SPRUCE paper source after the retained `bb_tran` migration. It is not the
protocol specification; that role belongs to [protocol.md](protocol.md).

## Reading Rule

When descriptions disagree, use this precedence:

1. the current codebase and tracked runtime assets define live behavior
2. the paper under `docs/ARC_Spruce/` is the comparison target
3. older repo prose is subordinate to both

## Comparison Scope

Primary paper anchors:

- `docs/ARC_Spruce/sections/02_preliminaries.tex`
- `docs/ARC_Spruce/sections/03_blind_signature.tex`
- `docs/ARC_Spruce/sections/04_arc_construction.tex`
- `docs/ARC_Spruce/sections/05_smallwood_model.tex`
- `docs/ARC_Spruce/appendix/C_smallwood_details.tex`
- `docs/ARC_Spruce/sections/06_parameters.tex`
- `docs/ARC_Spruce/appendix/D_extended_parameters.tex`

Primary code anchors:

- `credential/hash_relation.go`
- `credential/helpers.go`
- `credential/public_params.go`
- `issuance/flow.go`
- `cmd/issuance/*.go`
- `cmd/showing/main.go`
- `PIOP/credential_rows.go`
- `PIOP/credential_constraints.go`
- `PIOP/hash_relation.go`
- `PIOP/hash_relation_rows.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/showing_transform_bridge_constraints.go`
- `PIOP/showing_transform_bridge_eval.go`
- `ntru/hash_bridge.go`

## At A Glance

- The canonical concrete hash relation is now `bb_tran` on both the live
  branch and the updated paper path.
- The branch still preserves the same architecture:
  holder computes public `T`, issuer signs `T`, showing proves possession of a
  signature on `T` together with PRF-tag correctness.
- The live implementation keeps `bbs` only as an explicit transition mode
  through alternate public params; the canonical runtime artifact is
  `Parameters/credential_public.json`.
- The important remaining paper-vs-runtime differences are no longer about the
  hash algebra itself. They are about runtime compression choices and command
  surface choices: reduced replay by default, compressed non-sign source rows,
  a mandatory PRF companion route, and the absence of a shipped spent-tag
  database.

## Core Alignment Matrix

| Paper term / claim | Live implementation | Status | Code anchor | Paper anchor |
| --- | --- | --- | --- | --- |
| Concrete target relation is `bb_tran` | `credential.HashRelationBBTran` is the canonical mode selected by `Parameters/credential_public.json` | Aligned | `credential/hash_relation.go`, `credential/public_params.go`, `credential/helpers.go` | `sections/02_preliminaries.tex` |
| `bbs` remains available only as a transition mode | Alternate public params select `hash_relation=bbs`; no mixed-relation credential flow is supported | Aligned as a transition rule | `Parameters/credential_public_bbs.json`, `cmd/issuance/flow_helpers.go`, `cmd/showing/main.go` | repo-level migration note; paper treats `bb_tran` as canonical |
| Issuance keeps `T` public and proves it against committed hidden rows | Pre-sign proof takes `T` as a public input and signs the verified public `T` | Aligned | `issuance/flow.go`, `cmd/issuance/*.go` | `sections/03_blind_signature.tex`, `sections/04_arc_construction.tex`, `sections/05_smallwood_model.tex` |
| Canonical cleared BB-tran relation uses two auxiliary products | Pre-sign and showing both add `MSigmaR1=(M1+M2)*R1` and `R0R1=R0*R1` when `hash_relation=bb_tran` | Aligned | `PIOP/hash_relation_rows.go`, `PIOP/credential_rows.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go` | `sections/02_preliminaries.tex`, `sections/05_smallwood_model.tex`, `appendix/C_smallwood_details.tex` |
| Pre-sign surface includes carrier rows, decoded aliases, and BB-tran product families | Canonical `bb_tran` pre-sign witness commits 5 carriers, 9 aliases, 2 source product rows, 4 transform aliases, and 2 product transform aliases | Aligned | `PIOP/credential_rows.go`, `PIOP/credential_constraints.go` | `sections/05_smallwood_model.tex`, `appendix/C_smallwood_details.tex` |
| Showing surface keeps cert-side signature rows, compressed non-sign witness, replay families, and PRF companion rows | Live retained runtime commits carrier rows `C^M`, `C^ctr`, explicit `T` source blocks, replay families for `hat(T)`, `hat(M1+M2)`, `hat(R0)`, `hat(R1)`, and in `bb_tran` mode also `MSigmaR1`, `R0R1`, `hat(MSigmaR1)`, `hat(R0R1)` | Aligned at retained compiled-statement level | `PIOP/showing_coeff_native_literal_packed_runtime.go`, `PIOP/showing_transform_bridge_constraints.go` | `sections/05_smallwood_model.tex`, `appendix/C_smallwood_details.tex` |
| No source-side inverse witness `Z` appears in the canonical BB-tran statement | The live runtime has no rational-hash inverse row `Z`; it uses the two product rows instead | Aligned | absence of `IdxZ`-style row in `PIOP/showing_coeff_native_literal_packed_runtime.go`; presence of `IdxMSigmaR1`, `IdxR0R1` | `sections/02_preliminaries.tex`, `sections/05_smallwood_model.tex`, `appendix/C_smallwood_details.tex` |
| Showing theorem extracts `(u,T,M,K,R0,R1,MSigmaR1,R0R1)` instead of `(u,T,M,K,R0,R1,Z)` | The verifier and replay builders enforce the BB-tran expanded relation directly; no `Z` witness is reconstructed | Aligned | `PIOP/showing_transform_bridge_eval.go`, `PIOP/constraint_eval.go` | `sections/05_smallwood_model.tex`, `sections/04_arc_construction.tex` |
| Signed hidden PRF key is the second packed message half | The live command extracts PRF key lanes from signed `M2` and the proof re-binds them through the message carrier row | Aligned with concrete naming difference | `cmd/showing/main.go`, `PIOP/showing_transform_bridge_constraints.go` | `sections/04_arc_construction.tex`, `sections/05_smallwood_model.tex` |
| Full replay exists semantically | The runtime supports both `full` and `reduced` replay, but defaults to `reduced` | Partially aligned; same relation family, narrower default runtime | `PIOP/run.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go`, `cmd/showing/main.go` | `sections/05_smallwood_model.tex`, `sections/06_parameters.tex` |
| PRF companion constraints bind the tag to the same signed secret | The live builder forces the PRF companion route and rejects the legacy PRF layout | Aligned semantically, stricter operationally | `PIOP/showing_builder.go`, `PIOP/prf_companion_bridge.go`, `PIOP/generic_builder.go` | `sections/05_smallwood_model.tex` |
| Concrete showing verifier includes spent-tag policy state | The shipped CLI proves and verifies locally but does not maintain the application-layer spent-tag database | Intentionally outside the current command surface | `cmd/showing/main.go` | `sections/04_arc_construction.tex` |

## Concrete BB-tran Statement Used Live

The canonical public params file `Parameters/credential_public.json` sets:

- `hash_relation = bb_tran`
- `BPath = Parameters/Bmatrix_bb_tran.json`

The retained concrete target is therefore

`T = B1 * (M1 + M2) + B2 * R0 + 1 / (B3 - R1)`

whenever `B3 - R1` is invertible in `Rq`.

The compiled proofs certify the expanded retained form

`B3*T - T*R1 - (B3*B1)*(M1+M2) - (B3*B2)*R0 + B1*MSigmaR1 + B2*R0R1 - 1 = 0`

with auxiliary products

- `MSigmaR1 = (M1 + M2) * R1`
- `R0R1 = R0 * R1`

This is the exact reason the live `bb_tran` witness geometry is larger than
the former `bbs` geometry.

## Remaining Compression Choices

### 1. The showing source witness is still compressed

The retained live runtime does not commit separate top-level source rows for
`M`, `K`, `R0`, and `R1`. Instead:

- `M` and `K` are recovered from `C^M`
- `R0` and `R1` are recovered from `C^ctr`
- `T` remains an explicit source family
- `MSigmaR1` and `R0R1` are explicit proof-only source rows in `bb_tran`

This is deliberate. The paper now describes the retained compiled statement in
that compressed form rather than pretending the implementation commits a fully
expanded source tuple.

### 2. Reduced replay is still the default runtime

The compiled relation supports full replay families, but the shipped defaults
continue to use:

- `ReplayMode = reduced`
- one replay block for each retained replay family

So the canonical theorem statement and the runtime agree on the replay family,
while the default CLI still picks the narrower geometry for proof size.

### 3. The runtime is relation-bound

Credentials are now explicitly tied to the relation selected by the public
params. In practice this means:

- `bb_tran` credentials are issued and shown against
  `Parameters/credential_public.json`
- `bbs` credentials are issued and shown only against the alternate
  `Parameters/credential_public_bbs.json`
- showing rejects mismatches between the state's stored relation and the
  loaded public params

There is no cross-relation compatibility layer.

## Supported-Mode Matrix

| Expectation | Live branch status | Status | Code anchor |
| --- | --- | --- | --- |
| Canonical relation is `bb_tran` | Yes | Implemented | `credential/public_params.go`, `cmd/issuance/flow_helpers.go` |
| Transition `bbs` mode still exists | Yes, only behind an explicit selector | Implemented | `credential/hash_relation.go`, `Parameters/credential_public_bbs.json` |
| Multiple coeff-native showing layouts remain supported | No; only `literal_packed_aggregated_v3` is retained | Intentionally narrowed | `PIOP/run.go`, `PIOP/showing_builder.go` |
| Legacy PRF replay layout still exists | No; PRF companion is mandatory | Intentionally narrowed | `PIOP/showing_builder.go`, `PIOP/generic_builder.go` |
| Shipped verifier enforces spent-tag policy state | No; local CLI only | Not part of current command surface | `cmd/showing/main.go` |

## What To Trust

If you are checking a claim about the current branch:

- trust the code and tracked assets for live behavior
- trust the paper for the intended theorem-facing retained BB-tran statement
- use this note to distinguish true cryptographic changes from runtime
  compression or operator-surface choices
