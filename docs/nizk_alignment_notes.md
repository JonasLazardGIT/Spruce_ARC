# NIZK Alignment Notes

This note records how the live SPRUCE branch aligns with the current
ARC-SPRUCE paper source after the retained reduced-path showing rewrite. It is
not the protocol specification; that role belongs to [protocol.md](protocol.md).

## Reading Rule

When descriptions disagree, use this precedence:

1. the current codebase and tracked runtime assets define live behavior
2. the paper under `docs/ARC_Spruce/` is the comparison target
3. older repo prose is subordinate to both

## At A Glance

- The canonical concrete hash relation is `bb_tran`.
- The branch still preserves the same high-level architecture:
  holder computes public `T`, issuer signs `T`, showing proves possession of a
  signature on `T` together with PRF-tag correctness.
- The main remaining deltas are runtime choices:
  reduced replay by default, compressed carriers for non-sign source rows, a
  mandatory PRF companion route, `SigShortness` V4, and no shipped spent-tag
  database.

## Core Alignment Matrix

| Paper term / claim | Live implementation | Status | Code anchor |
| --- | --- | --- | --- |
| Concrete target relation is `bb_tran` | `credential.HashRelationBBTran` is the canonical mode selected by `Parameters/credential_public.json` | Aligned | `credential/hash_relation.go`, `credential/public_params.go`, `credential/helpers.go` |
| `bbs` remains available only as a transition mode | Alternate public params select `hash_relation=bbs`; no mixed-relation credential flow is supported | Aligned as a transition rule | `Parameters/credential_public_bbs.json`, `cmd/issuance/flow_helpers.go`, `cmd/showing/main.go` |
| Issuance keeps `T` public and proves it against committed hidden rows | Pre-sign proof takes `T` as a public input and signs the verified public `T` | Aligned | `issuance/flow.go`, `cmd/issuance/*.go` |
| Canonical cleared `bb_tran` relation uses two auxiliary products | Pre-sign and showing both add `MSigmaR1=(M1+M2)*R1` and `R0R1=R0*R1` | Aligned | `PIOP/hash_relation_rows.go`, `PIOP/credential_rows.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go` |
| Reduced showing keeps the relation but narrows the replay surface | The runtime supports both `full` and `reduced` replay, but ships `reduced` by default | Partially aligned by runtime choice | `PIOP/run.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go`, `cmd/showing/main.go` |
| Showing surface authenticates the signature against `T` | The reduced runtime commits `THat` and uses `SigShortness` V4 to prove `digits -> sigHat -> THat` | Aligned at the retained compiled-statement level | `PIOP/sig_shortness_replay.go`, `PIOP/showing_transform_bridge_constraints.go` |
| PRF companion constraints bind the tag to the same signed secret | The live builder forces the packed PRF companion route and rejects the legacy PRF layout | Aligned semantically, stricter operationally | `PIOP/showing_builder.go`, `PIOP/prf_companion_bridge.go`, `PIOP/generic_builder.go` |
| Concrete showing verifier includes spent-tag policy state | The shipped CLI proves and verifies locally but does not maintain the application-layer spent-tag database | Intentionally outside the current command surface | `cmd/showing/main.go` |

## Concrete `bb_tran` Statement Used Live

The canonical public params file `Parameters/credential_public.json` sets:

- `hash_relation = bb_tran`
- `BPath = Parameters/Bmatrix_bb_tran.json`

The retained concrete target is therefore

`T = B1 * (M1 + M2) + B2 * R0 + 1 / (B3 - R1)`

whenever `B3 - R1` is invertible in `Rq`.

The compiled proofs certify the expanded retained form

`B3*T - T*R1 - (B3*B1)*(M1+M2) - (B3*B2)*R0 + B1*MSigmaR1 + B2*R0R1 - 1 = 0`

with auxiliary products:

- `MSigmaR1 = (M1 + M2) * R1`
- `R0R1 = R0 * R1`

## Current Showing Surface

On the shipped reduced showing path, the committed witness surface is:

- carrier rows `C^M`, `C^ctr`
- source-product rows `MSigmaR1`, `R0R1`
- non-sign transform aliases:
  `hat(M1+M2)`, `hat(R0)`, `hat(R1)`, `hat(MSigmaR1)`, `hat(R0R1)`
- committed replay image `THat`
- packed PRF companion rows
- packed signature digit rows used by `SigShortness` V4

The important paper-vs-runtime consequences are:

- reduced showing does not commit the legacy signature-source replay basis
- reduced showing does not commit hidden `T` source rows
- the signature bridge no longer lives in the main transform bridge
- the signature basis is authenticated by shortness through
  `digits -> sigHat -> THat`
- the runtime still does not use a source-side inverse row `Z`; it uses the
  explicit product rows `MSigmaR1` and `R0R1`

## Remaining Runtime Deltas That Matter

These are the paper-vs-code differences that still matter now:

- reduced replay is the shipped default, not full replay
- the non-sign source witness is compressed through carrier rows
- the PRF companion route is mandatory on the live path
- the shipped showing CLI is local-only and does not implement spent-tag state

Older deltas about explicit reduced-path hidden-`T` source families, the
legacy signature-source replay basis, or pre-V4 shortness defaults are
superseded.

## Supported-Mode Matrix

| Expectation | Live branch status | Status | Code anchor |
| --- | --- | --- | --- |
| Canonical relation is `bb_tran` | Yes | Implemented | `credential/public_params.go`, `cmd/issuance/flow_helpers.go` |
| Transition `bbs` mode still exists | Yes, only behind an explicit selector | Implemented | `credential/hash_relation.go`, `Parameters/credential_public_bbs.json` |
| Multiple coeff-native showing layouts remain supported | No; only `literal_packed_aggregated_v3` is retained | Intentionally narrowed | `PIOP/run.go`, `PIOP/showing_builder.go` |
| Legacy PRF replay layout still exists | No; PRF companion is mandatory | Intentionally narrowed | `PIOP/showing_builder.go`, `PIOP/generic_builder.go` |
| Default shortness proof is pre-V4 | No; the shipped reduced path emits `SigShortness` V4 | Implemented | `PIOP/generic_builder.go`, `PIOP/sig_shortness_replay.go` |
| Shipped verifier enforces spent-tag policy state | No; local CLI only | Not part of current command surface | `cmd/showing/main.go` |

## What To Trust

If you are checking a claim about the current branch:

- trust the code and tracked assets for live behavior
- trust the paper for the intended theorem-facing `bb_tran` statement
- use this note to distinguish true cryptographic changes from runtime
  compression or operator-surface choices
