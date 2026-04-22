# NIZK Alignment Notes

This note records paper-to-code alignment for the current SPRUCE checkout
against [ARC_Spruce/main.pdf](ARC_Spruce/main.pdf).

## Reading Rule

Use this precedence, in this order:

1. target semantics and claimed properties: the paper
2. live implementation behavior: the current code and tracked runtime assets
3. measurements: the commands listed in [protocol.md](protocol.md)
4. repo prose: only when consistent with the first three

Keep these categories separate:

- paper-stated fact
- paper-stated conditional claim
- paper-explicit open gap / non-claim
- code-backed fact
- measured fact
- inference

## Current Bottom Line

- `go run ./cmd/showing -showing-preset compact_l1_research -full` is now the
  theorem-clean showing path.
- `go run ./cmd/showing -showing-preset compact_l1_research` remains a reduced
  engineering benchmark path and is not the paper's full replay-image theorem
  instance.
- issuance remains structurally aligned with the paper's public-target pre-sign
  statement.

## Claim Matrix

| Property | Paper | Code / Measurement | Status | Notes |
| --- | --- | --- | --- | --- |
| issuance coherence: one hidden witness binds both `c` and public `T` | Paper fact: Sections 3 and 5.2 use one coherent hidden witness behind the commitment and public target. | Code fact: [issuance/flow.go](../issuance/flow.go) passes one witness set into `ProvePreSign`, with `Com` and `T` both public in the same proof; [cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go) persists the finalized state built from that same flow. Measured fact: `go run ./cmd/issuance demo-local -seed 21` succeeds. | aligned | The code uses row-level auxiliaries, but the pre-sign proof still binds one coherent hidden opening surface to both public objects. |
| issuance inverse-witness correctness | Paper fact: issuance proves the public target relation, including the inverse witness semantics. | Code fact: [issuance/flow.go](../issuance/flow.go) derives `R0`, `R1`, `K0`, `K1`, then `T`, and [PIOP/credential_constraints.go](../PIOP/credential_constraints.go) enforces the cleared relation over those derived rows. | aligned | The code realizes the inverse semantics through the cleared `bb_tran` relation and helper products rather than a serialized explicit `Z` row. |
| showing signature shortness | Paper fact: showing needs a bounded hidden signature witness. | Code fact: the live path uses hidden `SigShortnessV6` in [PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go). Measured fact: reduced and full showing both verify with `SigShortnessV6`. | aligned | No exact signature heads are serialized. |
| showing replay witness shape | Paper fact: Sections 5.3, 5.5, and 6.4 are written around the exact full replay image. | Code fact: `ShowingReplayModeFull` in [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go) commits full replay blocks and derives `THat` directly from signature replay heads without committed `T` source rows. Measured fact: the full CLI and `TestTransformBridgeCombinedReplayDebugFull` now pass. | aligned | This row is about the full path. Reduced replay remains narrower by design. |
| exact source-to-replay bridges | Paper fact: theorem transport uses exact source-to-replay bridges. | Code fact: full replay keeps exact replay-image families in [PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go) and [PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go), with `THat` derived from signature replay heads instead of committed `T` source rows. Measured fact: `TestTransformBridgeTamperedFullHiddenTBreaksSourceBridge` and `TestTransformBridgeTamperedFullRHatBreaksBridge` pass. | aligned | Reduced replay intentionally omits the full replay-image surface. |
| exact replay residual over all replay blocks | Paper fact: the showing statement uses the residual on the full replay image. | Code fact: full replay sets `ReplayTHatCount == ReplayBlockCount == SigBlocks` and evaluates the residual over that whole surface. Measured fact: `TestTransformBridgeFullReplaySurfaceUsesAllBlocks` passes. | aligned | This is the main reason `-full` is the theorem-clean path. |
| coefficient-domain `bb_tran` consequence | Paper conditional claim: coefficient-domain consequence is derived from the implemented full replay statement. | Code fact: the canonical live relation is still `bb_tran` through [credential/public_params.go](../credential/public_params.go). Inference: the code now instantiates the right full replay geometry, but the higher-level theorem transport still depends on the paper's proof. | conditionally aligned | The code now matches the theorem-facing statement shape; the mathematical consequence still rests on the paper argument. |
| abstract rational-hash consequence | Paper conditional claim: the abstract rational-hash story is broader than the concrete `bb_tran` instantiation. | Code fact: the concrete live path is `bb_tran`; `bbs` remains only as a transition mode. | conditionally aligned | The repo does not claim a broader theorem than the concrete relation it actually instantiates. |
| PRF correctness | Paper fact: showing proves the PRF/tag relation for the same hidden witness. | Code fact: the live showing path uses the PRF companion route in [PIOP/prf_companion_bridge.go](../PIOP/prf_companion_bridge.go) and [PIOP/generic_builder.go](../PIOP/generic_builder.go). Measured fact: reduced and full showing both verify. | aligned | The PRF proof is part of the executable statement, not external prose. |
| rate limiting | Paper conditional claim: rate limiting depends on spent-tag policy state outside the algebraic proof core. | Code fact: `cmd/showing` is local proof construction / verification only and does not maintain a spent-tag database. | unproven | The tag relation is proven, but application-layer rate-limit enforcement is not implemented in this CLI. |
| hidden signature / zero knowledge | Paper conditional claim: hiding relies on the theorem model and the instantiated proof system. | Code fact: `SigShortnessV6` is hidden, nested, and bound back only through authenticated outer `THat`; the leaking V5 exact-head path is not used. | conditionally aligned | The implementation preserves signature hiding at the protocol surface, but theorem-level ZK still follows the paper's assumptions. |
| blindness | Paper-explicit open gap / non-claim. | Code fact: the repo does not add a new blindness proof beyond the paper. | unproven | The implementation should not be described as closing this gap. |
| one-more unforgeability | Paper-explicit open gap / non-claim. | Code fact: the repo does not add a new one-more unforgeability proof beyond the paper. | unproven | The implementation should not be described as closing this gap. |
| presentation unlinkability | Paper conditional claim: unlinkability relies on the full showing statement, PRF/tag model, and application context. | Code fact: the full path now preserves hidden shortness and exact replay geometry; reduced replay is explicitly labeled narrower. Inference: the live theorem-clean path is the correct protocol surface for the paper's unlinkability story. | conditionally aligned | The proof surface is now aligned, but the full claim still inherits the paper's conditions and the missing rate-limit service. |
| reduced replay as a theorem-clean paper instance | Paper fact: the main theorem story is not written around reduced replay. | Code fact: reduced replay is still shipped as the default benchmark path. | misaligned | Reduced replay is kept only as a secondary engineering benchmark path. |
