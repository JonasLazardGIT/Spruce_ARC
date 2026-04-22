# Protocol

This is the implementation-canonical protocol note for the current SPRUCE
branch.

It is intentionally strict about source-of-truth boundaries:

- target semantics and claimed protocol properties come from
  [ARC_Spruce/Spruce_ARC_htran.pdf](ARC_Spruce/Spruce_ARC_htran.pdf)
- live behavior comes from the current code and tracked runtime assets
- this note exists to say exactly where those two currently coincide and where
  they do not

## Commands

Run all commands from the repository root.

### Reduced showing benchmark

```bash
go run ./cmd/showing -showing-preset compact_l1_research
```

This is the retained reduced engineering benchmark path.

### Full replay showing

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

This is the theorem-clean full replay showing path.

### Issuance

```bash
go run ./cmd/issuance demo-local -seed 21
```

This runs the role-separated public-target issuance flow locally and updates the
tracked holder artifacts.

## Source Of Truth

### Target semantics

Use the paper first for these questions:

- what issuance is supposed to prove
- what showing is supposed to prove
- which properties are proved, conditional, or explicitly left open

The most important paper sections for current code alignment are:

- Section 3: issuance / blind-sign flow
- Section 4: ARC, PRF/tag, and conditional security decomposition
- Section 5.2: issuance statement
- Section 5.3: showing statement
- Section 5.4: PRF companion relation
- Section 5.5: hiding and statement strength
- Section 6.4: full replay-image geometry
- Section 7: retained reduced-replay implementation result

### Live behavior

Use the code and tracked assets first for these questions:

- which path the CLI actually runs
- which rows are committed
- which openings are emitted
- whether a command or test passes

Primary runtime anchors:

- [cmd/showing/main.go](../cmd/showing/main.go)
- [cmd/showing/integration_test.go](../cmd/showing/integration_test.go)
- [cmd/issuance/flow_helpers.go](../cmd/issuance/flow_helpers.go)
- [issuance/flow.go](../issuance/flow.go)
- [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go)
- [PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go)
- [PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go)
- [PIOP/generic_builder.go](../PIOP/generic_builder.go)
- [PIOP/VerifyNIZK.go](../PIOP/VerifyNIZK.go)
- [PIOP/proof_report.go](../PIOP/proof_report.go)

Tracked runtime assets:

- `Parameters/Parameters.json`
- `Parameters/credential_public.json`
- `prf/prf_params.json`
- `ntru_keys/public.json`
- `credential/keys/credential_state.json`

## Shared Live Parameters

### Canonical credential relation

The canonical tracked public parameter file is
`Parameters/credential_public.json`.

Its live relation label is:

- `hash_relation = bb_tran`

So the concrete target relation implemented by issuance and showing is still
the `bb_tran` target.

### Shared proof-system ring

The proof-system ring comes from `Parameters/Parameters.json`.

The important live fact is not the exact numeric tuple by itself; it is that
issuance, showing, PRF proving, and the replay bridge all share the same proof
ring, while the NTRU signer uses its own modulus from `ntru_keys/public.json`.

## Issuance

Issuance remains the public-target pre-sign proof.

The holder proves a public `T` before the issuer signs that `T`.

### Public issuance surface

At the semantic level, the live public issuance statement is still the paper's
public-target object family:

- commitment object `c` / `Com`
- public target `T`
- issuer challenge rows
- public matrices `Ac` and `B`

In the current code this surfaces through [issuance/flow.go](../issuance/flow.go):

- `PrepareCommit` builds `Com`
- `ApplyChallenge` derives `R0`, `R1`, carries, and `T`
- `ProvePreSign` builds one proof with `Com` and `T` both public
- `VerifyPreSign` checks that proof before signing

### Hidden issuance witness

At the semantic level the paper speaks about a witness surface that includes
message rows, challenge-response rows, and inverse witness structure.

The current code realizes that witness with:

- `M1`, `M2`
- `RU0`, `RU1`
- `R`
- derived `R0`, `R1`
- carry rows `K0`, `K1`

The important alignment fact is that one coherent hidden witness surface feeds
both the commitment and the public target proof.

### Issuance alignment status

Current code-backed judgment:

- issuance is already close to the paper
- no semantic repair was needed in this pass
- the repo still issues a signature on the verified public target and persists
  the resulting credential state for showing

## Showing Modes

The current branch deliberately exposes two different showing modes.

### `theorem_clean_full_replay`

Command:

```bash
go run ./cmd/showing -showing-preset compact_l1_research -full
```

This is the path that now aligns with the paper's theorem-facing full
replay-image model.

Live properties of this mode:

- full replay blocks are committed
- `THat` is derived directly from signature replay heads; committed `T` source
  rows are not part of the live baseline witness
- exact source-to-replay bridges are enforced
- replay residual is enforced across all replay blocks
- the proof report labels the statement as
  `theorem_clean_full_replay`

This is the mode to use when the question is "does the live code instantiate
the paper's full showing statement as closely as possible in this checkout?"

### `reduced_engineering_replay`

Command:

```bash
go run ./cmd/showing -showing-preset compact_l1_research
```

This remains in the repo as the retained engineering benchmark path.

Live properties of this mode:

- replay is intentionally reduced
- committed `T` source rows are omitted
- the proof report labels the statement as
  `reduced_engineering_replay`

This mode is still useful for transcript engineering and local benchmarking,
but it is not the paper's theorem-clean showing instance.

## Hidden Shortness

The live showing path uses hidden `SigShortnessV6`.

It does not use:

- the older same-root shortness opening as the live default
- the leaking V5 exact-head path

Current live shortness shape:

- a nested hidden SmallWood proof over the shortness witness
- an authenticated outer `THat` opening under the main proof root
- a round-0 binding digest that binds the nested proof back into the outer
  transcript

The verifier learns that a hidden bounded signature witness induces the
authenticated outer `THat`, without learning the exact packed signature heads.

## Full Replay Fix

The previous full replay failure was in the `SigShortnessV6` `THat` opening
path.

The repaired behavior is:

- reduced one-block openings may still omit all serialized `M` values
- full multi-slot openings keep explicit authenticated `M` values

This keeps hidden shortness intact while making the full replay opening stable
under verifier reconstruction.

The bug surface was the outer `SigShortnessV6` same-root `THat` opening. The
reduced one-block path safely reconstructs omitted `M` values on the verifier
side, but the full multi-slot replay opening diverged when those `M` values
were omitted before packing. The live repair is in
[PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go): reduced mode
still omits `M` values, while full replay keeps them explicit so the verifier
reconstructs the same authenticated subset opening the prover committed.

## What Each Showing Mode Certifies

### Full replay

The full path certifies, at the live code level, a statement with:

- full replay-image geometry
- exact source-to-replay bridges
- replay residual over all replay blocks
- hidden shortness bound back to the authenticated outer `THat`
- PRF/tag correctness for the same hidden signed witness

### Reduced replay

The reduced path certifies a narrower engineering statement:

- authenticated reduced replay surface
- hidden shortness bound back through the authenticated outer `THat`
- PRF/tag correctness

It is intentionally smaller, but it should not be described as the paper's full
replay-image theorem instance.

## Measurement Notes

### Showing

`cmd/showing` prints:

- statement class
- replay mode
- shortness mode
- paper transcript size
- current verifier payload size
- replay / witness geometry
- theorem-style soundness summary

For the current branch, the two most important showing measurements are:

- reduced engineering benchmark:
  `go run ./cmd/showing -showing-preset compact_l1_research`
- theorem-clean full replay path:
  `go run ./cmd/showing -showing-preset compact_l1_research -full`

A current measured snapshot and the current optimization feasibility map are
recorded in [full_baseline_proof_study.md](full_baseline_proof_study.md).

Do not compare reduced replay numbers directly to the paper's full replay-image
theorem claims.

### Issuance

`cmd/issuance` is still artifact-first rather than report-first.

It materializes the pre-sign proof at:

- `credential/issuance/presign_submission.json`

So issuance measurement currently means:

1. run `go run ./cmd/issuance demo-local -seed 21`
2. inspect the generated artifact and success logs
3. if needed, load the embedded proof and pass it through
   `PIOP.BuildProofReport`

## Security Status

Implemented and live:

- public-target issuance proof
- reduced engineering showing path
- theorem-clean full replay showing path
- hidden `SigShortnessV6`
- PRF/tag correctness inside the live showing proof

Still conditional or external:

- coefficient-domain theorem transport still follows the paper's proof
- application-layer rate limiting still requires spent-tag state outside the
  local CLI

Still open because the paper leaves them open:

- blindness
- one-more unforgeability

## Read Next

- [nizk_alignment_notes.md](nizk_alignment_notes.md)
- [full_baseline_proof_study.md](full_baseline_proof_study.md)
