# Full Baseline Proof Study

This note is the current workflow and handoff note for the theorem-clean full
replay showing baseline after the shared-randomness `h_tran` migration.

It is not an archival note for the old source-product design.

## Commands

- reduced engineering control:
  `go run ./cmd/showing -showing-preset compact_l1_research`
- theorem-clean full replay:
  `go run ./cmd/showing -showing-preset compact_l1_research -full`

## What The Full Baseline Now Proves

The full replay baseline uses the same semantic credential witness as the rest
of the live branch:

- `u`
- `m`
- `k`
- `r0`
- `r1`
- `Z`

with public `(A, B, tag, nonce)`, where:

```text
(B3 - r1) ⊙ Z = 1
A u = B0 + B1 * (m || k) + B2 * r0 + Z
tag = F(k, nonce)
```

This baseline is about replay geometry and transcript shape, not a different
credential semantics.

## Current Full-Replay Implementation Shape

The current theorem-clean full replay path:

- uses the direct `bb_tran` witness surface built from `m`, `k`, `r0`, `r1`,
  and `Z`
- derives replay-domain rows directly from those semantic objects
- does not commit a separate source `T` row
- does not rely on committed `MSigmaR1` / `R0R1` source rows
- does not carry the old source-product bridge as part of the live baseline

When reading current code, start here:

- [PIOP/showing_coeff_native_literal_packed_runtime.go](../PIOP/showing_coeff_native_literal_packed_runtime.go)
- [PIOP/showing_transform_bridge_constraints.go](../PIOP/showing_transform_bridge_constraints.go)
- [PIOP/showing_transform_bridge_eval.go](../PIOP/showing_transform_bridge_eval.go)
- [PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go)
- [cmd/showing/main.go](../cmd/showing/main.go)

## Current Reduced-vs-Full Split

- reduced replay remains the shipped engineering benchmark
- full replay remains the theorem-clean control surface
- both use the same stored credential state and the same `bb_tran` semantics
- the difference is witness packing, replay coverage, and transcript geometry

## Re-run Checklist

Use these commands when refreshing the full baseline after protocol or proof
changes:

```bash
go run ./cmd/issuance demo-local
go run ./cmd/showing -showing-preset compact_l1_research
go run ./cmd/showing -showing-preset compact_l1_research -full
go test ./PIOP ./cmd/showing
```

If the state file predates the shared-randomness migration, regenerate it
before measuring the baseline.

## Measurement Rule

Do not treat one historical transcript byte count as the protocol definition.
For this branch, the stable facts are:

- the full baseline is the `-full` replay surface
- it proves the direct `bb_tran` relation on `(u,m,k,r0,r1,Z)`
- it no longer documents or depends on the deprecated
  commitment-derived/source-product path
