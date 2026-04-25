# Command Programs

## `cmd/showing`

Live showing surface:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

The optimized preset is the clean V18 profile:

- preset: `aggregate_inline_target_replay_compact_research`
- mode: `sig_shortness_inline_target_replay_compact_hiding`
- payload: `SigShortnessProofV18`, version `18`
- tuple: `lvcs_ncols=84`, `eta=39`, `theta=3`, `rho=2`, `ell'=2`,
  `kappa={10,0,0,5}`, `R11,L4`
- replay shape: no `TargetMR0Hat`, keep `RHat1=64` and `ZHat=64`,
  no `THat`, hidden proof, sidecar root, lookup proof, or pullback proof

Unknown or pruned showing preset strings fail explicitly.

## Transcript Sweep

The transcript sweep keeps reduced/full V6 controls and the clean inline-target
replay-compact control. Removed V11/V14/V15/V16/V17/V19 controls are not live
sweep tracks.
