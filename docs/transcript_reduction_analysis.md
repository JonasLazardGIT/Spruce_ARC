# Transcript Reduction Analysis

The live transcript-size work is now consolidated around V6 controls and the
canonical optimized inline-target replay-compact profile.

## Live Measurements To Track

Run:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

For the optimized profile, reports should show:

```text
proof version = 18
mode          = sig_shortness_inline_target_replay_compact_hiding
target_mr0    = 0
rhat1         = 64
zhat          = 64
dQ            = 378
selected      = 19
activeBlocks  = 1
```

The canonical tuple is `lvcs_ncols=84`, `eta=39`, `kappa={10,0,0,5}`,
`R11,L4`, `theta=3`, `rho=2`, and `ell'=2`.

## Removed Work

The old direct-target, pair-packing, coefficient-lookup, rowless Z-elimination,
legacy replay-compact, and inline-R1 research presets are pruned from the public
surface. They should not be used as benchmark controls or promoted aliases.

The next real transcript reduction must either remove enough committed rows to
change LVCS geometry, lower `dQ` without increasing another bucket, or replace
private digit shortness with a sound fixed-table lookup backend. Digest-only or
auxiliary-proof-only variants are not considered live reductions.
