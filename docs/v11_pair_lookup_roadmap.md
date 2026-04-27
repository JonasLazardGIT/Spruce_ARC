# Historical Showing Surface Cleanup Note

This file used to track pair-lookup and related experimental showing surfaces.
Those research branches have been pruned from the public CLI. The maintained
showing surface is now the three-profile optimized inline-target replay-compact
path documented in [`current_showing_defaults.md`](current_showing_defaults.md).

## Live Surface

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

All three profiles use:

```text
relation = aggregate_inline_target_replay_compact_research
mode     = sig_shortness_inline_target_replay_compact_hiding
version  = 18
x0_len   = 70
```

## Regression Checks

- exactly three maintained profiles are registered;
- all maintained profiles verify with canonical x0_len=70 artifacts;
- profile, ring degree, and x0 length are reported and bound into proof
  material;
- removed research labels are rejected rather than mapped to the optimized
  profile;
- shape checks reject public private-witness digits, hidden/auxiliary material,
  sidecar roots, and old lookup metadata.
