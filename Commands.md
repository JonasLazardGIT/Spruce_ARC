# Commands

## Showing

Live commands:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

`go run ./cmd/showing` is the reduced `soundness_balanced` path.

`go run ./cmd/showing -full` is the maintained V6 hidden-shortness full replay
baseline.

`aggregate_v6_research` is the aggregate V6 control.

`aggregate_inline_target_replay_compact_research` is the canonical optimized
profile. It uses internal proof version `18`, mode
`sig_shortness_inline_target_replay_compact_hiding`, `R11,L4`, `lvcs_ncols=84`,
`eta=39`, `theta=3`, `rho=2`, `ell'=2`, and `kappa={10,0,0,5}`.

## Tests

```bash
go test ./PIOP
go test ./cmd/showing
```

## Pruned Presets

Removed research labels are invalid and are not mapped to the optimized profile.
This includes the old V11, V14, V15, V16, V17, legacy V18/W84, V19,
`compact_l1_research`, `transcript_first`, and `production_balance` strings.
