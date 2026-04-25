# SPRUCE

This repository contains the ARC-SPRUCE showing prototype and local demo
commands. The live showing surface is intentionally narrow.

## Live Showing Commands

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

The default command uses the reduced `soundness_balanced` profile. `-full`
keeps the maintained V6 hidden-shortness full replay baseline. The
`aggregate_v6_research` preset is the aggregate V6 control.

`aggregate_inline_target_replay_compact_research` is the optimized private
inline-target replay-compact profile. It uses proof payload version `18` with
mode `sig_shortness_inline_target_replay_compact_hiding`, `R11,L4`,
`lvcs_ncols=84`, `eta=39`, `theta=3`, `rho=2`, `ell'=2`,
`kappa={10,0,0,5}`, and one 16-column main row oracle.

The optimized profile keeps the direct `bb_tran` relation, removes
`TargetMR0Hat`, keeps `RHat1` and `ZHat`, uses private signature digit rows,
and has no public digits, `T`, `THat`, `THatHeads`, hidden proof, sidecar root,
or auxiliary lookup/pullback proof.

## Removed Research Surfaces

The old V11, V14, V15, V16, V17, V18 legacy-name, V18 W84 legacy-name, V19,
`compact_l1_research`, `transcript_first`, and `production_balance` preset
strings are no longer public aliases. Passing them to `cmd/showing` fails as an
unknown preset.

## Useful Checks

```bash
go test ./PIOP
go test ./cmd/showing
```

See [Commands.md](Commands.md), [cmd/README.md](cmd/README.md),
[PIOP/README.md](PIOP/README.md), and [docs/protocol.md](docs/protocol.md) for
the current protocol and command notes.
