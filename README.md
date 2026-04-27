# SPRUCE

This repository contains the ARC-SPRUCE showing prototype and local demo
commands. The live showing surface is intentionally narrow.

## Live Showing Commands

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

The no-flag command resolves to `showing_n512_x0len70_100`. All three maintained
profiles use `x0_len=70` and the optimized inline-target replay-compact
relation `aggregate_inline_target_replay_compact_research`.

The optimized relation uses proof payload version `18`, mode
`sig_shortness_inline_target_replay_compact_hiding`, private `R11,L4`
signature digit rows, and one 16-column main row oracle. It keeps the direct
`bb_tran` relation, removes `TargetMR0Hat`, keeps `RHat1` and `ZHat`, and has no
public `mu`, message, key, `r0`, `r1`, `Z`, or signature digits.

The maintained profile table and current measurements are in
[docs/current_showing_defaults.md](docs/current_showing_defaults.md).

## Artifacts

Canonical x0_len=70 artifacts are committed for ring degrees 512 and 1024.
The showing CLI validates public params, B matrix metadata, credential state,
proof layout, ring degree, and x0 length before verification. Artifacts are not
silently reused across ring degrees or x0 layouts.

## Useful Checks

```bash
go test ./ntru/io ./credential ./cmd/issuance ./cmd/showing ./PIOP
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

See [Commands.md](Commands.md), [cmd/README.md](cmd/README.md),
[PIOP/README.md](PIOP/README.md), and [docs/protocol.md](docs/protocol.md) for
the current protocol and command notes.
