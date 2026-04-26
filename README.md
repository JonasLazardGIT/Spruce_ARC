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
`lvcs_ncols=84`, `nleaves=5760`, `ell=16`, `eta=41`, `theta=3`,
`rho=2`, `ell'=2`, `kappa={10,0,0,6}`, and one 16-column main row
oracle. The default/public optimized path runs at `ring_degree=1024`. In this
profile the full-capacity ternary `mu` payload is represented
with the internal packed carrier `mu_pack=2`: 64 logical `mu` blocks are carried
by 32 private packed rows and decoded inside the PACS constraints.

The optimized profile keeps the direct `bb_tran` relation, removes
`TargetMR0Hat`, keeps `RHat1` and `ZHat`, uses private signature digit rows,
and has no public digits, `T`, `THat`, `THatHeads`, hidden proof, sidecar root,
or auxiliary lookup/pullback proof.

Current reference measurements for the optimized profile are approximately
`43163` bytes paper transcript, `71740` bytes verifier payload, `dQ=356`, and
`100.27` theorem bits. The p=4 `mu` packing experiment verifies only as a
high-degree internal path and is not selected by a public preset.

## Degree-512 Research Fork

The optimized V18 path also has an explicit unsafe research fork over
`R_q[X]/(X^512+1)`. It is not the default and is not equivalent to public V18:
the same full-capacity `mu` semantics are interpreted over only 512
coefficients, with the PRF key window starting at coefficient `256`.

Use separate research artifacts:

```bash
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research \
  -research-ring-degree 512 \
  -state-path credential/keys/credential_state.research_n512.json
```

The generated research measurement is `32526` bytes paper transcript,
`61187` bytes verifier payload, `dQ=356`, and `100.27` theorem bits. Production
validity remains blocked on degree-512 lattice/security review.

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
