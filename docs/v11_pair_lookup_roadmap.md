# Showing Surface Cleanup Roadmap

This file replaces the old V11 pair-lookup roadmap. The V11/V14/V15/V16/V17/V19
research surfaces have been pruned from the public CLI. The live optimized
profile is the clean V18 inline-target replay-compact profile.

## Live Surface

- default reduced showing: `go run ./cmd/showing`
- V6 full replay baseline: `go run ./cmd/showing -full`
- aggregate V6 control:
  `go run ./cmd/showing -showing-preset aggregate_v6_research`
- optimized inline-target replay-compact profile:
  `go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research`

## Optimized Profile

```text
preset  = aggregate_inline_target_replay_compact_research
mode    = sig_shortness_inline_target_replay_compact_hiding
version = 18
tuple   = lvcs_ncols=84, nleaves=5760, ell=16, eta=41,
          kappa={10,0,0,6}, R11,L4, theta=3, rho=2, ell'=2
```

The proof keeps one 16-column row root, private digit shortness, compact PRF
replay scheduling, `RHat1=64`, and `ZHat=64`. It also uses showing-only
packed full-`mu` witness compression with `mu_pack=2`, so 64 logical `mu`
blocks are represented by 32 private carrier rows and virtual decode
constraints. It omits `TargetMR0Hat`, `THat`, public heads, hidden/aux proofs,
pair extraction rows, lookup metadata, and pullback metadata.

Default/public optimized V18 uses `ring_degree=1024`. The explicit
`-research-ring-degree 512` mode is a separate unsafe research statement fork
with fresh `research_n512` artifacts, `RHat1=32`, `ZHat=32`, `mu_rows=16`, and
256 signature shortness rows. It is not a replacement preset and does not
revive any pruned V11/V14/V15/V16/V17/V19 surface.

## Removed Labels

The following old labels are intentionally invalid:

```text
aggregate_v11_direct_target_research
aggregate_v11_pair_lookup_research
aggregate_v15_coeff_lookup_research
aggregate_v16_inline_target_research
aggregate_v17_z_elim_inline_target_research
aggregate_v18_replay_compact_research
aggregate_v18_replay_compact_w84_research
aggregate_v19_inline_r1_research
compact_l1_research
transcript_first
production_balance
```

They are not aliases for the clean optimized profile.

## Required Regression Checks

- V6 controls still verify.
- The optimized profile verifies with version `18` and the clean mode label.
- The optimized profile reports `target_mr0=0`, `rhat1=64`, `zhat=64`,
  `mu_pack=2`, `mu_rows=32`, `dQ=356`, `selected=51`, and
  `activeBlocks=3`.
- The degree-512 research fork reports `ring_degree=512` and fails clearly if
  pointed at default `N=1024` credentials or NTRU artifacts.
- Shape checks reject `TargetMR0Hat`, `THat`, hidden/aux material, old lookup or
  pair metadata, sidecar roots, and pruned preset strings.
