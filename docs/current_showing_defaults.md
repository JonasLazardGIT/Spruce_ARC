# Current Showing Defaults

The public showing surface has exactly three maintained profiles. All three use
`x0_len=70` and the optimized V18 relation
`aggregate_inline_target_replay_compact_research`.

| Profile | Ring degree | x0_len | Target | Measured bits | Transcript bytes | Tuple | Status |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `showing_n512_x0len70_100` | 512 | 70 | 100 | 103.05 | 34843 | `lvcs=70 nleaves=6400 eta=39 theta=3 rho=2 ell'=2 kappa={10,0,0,6}` | no-flag default; research ring |
| `showing_n512_x0len70_128` | 512 | 70 | 128 | 128.06 | 37540 | `lvcs=70 nleaves=13120 eta=44 theta=2 rho=3 ell'=4 kappa={10,10,10,10}` | research ring |
| `showing_n1024_x0len70_100` | 1024 | 70 | 100 | 100.27 | 45927 | `lvcs=84 nleaves=5760 eta=41 theta=3 rho=2 ell'=2 kappa={10,0,0,6}` | degree-1024 maintained profile |

The no-flag command resolves to `showing_n512_x0len70_100`:

```bash
go run ./cmd/showing
```

The explicit profile commands are:

```bash
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

## Measured Buckets

| Profile | Pdecs | VTargets | R | Q | Auth | BarSets | SigShortness | Witness | Committed | Selected replay | Active blocks | dQ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `showing_n512_x0len70_100` | 10713 | 7728 | 6828 | 5298 | 2198 | 1774 | 39 | 490 | 133 | 99/490 | 6/26 | 356 |
| `showing_n512_x0len70_128` | 8963 | 10300 | 7704 | 5268 | 2635 | 2362 | 39 | 490 | 126 | 99/490 | 6/28 | 356 |
| `showing_n1024_x0len70_100` | 13522 | 13240 | 8614 | 5298 | 2418 | 2530 | 39 | 826 | 190 | 115/826 | 7/44 | 356 |

Transcript totals have small run-to-run movement because authenticated/opened
material is transcript-sampled. The table above records the latest explicit
profile smoke run after the preset-pruning cleanup; the no-flag command in that
same pass resolved to `showing_n512_x0len70_100` and reported `35165` bytes.

## Artifact Set

The canonical committed profile artifacts are:

- `Parameters/credential_public.n512_x0len70.json`
- `Parameters/Bmatrix_bb_tran_n512_x0len70.json`
- `credential/keys/credential_state.n512_x0len70.json`
- `credential/keys/signature.n512_x0len70.json`
- `Parameters/credential_public.n1024_x0len70.json`
- `Parameters/Bmatrix_bb_tran_n1024_x0len70.json`
- `credential/keys/credential_state.n1024_x0len70.json`
- `credential/keys/signature.n1024_x0len70.json`

The verifier and showing CLI reject mismatched ring degree or `x0_len` layouts.
Ring degree and `x0_len` are included in proof reports, transcript reports,
public-input label binding, and the optimized V18 layout digest.

## Sweep Notes

The focused real-proving sweep covered the maintained V18 shape around the known
candidate tuples:

- N=512/100: LVCS widths `64,70,76,84,96`, nleaves `5120,5760,6400,7040`,
  eta `39..43`, and a theta/rho/ell-prime variant.
- N=512/128: LVCS widths `64,68,70,72,76,84`, nleaves
  `11584,13120,14080,14720`, eta `42..47`, and theta/rho/ell-prime variants.
- N=1024/100: LVCS widths `70,76,80,84,96,112,128,160`, nleaves
  `5120,5760,6400,7040`, eta `39..45`, and a theta/rho/ell-prime variant.

The default signature shortness profile remains `r11_l4_production`. Compact
signature shortness profiles were not promoted because earlier degree-512 probes
increased the degree/transcript tradeoff rather than improving the V18 profile.
