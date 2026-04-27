# ARC-SPRUCE Showing Defaults Cleanup Plan

## Public CLI/Profile Surface

The maintained showing surface is reduced to exactly three optimized V18 profiles.
All three use `x0_len=70` and the `aggregate_inline_target_replay_compact_research`
relation.

| Profile | Ring degree | x0_len | Soundness target | Default artifacts |
| --- | ---: | ---: | ---: | --- |
| `showing_n512_x0len70_100` | 512 | 70 | 100 bits | `credential/keys/credential_state.n512_x0len70.json` |
| `showing_n512_x0len70_128` | 512 | 70 | 128 bits | `credential/keys/credential_state.n512_x0len70.json` |
| `showing_n1024_x0len70_100` | 1024 | 70 | 100 bits | `credential/keys/credential_state.n1024_x0len70.json` |

The no-flag command resolves to `showing_n512_x0len70_100`:

```bash
go run ./cmd/showing
```

Explicit profile commands are:

```bash
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

Public help and current documentation advertise `-showing-profile` and the three
profiles above, not historical research presets.

## Removed Or Hidden Presets

The following labels are not maintained public defaults and must not be presented
as supported showing profiles:

- old balanced or aggregate research presets
- removed public proof-profile labels
- compact-full candidates
- old research soundness presets

Internal constants may remain only where needed for compatibility tests,
historical reports, or controlled manual sweeps.

## Artifact Compatibility

All maintained profiles require canonical `x0_len=70` artifacts generated for the
matching ring degree:

- `Parameters/credential_public.n512_x0len70.json`
- `Parameters/Bmatrix_bb_tran_n512_x0len70.json`
- `credential/keys/credential_state.n512_x0len70.json`
- `credential/keys/signature.n512_x0len70.json`
- `Parameters/credential_public.n1024_x0len70.json`
- `Parameters/Bmatrix_bb_tran_n1024_x0len70.json`
- `credential/keys/credential_state.n1024_x0len70.json`
- `credential/keys/signature.n1024_x0len70.json`

Public parameters, B-matrix metadata, credential state, proof, row layout, proof
report, and transcript report must expose `ring_degree` and `x0_len`. The verifier
must reject mismatches. Artifacts generated for one ring degree or one x0 layout
must never be silently reused under another profile.

## Sweep Search Space

Sweeps must use fresh canonical `x0_len=70` artifacts for the target ring degree.
`BuildProofReport` is the only accepted source for theorem bits and transcript
buckets.

Search dimensions:

- `lvcs_ncols`: `48..160` for N=512, `64..224` for N=1024
- `nleaves`: `4096..32768`, step `64`
- `eta`: `28..70`
- `theta`: `1..8`
- `rho`: `1..4`
- `ell_prime`: `1..8`
- `kappa1..kappa4`: `0..10`
- signature shortness profiles: keep `r11_l4_production` as default; only test
  `r24_l3_compact`, `r111_l2_compact`, and raw overrides as sweep candidates

Promotion rule: minimize mean optimized paper transcript bytes, then prefer a
larger theorem-bit margin, then smaller verifier payload.

## Expected Transcript Drivers

The main drivers are LVCS width, number of leaves, `eta`, `theta`, `rho`,
`ell_prime`, grinding `kappa`, witness rows from `x0_len=70`, selected replay
rows, and the signature shortness row/degrees. Signature shortness candidates
must be rejected when they increase `dQ` or miss the soundness floor enough to
lose transcript size.

Known starting points:

- N=512, x0_len=70, 100-bit: `lvcs=70 nleaves=6400 eta=39 theta=3 rho=2 ell'=2
  kappa={10,0,0,6}`, transcript `34843` bytes, theorem bits `103.05`.
- N=512, x0_len=70, 128-bit probe: `lvcs=70 nleaves=13120 eta=44 theta=2 rho=3
  ell'=4 kappa={10,10,10,10}`, transcript `37540` bytes, theorem bits `128.06`.
- N=1024, x0_len=70, 100-bit: `lvcs=84 nleaves=5760 eta=41 theta=3 rho=2 ell'=2
  kappa={10,0,0,6}`, transcript `45927` bytes, theorem bits `100.27`.

## Tests Required

- no-flag `cmd/showing` resolves to `showing_n512_x0len70_100`
- all three maintained profiles use `x0_len=70`
- all three profiles verify with committed canonical artifacts
- N=1024 profile reports theorem bits `>=100`
- N=512 100-bit profile reports theorem bits `>=100`
- N=512 128-bit profile reports theorem bits `>=128`
- proof and transcript reports include `ring_degree` and `x0_len`
- proof/layout digest changes when either `ring_degree` or `x0_len` changes
- verifier rejects ring-degree, B-matrix, public-param, credential-state, and
  proof-layout mismatches
- old research-only presets are not listed in public CLI help and are rejected or
  clearly deprecated
- optimized V18 privacy surface remains: no public `mu/message/key/r0/r1/Z/signature`
  digits, no `T/THat/THatHeads`, no `TargetMR0Hat`, no hidden proof, no sidecar root

## Known Blockers

N=512 is a research statement fork over a lower-degree ring. Passing theorem
accounting does not by itself establish production security or lattice-assumption
equivalence. If any maintained target cannot be reached with optimized V18 and
`x0_len=70`, the implementation must report the blocker rather than weaken the
statement or silently lower the soundness target.
