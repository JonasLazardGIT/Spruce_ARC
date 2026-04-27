# PIOP Notes

The live showing implementation keeps one maintained family: the optimized
inline-target replay-compact relation, exposed through the three public showing
profiles in `cmd/showing`.

The optimized family stores `SigShortnessProofV18` with version `18` and reports
mode `sig_shortness_inline_target_replay_compact_hiding`. It is single-root,
uses the existing 16-column main row oracle, keeps private `R11,L4` signature
digit rows, omits committed `TargetMR0Hat`, and keeps `RHat1` and `ZHat` rows.
The maintained profiles use x0_len=70 at ring degrees 512 and 1024. The
optimized relation also uses internal showing-only full-`mu` witness
compression:

```text
mu_pack_width      = 2
mu_carrier_rows    = 32
mu_virtual_blocks  = 64
alias_mu_rows      = 0
```

Each packed `mu` carrier value encodes two ternary coefficients from matching
columns of adjacent logical `mu` blocks. The public statement remains direct
`bb_tran`; decode and membership constraints are private PACS constraints.

The current canonical tuple is:

```text
lvcs_ncols=84
nleaves=5760
ell=16
eta=41
ell'=2
theta=3
rho=2
kappa={10,0,0,6}
sig_profile=r11_l4_production
```

The p=4 `mu` packing experiment is supported only as an internal degree-study
override. It raises the `mu` membership/decode degree to `81`, drives
`dQ=2526`, and is not selected by any live public preset.

The explicit `ring_degree=512` path is a research statement fork of the same
V18 optimized relation shape. It binds `ring_degree` into public-input labels,
proof reports, transcript reports, row layouts, and V18 layout digests, and the
verifier rejects proof/layout/ring mismatches. It requires separately generated
credential and NTRU artifacts and remains unsafe for production until the
degree-512 assumptions are reviewed.

Old research payloads are no longer public proof surfaces. Removed preset
labels fail closed when requested through the CLI.
