# Transcript Reduction Analysis

The live transcript-size work is now consolidated around the three maintained
`x0_len=70` optimized V18 profiles documented in
[`current_showing_defaults.md`](current_showing_defaults.md). Historical V6 and
other research controls are no longer public defaults.

## Live Measurements To Track

Run:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

For the no-flag optimized profile, reports should show:

```text
proof version = 18
mode          = sig_shortness_inline_target_replay_compact_hiding
target_mr0    = 0
rhat1         = 32
zhat          = 32
dQ            = 356
mu_pack       = 2
mu_rows       = 16
mu_blocks     = 32
selected      = 99
activeBlocks  = 6
ring_degree   = 512
x0_len        = 70
```

The no-flag tuple is `lvcs_ncols=70`, `nleaves=6400`, `ell=16`, `eta=39`,
`kappa={10,0,0,6}`, `R11,L4`, `theta=3`, `rho=2`, and `ell'=2`.

Current live measurements from the checked-in x0_len=70 artifacts:

```text
showing_n512_x0len70_100:
  paper transcript = 34843 bytes
  theorem bits     = 103.05
  dQ               = 356
  mu_pack          = 2
  selected rows    = 99
  active blocks    = 6

showing_n512_x0len70_128:
  paper transcript = 37540 bytes
  theorem bits     = 128.06
  dQ               = 356
  mu_pack          = 2
  selected rows    = 99
  active blocks    = 6

showing_n1024_x0len70_100:
  paper transcript = 45927 bytes
  theorem bits     = 100.27
  dQ               = 356
  mu_pack          = 2
  selected rows    = 115
  active blocks    = 7
```

## Packed Full-`mu` Witness Compression

The optimized profile applies the lattice-witness compression idea to the
full-capacity ternary `mu` carrier, not to signature shortness. For N=1024 the
witness representation changes from 64 singleton carrier rows and 64 decoded
alias rows to:

```text
64 logical mu blocks / pack width 2 = 32 packed carrier rows
0 explicit alias mu rows
64 virtual decoded blocks consumed by target and PRF constraints
```

For `BoundB=1`, p=2 has a 9-value membership set and degree-8 decode
polynomials. The global optimized degree remains dominated by the `R11,L4`
signature shortness degree, so `dQ` stays `356`.

Ternary p=3 is not expected to improve the transcript on the current backend.
It would reduce carrier rows to 22 padded rows, but its 27-value membership set
raises the degree driver to 27 and gives:

```text
dQ = 27*(ell+s-1)+s-1 = 27*31+15 = 852
```

That increases mask chunks and the `Q` bucket enough to outweigh the saved
carrier rows.

Ternary p=4 was measured as an internal experiment. It verifies only when the
high-degree formal residuals are kept rather than reduced modulo `X^N+1`:

```text
mu_pack          = 4
mu_rows          = 16
paper transcript = 89007 bytes
verifier payload = 324983 bytes
theorem bits     = 97.29
dQ               = 2526
mask rows        = 186
Q bucket         = 37861 bytes
```

The conclusion is that p=2 is the best ternary packed-`mu` point for the
current one-Q PACS backend. Larger ternary packs need degree-isolated lookup
machinery to become transcript reductions. Binary `mu` packing would only help
if the credential payload semantics changed from ternary to binary; encoding
ternary values as bits is not a proof-size win.

The N=512 profiles are separate statement forks, not p=2 packing variants of
the same N=1024 statement. They keep the private V18 surface, but `mu` has only
512 coefficients, the PRF-key window moves to `256..263`, and fresh N=512
artifacts are mandatory.

## Removed Work

The old direct-target, pair-packing, coefficient-lookup, rowless Z-elimination,
legacy replay-compact, and inline-R1 research presets are pruned from the public
surface. They should not be used as benchmark controls or promoted aliases.

The next real transcript reduction must either remove enough committed rows to
change LVCS geometry, lower `dQ` without increasing another bucket, or replace
private digit shortness with a sound fixed-table lookup backend. Digest-only or
auxiliary-proof-only variants are not considered live reductions.
