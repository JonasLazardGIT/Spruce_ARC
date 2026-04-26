# Transcript Reduction Analysis

The live transcript-size work is now consolidated around V6 controls and the
canonical optimized inline-target replay-compact profile.

## Live Measurements To Track

Run:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

For the optimized profile, reports should show:

```text
proof version = 18
mode          = sig_shortness_inline_target_replay_compact_hiding
target_mr0    = 0
rhat1         = 64
zhat          = 64
dQ            = 356
mu_pack       = 2
mu_rows       = 32
mu_blocks     = 64
selected      = 51
activeBlocks  = 3
ring_degree   = 1024
```

The canonical tuple is `lvcs_ncols=84`, `nleaves=5760`, `ell=16`,
`eta=41`, `kappa={10,0,0,6}`, `R11,L4`, `theta=3`, `rho=2`, and
`ell'=2`.

Current live measurements from the checked-in artifacts:

```text
default reduced showing:
  paper transcript = 34775 bytes
  theorem bits     = 102.15
  dQ               = 378
  mu_pack          = 1

full V6 baseline:
  paper transcript = 63102 bytes
  theorem bits     = 100.03
  dQ               = 378
  mu_pack          = 1

aggregate V6 control:
  paper transcript = 53284 bytes
  theorem bits     = 102.74
  dQ               = 378
  mu_pack          = 1

optimized V18 packed full-mu:
  paper transcript = 43163 bytes
  verifier payload = 71740 bytes
  theorem bits     = 100.27
  dQ               = 356
  mu_pack          = 2
  selected rows    = 51
  active blocks    = 3

degree-512 V18 research fork:
  paper transcript = 32526 bytes
  verifier payload = 61187 bytes
  theorem bits     = 100.27
  dQ               = 356
  mu_pack          = 2
  selected rows    = 35
  active blocks    = 2
```

## Packed Full-`mu` Witness Compression

The optimized profile now applies the lattice-witness compression idea to the
full-capacity ternary `mu` carrier, not to signature shortness. The payload is
still one private `N=1024` coefficient-bounded ring element on the default
public path. The witness
representation changes from 64 singleton carrier rows and 64 decoded alias rows
to:

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

The `-research-ring-degree 512` path is a separate statement fork, not a p=2
packing variant of the same public statement. It keeps the private V18 surface,
but `mu` has only 512 coefficients, the PRF-key window moves to `256..263`, and
fresh `research_n512` artifacts are mandatory.

## Removed Work

The old direct-target, pair-packing, coefficient-lookup, rowless Z-elimination,
legacy replay-compact, and inline-R1 research presets are pruned from the public
surface. They should not be used as benchmark controls or promoted aliases.

The next real transcript reduction must either remove enough committed rows to
change LVCS geometry, lower `dQ` without increasing another bucket, or replace
private digit shortness with a sound fixed-table lookup backend. Digest-only or
auxiliary-proof-only variants are not considered live reductions.
