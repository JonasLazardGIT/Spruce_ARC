# Protocol Surface

The maintained showing relation is the direct shared-randomness `bb_tran`
relation:

```text
A*u = B0 + B1*mu + sum_i B2[i]*r0_i + Z
(B3 - r1) * Z = 1
```

The maintained showing surface has exactly three optimized V18 profiles, all
with `x0_len=70`:

```text
showing_n512_x0len70_100   N=512,  100-bit theorem target
showing_n512_x0len70_128   N=512,  128-bit theorem target
showing_n1024_x0len70_100  N=1024, 100-bit theorem target
```

The no-flag command resolves to `showing_n512_x0len70_100`. Current
documentation and tests use `-showing-profile`; removed preset labels are not
public aliases.

Each profile uses one full-capacity coefficient-bounded ring element
`mu = m || k` with layout `full_capacity_halves_v1`. For `N=1024`,
coefficients `0..511` are the message half and PRF-key coefficients live at
`512..519`. For `N=512`, coefficients `0..255` are the message half and
PRF-key coefficients live at `256..263`. All coefficients are bounded by
`BoundB`. The proof `ncols = 16` value is only the carrier block width, not the
semantic payload width.

Artifacts are degree/layout-specific. Public parameters, B matrices, credential
state, signatures, proofs, row layouts, proof reports, and transcript reports
bind and report both `ring_degree` and `x0_len`; mismatches are rejected.

The optimized showing preset represents this full `mu` privately with
showing-only witness compression. With `BoundB=1`, two ternary coefficients are
packed into one field element:

```text
code = (v0 + 1) + 3*(v1 + 1),  v0,v1 in {-1,0,1}
```

Logical block `2r` and logical block `2r+1` at the same column are carried in
packed carrier row `r`. Thus the N=1024 payload keeps 64 logical `mu` blocks
but uses 32 private carrier rows; the N=512 payload keeps 32 logical `mu`
blocks but uses 16 private carrier rows. There are no explicit
`AliasMuBlockRows`; virtual decode polynomials are consumed inside the
constraints.

The public command surface is:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

## Optimized Inline-Target Replay-Compact Profile

All three maintained profiles use:

```text
preset = aggregate_inline_target_replay_compact_research
mode   = sig_shortness_inline_target_replay_compact_hiding
proof  = SigShortnessProofV18, version 18
```

It uses:

```text
ell        = 16
ncols      = 16
mu_pack    = 2
sig        = R11,L4
```

Current measured tuples are tracked in
[`current_showing_defaults.md`](current_showing_defaults.md).

It keeps one main row oracle and no auxiliary proof or sidecar root. The row
shape removes committed `TargetMR0Hat` rows and checks the target equation
inline from private carrier material:

```text
sum_c,l A_c[b,j] * R^l * d[c,b,l,j]
  = B0[b,j] + B1[b,j]*mu[16*b+j] + sum_i B2[i,b,j]*r0_i[j] + ZHat_b[j]
```

It still commits `RHat1` and `ZHat` rows and checks `(B3-r1)*Z=1` through the
existing SmallWood/PACS row constraints. It does not expose `u`, signature
digits, `T`, `THat`, `THatHeads`, `m`, `k`, `r0`, `r1`, or `Z`.

The p=4 packed-`mu` experiment is not part of the live protocol. It is sound in
the current PACS model only if high-degree formal residuals are retained, which
raises the measured optimized profile to `dQ=2526` and makes the transcript
larger than the singleton/full-capacity baseline.

Removed historical public labels are invalid rather than aliases.
