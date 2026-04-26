# Protocol Surface

The maintained showing relation is the direct shared-randomness `bb_tran`
relation:

```text
A*u = B0 + B1*mu + sum_i B2[i]*r0_i + Z
(B3 - r1) * Z = 1
```

The default/public signed payload is one full-capacity coefficient-bounded ring
element `mu = m || k` over `N=1024` with layout
`full_capacity_halves_v1`. Coefficients `0..511` are the message half, PRF-key
coefficients live at `512..519`, and all `1024` coefficients are bounded by
`BoundB`. The proof `ncols = 16` value is only the carrier block width, not the
semantic payload width.

The explicit `-research-ring-degree 512` fork keeps the same relation shape over
`R_q[X]/(X^512+1)`, but it is a research statement fork: `mu` has 512
coefficients, the message half is `0..255`, and the PRF-key coefficients live at
`256..263`. It requires separately generated public params, B matrix, NTRU
params/key material, credential state, and signature artifacts.

The optimized showing preset represents this full `mu` privately with
showing-only witness compression. With `BoundB=1`, two ternary coefficients are
packed into one field element:

```text
code = (v0 + 1) + 3*(v1 + 1),  v0,v1 in {-1,0,1}
```

Logical block `2r` and logical block `2r+1` at the same column are carried in
packed carrier row `r`. Thus the full payload keeps 64 logical `mu` blocks but
uses 32 private carrier rows, no explicit `AliasMuBlockRows`, and virtual
decode polynomials inside the constraints. Default, `-full`, and
`aggregate_v6_research` keep the singleton `mu` carrier.

The public command surface is:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

## V6 Controls

V6 remains the maintained hidden-shortness baseline/control. `-full` runs the
full replay baseline, and `aggregate_v6_research` runs the aggregate V6 control.

## Optimized Inline-Target Replay-Compact Profile

The optimized profile is exposed only as:

```text
preset = aggregate_inline_target_replay_compact_research
mode   = sig_shortness_inline_target_replay_compact_hiding
proof  = SigShortnessProofV18, version 18
```

It uses:

```text
R11,L4
lvcs_ncols = 84
nleaves    = 5760
ell        = 16
eta        = 41
ell'       = 2
theta      = 3
rho        = 2
kappa      = {10,0,0,6}
ncols      = 16
mu_pack    = 2
```

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

Removed V11/V14/V15/V16/V17/V19 public labels are invalid rather than aliases.
