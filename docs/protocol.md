# Protocol Surface

The maintained showing relation is the direct shared-randomness `bb_tran`
relation:

```text
A*u = B0 + B1*mSigma + sum_i B2[i]*r0_i + Z
(B3 - r1) * Z = 1
```

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
nleaves    = 4096
eta        = 39
ell'       = 2
theta      = 3
rho        = 2
kappa      = {10,0,0,5}
ncols      = 16
```

It keeps one main row oracle and no auxiliary proof or sidecar root. The row
shape removes committed `TargetMR0Hat` rows and checks the target equation
inline from private carrier material:

```text
sum_c,l A_c[b,j] * R^l * d[c,b,l,j]
  = B0[b,j] + B1[b,j]*mSigma[j] + sum_i B2[i,b,j]*r0_i[j] + ZHat_b[j]
```

It still commits `RHat1` and `ZHat` rows and checks `(B3-r1)*Z=1` through the
existing SmallWood/PACS row constraints. It does not expose `u`, signature
digits, `T`, `THat`, `THatHeads`, `m`, `k`, `r0`, `r1`, or `Z`.

Removed V11/V14/V15/V16/V17/V19 public labels are invalid rather than aliases.
