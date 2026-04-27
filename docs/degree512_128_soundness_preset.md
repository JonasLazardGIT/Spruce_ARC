# Degree-512 128-Bit Soundness Research Preset

Status: historical retuning note. The maintained x0_len=70 128-bit profile is
now `showing_n512_x0len70_128`; current measured values are recorded in
[`current_showing_defaults.md`](current_showing_defaults.md). The older manual
soundness-preset surface is removed from the maintained CLI.

This note records the 128-bit soundness retuning for the opt-in degree-512 V18
research path. It is based on the SmallWood paper in `docs/2025-1085.pdf`,
specifically the Eq. (8) round errors and Theorem 9 ROM aggregation.

The preset does not change the default V18 path. It remains an unsafe research
mode because degree-512 lattice assumptions and the statement fork still require
external review.

## SmallWood Soundness Mapping

SmallWood-ARK uses four round errors before Fiat-Shamir grinding:

```text
eps1 = C(N, ddecs + 2) / |F|^eta
eps2 = 1 / |F|^rho
eps3 = C(dQ, ell_prime) / C(|S|, ell_prime)
eps4 = C(ncols + ell - 1, ell) / C(N, ell)
```

The repository's small-field branch evaluates the PACS sampling terms over the
extension field `K/F_q` of degree `theta`, so the effective field size for
rounds 2 and 3 is `q^theta`. The code reports the theorem-level aggregation
from Theorem 9:

```text
collision + Q1*eps1/2^kappa1 + Q2*eps2/2^kappa2
          + Q3*eps3/2^kappa3 + Q4*eps4/2^kappa4
```

Current reports use `Q0=...=Q4=1` and a collision term near 510 bits, so the
four theorem terms dominate.

## Why The 100-Bit Tuple Cannot Scale Directly

The 100-bit degree-512 tuple uses:

```text
theta=3 rho=2 ell_prime=2 eta=38 nleaves=4992 lvcs_ncols=73
```

Its round-2 raw term is approximately:

```text
theta * rho * log2(q) = 3 * 2 * log2(1054721) = 120.05 bits
```

With a grinding cap of `kappa_i <= 5`, round 2 can reach only about 125 bits.
Therefore a 128-bit profile needs a larger `theta*rho` product; increasing only
`eta` or `nleaves` cannot fix this.

## Chosen Shape

The compact 128-bit shape is:

```text
ring_degree = 512
lvcs_ncols  = 73
nleaves     = 16640
eta         = 47
theta       = 7
rho         = 1
ell_prime   = 1
kappa       = {0,0,2,5}
signature   = R=11, L=4
```

Current maintained command:

```bash
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
```

Representative measured report:

```text
Paper transcript ~= 35852 bytes
round={137.73,140.06,133.58,128.09}
total=128.06
dQ=356
```

Geometry:

```text
blocks=32 lvcs=73 nleaves=16640 rowsBlock=5 maskChunks=5
witness=362 nrows=150 m=35 pcols=115 omitP=35
sig=256 mask=35
```

Stable bucket focus:

```text
Pdecs=9698 VTargets=6717 BarSets=1480 Q=6198 SigShortness=39
```

## Parameter Rationale

`theta=7, rho=1, ell_prime=1` is the smallest measured extension/query family
that clears the 128-bit floor while keeping the query surface compact:

- `theta=6, rho=1` cannot clear round 2 with `kappa2 <= 5`.
- `theta=7, rho=1` gives round 2 about 140 raw bits without using grinding.
- `ell_prime=1` is viable only because `theta=7` also lifts round 3 above 128.
- `rho=1` halves the mask/Q pressure compared with `rho=2`.
- `lvcs_ncols=73` keeps the same `rowsBlock=5` geometry; `72` crosses to
  `rowsBlock=6` and is larger.
- `kappa4=5` is used to keep `nleaves` low.
- `kappa3=2` lets `nleaves=16640` clear the theorem aggregation; without it the
  closest clean no-round-3-grinding point is `nleaves=16704`.

## Alternatives Measured

All rows below use `ring_degree=512`, `lvcs_ncols=73`, `eta=47`,
`nleaves=16832`, and `kappa={0,0,0,5}` unless noted.

| Shape | Transcript | Theorem bits | Notes |
| --- | ---: | ---: | --- |
| `theta=7 rho=1 ell_prime=1` | about `35.0k bytes` | `128.20` | Best family. |
| `theta=4 rho=2 ell_prime=2` | about `36.7k bytes` | `128.35` | More `Q` and `VTargets`. |
| `theta=5 rho=2 ell_prime=2` | about `41.3k bytes` | `128.35` | Larger `m`, mask, and `Q`. |
| `theta=8 rho=1 ell_prime=1` | about `38.3k bytes` | `128.35` | More `m`, `Pdecs`, and `Q`. |
| `theta=7 rho=1 ell_prime=1 lvcs=72` | about `38.5k bytes` | `128.47` | Better theorem terms but worse geometry. |

The tighter `nleaves` sweep around the chosen family found:

| `nleaves` | `kappa` | Theorem bits | Notes |
| ---: | --- | ---: | --- |
| 16576 | `{0,0,5,5}` | `128.00` | Too close to the floor. |
| 16640 | `{0,0,1,5}` | `128.03` | Passes, minimal extra grinding. |
| 16640 | `{0,0,2,5}` | `128.06` | Chosen for a small margin. |
| 16704 | `{0,0,0,5}` | `128.05` | Avoids round-3 grinding but uses more leaves. |

## CLI Surface

The maintained CLI exposes this target as:

```text
-showing-profile showing_n512_x0len70_128
```

Manual transcript/soundness sweeps should start from that profile and pass the
individual knob overrides explicitly.

## Production Status

This is not a production preset. It only raises the code-reported SmallWood
Theorem 9 accounting above 128 bits for the degree-512 research statement fork.
Production validity remains blocked on the degree-512 lattice/security review
and on agreement that the repository's small-field extension-field accounting
matches the intended deployment model.
