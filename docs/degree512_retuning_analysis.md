# Degree-512 V18 Retuning Analysis

Status: historical retuning note. The maintained x0_len=70 degree-512 profiles
are now `showing_n512_x0len70_100` and `showing_n512_x0len70_128`; current
measured values are recorded in
[`current_showing_defaults.md`](current_showing_defaults.md). Older measurements
in this note may refer to the prior x0_len=6 research artifact set.

This note studies transcript retuning for the current opt-in degree-512 V18
research path. It does not change the public/default V18 path and does not make
degree 512 production-ready. All security numbers below are the theorem bits
reported by the existing code for the measured proof run; the external lattice
assumptions for `N=512` remain a separate blocker.

## Measurement Setup

Baseline command:

```bash
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
```

Unless stated otherwise, the relation keeps the current degree-512 research
statement fork:

- `ring_degree=512`
- `blocks=32`
- `mu_pack=2`
- `mu_rows=16`
- `RHat1=32`, `ZHat=32`
- packed signature rows `256`
- no public private witness digits
- no `T/THat/THatHeads`, no `TargetMR0Hat`, no hidden proof, no sidecar root

The optimized paper transcript byte total has small run-to-run movement because
some opened/authenticated material is sampled by the proof transcript. The
stable comparison points are the geometry, theorem rounds, and major buckets
such as `Pdecs`, `R`, `VTargets`, and `Q`.

## Current Degree-512 Baseline

Representative measured baseline:

| Field | Value |
| --- | ---: |
| `lvcs_ncols` | 84 |
| `nleaves` | 5760 |
| `eta` | 41 |
| `theta` | 3 |
| `rho` | 2 |
| `ell_prime` | 2 |
| `kappa` | `{10,0,0,6}` |
| `witness` | 362 |
| `nrows` | 125 |
| `m` | 30 |
| `pcols` | 95 |
| `dQ` | 356 |
| theorem bits | `100.27` |
| paper transcript | about `32.4k bytes` |

Representative bucket breakdown:

| Bucket | Bytes |
| --- | ---: |
| `R` | 8614 |
| `Pdecs` | 8013 |
| `VTargets` | 6625 |
| `Q` | 5298 |
| `Auth` | about 2280 |
| `BarSets` | about 1210-1270 |
| `SigShortness` | 39 |

The baseline is just over the 100-bit theorem floor. The tight terms are round 1
and round 4:

```text
round={101.36,120.05,103.10,101.62} total=100.27
```

## Useful Retuning Direction

### 1. Lower LVCS width to the geometry boundary

`lvcs_ncols=73` is the strongest safe width reduction seen in the current
degree-512 model. It keeps the same main geometry:

```text
rowsBlock=5 maskChunks=5 witness=362 nrows=125 m=30 pcols=95 mask=30
```

Representative result:

| Setting | Paper transcript | Theorem bits | Rounds |
| --- | ---: | ---: | --- |
| baseline | about `32.4k bytes` | `100.27` | `{101.36,120.05,103.10,101.62}` |
| `-lvcs-ncols 73` | about `30.5k bytes` | `102.66` | `{166.08,120.05,103.10,104.58}` |

The stable bucket changes are:

| Bucket | Baseline | `lvcs=73` | Delta |
| --- | ---: | ---: | ---: |
| `R` | about 8614 | about 7486 | about `-1128` |
| `VTargets` | 6625 | 5759 | `-866` |
| `Pdecs` | 8013 | 8013 | 0 |
| `Q` | 5298 | 5298 | 0 |

Do not push below `73` without changing the layout. At `lvcs_ncols=72`, the
geometry crosses a boundary:

```text
rowsBlock=6 nrows=144 m=36 pcols=108
Pdecs=9111 VTargets=6814 BarSets=1522
paper transcript~32.7k bytes
```

So `72` and nearby lower widths lose the transcript win even though the nominal
column count is smaller.

### 2. Retune `eta` after lowering LVCS

At the default `lvcs=84`, lowering `eta` was unsafe. After moving to
`lvcs=73`, round 1 has enough margin to reduce `eta`.

Representative results at `lvcs=73`, `nleaves=5760`:

| `eta` | Paper transcript | Theorem bits | Round bits |
| ---: | ---: | ---: | --- |
| 41 | about `30.5k bytes` | `102.66` | `{166.08,120.05,103.10,104.58}` |
| 40 | about `30.4k bytes` | `102.66` | `{146.08,120.05,103.10,104.58}` |
| 39 | about `30.2k bytes` | `102.66` | `{126.07,120.05,103.10,104.58}` |
| 38 | about `30.0k bytes` | `102.53` | `{106.06,120.05,103.10,104.58}` |
| 37 | about `29.7k bytes` | `86.05` | `{86.05,120.05,103.10,104.58}` |

`eta=38` is the lowest safe value at the original `nleaves=5760`. `eta=37`
can be made safe only when paired with a smaller `nleaves`, because smaller
`nleaves` improves round 1 but weakens round 4.

### 3. Retune `nleaves` as a round-1/round-4 balance

At `lvcs=73`, default `eta=41`, and default `kappa={10,0,0,6}`, the domain can
be reduced until about `4800` leaves before the theorem floor becomes too thin:

| `nleaves` | Theorem bits | Round bits |
| ---: | ---: | --- |
| 5120 | `101.35` | `{181.50,120.05,103.10,101.86}` |
| 4992 | `100.92` | `{184.82,120.05,103.10,101.28}` |
| 4864 | `100.43` | `{188.22,120.05,103.10,100.67}` |
| 4800 | `100.17` | `{189.96,120.05,103.10,100.37}` |
| 4736 | `99.89` | `{191.72,120.05,103.10,100.06}` |

`4800` is technically above 100 in the report but leaves little margin.
`4992` is a better default candidate if we want a stable 100-bit research
profile without adding more grinding.

### 4. Combine `eta`, `nleaves`, and kappa

The best measured candidates keep `theta=3`, `rho=2`, and `ell_prime=2`.

| Candidate | Command tail | Paper transcript | Theorem bits | Rounds | Notes |
| --- | --- | ---: | ---: | --- | --- |
| Conservative | `-lvcs-ncols 73 -eta 38 -nleaves 4992 -kappa1 0 -kappa2 0 -kappa3 0 -kappa4 6` | about `29.8k bytes` | `100.92` | `{114.80,120.05,103.10,101.28}` | Removes round-1 grinding, keeps comfortable round-1 margin. |
| Transcript-forward | `-lvcs-ncols 73 -eta 37 -nleaves 4992 -kappa1 8 -kappa2 0 -kappa3 0 -kappa4 6` | about `29.6k bytes` | `100.57` | `{102.79,120.05,103.10,101.28}` | Best practical transcript candidate seen; narrower margin. |
| Extra-grind | `-lvcs-ncols 73 -eta 37 -nleaves 4608 -kappa1 7 -kappa2 0 -kappa3 0 -kappa4 8` | about `29.6-29.7k bytes` | `101.03` | `{112.28,120.05,103.10,101.42}` | More round-4 grinding; no clear byte win in current samples. |

The conservative candidate is the safer next research profile because it lowers
the transcript by roughly `2.6k bytes` versus the current degree-512 baseline and
also removes the expensive round-1 grinding. The transcript-forward candidate
saves a little more, but it relies on a narrower round-1/round-4 balance.

## Unsafe Or Low-Value Directions

### Lowering `theta`

At `lvcs=73`:

```text
-theta 2
paper transcript~26.1k bytes
round={166.08,80.03,63.09,104.58}
total=63.09
```

This is a large byte reduction, but it would require about 37-40 additional
round-2/round-3 grinding bits to recover a 100-bit theorem floor. That is not a
practical live proving profile.

### Lowering `rho`

At `lvcs=73`:

```text
-rho 1
paper transcript~26.6k bytes
round={166.08,60.03,103.10,104.58}
total=60.03
```

The byte reduction is mostly from `Q` and mask rows, but the round-2 loss is too
large. Recovering it through grinding is not practical.

### Lowering `ell_prime`

At `lvcs=73`:

```text
-ell-prime 1
paper transcript~28.2k bytes
round={166.08,120.05,51.55,104.58}
total=51.55
```

The `VTargets` and `BarSets` shrink, but round 3 collapses. This should not be
used for a 100-bit profile.

### Lowering PRF checkpoint samples

In the current degree-512 fixture, changing `-prf-checkpoint-samples` from 8 to
6 or 4 did not change the stable replay selection:

```text
selected=35/362 rows activeBlocks=2/20 selectedFamilies=carrier, prf_companion
```

The measured byte total moved within normal sample variance. This knob should
not be counted as a transcript reduction unless the PRF audit model is updated
and the selected rows actually change deterministically.

### Alternate signature shortness profile

The current CLI cannot directly test `r24_l3_compact` on the optimized V18
packed-mu path; the override resolves to a custom path and is rejected by the
packed mu witness checks. Evaluating an alternate shortness profile would be a
protocol/code change, not a simple retuning.

## Recommended Next Step

For an opt-in degree-512 research retuned profile, use the conservative
candidate first:

```bash
go run ./cmd/showing \
  -showing-profile showing_n512_x0len70_100 \
  -lvcs-ncols 73 \
  -eta 38 \
  -nleaves 4992 \
  -kappa1 0 -kappa2 0 -kappa3 0 -kappa4 6
```

Measured result:

```text
paper transcript~29.8k bytes
round={114.80,120.05,103.10,101.28}
total=100.92
dQ=356
```

If a smaller transcript is worth the narrower theorem margin, the
transcript-forward candidate is:

```bash
go run ./cmd/showing \
  -showing-profile showing_n512_x0len70_100 \
  -lvcs-ncols 73 \
  -eta 37 \
  -nleaves 4992 \
  -kappa1 8 -kappa2 0 -kappa3 0 -kappa4 6
```

Measured result:

```text
paper transcript~29.6k bytes
round={102.79,120.05,103.10,101.28}
total=100.57
dQ=356
```

Before promoting either candidate beyond manual flags, add deterministic
reporting or fixed-salt benchmarking so the optimized byte totals are stable in
CI, then add tests that assert `ring_degree=512`, the retuned parameters, proof
verification, and `total_bits >= 100`.
