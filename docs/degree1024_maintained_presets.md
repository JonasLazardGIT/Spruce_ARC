# Degree-1024 Maintained IntGenISIS Presets

Run date: 2026-05-29

This note records the curated degree-1024 IntGenISIS preset surface. The
primary transcript metric is `showing.paper_transcript_bytes`; this is the
paper-facing byte count, not JSON proof size and not KiB.

## Maintained Presets

| Preset | Status | Target | Live theorem bits | Observed showing paper bytes | Gate |
| --- | --- | ---: | ---: | ---: | --- |
| `n1024-compact96` | maintained | 96 | 96.02 | 25,577-25,661 | `<27,500`, `>=96` |
| `n1024-compact125` | maintained low-grind frontier | 125+ | 125.17 | 34,322-34,424 | `<35,000`, `>=125` |

The public registry intentionally contains only the compact maintained names.
Removed selectors are invalid rather than aliases. The high preset is a 125+
live preset, not a 128-bit claim.

## Latest E2E Timing Snapshot

Measurements from `benchmark-intgenisis-e2e` on 2026-05-29. The benchmark
exercises both issuance and showing. The degree-1024 rows retain the observed
range across the all-preset run and a gate rerun. The randomized auth bucket
moves the paper/proof byte totals slightly; theorem bits and row/degree
accounting stayed fixed.

| Preset | NTRU setup ms | Issuance prove ms | Issuance verify ms | Issuer verify+sign ms | Showing prove ms | Showing verify ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `n512-compact96` | 492.97 | 1,749.49 | 260.94 | 533.18 | 1,769.25 | 308.19 |
| `n1024-compact96` | 1,782.93-2,813.28 | 1,606.50-2,038.63 | 222.49-268.94 | 939.23-996.80 | 2,819.34-2,876.57 | 344.11-378.12 |
| `n1024-compact125` | 1,901.69-2,621.60 | 3,340.24-3,531.15 | 769.21-839.58 | 1,528.29-1,535.29 | 5,811.26-5,828.13 | 910.61-940.80 |

The full three-preset timing batch completed with coarse wrapper wall timings
of `5 s` for `n512-compact96`, `8 s` for `n1024-compact96`, and `15 s` for
`n1024-compact125`. NTRU setup includes Annulus keygen retry overhead when a
run triggers a retry, so it should not be read as the main protocol
optimization target.

Showing prover phase timings from the same measurements:

| Preset | LVCS commit ms | Constraints ms | Projected sig ms | Transform cache ms | Y-linear plan ms | Bounds ms | Q/masks ms | Rows ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `n512-compact96` | 954.79 | 287.40 | 79.83 | 60.55 | 138.96 | 63.19 | 93.91 | 86.70 |
| `n1024-compact96` | 1,043.04-1,059.36 | 1,067.80-1,080.53 | 557.60-579.45 | 485.98-504.46 | 380.50-387.90 | 104.81-106.12 | 163.29-166.69 | 168.29-172.98 |
| `n1024-compact125` | 3,182.18-3,221.34 | 1,133.74-1,166.49 | 544.82-555.33 | 473.10-479.31 | 390.18-405.95 | 182.98-188.52 | 272.31-274.20 | 102.14-168.73 |

Optimization priority from this run:

1. Showing LVCS commitment dominates `n1024-compact125` proving time
   (`3,182.18 ms`) and remains the largest single component for every preset.
2. The 1024-degree showing constraint path is the next priority. Inside it,
   `projected_signature`, `projected.transform_cache`, and `y_linear_plan`
   account for most of the measured cost.
3. `RunMaskFS.BuildQAndMasks` and bounds rows are visible but secondary.
   Row construction is no longer the main wall-time driver after the current
   optimizations.

## `n1024-compact96`

```text
N=1024, profile-C, B=1
ncols=32
lvcs=43
nleaves=230208
eta=40
theta=5 rho=1 ell'=1
ell=7
kappa={0,0,6,11}
shortness=R7/L5
compression=1
projection=project_u_digits_y_w_residual_v5
transcript_mode=smallfield_2025_1085_v1
prf=direct_auth, group_rounds=2, checkpoint_samples=1
```

Fresh live issuance snapshot:

```text
q=1017857
paper_transcript_bytes=16047-16082
proof_size_bytes=29445-29515
prove_ms=1606.50-2038.63
verify_ms=222.49-268.94
theorem_total_bits=96.46
rows=165
rows_block=4
dQ=145
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=1784/4291/5204/0/1982-2017/0/2160/360
transcript_security_status=baseline_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=25577-25661
proof_size_bytes=23266-23350
prove_ms=2819.34-2876.57
verify_ms=344.11-378.12
theorem_total_bits=96.02
rows=471
rows_block=11
dQ=373
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4628/4291/6864/0/1730-1814/0/6460/1060
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

## `n1024-compact125`

```text
N=1024, profile-C, B=1
ncols=32
lvcs=46
nleaves=608192
eta=48
theta=7 rho=1 ell'=1
ell=9
kappa={0,0,0,5}
shortness=R11/L4
compression=1
projection=project_u_digits_y_w_residual_v5
transcript_mode=smallfield_2025_1085_v1
prf=direct_auth, group_rounds=2, checkpoint_samples=1
```

Fresh live issuance snapshot:

```text
q=1017857
paper_transcript_bytes=21897-22136
proof_size_bytes=38741-39219
prove_ms=3340.24-3531.15
verify_ms=769.21-839.58
theorem_total_bits=125.19
rows=165
rows_block=4
dQ=151
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=2602/5509/7052/0/2590-2829/0/3230/640
transcript_security_status=baseline_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=34322-34424
proof_size_bytes=30856-30958
prove_ms=5811.26-5828.13
verify_ms=910.61-940.80
theorem_total_bits=125.17
rows=407
rows_block=9
dQ=471
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=8190/5509/8059/0/2375-2477/0/8060/1585
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

## Live Gate

```bash
go run ./cmd/issuance gate-degree1024-maintained-presets \
  -artifact-root "$(mktemp -d)"
```

Gate conditions:

```text
n1024-compact96:
  showing.theorem_total_bits >= 96
  showing.paper_transcript_bytes < 27500
  showing.transcript_security_status == smallwood_2025_1085_live
  showing.clamped all false

n1024-compact125:
  showing.theorem_total_bits >= 125
  showing.paper_transcript_bytes < 35000
  showing.transcript_security_status == smallwood_2025_1085_live
  showing.clamped all false
```

The q20 modulus moves packed `Pdecs`, `VTargets`, and `BarSets` onto a 20-bit
residue width. The maintained high preset deliberately spends about 34.4kB so
that each theorem-grinding point stays below six bits while keeping live
theorem accounting above 125 bits.

## Benchmark Commands

```bash
tmpdir="$(mktemp -d)"
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n512-compact96 \
  -artifact-dir "$tmpdir" \
  -json-out "$tmpdir/report.json" \
  -force
```

```bash
tmpdir="$(mktemp -d)"
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-compact96 \
  -artifact-dir "$tmpdir" \
  -json-out "$tmpdir/report.json" \
  -force
```

```bash
tmpdir="$(mktemp -d)"
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-compact125 \
  -artifact-dir "$tmpdir" \
  -json-out "$tmpdir/report.json" \
  -force
```
