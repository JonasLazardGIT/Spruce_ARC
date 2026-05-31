# Degree-1024 Maintained IntGenISIS Presets

Run date: 2026-05-30

This note records the curated degree-1024 IntGenISIS preset surface. The
primary transcript metric is `showing.paper_transcript_bytes`; this is the
paper-facing byte count, not JSON proof size and not KiB.

## Maintained Presets

| Preset | Status | Target | Live theorem bits | Observed showing paper bytes | Gate |
| --- | --- | ---: | ---: | ---: | --- |
| `n1024-compact96` | maintained | 96 | 96.02 | 25,539-25,610 | `<27,500`, `>=96` |
| `n1024-compact125` | maintained low-grind frontier | 125+ | 125.17 | 34,356-34,458 | `<35,000`, `>=125` |

The public registry intentionally contains only the compact maintained names.
Removed selectors are invalid rather than aliases. The high preset is a 125+
live preset, not a 128-bit claim.

## Latest E2E Timing Snapshot

Measurements from `benchmark-intgenisis-e2e` on 2026-05-30 after the
legacy-compatible proving optimizations. The benchmark exercises both issuance
and showing. The randomized auth bucket moves the paper/proof byte totals
slightly; theorem bits and row/degree accounting stayed fixed.

| Preset | NTRU setup ms | Issuance prove ms | Issuance verify ms | Issuer verify+sign ms | Showing prove ms | Showing verify ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `n512-compact96` | 492.97 | 1,749.49 | 260.94 | 533.18 | 1,769.25 | 308.19 |
| `n1024-compact96` | 2,839.55 | 1,141.75 | 231.67 | 942.42 | 1,935.23 | 320.28 |
| `n1024-compact125` | 3,031.52 | 2,599.23 | 782.15 | 1,501.93 | 3,987.52 | 877.75 |

`n512-compact96` was not rerun in this pass. NTRU setup includes Annulus keygen
retry overhead when a run triggers a retry, so it should not be read as the
main protocol optimization target.

Showing prover phase timings from the same measurements:

| Preset | LVCS commit ms | Constraints ms | Projected sig ms | Transform cache ms | Y-linear plan ms | Bounds ms | Q/masks ms | Rows ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `n512-compact96` | 954.79 | 287.40 | 79.83 | 60.55 | 138.96 | 63.19 | 93.91 | 86.70 |
| `n1024-compact96` | 762.91 | 395.77 | 192.95 | 121.35 | 80.42 | 105.38 | 162.84 | 171.90 |
| `n1024-compact125` | 2,051.17 | 482.97 | 199.12 | 126.56 | 83.25 | 183.97 | 269.57 | 168.65 |

Optimization priority from this run:

1. The main win in this pass is using the actual LVCS committed-row degree for
   the row commitment while keeping the paper-conservative `MaskDegreeBound`
   and `QDegreeBound` metadata. This cuts the high-preset LVCS commit from
   about `3.2 s` to about `2.05 s`.
2. Showing LVCS commitment still dominates `n1024-compact125`. The exposed
   DECS wall split is `decs.eval_hash=1,849.81 ms`, `decs.merkle=65.84 ms`,
   with interpolation and row NTT below `20 ms` combined.
3. The next visible costs are `RunMaskFS.BuildQAndMasks`, bounds rows, and the
   projected-signature constraint path. These are now secondary to DECS formal
   evaluation.

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
paper_transcript_bytes=16099
proof_size_bytes=29549
prove_ms=1141.75
verify_ms=231.67
theorem_total_bits=96.46
rows=165
rows_block=4
dQ=145
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=1784/4291/5204/0/2034/0/2160/360
transcript_security_status=baseline_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=25539
proof_size_bytes=23228
prove_ms=1935.23
verify_ms=320.28
theorem_total_bits=96.02
rows=471
rows_block=11
dQ=373
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4628/4291/6864/0/1692/0/6460/1060
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
paper_transcript_bytes=22119
proof_size_bytes=39185
prove_ms=2599.23
verify_ms=782.15
theorem_total_bits=125.19
rows=165
rows_block=4
dQ=151
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=2602/5509/7052/0/2812/0/3230/640
transcript_security_status=baseline_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=34356
proof_size_bytes=30890
prove_ms=3987.52
verify_ms=877.75
theorem_total_bits=125.17
rows=407
rows_block=9
dQ=471
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=8190/5509/8059/0/2409/0/8060/1585
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
