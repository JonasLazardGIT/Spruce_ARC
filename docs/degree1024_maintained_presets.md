# Degree-1024 Maintained IntGenISIS Presets

Run date: 2026-05-31

This note records the curated degree-1024 IntGenISIS preset surface. The
primary transcript metric is `showing.paper_transcript_bytes`; this is the
paper-facing byte count, not JSON proof size and not KiB.

## Maintained Presets

| Preset | Status | Target | Live theorem bits | Observed showing paper bytes | Gate |
| --- | --- | ---: | ---: | ---: | --- |
| `n1024-compact96` | maintained | 96 | 96.02 | 25,539-25,610 | `<27,500`, `>=96` |
| `n1024-compact125` | maintained low-grind frontier | 125+ | 125.17 | 34,356-34,508 | `<35,000`, `>=125` |

The public registry intentionally contains only the compact maintained names.
Removed selectors are invalid rather than aliases. The high preset is a 125+
live preset, not a 128-bit claim.

## Latest E2E Timing Snapshot

Measurements from `benchmark-intgenisis-e2e` on 2026-05-31 after the
legacy-compatible bounded-degree DECS formal-evaluation optimization. The
benchmark exercises both issuance and showing. The randomized auth bucket moves
the paper/proof byte totals slightly; theorem bits and row/degree accounting
stayed fixed.

| Preset | NTRU setup ms | Issuance prove ms | Issuance verify ms | Issuer verify+sign ms | Showing prove ms | Showing verify ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `n512-compact96` | 492.97 | 1,749.49 | 260.94 | 533.18 | 1,769.25 | 308.19 |
| `n1024-compact96` | 1,805.72 | 1,217.83 | 215.67 | 902.97 | 1,669.19 | 289.16 |
| `n1024-compact125` | 3,960.63 | 2,178.05 | 727.74 | 1,469.65 | 3,411.76 | 794.38 |

`n512-compact96` was not rerun in this pass. NTRU setup includes Annulus keygen
retry overhead when a run triggers a retry, so it should not be read as the
main protocol optimization target.

Showing prover phase timings from the same measurements:

| Preset | LVCS commit ms | Constraints ms | Projected sig ms | Transform cache ms | Y-linear plan ms | Bounds ms | Q/masks ms | Rows ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `n512-compact96` | 954.79 | 287.40 | 79.83 | 60.55 | 138.96 | 63.19 | 93.91 | 86.70 |
| `n1024-compact96` | 588.22 | 401.70 | 203.71 | 131.25 | 76.90 | 105.40 | 162.01 | 169.72 |
| `n1024-compact125` | 1,593.56 | 473.21 | 196.37 | 127.52 | 78.69 | 182.51 | 268.40 | 166.91 |

Optimization priority from this run:

1. The main win in this pass is the bounded-degree dense DECS formal evaluator
   for the maintained showing row matrices. It keeps the legacy leaf/tree
   encoding unchanged and cuts the high-preset showing prove time from about
   `3.99 s` to about `3.41 s`.
2. Showing LVCS commitment still dominates `n1024-compact125`. The exposed
   DECS wall split is now `decs.eval_hash=1,427.68 ms`, `decs.merkle=63.85 ms`,
   with interpolation and row NTT below `20 ms` combined.
3. The next visible one-shot costs are `RunMaskFS.BuildQAndMasks`, bounds rows,
   and the projected-signature constraint path. Prepared showing contexts now
   provide a path to reuse Y-linear and projected-transform public planning for
   repeated showings.

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
paper_transcript_bytes=16133
proof_size_bytes=29616
prove_ms=1217.83
verify_ms=215.67
theorem_total_bits=96.46
rows=165
rows_block=4
dQ=145
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=1784/4291/5204/0/2068/0/2160/360
transcript_security_status=baseline_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=25610
proof_size_bytes=23299
prove_ms=1669.19
verify_ms=289.16
theorem_total_bits=96.02
rows=471
rows_block=11
dQ=373
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4628/4291/6864/0/1763/0/6460/1060
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
paper_transcript_bytes=22084
proof_size_bytes=39115
prove_ms=2178.05
verify_ms=727.74
theorem_total_bits=125.19
rows=165
rows_block=4
dQ=151
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=2602/5509/7052/0/2777/0/3230/640
transcript_security_status=baseline_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=34356
proof_size_bytes=30890
prove_ms=3411.76
verify_ms=794.38
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
