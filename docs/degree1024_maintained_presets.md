# Degree-1024 Maintained IntGenISIS Presets

Run date: 2026-05-31

This note records the curated degree-1024 IntGenISIS preset surface. The
primary transcript metric is `showing.paper_transcript_bytes`; this is the
paper-facing byte count, not JSON proof size and not KiB. The proof-size
accounting includes the live `R` polynomials, so these proof-byte numbers should
not be compared against older undercounted proof bytes.

## Maintained Presets

| Preset | Paper name | Status | Target | Live theorem bits | Observed showing paper bytes | Gate |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `n1024-compact96` | `N1024-96` | maintained | 96 | 96.02 | 25,678 | `<27,500`, `>=96` |
| `n1024-compact125` | `N1024-125` | maintained low-grind frontier | 125+ | 125.17 | 34,457 | `<35,000`, `>=125` |

The public registry intentionally contains only the compact maintained names.
Removed selectors are invalid rather than aliases. The high preset is a 125+
live preset, not a 128-bit claim. Maintained issuance and showing both use
`smallfield_2025_1085_v1` by default; `-issuance-transcript-mode baseline`
remains available only for comparison.

## Fresh E2E Snapshot

Measurements below come from JSON-backed `benchmark-intgenisis-e2e` runs on
2026-05-31 with `GOMAXPROCS=16`. The benchmark exercises both issuance and
showing. NTRU setup includes randomized annulus key-generation retries when
they occur; the proof-system timing columns are the stable comparison target.

| Preset | NTRU setup ms | Issuance prove ms | Issuance verify ms | Issuer verify+sign ms | Showing prove ms | Showing verify ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `n1024-compact96` | 3,047.23 | 521.04 | 152.80 | 1,041.17 | 1,419.86 | 221.76 |
| `n1024-compact125` | 2,853.60 | 1,410.21 | 560.22 | 1,186.62 | 3,001.57 | 610.77 |

Showing prover phase timings from the same measurements:

| Preset | LVCS commit ms | `decs.eval_hash` ms | `decs.merkle` ms | Constraints ms | PRF full ms | Projected sig ms | Transform cache ms | Y-linear plan ms | Q/masks ms | Rows ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `n1024-compact96` | 561.13 | 508.72 | 18.14 | 289.37 | 24.14 | 176.54 | 116.35 | 63.95 | 163.69 | 104.90 |
| `n1024-compact125` | 1,505.96 | 1,377.40 | 59.76 | 315.76 | 24.95 | 193.45 | 133.88 | 65.35 | 277.30 | 104.92 |

The maintained showing path now uses `direct_full` PRF companion constraints.
The added full-PRF constraint phase is small relative to DECS/LVCS commitment:
about `24.14 ms` for `n1024-compact96` and `24.95 ms` for
`n1024-compact125`. `RunMaskFS.PRFCompanionOpenings` is `0.00 ms` because
`direct_full` proves the relation inside the main SmallWood constraint system
instead of emitting sampled scalar audit openings.

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
prf=direct_full, group_rounds=2, checkpoint_samples=1
artifact_dir=/tmp/spruce-opt-e2e-96.BwhF0u
report=/tmp/spruce-opt-e2e-96.BwhF0u/report.json
```

Fresh live issuance snapshot:

```text
q=1017857
paper_transcript_bytes=14052
proof_size_bytes=15100
prove_ms=521.04
verify_ms=152.80
theorem_total_bits=96.46
rows=165
rows_block=4
dQ=145
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=1784/4291/2507/0/1780/0/2698/448
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=25678
proof_size_bytes=28313
prove_ms=1419.86
verify_ms=221.76
theorem_total_bits=96.02
rows=471
rows_block=11
dQ=373
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4628/4291/6864/0/1831/0/6460/1060
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
prf=direct_full, group_rounds=2, checkpoint_samples=1
artifact_dir=/tmp/spruce-opt-e2e-125.6YXSif
report=/tmp/spruce-opt-e2e-125.6YXSif/report.json
```

Fresh live issuance snapshot:

```text
q=1017857
paper_transcript_bytes=19220
proof_size_bytes=20707
prove_ms=1410.21
verify_ms=560.22
theorem_total_bits=125.19
rows=165
rows_block=4
dQ=151
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=2602/5509/3357/0/2375/0/4035/798
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=34457
proof_size_bytes=37537
prove_ms=3001.57
verify_ms=610.77
theorem_total_bits=125.17
rows=407
rows_block=9
dQ=471
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=8190/5509/8059/0/2510/0/8060/1585
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

## Sanity Checks

- `proof_size_bytes` is greater than `paper_transcript_bytes` for all four
  issuance/showing measurements, as expected now that live `R` polynomials are
  included in proof-size accounting.
- Maintained issuance uses `smallfield_2025_1085_v1`. The serialized proof
  carries `QPayload`; `QRoot` is an all-zero compatibility field, while
  `QRBits` and `QOpening` are null.
- Showing now uses the maintained `direct_full` PRF companion relation. The
  projection selector and theorem-bit accounting remain consistent with the
  previous maintained runs, while the PRF companion proves the full
  `tag = PRF(k, nonce)` relation instead of the sampled output-audit predicate.

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

## Commands Run

```bash
go test ./...
```

```bash
GOMAXPROCS=16 go test ./PIOP -run '^$' \
  -bench 'BenchmarkDECSMaintainedShowingRowsN1024Compact(96|125)' \
  -benchmem
```

```bash
GOMAXPROCS=16 go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-compact96 \
  -artifact-dir /tmp/spruce-opt-e2e-96.BwhF0u \
  -json-out /tmp/spruce-opt-e2e-96.BwhF0u/report.json \
  -force
```

```bash
GOMAXPROCS=16 go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-compact125 \
  -artifact-dir /tmp/spruce-opt-e2e-125.6YXSif \
  -json-out /tmp/spruce-opt-e2e-125.6YXSif/report.json \
  -force
```

```bash
go test ./...
```
