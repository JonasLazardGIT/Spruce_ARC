# Degree-1024 Maintained IntGenISIS Presets

Run date: 2026-06-03

This note records the curated degree-1024 IntGenISIS preset surface. The
primary transcript metric is `showing.paper_transcript_bytes`; this is the
paper-facing byte count, not JSON proof size and not KiB. The proof-size
accounting includes the live `R` polynomials, so these proof-byte numbers should
not be compared against older undercounted proof bytes.

## Maintained Presets

| Preset | Paper name | Status | Target | Live theorem bits | Observed showing paper bytes | Gate |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `n1024-compact96` | `N1024-96` | maintained | 96 | 96.02 | 25,882 | `==25,882`, `>=96` |
| `n1024-compact125` | `N1024-125` | maintained low-grind fixed-size | 125+ | 125.17 | 34,853 | `==34,853`, `>=125` |

The public registry intentionally contains only the compact maintained names.
Removed selectors are invalid rather than aliases. The high preset is a 125+
live preset, not a 128-bit claim. Maintained issuance and showing both use
`smallfield_2025_1085_v1` and fixed-size DECS authentication.

## Fresh E2E Snapshot

Measurements below come from JSON-backed `benchmark-intgenisis-e2e` runs on
2026-06-03 with `GOMAXPROCS=16`. The benchmark exercises both issuance and
showing with maintained fixed-size transcript mode enabled. NTRU setup includes
randomized annulus key-generation retries when they occur; the proof-system
timing columns are the stable comparison target.

| Preset | NTRU setup ms | Issuance prove ms | Issuance verify ms | Issuer verify+sign ms | Showing prove ms | Showing verify ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `n1024-compact96` | 3,336.70 | 658.58 | 206.46 | 955.25 | 1,565.55 | 315.45 |
| `n1024-compact125` | 1,679.60 | 1,604.80 | 663.61 | 1,451.89 | 3,290.90 | 854.82 |

Showing prover phase timings from the same measurements:

| Preset | LVCS commit ms | `decs.eval_hash` ms | `decs.merkle` ms | Constraints ms | PRF full ms | Projected sig ms | Transform cache ms | Y-linear plan ms | Q/masks ms | Rows ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `n1024-compact96` | 611.69 | 543.08 | 21.89 | 320.62 | 26.93 | 188.68 | 126.36 | 80.24 | 172.68 | 111.08 |
| `n1024-compact125` | 1,627.78 | 1,447.21 | 62.67 | 333.99 | 27.79 | 185.67 | 123.68 | 82.67 | 283.71 | 106.55 |

The maintained showing path now uses `direct_full` PRF companion constraints.
The added full-PRF constraint phase is small relative to DECS/LVCS commitment:
about `26.93 ms` for `n1024-compact96` and `27.79 ms` for
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
fixed_transcript_size=true
artifact_dir=/tmp/spruce-fixed96-0y7xSd/artifacts-1
report=/tmp/spruce-fixed96-0y7xSd/run-1.json
```

Fresh live issuance snapshot:

```text
q=1017857
paper_transcript_bytes=14307
proof_size_bytes=15355
prove_ms=658.58
verify_ms=206.46
theorem_total_bits=96.46
rows=165
rows_block=4
dQ=145
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=1784/4291/2507/0/2035/0/2698/448
transcript_size_mode=fixed
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=25882
proof_size_bytes=28517
prove_ms=1565.55
verify_ms=315.45
theorem_total_bits=96.02
rows=471
rows_block=11
dQ=373
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4628/4291/6864/0/2035/0/6460/1060
transcript_size_mode=fixed
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
fixed_transcript_size=true
artifact_dir=/tmp/spruce-fixed125-0Uf3ZB/artifacts-1
report=/tmp/spruce-fixed125-0Uf3ZB/run-1.json
```

Fresh live issuance snapshot:

```text
q=1017857
paper_transcript_bytes=19751
proof_size_bytes=21238
prove_ms=1604.80
verify_ms=663.61
theorem_total_bits=125.19
rows=165
rows_block=4
dQ=151
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=2602/5509/3357/0/2906/0/4035/798
transcript_size_mode=fixed
transcript_security_status=smallwood_2025_1085_live
clamped={false,false,false,false}
```

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=34853
proof_size_bytes=37933
prove_ms=3290.90
verify_ms=854.82
theorem_total_bits=125.17
rows=407
rows_block=9
dQ=471
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=8190/5509/8059/0/2906/0/8060/1585
transcript_size_mode=fixed
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
- Maintained presets use fixed-size DECS authentication. Three
  repeated runs produced identical issuance/showing `paper_transcript_bytes`,
  `proof_size_bytes`, and `auth_bytes` for both degree-1024 presets.

## Live Gate

The preferred reviewer gate checks all maintained presets, including the
degree-512 compact profile:

```bash
go run ./cmd/issuance gate-maintained-presets -artifact-root "$(mktemp -d)"
```

The degree-1024-only gate remains available for the two entries in this note:

```bash
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root "$(mktemp -d)"
```

Gate conditions:

```text
n1024-compact96:
  showing.theorem_total_bits >= 96
  showing.paper_transcript_bytes == 25882
  showing.transcript_security_status == smallwood_2025_1085_live
  showing.clamped all false

n1024-compact125:
  showing.theorem_total_bits >= 125
  showing.paper_transcript_bytes == 34853
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
  -max-nleaves 0 \
  -artifact-dir /tmp/spruce-fixed96-0y7xSd/artifacts-1 \
  -json-out /tmp/spruce-fixed96-0y7xSd/run-1.json \
  -force
```

```bash
GOMAXPROCS=16 go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-compact125 \
  -max-nleaves 0 \
  -artifact-dir /tmp/spruce-fixed125-0Uf3ZB/artifacts-1 \
  -json-out /tmp/spruce-fixed125-0Uf3ZB/run-1.json \
  -force
```

```bash
go test ./...
```
