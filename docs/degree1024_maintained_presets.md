# Degree-1024 Maintained IntGenISIS Presets

Run date: 2026-05-29

This note records the curated degree-1024 IntGenISIS preset surface. The
primary transcript metric is `showing.paper_transcript_bytes`; this is the
paper-facing byte count, not JSON proof size and not KiB.

## Maintained Presets

| Preset | Status | Target | Live theorem bits | Showing paper bytes | Gate |
| --- | --- | ---: | ---: | ---: | --- |
| `n1024-compact96` | maintained | 96 | 96.02 | 25,661 | `<27,500`, `>=96` |
| `n1024-compact125` | maintained low-grind frontier | 125+ | 125.17 | 34,390 | `<35,000`, `>=125` |

The public registry intentionally contains only the compact maintained names.
Removed selectors are invalid rather than aliases. The high preset is a 125+
live preset, not a 128-bit claim.

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

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=25661
proof_size_bytes=23350
theorem_total_bits=96.02
rows=471
rows_block=11
dQ=373
DDECS=49
committed_cols=43
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4628/4291/6864/0/1814/0/6460/1060
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

Fresh live showing snapshot:

```text
q=1017857
paper_transcript_bytes=34390
proof_size_bytes=30924
theorem_total_bits=125.17
rows=407
rows_block=9
dQ=471
DDECS=54
committed_cols=46
q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=8190/5509/8059/0/2443/0/8060/1585
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
