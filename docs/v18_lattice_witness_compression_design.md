# V18 Packed Signature Shortness Compression Design

This note designs the application of the lattice-witness compression idea from
2025-1085 to the optimized Spruce showing profile:

```text
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

The original target was the 512 private signature shortness rows in the current
V18 inline-target replay-compact proof. After the full-capacity `mu` rewrite,
the same note also records the implemented packed-`mu` carrier result. The
conclusion is deliberately split:

1. p=2 ternary packing is a live transcript reduction for full-capacity `mu`.
2. The direct 2025-1085 polynomial compression for signature shortness is sound
   in the current PACS
   engine, but it is not a transcript reduction because it raises the global
   `dQ`.
3. A size-reducing packed-shortness version needs a new low-degree fixed-table
   lookup backend
   for packed shortness rows. That backend can preserve the one-root public
   surface if it is implemented against the existing committed row root.

No old public research preset string is required. If this design is promoted,
the optimized relation should point at a new internal proof payload while
removed research surfaces stay invalid.

## Current V18 Shape

Current measured optimized profile after the `ell=16`, `eta=41`,
`nleaves=5760`, packed full-`mu` update:

```text
paper transcript = 43163 bytes
verifier payload = 71740 bytes
theorem bits     = 100.27
dQ               = 356
mu_pack          = 2
mu carrier rows  = 32
mu virtual blocks= 64
sig rows         = 512
witness rows     = 698
committed rows   = 171 witness + 30 mask
LVCS blocks      = 9
m                = 54
```

Dominant buckets:

```text
Pdecs     12418 bytes
VTargets  11917 bytes
R          8614 bytes
Q          5298 bytes
Auth       2333 bytes
BarSets    2278 bytes
```

The current code already builds one row per signed digit lane:

- `buildLiteralPackedPolyWitness` decomposes each signature coefficient into
  `spec.L` signed digits and materializes `SigLimbs`
  (`PIOP/showing_coeff_native_literal_packed_runtime.go`).
- The V18 row builder appends `spec.L` shortness rows for every
  `(component, block)` group.
- `buildSigShortnessPackedMembershipFormalCoeffs` then enforces digit
  membership and recomposition with the current low-degree digit polynomials.

For the live profile, `R=11`, `L=4`, and each digit belongs to
`D={-5,...,5}`. With 2 signature components and 64 blocks, the shortness rows
are:

```text
2 components * 64 blocks * 4 digit rows = 512 rows
```

## Direct 2025-1085 Compression

The paper's lattice-witness compression packs `p` small values from an alphabet
of size `alpha` into one field element. Soundness is obtained by proving that
the packed element lies in a fixed set `S` of size `alpha^p`, and by using
polynomial decompression maps. In plain PACS this means:

```text
membership degree      = alpha^p
decompression degree   = alpha^p - 1
```

For Spruce shortness, `alpha=11`. Since `q=1054721`, at most 5 radix-11 digits
fit injectively in one base-field element (`11^5 < q < 11^6`), but the degree
cost becomes prohibitive well before `p=5`.

The natural adjacent-pair packing is:

```text
y0 = d0 + 11*d1 in [-60,60]
y1 = d2 + 11*d3 in [-60,60]
sig = y0 + 121*y1
```

This halves the row count from 512 to 256, but the membership polynomial for
`[-60,60]` has degree 121. The equivalent tighter balanced form is close to
the existing `R=111,L=2` shape:

```text
sig = e0 + 111*e1
e0,e1 in [-55,55]
degree = 111
capacity = 6160 >= beta=6142
```

That is sound as a bounded-signature statement, but in the current one-Q PACS
engine it raises the global Q degree. The code computes:

```text
dQ = max(d*(ell+s-1)+s-1, d'*(ell+s-1))
```

With `s=16` and `ell=16`, this is `dQ = 31*d + 15` for the shortness degree
dominating.

Cost table under the current `rho=2`, `theta=3`, `ell'=2`,
`lvcs_ncols=84` accounting:

```text
degree  rows/group  dQ     Q bytes  mask chunks  mask rows
11      4           356     5298     5            30
24      3           759    11345    10            60
111     2          3456    51817    42           252
121     2          3766    56469    45           270
1331    <=2       41276   619356   492          2952
```

So the direct paper construction is not a valid transcript-reduction candidate
for this backend. It saves witness rows, but it makes `Q` and mask rows much
larger. The degree tax dominates.

## Viable Variant: Low-Degree Packed-Shortness Lookup

The only viable application is to keep the row compression but remove the
high-degree membership polynomial from the main PACS relation. That requires a
new fixed-table lookup backend bound to the same committed row root.

Recommended packed relation:

```text
For each signature component c, block b, column j:

  witness rows:
    E0[c,b,j], E1[c,b,j]

  public fixed table:
    T111 = {-55, -54, ..., 55}

  lookup claims:
    E0[c,b,j] in T111
    E1[c,b,j] in T111

  linear recomposition:
    Sig[c,b,j] = E0[c,b,j] + 111*E1[c,b,j]
```

This uses 2 rows per `(component, block)` instead of 4:

```text
2 components * 64 blocks * 2 rows = 256 rows
```

The main PACS shortness degree stays linear if lookup membership is handled by
the lookup backend rather than by `prod_{t in T111}(X-t)`.

### Why R111/L2

`R=111,L=2` is preferable to raw radix-11 pair packing for this backend:

- It has a smaller table: 111 values instead of 121.
- It proves `|sig_i| <= 6160`, which covers `beta=6142`.
- It only needs the same linear reconstruction form already used by
  `LinfSpec`.
- It avoids decompression maps entirely: no public digits, no `Dec_j(y)` rows,
  and no high-degree interpolation polynomials.

The proof statement changes from:

```text
sig_i = d0 + 11*d1 + 11^2*d2 + 11^3*d3,
d_k in [-5,5]
```

to:

```text
sig_i = e0 + 111*e1,
e_k in [-55,55]
```

This remains a valid signature-shortness statement because the implied bound
`6160` still covers the live signature bound `beta=6142`. It is slightly
different from the current digit language, so it must be versioned and bound
into the transcript digest.

## Expected Bucket Movement

If lookup membership adds zero bytes, the row geometry moves approximately:

```text
witness rows: 668 -> 412
LVCS blocks:  8   -> 5
m:            48  -> 30
```

A measured proxy with the same 5-block row-opening geometry had:

```text
Pdecs     8013 bytes  vs current 11314  save 3301
VTargets  6625 bytes  vs current 10594  save 3969
BarSets   1270 bytes  vs current  2026  save  756
```

Ideal gross saving before lookup proof cost is therefore about:

```text
3301 + 3969 + 756 = 8026 bytes
```

That gives a practical budget:

```text
lookup proof < 8000 bytes: beats current optimized profile
lookup proof < 3000 bytes: moves profile near 35.8 KB
lookup proof < 1000 bytes: moves profile near 33.8 KB
```

If the lookup backend cannot stay below roughly 8 KB, this path is not worth
promoting.

## Backend Requirements

The lookup backend must prove fixed-table membership for committed row entries
without revealing entries and without adding an auxiliary public digit surface.

Required properties:

1. Same root binding: lookup witness rows are rows in the main one-root LVCS
   commitment.
2. Fixed public table: `T111 = {-55,...,55}` is transcript-bound by a digest.
3. Zero knowledge: lookup transcript must reveal no packed digit values beyond
   membership in the fixed table and the already-proven linear relation.
4. Soundness: a verifier accepting implies every opened committed row entry
   used as `E0` or `E1` is in `T111`, except with the backend's stated error.
5. Degree isolation: the main PACS `dQ` must not include degree 111. If it
   does, the construction is size-negative.

This is a new proof backend. It is not just a new accounting rule.

## Packed Full-`mu` Carrier Update

After the full-capacity `mu` rewrite, the message/key payload is no longer a
small `(M1,M2)` head. It is one private ternary ring element with 1024 bounded
coefficients on the default/public path and layout
`full_capacity_halves_v1`. That makes `mu` the cleanest place where the
2025-1085 lattice-witness compression technique applies on the current backend.
The opt-in `N=512` mode keeps the same layout over a smaller ring and is a
research statement fork, not an equivalent public V18 statement.

The implemented optimized profile uses p=2 block-aligned ternary packing:

```text
code = (v0 + 1) + 3*(v1 + 1),  v0,v1 in {-1,0,1}

logical mu block 2r, column c     -> lane 0 of carrier row r, column c
logical mu block 2r+1, column c   -> lane 1 of carrier row r, column c
```

Geometry:

```text
64 logical mu blocks
32 packed carrier rows
0 explicit AliasMuBlockRows
64 virtual decoded blocks
```

The membership set has size `3^2 = 9`. The decode polynomials have degree
`<= 8`, which remains below the live shortness degree driver `11`; therefore
the optimized profile keeps `dQ=356`.

Current optimized measurement:

```text
paper transcript = 43163 bytes
verifier payload = 71740 bytes
dQ               = 356
theorem bits     = 100.27
selected rows    = 51
active blocks    = 3
mu_pack          = 2
```

Measured degree-512 research fork:

```text
paper transcript = 32526 bytes
verifier payload = 61187 bytes
dQ               = 356
theorem bits     = 100.27
selected rows    = 35
active blocks    = 2
mu_pack          = 2
mu_rows          = 16
sig rows         = 256
```

### Larger Ternary Packs

The current one-Q PACS backend makes larger direct polynomial packs
size-negative.

For p=3:

```text
membership size = 3^3 = 27
dQ              = 27*(ell+s-1)+s-1 = 852
```

This would reduce the `mu` carrier surface from 32 rows to 22 padded rows, but
the degree increase expands masks and the `Q` bucket enough that it is not
expected to beat p=2.

For p=4, the measured internal experiment was:

```text
mu_rows          = 16
paper transcript = 89007 bytes
verifier payload = 324983 bytes
dQ               = 2526
theorem bits     = 97.29
mask rows        = 186
Q bucket         = 37861 bytes
```

The p=4 path is sound only when high-degree formal residuals are retained
instead of reducing `D(C(X))` modulo `X^N+1`; otherwise verifier tail
evaluation no longer matches the prover's Q polynomial. This confirms that p=4
needs a degree-isolated lookup/compression backend to become useful.

Binary packing is not a direct replacement for ternary `mu`. Encoding each
ternary coefficient with bits wastes density and still needs constraints to
exclude invalid bit patterns. A genuinely binary `mu` could make p=3 cheap, but
that would change issuance semantics and PRF-key/message distribution rather
than just the proof representation.

## Implementation Plan

### Phase 0: Cost-Model Gate

Add an internal, non-public cost estimator before changing the prover:

- Extend `cmd/showing/benchmark_transcript_sweep.go` or add an internal helper
  to estimate packed-shortness row count, `dQ`, `maskChunks`, `m`, and paper
  bucket movement.
- Include both modes:
  - `direct_polynomial`: raises `dQ` to 3456 or 3766 and should be rejected.
  - `lookup_degree_isolated`: keeps `dQ=356` and adds a configurable lookup
    proof byte budget.

Acceptance for implementation:

```text
estimated paper bytes <= 38000 with lookup_budget=3000
theorem bits >= 100
no new public preset string
```

### Phase 1: Packed R111/L2 Rows

Files:

- `PIOP/signature_bounds.go`
- `PIOP/bound_spec.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/row_layout_coeff_native.go`
- `PIOP/witness_geometry.go`

Work:

- Add an internal packed-shortness mode selecting `R=111,L=2` only for the new
  lookup-backed proof.
- Generate `SigPackedLimbs[comp][block][0..1]` from centered signature
  coefficients.
- Materialize 256 packed rows instead of 512 digit rows.
- Add row layout fields only if existing `PackedSigChain*` fields cannot
  distinguish lookup-backed packed rows from current V18 rows.

Do not expose a new CLI preset. Test-only opts are acceptable; public command
surface remains unchanged.

### Phase 2: Main Linear Constraints

Files:

- `PIOP/signature_shortness_packed.go`
- `PIOP/showing_coeff_native_literal_packed_runtime.go`
- `PIOP/constraint_eval.go`

Work:

- Add a constraint builder for:

```text
Sig - E0 - 111*E1 = 0
```

- Do not compose the degree-111 membership polynomial into `FparNorm`.
- Return `ParallelAlgDeg=1` or leave the global degree dominated by the
  existing bb_tran/shortness constraints, so `dQ` remains 356.

### Phase 3: Lookup Proof Object

Files:

- `PIOP/run.go`
- `PIOP/sig_shortness_replay.go`
- `PIOP/canonical_transcript.go`
- `PIOP/proof_report.go`
- likely new file: `PIOP/fixed_table_lookup.go`

Work:

- Add a versioned internal payload, e.g. `SigShortnessProofPackedLookup`.
- Bind into Fiat-Shamir:
  - table digest,
  - packed-row layout digest,
  - lookup backend parameters,
  - main root,
  - recomposition relation digest.
- Report lookup bytes as a new bucket or as part of `SigShortness`, but keep
  paper accounting explicit.

The verifier must reject if:

- table digest mismatches,
- row layout digest mismatches,
- packed row count is not 256,
- any lookup transcript is invalid,
- recomposition constraints are absent from the main PACS relation.

### Phase 4: Verification and Tests

Required tests:

- `PIOP/signature_bounds_test.go`
  - `R111,L2` covers `beta=6142`.
  - boundary coefficients decompose/recompose correctly.
  - coefficients outside the bound reject.

- `PIOP/signature_shortness_packed_test.go`
  - table digest is stable.
  - invalid packed row membership rejects.
  - direct degree-111 polynomial mode is not selected by the optimized preset.

- `PIOP/run_test.go`
  - optimized preset still verifies.
  - removed historical shortness-version public surfaces remain invalid.
  - no public digits appear in `SigShortnessProof`.

- `cmd/showing/integration_test.go`
  - the three maintained x0_len=70 optimized V18 profiles still run.
  - optimized command reports theorem bits >= 100.
  - optimized command reports the new packed row count and lookup bucket.

- Negative tests:
  - tamper one packed limb row value outside `[-55,55]`.
  - tamper recomposition by changing one signature source row.
  - tamper table digest.
  - tamper layout digest.

### Phase 5: Measurement Acceptance

Run:

```text
go test ./PIOP
go test ./cmd/showing
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

Accept only if:

```text
optimized paper transcript < 43163 bytes
theorem bits >= 100
dQ remains near 356, not 3456+
direct bb_tran semantics remain
no public private-witness digits
one-root profile retained
removed public research presets remain invalid
```

## Decision

Do not implement direct 2025-1085 polynomial decompression in the current PACS
backend as a transcript reduction. It is provably sound, but the global `dQ`
increase makes it size-negative.

The implementation-worthy path is a new one-root, fixed-table, low-degree
lookup backend for `R111,L2` packed signature shortness. Its entire value
depends on proving lookup membership without paying degree 111 in `Q` and
without adding more than about 8 KB of lookup transcript.
