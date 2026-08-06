# BQ128-128 and WF128 credential-size optimization

## Status and claim boundary

This report records four measured strict-v3 epochs—the security-correct
foundation, transcript reduction, non-research optimization, and codec-6
final-size optimization—for
exactly two presets:

- `poc-n1024-bq128-r128-v3` (BQ128-128); and
- `system-n1024-wf128-crom-v2` (WF128; the historical identifier is retained,
  but its target manifest is now version 3).

The result is deliberately narrow: after the implemented checks described
below, there is no known deviation in these two presets' **per-proof
SmallWood flow** from the applicable argument in
[`2025-1085.pdf`](</Users/jolaz/Desktop/ARC/Better-Lattice-based-Blind-Signatures/2025-1085.pdf>).
The maintained claim remains `claim_scope=proof_only`.

This is **not** a claim of full credential-game security, QROM security,
unconditional security, or complete security of the commitment and lattice
signature primitives. In particular, simultaneous extraction/composition,
multi-user and multi-context lifts, the programming-conflict accounting, an
MSIS binding estimate, and a lattice-signature estimate remain outside the
accepted claim. The presets are custom theorem instantiations, and the local
input-trace, public-linear hat-fusion, source-only issuance, and aggregate-dot
reformulations rely on the equivalence lemmas in this report.

The other seven maintained presets and their v2 measurements remain historical
v2 data. No migration, fallback, or reinterpretation of those measurements is
part of this work.

## Source and evidence integrity

The paper repository was read but never written.

| Checkpoint | Paper repository HEAD | Status |
|---|---|---|
| Before implementation | `d19818571f04c8c12425e2e7c10ceb41f7a1762d` | clean |
| After first implementation and measurements | `d19818571f04c8c12425e2e7c10ceb41f7a1762d` | clean |
| After final codec-5 implementation and measurements | `d19818571f04c8c12425e2e7c10ceb41f7a1762d` | clean |
| After codec-6/R11-L4 implementation and measurements | `d19818571f04c8c12425e2e7c10ceb41f7a1762d` | clean |

The v2 comparison baseline is Spruce commit
`f8973f05473c9110081324a0f2671fa410fb12f3`. The first strict-v3 runs were made
from the implementation worktree based on that commit; the reports
intentionally record `modified=true`, because the implementation had not been
committed when it was measured. The subsequent transcript-reduction runs were
also measured from the implementation worktree. The recorded environment is
Go 1.23.12, Darwin/arm64, 15 CPUs, and `GOMAXPROCS=15`.

Because a dirty-bit flag alone does not identify an implementation, every
final raw report also binds the canonical Go build-input snapshot
`sha256-length-framed-go-list-build-inputs-v2`: 202 local compiled/embed/module
inputs with digest
`2b963f0ddebfa6c7ec80154a6c5b353c0dcbd94cbff3e929f3b4bf61830b6e16`.
The snapshot is derived from `go list -deps -json ./cmd/issuance`, includes the
embedded PRF parameter JSON, excludes tests/artifacts/cache files, and is
recomputed by the evidence validator.

The final bound manifest digests are
`f08dc90c5e319dfd667a4b960050aa2f0932eb2353a528c280299354452d3a08`
for BQ128 and
`4063d1422055d5753355781160188abdb98dd683f5e42978abcb3d273e89e4c7`
for WF128. In addition to the versioned geometry, each target manifest pins the
fixed field and PRF profile identities. The complete canonical field profile,
decoded PRF constants, and reconstructed semantic-message layout are bound
directly in the v3 public statement. The final checked record is
`evidence/focused-v3-nonresearch-optimization.json`, whose SHA-256 digest is
`eeade3fe96a1fdcaff89016f964a3b34d12eb78692308752c5325c2141c04d59`.

Evidence locations:

- v2 baselines: `artifacts/smallwood-v3/baseline-f8973/{bq128,wf128}/run-{1,2,3}`;
- first strict-v3 BQ128: `artifacts/smallwood-v3/final/bq128-l43/run-{1,2,3}`;
- first strict-v3 WF128: `artifacts/smallwood-v3/final/wf128-l41/run-{1,2,3}`;
- transcript-reduction BQ128:
  `artifacts/smallwood-v3/transcript-reduction/bq128-l43/run-{1,2,3}`;
- transcript-reduction WF128:
  `artifacts/smallwood-v3/transcript-reduction/wf128-l41/run-{1,2,3}`;
- preceding BQ128 codec-5 runs:
  `artifacts/smallwood-v3/nonresearch-optimization/bq128/run-{1,2,3}`; and
- preceding WF128 codec-5 runs:
  `artifacts/smallwood-v3/nonresearch-optimization/wf128/run-{1,2,3}`.

For every final run, the checked evidence binds the exact ordered set of 15
production artifacts, their canonical paths, byte lengths, and SHA-256
digests, plus the report/resource and nested issuance/showing proof digests.
Validation requires regular files inside the fixed run directory, so an
alternate matrix, key, response, NTRU object, state, or presentation cannot be
substituted without invalidating the evidence.

All generated evidence and work material is inside Spruce_ARC. The ignored
retune overlay is under the underscore-prefixed
`artifacts/retune-v2/_overlay` directory, so Go package discovery does not treat
it as a mixed-package source directory.

## Metric definitions

Four metrics are reported separately throughout this document:

1. **Persistent canonical credential-state bytes**: the exact length of the
   state-v8 binary file.
2. **Actual canonical presentation-wire bytes**: the exact presentation-v3
   binary length, consisting only of its packed tag and canonical showing
   proof.
3. **Actual canonical proof-wire bytes**: the exact schema-3 issuance or
   showing proof produced by `MarshalCanonicalProof`.
4. **Paper-accounted transcript bytes**: the paper-facing SmallWood message
   accounting, with each independently framed bucket rounded to bytes before
   summation.

The historical `proof_size_bytes` field in the v2 reports is a **modeled
verifier-message estimate**. It is not an actual binary wire length and must
not be interpreted as one. Current code exposes the estimate as
`modeled_verifier_message_bytes`; actual v3 claims use the `canonical_*` fields.

The historical presentation JSON is likewise not a canonical verification
wire. There is therefore no like-for-like actual presentation-wire or proof-wire
baseline. This report does not manufacture one by comparing JSON length with
binary length.

## Current codec-6 final-size result

This epoch makes two independently gated changes. First, codec 6 removes the
zero-only suffix that codec 5 appended after a positional Merkle multiproof.
The verifier already reconstructs the Fiat–Shamir tail before decoding the
opening; the exact frontier positions and therefore the exact number of hashes
are deterministic functions of that tail and public `NLeaves`. Codec 6 sends
only those hashes. It transmits no count, index, position, or path reference,
bounds the derived count by the unchanged public worst case, and rejects
truncation, any extra former-padding byte, and all codec-5 artifacts. This is
an injective representation change: the Merkle root, queried leaves,
independent tapes, frontier nodes, and verification equation are unchanged.

Second, BQ128 showing changes its balanced signature-digit representation from
R7/L5 to R11/L4. For digits in `[-5,5]`, four limbs cover
`(11^4-1)/2 = 7,320`; the finalized signature bound 6,142 remains inside that
range. Recomposition is still `u = sum_j 11^j d_j`, and the degree-11
membership polynomial accepts exactly those eleven digit values. This narrows
the former conservative proof bound 8,403 rather than weakening it. Honest
completeness is retained because finalized credentials already enforce the
6,142 bound. The relation compiler, not a hand projection, derives the new
degree and every dependent SmallWood dimension.

| BQ128 showing quantity | Codec 5 R7/L5 | Codec 6 R11/L4 |
|---|---:|---:|
| Shortness rows | 320 | 256 |
| Total logical rows | 487 | 423 |
| Parallel / aggregated degree | 9 / 8 | 11 / 8 |
| `dQ` | 472 | 570 |
| Witness layers | 12 | 10 |
| Replay rows | 540 | 450 |
| Mask rows | 156 | 195 |
| Physical rows | 696 | 645 |
| Queries | 169 | 143 |
| Opened `P` columns | 527 | 502 |

The higher degree costs 3,179 canonical Q bytes and 39 mask rows, but 64 fewer
witness rows remove two witness layers and reduce `VTargets`, `BarSets`, and
opened rows. Before Merkle encoding, the exact structural wire reduction is
1,251 B; the paper-accounted showing reduction is 1,262 B.

All values below are independent scalar medians of three accepted runs.

| Preset | State | Issuance proof | Showing proof | Presentation | Issuance/showing paper | Showing time | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| BQ128 | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B | 3,692.639 ms | 601,784,320 B |
| WF128 | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B | 1,421.167 ms | 326,336,512 B |

Relative to codec 5, BQ saves 490 B issuance, 2,084 B showing, and 2,084 B
presentation; WF saves 330 B issuance, 132 B showing, and 132 B presentation.
The Merkle saving is challenge-dependent: at the median-size selected runs BQ
uses 263/273 issuance nodes and 256/273 showing nodes, while WF uses 126/136
and 132/136. Consequently the earlier 686 B / 165 B examples were valid
single-tail projections, not guaranteed fixed savings.

The component rows below are actual runs whose total equals the independently
selected median for that phase; authentication is exact, never padded.

| Preset/phase | Header/root/salt | Counters | `R` | `QPayload` | `VTargets` | `BarSets` | Opened rows | Tapes | Auth nodes / bytes | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BQ issuance | 84 | 6 | 8,980 | 15,310 | 2,985 | 1,752 | 9,297 | 594 | 263 / 12,887 | 51,895 |
| BQ showing | 84 | 6 | 8,980 | 18,489 | 15,051 | 6,423 | 22,546 | 594 | 256 / 12,544 | 84,717 |
| WF issuance | 75 | 5 | 5,472 | 6,829 | 1,555 | 472 | 3,010 | 144 | 126 / 4,158 | 21,720 |
| WF showing | 75 | 5 | 5,365 | 8,227 | 8,087 | 1,886 | 9,791 | 144 | 132 / 4,356 | 37,936 |

All six runs have `claim_scope=proof_only`, pass the live parameter audit,
proof verification and replay rejection, both phase ZK gates, and the
query-adjusted theorem target. BQ showing has 131.222 theorem bits; WF has
128.421. Median proving time and peak RSS, and every individual run, remain
below 2× the accepted codec-5 values. κ, `NLeaves`, query caps, salt/hash/tape
widths, nonce/seed widths, and grinding policy are unchanged.

| Preset/run | Issue prove | Issue verify | Show prove | Show verify | Max RSS |
|---|---:|---:|---:|---:|---:|
| BQ/1 | 2,314.490 ms | 622.329 ms | 4,407.041 ms | 384.555 ms | 619,200,512 B |
| BQ/2 | 1,706.772 ms | 637.774 ms | 3,491.742 ms | 392.115 ms | 601,784,320 B |
| BQ/3 | 1,645.068 ms | 603.275 ms | 3,692.639 ms | 465.378 ms | 592,592,896 B |
| WF/1 | 735.020 ms | 284.793 ms | 1,534.680 ms | 184.277 ms | 304,381,952 B |
| WF/2 | 667.702 ms | 282.874 ms | 1,400.498 ms | 185.728 ms | 326,336,512 B |
| WF/3 | 729.139 ms | 311.589 ms | 1,421.167 ms | 185.321 ms | 326,615,040 B |

### Exact row-alias audit

No row alias was adopted. The live ownership audit covers every logical row:
256 BQ (or 256 WF) shortness rows, 97 bounded/carrier rows, 32 `x1` transform
rows, 32 `Z` transform rows, and six PRF input-trace rows. Each logical row is
an interpolation of exactly 32 support values; the apparent LVCS width is a
layer width, not spare per-row coefficient capacity. Therefore sharing a row
between two families would assert equality of independently variable witness
vectors. BQ's last PRF row has only three unused scalar slots, insufficient to
remove a row; WF's PRF payload fills all 192 slots.

After R11/L4, BQ would need another 36 rows removed to cross from ten witness
layers to nine; WF still needs 13 to cross from eleven to ten. Mixing unrelated
slots into another family would require selector-weighted constraint changes
and new two-way language and degree proofs, so it is research work rather than
an exact alias. The implementation deliberately leaves it disabled.

The checked summary is
`evidence/focused-v3-final-size-optimization.json`; raw reports and resource
sidecars are under
`artifacts/smallwood-v3/final-size-optimization-v2/{bq128,wf128}/run-{1,2,3}`.
They bind implementation base
`f8973f05473c9110081324a0f2671fa410fb12f3`, source snapshot
`07035083fc3a35ae3226a2598b1f879bc12b36e06b1ada863b92d4f228df23ff`,
and the unchanged clean paper HEAD recorded above. Current manifest digests are
`ed2ef5aebe3fe38c07fd85f02b15cd2f0f9ee56c3be4ca49cd1fe83cc802a193`
for BQ and
`4063d1422055d5753355781160188abdb98dd683f5e42978abcb3d273e89e4c7`
for WF.

## Previous codec-5 result summary

The accepted result combines source-only issuance, the existing showing-row
reformulations, grouped radix-`q` field packing, and exact-`N` positional
Merkle authentication. It changes no preset parameter or grinding budget.
All values below are independent scalar medians of three fresh end-to-end
proof-codec-5 runs.

| Preset | Metric | Immediately preceding accepted v3 | Final codec-5 result | Saving |
|---|---|---:|---:|---:|
| BQ128 | Persistent state | 4,926 B | 4,926 B | 0 B |
| BQ128 | Issuance proof wire | 60,426 B | 52,385 B | 8,041 B |
| BQ128 | Showing proof wire | 87,091 B | 86,801 B | 290 B |
| BQ128 | Presentation wire | 87,124 B | 86,834 B | 290 B |
| BQ128 | Paper issuance/showing | 65,091 / 91,756 B corrected | 57,271 / 91,756 B | 7,820 / 0 B |
| WF128 | Persistent state | 4,894 B | 4,894 B | 0 B |
| WF128 | Issuance proof wire | 25,935 B | 22,050 B | 3,885 B |
| WF128 | Showing proof wire | 38,199 B | 38,068 B | 131 B |
| WF128 | Presentation wire | 38,240 B | 38,109 B | 131 B |
| WF128 | Paper issuance/showing | 27,575 / 39,837 B corrected | 23,790 / 39,837 B | 3,785 / 0 B |

The final combined paper totals are 149,027 B for BQ128 and 63,627 B for
WF128. The immediately preceding evidence JSON is immutable; its paper
estimator had removed two `Q` coordinates per extension-field limb. The
comparison above corrects that historical projection by 33 B per BQ phase and
17 B per WF phase without changing any historical measured wire or runtime.

An intermediate proof-codec-4 implementation also removed a second `Q`
coefficient by solving Eq. (4) after the Fiat--Shamir evaluation point was
known. That made the check repairable after the challenge and was unsound.
Its six provisional runs were withdrawn and overwritten. Codec 5 rejects
`SPRUCEP4` bytes and omits only the constant coefficient already fixed before
the evaluation challenge by
`sum_{omega in Omega} Q(omega)=0`. None of the final numbers is projected from
the withdrawn runs.

The historical v2 compact-state medians were 37,084 B (BQ128) and 37,074 B
(WF128); their proof-size fields were modeled estimates, not actual wires.
The seven non-target presets and their historical measurements remain
unchanged.

### Canonical state-v8 components

Both target presets use the same N=1024 secret geometry and signature bound.
Their only size difference is the configured binding width.

| Component | BQ128 | WF128 | Encoding |
|---|---:|---:|---|
| Magic/version | 8 B | 8 B | fixed |
| Public-parameter and verifier-key bindings | 98 B | 66 B | two SHAKE-256 bindings at 49 B / 33 B |
| 960 ternary message attributes | 192 B | 192 B | five base-3 digits per byte |
| 48 base-9 PRF seed digits | 20 B | 20 B | five digits per little-endian `uint16` |
| `S`, `E`, `mu_sig`, `x0`, `x1` | 1,024 B | 1,024 B | 5,120 ternary values, five per byte |
| Two 1,024-coefficient signature vectors | 3,584 B | 3,584 B | shifted bound, four 14-bit values per 7-byte group |
| **Total** | **4,926 B** | **4,894 B** | exact in all three runs |

The codec omits the reserved zero tail and reconstructs `MAttr`, the packed
Poseidon key, preset/layout metadata, paths, NTRU public material, and the
signature bound from trusted context. Saves are atomic and mode `0600`; all six
measured state files have that mode. The credential fingerprint is derived from
the canonical bytes plus configured-width public/key bindings and is an
identifier, not a MAC.

### Actual canonical proof-wire components

The table gives the component medians. Counter bytes vary because the frozen
grinding counters use minimal unsigned LEB128. “Opening” is the one
authoritative DECS opening: packed opened rows, independent tapes, and the
zero-padded positional Merkle frontier.

| Preset/phase | Header + root + salt | Counters | `R` | `QPayload` | `VTargets` | `BarSets` | Opened rows | Tapes | Auth frontier | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BQ128 issuance | 84 | 6 | 8,980 | 15,310 | 2,985 | 1,752 | 9,297 | 594 | 13,377 | 52,385 |
| BQ128 showing | 84 | 6 | 8,980 | 15,310 | 17,191 | 7,590 | 23,669 | 594 | 13,377 | 86,801 |
| WF128 issuance | 75 | 5 | 5,472 | 6,829 | 1,555 | 472 | 3,010 | 144 | 4,488 | 22,050 |
| WF128 showing (`L=41`) | 75 | 5 | 5,365 | 8,227 | 8,087 | 1,886 | 9,791 | 144 | 4,488 | 38,068 |

BQ wire sizes were fixed at 52,385 B issuance, 86,801 B showing, and 86,834 B
presentation. WF run 1 used one additional counter byte (22,051 / 38,069 /
38,110 B); runs 2 and 3 equal the medians in the table. Presentation-v3 adds
an 8-byte envelope and a packed tag: 25 B for BQ128 and 33 B for WF128, for
overheads of 33 B and 41 B respectively.

The wire contains no dimensions, layouts, field profile, `Chi`,
`omegaExtra`, challenge matrices, challenge indices, coefficient plans, or
debug coefficients. It retains the complete executed `R`. For every one of
the `theta` split-coordinate `Q` polynomials, codec 5 transmits `q_1,...,q_d`
and derives only `q_0`. Thus BQ transmits 6,136 of 6,149 field elements and WF
issuance transmits 2,737 of 2,744; the full `QPayload` is reconstructed and
absorbed before round 3 derives the K-field evaluation point.

### Paper transcript components

The v3 fixed bucket is 680 B for BQ128 and 648 B for WF128. Every bucket is
rounded to bytes independently.

| Preset/phase | Fixed | full `R` | safe compact `Q` | `Pdecs` | standalone `Mdecs` | Auth | Tapes | `VTargets` | `BarSets` | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BQ128 issuance | 680 | 8,979 | 15,308 | 9,315 | 0 | 17,640 | 594 | 2,990 | 1,765 | 57,271 |
| BQ128 showing | 680 | 8,979 | 15,308 | 23,715 | 0 | 17,640 | 594 | 17,225 | 7,615 | 91,756 |
| WF128 issuance | 648 | 5,471 | 6,828 | 3,015 | 0 | 5,643 | 144 | 1,558 | 483 | 23,790 |
| WF128 showing (`L=41`) | 648 | 5,364 | 8,225 | 9,810 | 0 | 5,643 | 144 | 8,103 | 1,900 | 39,837 |

The paper accounting uses full `R` and omits standalone `M(e)`, never both a
shortened `R` and omitted `M`. Its optimized `Q` term is exactly
`rho*dQ*theta` base-field elements: one constant per limb is derivable from
the support-sum identity, but no coefficient is derived from the later
evaluation target. Authentication follows the paper's fixed path accounting;
the actual codec uses the smaller positional frontier shown above.

## Corrected geometry

For v3, the DECS row-degree bound is derived rather than transmitted:

`dDECS = LVCSNCols + ell - 1`.

The mask shape follows the paper's small-field construction exactly:

`mu = ceil(dQ / L)`, `maskChunks = mu + 1`, and
`maskRows = (mu + 1) * theta`.

| Preset/phase | Logical rows | `(d,d')` | `dQ` | `L` | `dDECS` | Witness layers | Replay rows | Mask chunks / rows | Physical rows | Queries | Opening rows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BQ128 issuance | 49 | (9,8) | 472 | 43 | 60 | 2 | 90 | 12 / 156 | 246 | 39 | 207 |
| BQ128 showing | 487 | (9,8) | 472 | 43 | 60 | 12 | 540 | 12 / 156 | 696 | 169 | 527 |
| WF128 issuance | 49 | (9,8) | 391 | 42 | 50 | 2 | 78 | 11 / 77 | 155 | 21 | 134 |
| WF128 showing | 423 | (11,8) | 471 | 41 | 49 | 11 | 429 | 13 / 91 | 520 | 84 | 436 |

The first structural pass removed 49 logical rows in each target:

- input-trace v3 fits the necessary PRF payload in six 32-column rows instead
  of seven, saving one row; and
- 96 `mu_sig`, `x0`, and `x1` source rows become 48 two-lane carrier rows,
  saving 48 rows without retaining duplicate raw rows.

The second pass removes another 64 rows by eliminating 32 materialized
`mu_sig` hats and 32 materialized `x0` hats. These hats are public-linear
expressions of already committed, bounded carrier lanes; they are substituted
directly into the projected signature aggregate. The 32 `x1` hats and 32 `Z`
hats remain materialized because they participate in the nonlinear inverse
chain. The progression is therefore BQ128 `600 -> 551 -> 487` and WF128
`536 -> 487 -> 423` logical showing rows.

The final non-research issuance pass replaces the 165-row core/view layout by
49 committed sources: 15 paired ordinary-message carriers, two semantic tail
rows, 16 paired `S` carriers, and 16 paired `E` carriers. Carrier membership,
reserved/key-slot policy, and the full 1,024-coordinate commitment transform
are evaluated from those sources. No raw duplicate or coefficient-view rows
remain. The aggregate family still contains all 1,024 commitment residuals;
production evaluates their Fiat--Shamir-weighted dot product directly, while
the formal builder remains an independent audit oracle.

The six legacy PRF bridge matrices and their v3 metadata have no v3
representation. Their old raw payload would be 1,536 B, but the historical
paper accounting already excluded it; it is therefore **not** added to either
pass's paper reduction.

### Source-only issuance equivalence lemma

Split `M` into 30 ordinary 32-coefficient blocks and two raw tail blocks. Pair
the ordinary blocks into 15 `Enc(a,b)` carriers; keep the 64-coordinate
reserved/seed tail raw; and pair the 32 `S` blocks and 32 `E` blocks into 16
carriers each. Degree-9 membership plus the fixed degree-at-most-8 decoders
uniquely recovers every ordinary `M`, `S`, and `E` lane. The public policy fixes
the 960 ordinary-message coefficients, a reserved selector enforces the 16
reserved coordinates as zero, and range membership enforces the 48 seed
coordinates.

The fixed transform basis reconstructs all 1,024 NTT coordinates. The
aggregate family retains every residual

```text
CM[t] * M[t] + AS[t] * S[t] + E[t] - Com[t],  t=0,...,1023.
```

Therefore every former core/view witness maps to the 49 source rows by
encoding, and every satisfying source-only witness uniquely reconstructs the
former sources and views. The extractor-visible `M`, `S`, and `E` values and
the commitment language are unchanged. The resulting issuance degrees are
`(d,d')=(9,8)`, with `dQ=472` for BQ128 and `dQ=391` for WF128.

For the production aggregate-dot path, round-2 challenges are consumed in the
canonical order `gamma[out*N+t]`. Distributing the fixed `CM`, `AS`, transform,
and Lagrange weights gives one precomputed K-polynomial weight per source block
plus a public term. This is only a reassociation of the same finite sum over
all output coordinates and all K limbs; no residual is dropped and neither
`Q` nor its transcript position changes. The 1,024-polynomial builder remains
an independent formal oracle. Tests at both `(theta,dQ)=(13,472)` and
`(7,391)` require complete coefficient-for-coefficient `Q` equality, alongside
support and independent-K-point equality.

The `m_eq` public policy is part of this equivalence boundary. Its JSON is
strictly decoded; attribute coordinates must be exactly `-1`, `0`, or `1`, and
every key/reserved non-attribute coordinate must be zero. Only `-1` is lifted
to `q-1`. Arbitrary public integers are never reduced modulo `q`, so `q-1`,
`q+1`, unknown fields, trailing JSON, and nonzero reserved/key slots reject.

## Security-correct v3 foundation

Compression was enabled only after the following fail-closed foundation was in
place.

### Exact challenge distributions

All strict-v3 reductions use domain-separated SHAKE-256 rejection streams:

- canonical `Fq` sampling;
- extension-field `K` sampling limb by limb;
- bounded integers;
- distinct tail indices; and
- exact sampling from `K \ Omega`.

Witness and mask randomizers use the same exact-uniform rule. The legacy modulo
reducers remain isolated for v2 callers; target-v3 call sites do not silently
fall back to them. The verifier recomputes the fourth-round tail challenge and
rejects a range-valid but transcript-inconsistent tail.

### Complete Fiat-Shamir binding

The v3 transcript length-frames and absorbs the complete canonical public
statement directly into SHAKE-256. Every round expands from the full 64-byte
SHAKE digest. The old SHA-256 `LabelsDigest` is not the sole binding for any v3
statement. The field-profile identifier, digest, and complete canonical profile
bytes; the complete decoded PRF constants; the complete canonical semantic-
message layout bytes; the injectively framed complete reconstructed `RowLayout`;
the version tuple and canonical preset manifest; public parameters;
key-dependent statement values; context; and tag are all bound before
acceptance. Row-layout framing includes field names, zero values, nil/present
markers, and slice lengths, so the former materialized-hat layout and the fused
layout are distinct public statements. The foundational PIOP loader resolves
runtime PRF paths only as operational hints and requires their decoded
constants to equal the embedded target profile. The canonical verifier
independently reconstructs the semantic
layout and rejects any public binding that differs byte-for-byte. Consequently,
a path cannot select a same-shape but algebraically different relation.

The four grinding parameters remain byte-for-byte fixed:

- BQ128: `[5,6,12,13]`;
- WF128: `[1,0,2,13]`.

No `NLeaves`, query cap, salt width, hash width, tape width, tag width, nonce,
or seed size was increased.

### Fixed extension-field profiles

The maintained profiles fix `q=1017857`, `theta`, a vetted monic irreducible
`Chi`, and `omegaExtra = X mod Chi`:

- `spruce-smallwood-kfield-q1017857-theta13-v3` for BQ128; and
- `spruce-smallwood-kfield-q1017857-theta7-v3` for WF128.

Construction validates irreducibility, support separation, and interpolation
inverses. The profile and its canonical bytes are manifest/transcript-bound,
but neither `Chi` nor `omegaExtra` is transmitted. Relative to transmitting
them, this removes 216 B per BQ128 phase and 120 B per WF128 phase from the
physical wire.

### Witness and mask randomization

Every logical witness row receives an independent `rho_i` in `K`. Its
interpolant preserves all values on the witness support `Omega` and evaluates
to `rho_i` at `omegaExtra`; the `theta` base-field coordinates are stored in
the existing tail rows. Consequently, re-proving the same logical witness
changes its commitment without changing its relation values on `Omega`.

For the mask polynomial of degree `dQ`, v3 implements the shifted final column
and independent randomizers of the paper's Equation (2). Semantic
multiplication queries reconstruct and authenticate `M(e)` through
`VTargets`; the old identity/rank padding queries are not used as a substitute.

### One semantic relation and Q construction

V3 does not use the legacy formal `BuildQK` path. One witness-independent
relation IR supplies both prover construction and verifier evaluation. The
prover evaluates the paper's Equation (4) at `dQ+1` fixed distinct base-field
points and interpolates limbwise. Tests compare the resulting `Q` with the
same semantic evaluator at independent extension-field points.

`MaskCoeffDebug`, `FparCoeffDebug`, `FaggCoeffDebug`, `QCoeffDebug`, `MKData`,
and `QKData` have neither a v3 wire representation nor a v3 verifier fallback.
`M(e)` is authenticated by mask queries and `Q` comes only from `QPayload`.

## Relation reformulation

### Input-trace v3 equivalence lemma

Let the authenticated initial Poseidon state be formed from the existing key,
public context, and hidden-slot sources. For every active S-box at round `r`
and lane `j`, input-trace v3 commits

`z[r,j] = state[r,j] + roundConstant[r,j]`.

It enforces this equality, derives the nonlinear value as `z[r,j]^3` inside
the relation, and applies the same full- or internal-round MDS map. The MDS
maps and additions are linear. Therefore, induction on the Poseidon schedule
shows that a satisfying input trace determines exactly the same state after
every round as the output-trace execution. Conversely, an honest output trace
uniquely supplies all 179 committed S-box inputs and satisfies every input-
trace recurrence.

For final tag lanes 4 and above, the terminal state and feed-forward equations
are both retained. For lanes 0 through 3, adding the terminal-MDS and feed-
forward equations eliminates the unique terminal state variable; the four
authenticated Boolean hidden-slot bits occupy those freed payload positions.
The summed equation is equivalent to the existence of that unique eliminated
value, not a relaxation. The public tag is checked directly from the final
MDS/feed-forward relation.

When a scalar is selected at a support point by Lagrange polynomial `L`, the
formal recurrence is `L * P^3`. Using `(L * P)^3` would yield `L^3 * P^3` and
would be a different off-support polynomial. The implementation and tests pin
the former expression.

The resulting PRF degree is three. The two-ternary carrier contributes degree
nine; it encodes

`Enc(a,b) = (a+1) + 3*(b+1)` for `a,b in {-1,0,1}`,

enforces membership in `{0,...,8}` with the degree-nine vanishing polynomial,
and recovers the two lanes with fixed degree-at-most-eight interpolants. The
original source-to-coefficient, CRT, NTT, and signature relations consume those
decoded lanes. The retained nonlinear hats remain explicitly bridged; the
public-linear hats are consumed through the exact substitution below.

The compiler-derived showing degrees remain `(d,d')=(9,8)` for BQ128 and
`(11,8)` for WF128, producing `dQ=472` and `dQ=471` respectively. The local
equivalence suite checks reference Poseidon execution, formal/semantic equality
on `Omega` and independent `K` points, and tampering of reused key, bit, slot,
context, input-trace, and tag sources.

### Public-linear `mu_sig`/`x0` hat-fusion lemma

The paper's transformed hats are algebraic expressions; the paper does not require
each expression to be a separately committed witness row. Let `C_r` be the
already committed carrier rows after the fixed degree-at-most-eight lane
decoder. For a target coefficient `t=(block,lane)`, the transform bridge has
fixed public weights `H_t` and `alpha[t,r]`, so the eliminated value is

```text
hat(a)[t] = sum_{x in Omega} H_t(x) *
            sum_r alpha[t,r] * Decode(C_r(x)).
```

For `a=mu_sig` or an `x0` component, every use of `hat(a)[t]` in the projected
signature equation is multiplied only by the public BB-tran coefficient
`B[t]`. The new aggregate substitutes the right-hand side and distributes the
public scalar. The pinned support identity is

```text
sum_{x in Omega} L_lane(x) * B_block(x) * hat(a)_block(x)
  = B[t] * sum_{x in Omega} H_t(x) *
             sum_r alpha[t,r] * Decode(C_r(x)).
```

Thus every satisfying materialized-hat witness satisfies the fused relation.
Conversely, the committed bounded carrier lanes uniquely reconstruct every
eliminated hat, extending a satisfying fused witness to the former relation.
This is a two-way language equivalence, not an omission of the transform
constraint. Extraction still returns the individual ternary `mu_sig` and `x0`
sources, and all source-to-coefficient, CRT, NTT, and projected-signature checks
remain present.

The 32 `x1` hats and 32 `Z` hats are deliberately retained. Their coordinate
relation contains the nonlinear product
`(B3[t]-hat(x1)[t])*hat(Z)[t]=1`. Substituting a decoded global transform into
that product would create a different relation and degree argument. This pass
does not do so: both nonlinear operands remain committed, source-bound, and
randomized at `omegaExtra`.

Zero knowledge is not obtained by publishing the eliminated expressions. Their
commitments disappear entirely; the carrier rows from which they are derived
remain independently randomized at `omegaExtra`, as do all other committed
witness rows. No tape is shared and no new source evaluation is transmitted.
The compiler then recomputes the witness-layer, mask, query, and four-term
theorem geometry for the smaller row set. Thus the local elimination neither
removes an extractor source nor consumes a blinding value needed by a surviving
commitment.

The fused term uses only public-linear weights applied to the existing
degree-at-most-eight decoder, so compiler degrees remain BQ128 `(9,8)` and
WF128 `(11,8)`, with `dQ=472` and `471`. Tests compare the old and fused
aggregates on every support coordinate, compare formal and semantic evaluators
at independent extension-field points, and show that tampering with a carrier,
retained `x1` hat, or retained `Z` hat produces a nonzero relation residual.

### Payload geometry

The target Poseidon schedule has `8*20 + 19 = 179` active cubic S-box inputs.
BQ128 carries 189 necessary scalars and WF128 carries 192; both occupy exactly
six 32-column rows. No checkpoint outputs, duplicated key/slot sources, bridge
matrices, or companion metadata remain in the strict-v3 layout.

## Canonical codecs and strict artifact boundary

The target version tuple is:

| Layer | Version |
|---|---:|
| Proof schema | 3 |
| Canonical proof codec | 6 (`SPRUCEP6`) |
| Fiat-Shamir domain/transcript | v3 |
| Relation | 3 |
| Layout | 3 |
| Preset manifest | 3 |
| Persistent state | 8 |
| Presentation | 3 |
| Issuance artifact | 4 |
| Holder usage | 3 |

Existing public-parameter and verifier-key container schemas remain unchanged;
their target manifest binding changes, not their outer structure.

The canonical proof codec accepts only the trusted target geometry and enforces
all of the following:

- every `Fq` value is a digit in a fixed-size, at-most-1,024-element radix-`q`
  group; group values at least `q^r`, nonzero spare bits, alternate encodings,
  truncation, and trailing data fail;
- all four counters are minimal unsigned LEB128 and are zero-extended to the
  unchanged `uint64` Fiat-Shamir input;
- dimensions, challenges, query positions, layouts, profiles, and metadata are
  reconstructed from the trusted context;
- the complete reconstructed `RowLayout` is injectively field-name-framed into
  the public statement, including zero values, nil/present markers, slice
  lengths, row indices, and the `mu_x0_aggregate_fused` mode;
- one constant coefficient per `Q` limb is reconstructed from
  `sum_{omega in Omega} Q(omega)=0`, after checking the trusted support sum is
  invertible, and the dense `QPayload` is restored before Fiat--Shamir replay;
- `VTargets` uses trusted ragged Equation (2) widths: only deterministic zero
  suffixes are omitted, and decoding restores them before transcript replay;
- Merkle authentication is a positional multiproof whose sibling positions
  and exact node count follow from the fourth-round tail; duplicate, missing,
  surplus, or retired-padding bytes fail;
- DECS tapes remain independent; no master tape seed is introduced; and
- decoding is bounded before large allocation.

Writing `Q(X)=sum_{i=0}^{dQ} q_i X^i`, the omitted value is uniquely
reconstructed as

```text
q_0 = -|Omega|^(-1) * sum_{i=1}^{dQ} q_i *
                         sum_{omega in Omega} omega^i.
```

This follows directly from the enforced `sum_Omega Q=0` identity. The encoder
rejects a proof whose supplied full in-memory `Q` does not have that constant;
the decoder restores it before deriving round three. This removes one `Fq`
constant per base-field limb—collectively one `K` coefficient—from the physical
wire without removing an independently variable message. The paper-accounted
table applies the same pre-challenge derivability and charges exactly
`rho*dQ*theta` base-field elements.

The ragged `VTargets` rule is likewise a trusted-shape reconstruction, not
challenge-dependent compression. The final issuance witness layer has 36
meaningful columns for BQ128 and 39 for WF128; the final showing layer has 14
and 13 respectively. The WF128 Equation (2) mask-query rows have 40 meaningful
columns rather than the phase widths 42/41; BQ128's mask-query width is 43.
The encoder requires every omitted suffix element to be
zero, and the decoder restores dense rows before Fiat--Shamir replay and mask
verification. Dimensions and row classes come only from the manifest-bound
relation compiler.

Final evidence regeneration exposed an integration-order defect in the
metrics-only decoder: it supplied the trusted preset/public context but not a
prover-mutated `semantic_message_layout` map entry. The canonical geometry
path now reconstructs all derivable public extras first and validates the full
target binding second. This is the intended wire contract—semantic layout is
trusted reconstruction data, not transmitted metadata—and a fresh-context
canonical proof round-trip test covers the path.

Presentation-v3 contains only the tag and canonical proof. Preset, public
parameters, verifier key, and context come from the verifier and are already
Fiat-Shamir-bound. Its JSON companion is a non-verifying diagnostic containing
only the binary digest, length, and report; JSON is not a lossless proof format.

Target legacy state, presentation, issuance, and usage artifacts are rejected.
Codec 4 is explicitly retired because its second, post-challenge `Q`
reconstruction was unsound. There is no silent v2/debug verification,
migration, or target fallback.

## Frozen-grinding retune

The structural compiler was corrected before retuning. The search froze
`NCols=32`, `rho=1`, `ellPrime=1`, both kappa arrays, query caps, salts,
hash/tape widths, PRF and signature parameters, transcript/relation versions,
and all nonce/seed/tag widths. It enumerated:

- `LVCSNCols`: incumbent +/- 4, lower bounded at 32;
- `NLeaves`: incumbent plus `step*16384`, `step=-32,...,0`;
- `eta`: incumbent -8 through +2, lower bounded at 1;
- `theta`: incumbent +/- 1, lower bounded at 2; and
- `ell`: incumbent +/- 2, lower bounded at 1.

Each candidate recomputed compiler degrees, `dQ`, ceiling mask rows, layer and
opening geometry, the four SmallWood terms, collision and primitive-profile
gates, zero-knowledge eligibility, transcript/manifest gates, paper bytes, and
canonical-wire projection. A retune candidate could not increase `NLeaves`,
projected work, or `NDECS*eta` relative to the corrected structural incumbent.
The necessary v2-to-v3 issuance mask correction is not misreported as a retune
increase.

The exact audit result was:

| Preset/phase | Analytically eligible / searched | Size-improving | Winner |
|---|---:|---:|---|
| BQ128 issuance | 1,035 / 49,005 | 0 | incumbent `L=43`, `N=688128`, `eta=59`, `theta=13`, `ell=18` |
| BQ128 showing | 1,104 / 49,005 | 0 | incumbent `L=43`, `N=688128`, `eta=59`, `theta=13`, `ell=18` |
| WF128 issuance | 835 / 29,700 | 0 | incumbent `L=42`, `N=327680`, `eta=43`, `theta=7`, `ell=9` |
| WF128 showing | 892 / 29,700 | 1 | `L=41`, `N=327680`, `eta=43`, `theta=7`, `ell=9` |

At the first-pass compiler geometry, the WF128 `L=41` candidate kept 487
logical rows, 12 witness layers, 13 mask chunks, 91 mask rows, 559 physical
rows, 91 queries, and 468 transmitted opening rows. A fresh proof
confirmed the projected canonical improvement:
showing proof 40,654 -> 40,319 B and presentation 40,695 -> 40,360 B, both
-335 B. Its paper showing transcript is 40,950 B. BQ128 had no eligible measured
size winner and remains at `L=43`.

The second structural pass did not rerun or alter this parameter decision. It
keeps WF128 at `L=41` and BQ128 at `L=43`; only the trusted relation geometry
changes to 423 and 487 logical rows respectively. No transcript reduction in
the current result comes from additional grinding.

The former broad-retune tuples were explicitly rejected:

- BQ128: `(L,N,eta,theta,ell,kappa) =
  (55,851968,68,13,18,[7,6,12,13])`;
- WF128: `(42,966656,46,7,8,[11,0,8,13])`.

Both change the frozen grinding vector and increase `NLeaves`; when reevaluated
with the mandatory frozen kappa they also fail the four-term target. They are
not silently revived as candidates.

## Security measurements and limitations

All three final runs for each preset reproduced the same geometry and paper
accounting, verified the issuance and showing proofs, and recorded
`replay_rejected=true` and `full_game_accounting_status=deferred_proof_only`.

| Preset/phase | Per-proof algebraic total | Per-proof theorem total | Collision term | ZK-eligible transcript |
|---|---:|---:|---:|---|
| BQ128 issuance | 131.548 bits | 131.251 bits | 133.678 bits | yes |
| BQ128 showing | 131.548 bits | 131.251 bits | 133.678 bits | yes |
| WF128 issuance | 128.060 bits | 128.060 bits | 261.678 bits | yes |
| WF128 showing | 128.421 bits | 128.421 bits | 261.678 bits | yes |

These numbers are the applicable per-proof SmallWood accounting; they are not
a complete credential ledger. Important remaining blockers are visible rather
than rounded away:

- both presets lack accepted MSIS-binding and lattice-signature estimates;
- full-game composition is deliberately zeroed/deferred in the final reports;
- the BQ128 challenge-bias and programming-conflict entries remain
  conservative pending reviewed theorem accounting; and
- WF128's conservative programming-conflict and multi-proof composition
  entries are 127.229 bits, and its derived complete-ledger ZK value is
  126.564 bits. These are below 128 and are a direct reason the WF128 result
  cannot be promoted beyond `proof_only`.

The implementation targets the paper's classical random-oracle flow. It makes
no QROM statement. Theorem 9's independent-oracle and uniform-challenge
assumptions are represented by domain separation and exact rejection sampling,
but applying the theorem to these custom statement compilers remains
conditional on the local relation/equivalence audit.

## Three-run resource gate

`/usr/bin/time -l` supplied maximum resident-set size; the benchmark report
supplied proof construction and verification time. These are the six preceding
codec-5 runs, retained as the resource baseline for the current codec-6 gate.

| Preset/run | Issue prove | Issue verify | Show prove | Show verify | Max RSS |
|---|---:|---:|---:|---:|---:|
| BQ128/1 | 1,849.621 ms | 594.993 ms | 3,228.774 ms | 388.639 ms | 585,973,760 B |
| BQ128/2 | 1,880.686 ms | 740.770 ms | 3,799.993 ms | 392.770 ms | 605,274,112 B |
| BQ128/3 | 1,991.228 ms | 610.428 ms | 3,785.032 ms | 389.893 ms | 580,075,520 B |
| WF128/1 | 818.367 ms | 292.275 ms | 1,780.037 ms | 185.200 ms | 289,865,728 B |
| WF128/2 | 658.564 ms | 284.372 ms | 1,657.617 ms | 182.738 ms | 308,314,112 B |
| WF128/3 | 697.362 ms | 282.809 ms | 1,574.939 ms | 191.359 ms | 298,876,928 B |

| Preset | Prior accepted issue/show prove | Final median issue/show prove | Prior/final peak RSS | Per-run 2x gate |
|---|---:|---:|---:|---|
| BQ128 | 1,646.125 / 3,261.918 ms | 1,880.686 / 3,785.032 ms | 547,487,744 / 585,973,760 B | pass |
| WF128 | 573.129 / 1,470.093 ms | 697.362 / 1,657.617 ms | 299,810,816 / 298,876,928 B | pass |

Every individual run is below twice the prior accepted proving-time medians
and peak-memory median. No size improvement was obtained by increasing
grinding or the Merkle evaluation domain.

## Paper-to-code map

| Paper obligation | Implementation |
|---|---|
| Section 4.1 LVCS row interpolation and blinding | `PIOP/smallfield_helpers.go`: randomized witness interpolation preserving `Omega` and setting independent `rho` at the fixed extra point |
| Section 4.2, Equation (2), shifted/masked coefficient matrix | `PIOP/smallfield_mask_v3.go`: ceiling shape, shifted final column, independent randomizers, semantic `M(e)` queries |
| Section 5.2, Equation (3), `dQ` | `PIOP/intgenisis_semantic_factory_v3.go`, `PIOP/prf_input_trace_v3.go`, and compiler degree metadata; no caller-supplied `dQ` override on target v3 |
| Section 5.2, Equation (4), semantic `Q` relation | `PIOP/semantic_q_v3.go` and `PIOP/constraint_eval.go`: shared relation evaluator, fixed-point evaluation, limbwise interpolation |
| Source-only issuance language preservation | `PIOP/intgenisis_presign_source_v3.go` and `PIOP/intgenisis_presign_eval.go`: unique carrier decoding, strict public policy, all 1,024 commitment residuals; `PIOP/intgenisis_presign_source_v3_test.go` compares both complete-Q profiles with the formal oracle |
| Figure 6 witness/mask/Q/opening order | `PIOP/run.go`, `PIOP/masking_fs.go`, and `PIOP/VerifyNIZK.go` |
| Figure 8 four Fiat-Shamir rounds and counters | `PIOP/fs_helpers.go`, `PIOP/fs_binding.go`, `PIOP/public_statement_v3.go`, and the canonical proof reconstruction path; the statement directly absorbs the canonical field profile, decoded PRF constants, semantic-layout bytes, and complete injectively framed `RowLayout` |
| Equation (8) and Theorem 9 four soundness terms | benchmark proof reports and `cmd/issuance/v3_frozen_retune_internal_test.go`; kappa and query caps are manifest-frozen |
| Theorem 10 / PCS and DECS zero-knowledge prerequisites | independent witness/mask randomizers, independent DECS tapes, exact challenge samplers, and `zero_knowledge_eligible` validation |
| Section 5.4 small-field `K`, `K \ Omega`, `omegaExtra`, and Table 2 geometry | `internal/kfield/profile.go`, `internal/kfield/kfield.go`, `PIOP/smallfield_helpers.go`, and trusted canonical-proof geometry |
| Optimized proof redundancies and Merkle authentication | `PIOP/canonical_transcript.go`, `DECS/merkle_frontier_v3.go`, and `PIOP/canonical_proof_codec_v3.go`; only the sum-zero `Q` constant, trusted-zero ragged `VTargets` suffixes, and tail-derived Merkle positions are omitted |
| Local credential statement, Poseidon reformulation, and public-linear hat fusion | `prf/input_trace_v3.go`, `PIOP/prf_input_trace_v3_relation.go`, `PIOP/carrier_codec.go`, `PIOP/intgenisis_showing_eval.go`, `PIOP/mu_x0_hat_fusion_test.go`, and the two equivalence lemmas above |
| Target manifest and fail-closed version boundary | `credential/preset_manifest.go`, `credential/intgenisis_presets.go`, and the state/presentation/usage v3 codecs |

## Verification coverage

The implementation contains focused tests for:

- exact sampler vectors, rejection intervals and boundaries, exact `K \ Omega`,
  distinct tails, full-material transcript framing, and v2 isolation;
- fixed field-profile irreducibility, canonical bytes, pinned digests, support
  separation, and defensive copying;
- Equation (2) zero/nonzero shifts, independent mask randomizers, rank,
  `VTargets -> M(e)` reconstruction, and tampering;
- fresh witness `rho`, unchanged `Omega` heads, extra-point evaluation, changed
  commitments, and semantic-Q equality at independent `K` points;
- Poseidon reference execution, input/output-trace induction, formal/semantic
  equality, selector-weighted cubes, degree envelopes, and source/tag tampering;
- exhaustive nine-code carrier encoding/decoding, invalid carriers, membership
  and decoder degrees, and live coefficient/NTT consumption;
- source-only issuance on all 1,024 commitment coordinates, non-unit/distinct
  `CM` and `AS`, nonzero `S`/`E`, reserved-tail tampering, strict `m_eq`
  rejection of `q-1`, `q+1`, nonzero reserved/key slots, unknown fields, and
  trailing JSON;
- aggregate-dot equality at support and independent K points plus complete,
  coefficient-for-coefficient `Q` equality for WF issuance/showing
  `dQ=391/471` and BQ issuance/showing `dQ=472/570`;
- materialized/fused `mu_sig` and `x0` aggregate equality on `Omega`,
  formal/semantic equality at independent `K` points, source tampering, absence
  of eliminated rows, and retained/tamper-detecting `x1`/`Z` hats;
- `Q`-constant reconstruction, violation of `sum_Omega Q=0`, trusted ragged
  `VTargets` round trips, nonzero omitted-suffix rejection, and reconstruction
  before Fiat--Shamir replay;
- injective complete-`RowLayout` framing, including mutations of the fusion
  mode, row indices, zero fields, and the distinction between nil and empty
  slices;
- canonical proof, state, presentation, issuance and usage round trips; wrong
  context/kind/version/bindings; noncanonical fields/counters/padding; every
  proof and state truncation boundary; trailing data; bounded decode; and fuzz
  entry points;
- grouped radix-`q` boundaries and spare bits, and explicit rejection of the
  retired `SPRUCEP4` post-challenge and `SPRUCEP5` padded grammars;
- positional Merkle frontiers for adjacent and non-power-of-two leaves, exact
  worst-case bounds, malformed frontiers, retired padding, and legacy
  isolation;
- in-memory verifier recomputation of the fourth-round tail and direct tail
  tampering; and
- target-only frozen-grid geometry, winner selection, historical-winner
  rejection, and focused evidence ingestion.

The six final end-to-end runs themselves all passed proof verification,
canonical round-trip verification, state/presentation persistence, quota/replay
acceptance, and second-use replay rejection. Final verification on the exact
source-bound tree also passed:

- `go test ./... -count=1 -timeout=20m`, `go vet ./...`, and `go build ./...`;
- race suites for DECS, credentials, evidence, source integrity, canonical
  round trips, strict policy lifting, aggregate evaluation, and semantic Q;
- the full complete-Q oracle comparison under the race detector for BQ128
  (417.823 s) and WF128 (187.906 s);
- five-second bounded fuzzing of the canonical proof, state, and presentation
  decoders (85,553 / 23,382 / 12,186 executions, no failures);
- all nine `gate-functional-presets` and `gate-artifact-presets` entries, plus
  every maintained N=1024 degree/exact-byte gate; and
- the focused evidence artifact/source snapshot gate, with the paper checkout
  still clean at its recorded HEAD.

As a final post-codec-6 closure check on 2026-08-05, the complete PIOP race
suite also passed with an extended harness deadline:
`go test -race ./PIOP -timeout=30m` (`ok`, 1,054.864 s). The earlier
ten-minute attempt had expired inside the bit-exact complete-Q test without a
race report; the extended run confirms that this was only a harness timeout.
This is validation metadata, not a replacement benchmark epoch, and does not
change any checked size or runtime median above.

## Final assessment

The credential-size reduction came from canonical representation and relation
reformulation, not added proof-of-work. The persistent state remains below the
5.25 KiB target for both presets. Under the current codec-6 epoch, the BQ128
presentation median is 84,750 B and the WF128 median is 37,977 B. Combined
paper transcripts are 147,765 B and 63,627 B respectively. The former
86,834 B / 38,109 B presentation medians and 149,027 B BQ combined-paper total
belong to the immutable codec-5 baseline documented above.

Within the explicit `proof_only` boundary, the implementation now has exact
challenge distributions, complete SHAKE-256 statement binding, the paper's
mask and witness-randomization geometry, a single semantic Q relation,
manifest-bound extension fields, source-only issuance and aggregate-dot
equivalence lemmas, a two-way public-linear hat-elimination lemma, strict public
policy canonicality, and fail-closed canonical artifacts. The remaining work
is security accounting and external review, not a broader security claim:
full-game composition, conservative programming bounds, missing primitive
estimates, and the local source-only, input-trace, aggregate-dot, and hat-fusion
lemmas must be reviewed before any complete credential-system claim is made.
