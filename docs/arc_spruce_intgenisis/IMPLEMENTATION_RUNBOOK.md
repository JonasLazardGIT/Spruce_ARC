# ARC-SPRUCE IntGenISIS Implementation Runbook

This document describes the IntGenISIS-style ARC-SPRUCE implementation currently present in this repository. It covers:

- what routines were added or rerouted;
- how those routines correspond to the IntGenISIS paper construction under `docs/arc_spruce_intgenisis`;
- how to run setup, issuance, showing, tests, and row-inventory benchmarks;
- which command flags matter for the IntGenISIS path;
- what is correct today;
- what is still incomplete relative to the paper.

The short status is:

The repository now has working IntGenISIS prototype paths for profile B (`N=512`) and profile A (`N=256`). They support target-shaped commitments, a canonical ring-tail-key semantic layout `M=m||k`, issuer-side target computation, PIOP verifier replay for the new pre-sign and showing rows, coefficient-view bound/key rows, a pre-sign policy hook, minimized issuer responses without serialized `T`, profile-routed CLI issuance, standalone presentation JSON, a public verifier-key artifact, and persistent verifier replay checks. The implementation is still not paper-complete. Remaining gaps are listed in [Correctness And Completeness Status](#correctness-and-completeness-status) and [Remaining Work](#remaining-work).

## Paper Construction Implemented

The new paper target is the committed-message IntGenISIS shape:

```text
M := m || k
c = C_M M + A_s s + e
T = B0 + B1 mu_sig + B2 x0 + Z + c
Z = (B3 - x1)^(-1)
A u = T
tag = PRF(k, nonce)
```

The semantic message `M` is no longer the BB-tran rational-hash message. The BB-tran characteristic is now `mu_sig`, sampled by the issuer. The old LHL/shared-randomness terms `r0H`, `r1H`, `r0I`, `r1I`, centered sums, and holder-computed `T` are not part of the IntGenISIS live branch.

The paper locations that define this shape are:

- `docs/arc_spruce_intgenisis/sections/03_blind_signature.tex`
  - holder commitment: `c = C_M M + A_s s + e`;
  - issuer samples `mu_sig`, `x0`, `x1`;
  - issuer computes `Z` and `T = B0 + B1 mu_sig + B2 x0 + Z + c`;
  - issuer returns the preimage signature `u`.
- `docs/arc_spruce_intgenisis/sections/04_arc_construction.tex`
  - ARC issuance signs `M = m || k`;
  - showing proves the signature equation, inverse equation, and PRF tag;
  - `c` is not public during showing.
- `docs/arc_spruce_intgenisis/sections/05_smallwood_model.tex`
  - SmallWood statement shapes for issuance and showing.
- `docs/arc_spruce_intgenisis/sections/06_parameters.tex`
  - profile B and compact profile A base row arithmetic. The pre-sign relation uses explicit `M`, `m`, and `k` rows. The default no-disclosure showing relation now commits a compact surface: packed coefficient views for `u`, `M`, `s`, `e`, and the combined commitment-linear term `Y = C_M M + A_s s + e`; direct hat rows for `mu_sig`, `x0`, `x1`, and `Z`; bridged hats only for `u` and `Y` in non-projected mode; and no standalone `m`/`k` projection rows.

## Implemented Repository Routines

### Profiles And Public Parameters

Files:

- `credential/intgenisis_profile.go`
- `credential/public_params.go`
- `credential/params.go`

Implemented profile names:

```text
intgenisis_profile_b
intgenisis_profile_a
```

Profile B is the N=512 target:

```text
N = 512
q = 1054721
ell_M = 1
k_s = 2
n_c = 1
B = 8
ell_mu_sig = 1
ell_x0 = 2
ell_x1 = 1
signature_preimage_len = 2
MLWE hiding estimate = 194.408 bits
MSIS binding estimate = 427.780 bits
```

Profile A is the compact N=256 target:

```text
N = 256
q = 1054721
ell_M = 1
k_s = 4
n_c = 1
B = 8
ell_mu_sig = 1
ell_x0 = 2
ell_x1 = 1
signature_preimage_len = 2
MLWE hiding estimate ~= 194.4 bits
MSIS binding estimate ~= 180.164 bits
```

Profile A is now wired through setup, NTRU keygen, issuance, showing, standalone presentation verification, and replay rejection. It remains a candidate profile until `parameter_search/run_intgenisis_degree256.sage` is rerun with the selected estimator and the promoted q/security tuple is reviewed.

Important public parameter fields:

- `Profile`: selects `intgenisis_profile_b` or `intgenisis_profile_a`.
- `RingDegree`: profile ring degree.
- `CM`: coefficient-domain serialized `C_M`.
- `AS`: coefficient-domain serialized `A_s`.
- `BPath`: file containing the BB-tran public `B` matrix.
- `BoundB` and `CommitmentBound`: profile compatibility envelope `B=8`; the live IntGenISIS proof domain for `M`, `s`, `e`, and the PRF key slots inside `M` is `ternary_v1` with live bound `1`.
- `EllM`, `KS`, `NC`, `EllMuSig`, `EllX0`, `EllX1`, `SignaturePreimageLen`: profile dimensions.
- `MLWEHidingBits`, `MSISBindingBits`: stored estimator notes.

Routing helper:

- `PublicParams.UsesIntGenISIS()` returns true when the profile or commitment matrices indicate the IntGenISIS schema.

### Target-Shaped Commitment

Files:

- `commitment/target.go`
- `issuance/intgenisis.go`

Core API:

```go
commitment.SampleTernaryCommitmentRandomness(params, rng)
commitment.CommitMessage(params, M, s, e)
commitment.VerifyCommitmentOpening(params, c, opening)

issuance.SampleIntGenISISCommitmentRandomness(params, rng)
issuance.PrepareIntGenISISCommit(params, inputs)
issuance.VerifyIntGenISISCommit(params, c, inputs)
```

Mathematical relation:

```text
c = C_M M + A_s s + e
```

Implementation details:

- `M`, `s`, and `e` are supplied in coefficient form.
- `C_M` and `A_s` are represented internally in NTT form.
- `CommitMessage` returns `c` in NTT form because issuance stores/transmits the commitment row in the same domain used by the PIOP transcript.
- `SampleTernaryCommitmentRandomness` samples live IntGenISIS `s` and `e` coefficient-wise from `{-1,0,1}`.
- `VerifyCommitmentOpening` checks dimensions, centered coefficient bounds for `M`, `s`, and `e`, recomputes `c`, and compares it to the supplied public commitment.

What this corresponds to in the paper:

- `docs/arc_spruce_intgenisis/sections/02_preliminaries.tex`, commitment preliminaries.
- `docs/arc_spruce_intgenisis/sections/03_blind_signature.tex`, pre-sign issuance relation.

Current note:

- The standalone commitment verifier checks the public compatibility bound directly.
- The PIOP pre-sign proof adds coefficient-view rows for `M`, `m`, `k`, `s`, and `e` and ternary membership constraints over those views.

### Issuer-Sampled BB-tran Data And Target

Files:

- `issuance/intgenisis.go`
- `vSIS-HASH/vSIS-BBS.go`
- `credential/helpers.go`

Core API:

```go
issuance.SampleSignatureHashData(ringQ, B, ellMuSig, ellX0, rng)
issuance.ComputeIntGenISISTarget(ringQ, B, c, data)
issuance.VerifyIntGenISISTarget(ringQ, B, c, data, tCoeff)
```

Mathematical relation:

```text
mu_sig in R_q^1
x0 in R_q^2
x1 in R_q
Z = (B3 - x1)^(-1)
T = B0 + B1 mu_sig + B2 x0 + Z + c
```

Implementation details:

- `SampleSignatureHashData` currently samples `mu_sig`, `x0`, and `x1` uniformly over `R_q`.
- It resamples `x1` until `B3 - x1` is invertible.
- `ComputeIntGenISISTarget` uses the BB-tran helper to compute the rational-hash contribution and then adds the public commitment `c`.
- `VerifyIntGenISISTarget` recomputes the target and compares coefficient form.

What this corresponds to in the paper:

- `docs/arc_spruce_intgenisis/sections/03_blind_signature.tex`, committed-message target.
- `docs/arc_spruce_intgenisis/sections/06_parameters.tex`, BB-tran target contribution.

Current limitation:

- The paper says the issuer samples from the prescribed DKLW/BB-tran domains. The current implementation uses uniform `R_q` sampling with invertibility resampling. That is a concrete placeholder unless the docs and security analysis decide full-ring sampling is the intended domain.

### Credential State

File:

- `credential/intgenisis_state.go`
- `credential/intgenisis_message.go`

State version:

```text
version = 5
```

Stored witness material:

```text
M
m
k
s
e
mu_sig
x0
x1
sig_s1
sig_s2
NTRU public row
profile and path metadata
```

Canonical semantic layout for profiles A and B:

```text
layout = intgenisis_message_ring_tail_key_v1
domain = ternary_v1
degree_mode = paper_eq3_v1
M[0][0..N-9] = ternary semantic message/attribute slots m
M[0][N-8..N-1] = ternary PRF key k
K uses the same key slots as M
M = m + K as ring-polynomial rows
```

The helper APIs are:

```go
credential.DefaultSemanticMessageLayout(profile, lenKey)
credential.EncodeSemanticMessage(layout, m, key)
credential.DecodeSemanticMessage(layout, M)
credential.ValidateSemanticMessage(layout, message)
credential.PRFKeyFromSemanticMessage(layout, M)
```

Not stored in the v5 IntGenISIS credential state:

```text
c
T
r0
r1
r0H
r1H
r0I
r1I
RI0
RI1
old LHL metadata
```

What this corresponds to in the paper:

- The holder keeps the raw post-issuance witness `(u,M,m,k,s,e,mu_sig,x0,x1)`.
- `Z` is recomputed from `x1` during showing.
- The issuance commitment `c` is not part of the showing statement.

### IntGenISIS Pre-Sign PIOP

Files:

- `PIOP/intgenisis_presign.go`
- `PIOP/intgenisis_presign_eval.go`
- `PIOP/intgenisis_layout.go`
- `PIOP/generic_builder.go`
- `PIOP/fs_binding.go`

Core API:

```go
PIOP.BuildIntGenISISPreSign(ringQ, pub, witness, opts)
PIOP.VerifyIntGenISISPreSign(pub, proof, opts)
```

Witness row order:

```text
M rows first: ell_M
m rows next: ell_M
k rows next: ell_M
s rows next: k_s
e rows next: n_c
```

For profile B this is:

```text
M: 1
m: 1
k: 1
s: 2
e: 1
total: 6 ring polynomials
```

The proof also commits coefficient-view rows after the six core rows. At `ncols=16`, profile B adds `6 * (512/16) = 192` view rows for bound, key-space, and policy replay.

Verified relation:

```text
C_M M + A_s s + e - c = 0
M - m - k = 0
coefficient-view membership for M,m,k,s,e in {-1,0,1}
optional policy relation over m
```

Verifier replay:

- `VerifyIntGenISISPreSign` no longer returns a not-implemented error.
- The verifier reconstructs a replay config from the proof row layout and public inputs.
- The replay explicitly rejects legacy public inputs in the IntGenISIS pre-sign statement:
  - `Ac`
  - `RI0`
  - `RI1`
  - `T`
  - old `B` challenge data
- Fiat-Shamir binding includes the IntGenISIS marker, `Com`, `C_M`, `A_s`, profile-relevant dimensions, the bound, semantic-layout digest, policy descriptor, sampler profile, and presentation schema marker.

What this corresponds to in the paper:

- `docs/arc_spruce_intgenisis/sections/03_blind_signature.tex`, `R_IssueBS`.
- `docs/arc_spruce_intgenisis/sections/04_arc_construction.tex`, `R_IssueARC`.
- `docs/arc_spruce_intgenisis/sections/05_smallwood_model.tex`, issuance as a SmallWood statement.

Current limitation:

- The proof now enforces coefficient-view range membership and the `m_eq` test policy. A theorem-final verifier bridge from core rows to coefficient-view rows remains a SmallWood review item.
- The default policy is `noop`; the implemented test policy is `m_eq`, which publicly fixes the full semantic `m` row.

### IntGenISIS Showing PIOP

Files:

- `PIOP/intgenisis_showing.go`
- `PIOP/intgenisis_showing_eval.go`
- `PIOP/showing_builder.go`
- `PIOP/generic_builder.go`
- `cmd/showing/main.go`

Core API:

```go
PIOP.BuildIntGenISISShowingCombined(pub, witness, opts)
PIOP.VerifyIntGenISISShowing(pub, proof, opts)
```

Logical holder/issuer witness material before PRF auxiliary rows:

```text
u:        2
M:        1
m:        1
k:        1
s:        2
e:        1
mu_sig:   1
x0:       2
x1:       1
Z:        1
total:   13 ring polynomials
```

The proof no longer commits full `u`/message/signature-equation rows as core theta rows. It commits packed coefficient-view rows for the values that need coefficient bounds, proves signed-radix shortness over `u` coefficient views, proves the commitment contribution `Y = C_M M + A_s s + e` in coefficient domain, bridges only `u` and `Y` into NTT/replay hat rows, and commits `mu_sig`, `x0`, `x1`, and `Z` directly as hat rows. At `ncols=16`, profile B has this non-PRF baseline:

```text
coefficient-view rows:           6 * 32 = 192   (u,M,s,e)
Y coefficient-view rows:          1 * 32 = 32
u R11/L4 shortness digit rows:   64 * 4 = 256
signature/inverse hat rows:       8 * 32 = 256   (u,Y,mu_sig,x0,x1,Z)
total non-PRF rows:                        736
bound-view subset M,s,e:          4 * 32 = 128
u/Y coeff-to-hat bridge families: 3 * 512 = 1536
Y coefficient-linear families:    1 * 512 = 512
```

The live `u` rows are still validated against the exact NTRU signature bound before proving, and that bound is bound into Fiat-Shamir. The default shortness shape is R11/L4. For the current profile-B bound `beta=6142`, that PIOP shortness surface proves the signed-radix representable bound `7320`:

```text
u_view = d0 + 11*d1 + 121*d2 + 1331*d3
d0,d1,d2,d3 in [-5,5]
```

Direct PIOP range membership for `u` remains enabled only for small synthetic signature bounds (`beta <= 64`). The exact large-beta comparison gadget remains a paper-facing follow-up item; the previous invalid full-`u` to raw-view bridge is gone because packed coefficient rows are now the canonical `u` source.

For transcript tuning, the IntGenISIS showing builder and verifier also accept Fiat-Shamir-bound signed-radix shapes R7/L5 and R5/L6 through the benchmark/sweep options. R121/L2 remains rejected for IntGenISIS.

Verified algebraic relations:

```text
(B3_hat - x1_hat) * Z_hat = 1
Y_coeff = C_M M + A_s s + e
A_hat u_hat = B0_hat + B1_hat mu_sig_hat + B2_hat x0_hat + Z_hat + Y_hat
coefficient-view membership for M,s,e in {-1,0,1}
coefficient-view-to-hat aggregate bridges for u,Y
R11/L4 signed-radix shortness over packed u views, proving bound 7320
signature-bound validation for u, with small-bound direct exact PIOP membership
paper Eq. (3) conservative d_Q and mask-degree accounting
```

PRF handling:

- The showing branch derives the PRF key lanes from the new `M` layout.
- It builds a PRF companion witness and verifies the public `(nonce, tag)` relation through the existing PRF companion machinery.
- The replay layout records PRF key-source slots and verifies aggregate equality between companion key rows and the semantic `M` coefficient-view key lanes.

Public showing inputs in the IntGenISIS branch:

```text
A
B
C_M
A_s
nonce
tag
profile/dimension metadata
```

Forbidden public inputs in the IntGenISIS showing branch:

```text
c
T
Ac
RI0
RI1
old r0/r1 challenge data
```

What this corresponds to in the paper:

- `docs/arc_spruce_intgenisis/sections/04_arc_construction.tex`, `R_ShowARC`.
- `docs/arc_spruce_intgenisis/sections/05_smallwood_model.tex`, showing as a SmallWood statement.

Current limitations:

- The current showing proof verifies the blockwise hat-row signature/inverse equations, coefficient-view bounds for `M,s,e`, the coefficient-domain linear relation `Y = C_M M + A_s s + e`, PRF key equality against the semantic key lanes inside `M`, signed-radix packed-view `u` shortness, small-bound direct `u` membership, coeff-to-hat aggregate bridges for `u,Y`, and the PRF companion relation.
- The default no-disclosure showing proof no longer commits explicit packed `m` and `k` coefficient-view rows. The holder still validates the ring-tail-key semantic message before proving, and policy/disclosure rows should be reintroduced only for presentation policies that need them.
- It does not yet prove `mu_sig`, `x0`, or `x1` distribution/range constraints if those are required by the final concrete DKLW domain.
- The live NTRU `u` shortness bound is carried in credential state/verifier key artifacts and bound into Fiat-Shamir. The current large-beta PIOP proves the `7320` signed-radix capacity while the builder enforces exact `beta=6142`; exact beta comparison inside the proof remains open.
- The executable sweep now includes the `theta>1` small-field branch from the 2025/1085 model. The PCS path preserves IntGenISIS literal row heads on Ω, expands them into the §5.4 small-field matrix, and commits split extension-field Q rows. Existing `theta=1, rho=7` candidates remain useful as a stable baseline while new `theta>1` sweeps are regenerated.

### SmallWood Row Inventory Benchmark

Files:

- `PIOP/intgenisis_layout.go`
- `cmd/issuance/benchmark_intgenisis.go`

Core API:

```go
PIOP.BuildIntGenISISRowInventory(profileName, packingFactor)
```

CLI command:

```bash
go run ./cmd/issuance benchmark-intgenisis
```

End-to-end proof-size command:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -artifact-dir credential/issuance/intgenisis_e2e \
  -force \
  -ncols 16 \
  -lvcs-ncols 32 \
  -nleaves 4096 \
  -ell 4 \
  -showing-compressed-rows 0 \
  -json-out credential/issuance/intgenisis_e2e_report.json
```

This command runs profile-routed setup, NTRU key setup, holder commit, holder pre-sign proof, issuer verify/sign, holder finalize, standalone showing proof, standalone presentation verification, and replay-state rejection. It prints live proof payload bytes plus the paper transcript byte buckets for both issuance and showing.

Profile B at `s_SW=16`:

```text
rows per ring polynomial = 512 / 16 = 32
pre-sign ring polynomials = 6
pre-sign rows = 192
showing logical witness ring polynomials = 13
showing committed coefficient-view polynomials = 7
coefficient-view rows = 224
u R11/L4 shortness rows = 256
signature/inverse hat rows = 256
non-PRF live showing rows = 736
bound-view subset rows = 128
u/Y coeff-to-hat bridge families = 1536
Y coefficient-linear families = 512
```

Profile A at `s_SW=16`:

```text
rows per ring polynomial = 256 / 16 = 16
pre-sign ring polynomials = 8
pre-sign rows = 128
showing non-PRF ring polynomials = 15
showing non-PRF rows = 240
```

The JSON report also includes relation-bucket metrics for coefficient-view rows, bound rows, R11/L4 shortness rows, hat rows, coeff-to-hat bridge families, degree metadata, proof-report bucket counts, and live proof-size/proving-time/verification-time measurements for the selected profile.

The live degree metadata now distinguishes the ternary witness domain from the public compatibility bound. For real IntGenISIS showing proofs with the default R11/L4 shortness, the parallel algebraic degree is dominated by shortness (`d=11`), not the old direct `[-8,8]` range polynomial. For pre-sign proofs, ternary membership gives `d=3`. Q and mask sampling use the paper Eq. (3) conservative degree:

```text
d_Q = max(d * (ell + ncols - 1) + ncols - 1, d_agg * (ell + ncols - 1))
```

### Optional SmallWood Ternary Carrier Compression

The showing branch now has an opt-in row-compression path for the ternary `M`, `s`, and `e` coefficient-view surface. This follows the lattice-witness compression method from `docs/2025-1085.pdf`: pack `p` small-alphabet values into one carrier `c in S`, prove `c in S`, and use public univariate decompression polynomials to recover the logical values inside the remaining constraints.

For IntGenISIS profiles A and B the source alphabet is centered ternary. The implementation maps:

```text
{-1,0,1} -> {0,1,2}
carrier c = sum_i (v_i + 1) * 3^i
S = {0, ..., 3^p - 1}
membership degree = 3^p
decompression degree = 3^p - 1
```

The flag is intentionally level-based:

```text
benchmark/sweep compressed_rows=0, showing CLI -intgenisis-compressed-rows 0: no compression
benchmark/sweep compressed_rows=1, showing CLI -intgenisis-compressed-rows 1: pack p=2, |S|=9
benchmark/sweep compressed_rows=2, showing CLI -intgenisis-compressed-rows 2: pack p=3, |S|=27
benchmark/sweep compressed_rows=3, showing CLI -intgenisis-compressed-rows 3: pack p=4, |S|=81
```

Only `M`, `s`, and `e` coefficient-view rows are compressed. The proof does not commit the removed raw views. Instead:

```text
non-projected and projection v1:
  M/s/e carrier rows -> Decompress_i(carrier) -> coefficient-domain Y = C_M M + A_s s + e -> YView -> coeff-to-hat aggregate bridge/projected signature

projection v2:
  M/s/e carrier rows -> Decompress_i(carrier) -> direct projected signature contribution C_M(omega_t) Transform(M) + A_s(omega_t) Transform(s) + Transform(e)
```

The PRF key-source equality also reads the semantic key slots through `Decompress_i(M carrier)`, so compressed `M` remains the single key source. Compression metadata, the selected level, the carrier alphabet, replay projection mode, and the resulting degree accounting are Fiat-Shamir-bound through the IntGenISIS public extras and row layout. The raw flag default remains `compressed_rows=0`; the promoted compact `sw96-lvcs64` preset uses `compressed_rows=1`.

Current V2 audit snapshot for `sw96-lvcs64`:

```text
mode / showing override                 show_bytes  proof_bytes  eq8_bits  rows  replay_rows  Pdecs  VTargets  Q     R
non-projected selected preset            35295       76459        98.01     375   228          12337  6058      5973  7524
project_u_y_hat_v1                       35463       76802        98.01     327   228          12337  6058      5973  7524
project_u_y_hat_and_y_view_v2            32418       73595        98.01     311   190          10645  5050      5973  7524
v2, nleaves=53500 eta=46 ell=10          32293       72612        96.10     311   190          10645  5050      5973  7364
v2, theta=5 ell_prime=2 ell=10           33632       74908        96.10     311   185           8989  8410      4965  7364
v2, ell=12 nleaves=19952 eta=41          34009       71571        96.13     311   190          12766  5050      6243  6563
v2, R11/L4 theta=3 rho=2 ell'=2 kappa4=6 31232       80590        91.38*    279   140           8323  4420      7189  8229
```

`*` The promoted R11/L4 tuple is gated by SmallWood Theorem 9, not raw Eq. (8): measured theorem_total_bits is `96.50`, with `kappa4=6`. Raw Eq. (8) remains printed and should not be confused with the theorem-grinding target.

The promoted compact 96-bit projection point is:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset sw96-lvcs64 \
  -artifact-dir /tmp/intgenisis_r11l4_lvcs70_leaf42000_ell10_ncols32_projection_v2_k4only \
  -force \
  -showing-replay-projection project_u_y_hat_and_y_view_v2 \
  -showing-ncols 32 \
  -showing-lvcs-ncols 70 \
  -showing-nleaves 42000 \
  -showing-eta 47 \
  -showing-ell 10 \
  -showing-theta 3 \
  -showing-rho 2 \
  -showing-ell-prime 2 \
  -showing-sig-shortness-radix 11 \
  -showing-sig-shortness-digits 4 \
  -showing-compressed-rows 1 \
  -kappa4 6 \
  -json-out /tmp/intgenisis_r11l4_lvcs70_leaf42000_ell10_ncols32_projection_v2_k4only.json
```

## Commands To Run In Order

The commands below assume the repository root is the current directory:

```bash
cd "/home/jonas/Desktop/Spruce Folder/SPRUCE"
```

The recommended IntGenISIS paths below keep artifacts separate from legacy default JSON files.

### 1. Generate IntGenISIS Public Parameters

```bash
go run ./cmd/issuance setup-intgenisis-public \
  -out Parameters/credential_public.intgenisis.json \
  -b-path Parameters/Bmatrix.intgenisis.json \
  -profile intgenisis_profile_b \
  -force
```

What it does:

- generates BB-tran public data `B` with `ell_x0=2`;
- generates `C_M in R_q^{1 x 1}`;
- generates `A_s in R_q^{1 x 2}`;
- writes an IntGenISIS public-parameter file;
- records the chosen profile and dimension metadata.

Flag meanings:

- `-out`: output public-parameter JSON path.
- `-b-path`: output path for the BB-tran `B` matrix. If omitted, the command writes a default `Bmatrix.<profile>.json` beside `-out`.
- `-profile`: IntGenISIS profile name. Use `intgenisis_profile_b` for the N=512 implementation or `intgenisis_profile_a` for the N=256 implementation.
- `-force`: overwrite existing `-out` and `-b-path` files.

Paper correspondence:

- setup for `C_M`, `A_s`, and `B` in `Setup`.

### 2. Generate NTRU/SampPre Keys

```bash
go run ./cmd/issuance setup-ntru-keys \
  -research-ring-degree 512 \
  -params-out Parameters/Parameters.research_n512.json \
  -public-out ntru_keys/public.research_n512.json \
  -private-out ntru_keys/private.research_n512.json \
  -force
```

For profile A / `N=256`, use:

```bash
go run ./cmd/issuance setup-ntru-keys \
  -research-ring-degree 256 \
  -params-out Parameters/Parameters.research_n256.json \
  -public-out ntru_keys/public.research_n256.json \
  -private-out ntru_keys/private.research_n256.json \
  -force
```

What it does:

- generates NTRU parameters for the selected ring degree;
- generates issuer public/private key material;
- produces the trapdoor-backed signing material used by `issuer-verify-sign`.

Flag meanings:

- `-research-ring-degree`: use `512` for profile B or `256` for profile A. If omitted, the command uses legacy defaults that are not profile-aligned for IntGenISIS.
- `-params-out`: output NTRU parameter path.
- `-public-out`: output public key path.
- `-private-out`: output private key path.
- `-force`: overwrite existing key files.
- `-keygen-trials`: maximum trials per annulus keygen attempt. Defaults to `10000`.
- `-attempts`: number of annulus keygen attempts before failing. Defaults to `4`.

Paper correspondence:

- this is the implementation's `IKeyGen` and trapdoor setup for the preimage equation `A u = T`.

### 3. Holder Commitment

```bash
go run ./cmd/issuance holder-commit \
  -public-params Parameters/credential_public.intgenisis.json \
  -prf-params prf/prf_params.json \
  -holder-secret credential/issuance/intgenisis_holder_secret.json \
  -commit-request credential/issuance/intgenisis_commit_request.json \
  -seed 11 \
  -ncols 16 \
  -lvcs-ncols 32 \
  -nleaves 4096
```

What it does on IntGenISIS public params:

- samples ternary message slots `m` and a ternary PRF key `k`;
- packs `m` and `k` with `intgenisis_message_ring_tail_key_v1` into the semantic message polynomial `M`;
- samples `s` and `e` from `{-1,0,1}`;
- computes `c = C_M M + A_s s + e`;
- writes local holder witness material to `-holder-secret`;
- writes the public issuance request to `-commit-request`.

Important artifact privacy:

- `holder_secret.json` is secret and contains `M`, `k`, `s`, and `e`.
- `commit_request.json` is public to the issuer and contains `c`, not the opening.

Flag meanings:

- `-public-params`: IntGenISIS public parameter JSON.
- `-prf-params`: PRF parameter JSON. Defaults to `prf/prf_params.json`.
- `-holder-secret`: local holder-secret artifact path.
- `-commit-request`: public issuance request artifact path.
- `-expert-input`: legacy-only. The IntGenISIS branch rejects it.
- `-seed`: deterministic local sampling seed for reproducible tests. Use `0` for nondeterministic local RNG behavior.
- `-ncols`: witness packing width used by the pre-sign PIOP. Examples use `16`.
- `-lvcs-ncols`: LVCS width. Examples use `32`, though the pre-sign builder internally narrows the prepared commitment rows to the witness width where needed.
- `-nleaves`: explicit-domain size. Fast examples use `4096`.
- `-research-ring-degree`: optional override. Normally omitted because the public params already state the ring degree.

Paper correspondence:

- holder step: sample `k`, form `M=m||k`, sample `s,e`, send `(c, pi_pre)` later.

Current implementation note:

- the default CLI uses zero attributes across the `N-8` semantic `m` slots and stores the PRF key in the final eight coefficients `M[0][N-8..N-1]`.

### 4. Issuer Challenge Is Intentionally Absent

Run this only to confirm the guard:

```bash
go run ./cmd/issuance issuer-challenge \
  -commit-request credential/issuance/intgenisis_commit_request.json
```

Expected result:

```text
issuer-challenge is legacy-only; IntGenISIS issuance has no issuer challenge step
```

Flag meanings:

- `-commit-request`: reads the holder's public commit request.
- `-issue-challenge`: legacy output path. Ignored because IntGenISIS rejects the command.
- `-seed`: legacy challenge seed. Ignored because IntGenISIS rejects the command.

Paper correspondence:

- the old ARC-SPRUCE flow had issuer-side randomness shares and a challenge step;
- IntGenISIS does not have that step. The issuer samples `mu_sig`, `x0`, and `x1` only after verifying the pre-sign proof.

### 5. Holder Pre-Sign Proof

```bash
go run ./cmd/issuance holder-prove \
  -holder-secret credential/issuance/intgenisis_holder_secret.json \
  -presign-submission credential/issuance/intgenisis_presign_submission.json
```

What it does on IntGenISIS state:

- reloads the holder opening `(M,m,k,s,e)`;
- recomputes `c`;
- builds `PIOP.BuildIntGenISISPreSign`;
- writes the pre-sign proof into the pre-sign submission.

Flag meanings:

- `-holder-secret`: holder secret from `holder-commit`.
- `-presign-submission`: output proof artifact.
- `-issue-challenge`: still exists for legacy CLI compatibility. It is not read on the IntGenISIS path.

Artifact privacy:

- the pre-sign submission contains the proof, not `M`, `k`, `s`, or `e`.
- the IntGenISIS submission does not contain `T`.

Paper correspondence:

- creates `pi_pre` for `c = C_M M + A_s s + e` and `M=m+k`.

Current implementation note:

- the proof covers the commitment-opening equation, `M=m+k`, coefficient-view bounds/key membership, and the configured pre-sign policy descriptor.

### 6. Issuer Verification And Signing

```bash
go run ./cmd/issuance issuer-verify-sign \
  -commit-request credential/issuance/intgenisis_commit_request.json \
  -presign-submission credential/issuance/intgenisis_presign_submission.json \
  -issue-response credential/issuance/intgenisis_issue_response.json \
  -verifier-key-out credential/issuance/intgenisis_verifier_key.json \
  -ntru-params Parameters/Parameters.research_n512.json \
  -ntru-public-key ntru_keys/public.research_n512.json \
  -ntru-private-key ntru_keys/private.research_n512.json
```

What it does on IntGenISIS public params:

- verifies `pi_pre` using `PIOP.VerifyIntGenISISPreSign`;
- samples `mu_sig`, `x0`, and `x1`;
- resamples `x1` until `B3 - x1` is invertible;
- computes `Z`;
- computes `T = B0 + B1 mu_sig + B2 x0 + Z + c`;
- signs `T` with the NTRU/SampPre backend;
- writes the issuer response.
- optionally writes a public verifier-key artifact when `-verifier-key-out` is provided.

Flag meanings:

- `-commit-request`: public holder request containing `c`.
- `-presign-submission`: holder proof artifact.
- `-issue-response`: output issuer response.
- `-max-trials`: maximum NTRU signing trials. Defaults to `2048`.
- `-ntru-params`: NTRU parameter path for the profile-B signer/verifier.
- `-ntru-public-key`: issuer public key path.
- `-ntru-private-key`: issuer private key path.
- `-ntru-signature-out`: optional extra issuer-side signature artifact path.
- `-verifier-key-out`: optional standalone verifier key containing profile, public-parameter digest, and issuer public row.
- `-issue-challenge`: still exists for legacy compatibility. It is not read on the IntGenISIS path.

Artifact privacy and compatibility:

- the paper response is conceptually `(u, mu_sig, x0, x1)`;
- this implementation response contains `sig_s1`, `sig_s2`, `mu_sig`, `x0`, `x1`, and the issuer public row needed by holder finalization;
- it no longer serializes `T` or the full signature bundle in the live IntGenISIS response.

Paper correspondence:

- issuer steps in `Issue`: verify `pi_pre`, sample `mu_sig,x0,x1`, compute `Z,T`, run `SampPre`.

Current implementation note:

- presentation verification should use `-verifier-key`; holder finalization still reads the issuer public row from the response to check `A u = T`.

### 7. Holder Finalization

```bash
go run ./cmd/issuance holder-finalize \
  -holder-secret credential/issuance/intgenisis_holder_secret.json \
  -commit-request credential/issuance/intgenisis_commit_request.json \
  -issue-response credential/issuance/intgenisis_issue_response.json \
  -state-out credential/keys/credential_state.intgenisis.json \
  -signature-out credential/keys/signature.intgenisis.json \
  -ntru-params Parameters/Parameters.research_n512.json
```

What it does on IntGenISIS state:

- recomputes the holder commitment from `M,s,e`;
- checks it matches the public commit request;
- recomputes `T` from `c,mu_sig,x0,x1`;
- checks `A u = T` against the issuer public row and returned preimage rows;
- writes v5 IntGenISIS credential state.

Flag meanings:

- `-holder-secret`: local holder opening from `holder-commit`.
- `-commit-request`: public request containing `c`.
- `-issue-response`: issuer response from `issuer-verify-sign`.
- `-state-out`: output v5 credential state.
- `-signature-out`: legacy compatibility flag. The live IntGenISIS response no longer carries a signature bundle to save.
- `-ntru-params`: legacy compatibility flag for this branch.
- `-issue-challenge`: legacy compatibility flag. It is not read on the IntGenISIS path.

Final credential state:

- contains `u`, `M`, `m`, `k`, `s`, `e`, `mu_sig`, `x0`, `x1`;
- does not contain `c`;
- does not contain `T`;
- does not contain old shared-randomness material.

Paper correspondence:

- holder verifies the returned preimage signature and stores the post-issuance witness.

### 8. One-Shot Local Issuance Alternative

The full issuance flow can be run in one process:

```bash
go run ./cmd/issuance demo-local \
  -public-params Parameters/credential_public.intgenisis.json \
  -prf-params prf/prf_params.json \
  -artifact-dir credential/issuance/intgenisis \
  -state-out credential/keys/credential_state.intgenisis.json \
  -signature-out credential/keys/signature.intgenisis.json \
  -seed 11 \
  -ncols 16 \
  -lvcs-ncols 32 \
  -nleaves 4096 \
  -ntru-params Parameters/Parameters.research_n512.json \
  -ntru-public-key ntru_keys/public.research_n512.json \
  -ntru-private-key ntru_keys/private.research_n512.json
```

What it does:

- runs holder commit;
- skips issuer challenge because public params are IntGenISIS;
- runs holder prove;
- runs issuer verify/sign;
- runs holder finalize.

Flag meanings:

- `-public-params`, `-prf-params`, `-ncols`, `-lvcs-ncols`, `-nleaves`, `-seed`: same meanings as above.
- `-artifact-dir`: directory for intermediate artifacts.
- `-state-out`: final v5 credential state.
- `-signature-out`: compatibility signature artifact.
- `-max-trials`: maximum NTRU signing trials. Defaults to `2048`.
- `-research-ring-degree`: optional ring-degree override. Normally omitted for IntGenISIS because public params define `N=512`.
- `-ntru-params`, `-ntru-public-key`, `-ntru-private-key`, `-ntru-signature-out`: NTRU signing artifacts.

### 9. Showing

```bash
go run ./cmd/showing \
  -showing-profile showing_intgenisis_profile_b \
  -state-path credential/keys/credential_state.intgenisis.json \
  -presentation-out credential/issuance/intgenisis_presentation.json \
  -ncols 16 \
  -lvcs-ncols 32 \
  -nleaves 4096 \
  -max-nleaves 65536 \
  -eta 8 \
  -rho 1 \
  -theta 1 \
  -ell 4 \
  -ell-prime 4 \
  -prf-companion-mode output_audit
```

What it does:

- loads v5 IntGenISIS credential state;
- loads the referenced IntGenISIS public params and PRF params;
- loads `B`, `C_M`, and `A_s`;
- rebuilds the signature matrix `A` from the stored NTRU public row;
- recomputes `Z = (B3 - x1)^(-1)`;
- samples a public nonce for the local demo;
- computes `tag = PRF(k, nonce)`;
- builds `PIOP.BuildIntGenISISShowingCombined`;
- verifies it immediately with `PIOP.VerifyIntGenISISShowing`;
- writes a standalone presentation JSON when `-presentation-out` is provided;
- prints proof/report data.

Flag meanings for the IntGenISIS branch:

- `-showing-profile`: must be `showing_intgenisis_profile_b` for the new path.
- `-state-path`: v5 IntGenISIS credential state. Pass this explicitly. The legacy default path is not the IntGenISIS artifact.
- `-ncols`: witness support width. Must be at least the PRF key width. The recommended profile-B value is `16`.
- `-lvcs-ncols`: LVCS width. Recommended value is `32`.
- `-nleaves`: explicit-domain size. Recommended value is `4096` for local runs.
- `-eta`: DECS soundness parameter used by the proof stack. The prototype default for this branch is `8`.
- `-rho`: mask row count. The prototype default is `1`.
- `-theta`: theta folding parameter. The prototype default is `1`.
- `-ell`: DECS/LVCS hiding/opening parameter. The prototype default is `4`.
- `-ell-prime`: DECS/LVCS extension parameter. The prototype default is `4`.
- `-kappa1`, `-kappa2`, `-kappa3`, `-kappa4`: optional grinding/soundness knobs. Defaults are zero in this branch unless provided.
- `-prf-companion-mode`: PRF companion mode. Use `output_audit` for the current default.
- `-prf-checkpoint-samples`: number of checkpoint audits. Defaults to `8`.
- `-presentation-out`: optional standalone presentation JSON path containing profile, public-parameter digest, nonce, tag, and proof.
- `-verify-presentation`: verify an existing IntGenISIS presentation instead of proving.
- `-public-params`: public parameter JSON required for verifier-only presentation mode.
- `-verifier-key`: public verifier-key JSON required for verifier-only presentation mode.
- `-verifier-state`: optional persistent verifier replay-state path. When provided, repeated `(nonce, tag)` pairs are rejected across runs.

Flags parsed but not currently meaningful in the IntGenISIS branch:

- `-coeff-model`
- `-sig-shortness-profile`
- `-sig-shortness-radix`
- `-sig-shortness-digits`
- `-packed-sig-chain-group-size`
- `-sig-shortness-ncols`
- `-unsafe-shadow-sig-lookup-r121-l2`

Those flags remain relevant to the legacy showing profiles, but the IntGenISIS branch returns before applying the legacy maintained-profile/signature-shortness path.

Paper correspondence:

- `Show`: recompute `Z`, compute `tag`, prove the showing relation.
- `Verify`: verify the proof against public `nonce` and `tag`.

Verifier-only mode:

```bash
go run ./cmd/showing \
  -showing-profile showing_intgenisis_profile_b \
  -public-params Parameters/credential_public.intgenisis.json \
  -verifier-key credential/issuance/intgenisis_verifier_key.json \
  -verify-presentation credential/issuance/intgenisis_presentation.json \
  -verifier-state credential/issuance/intgenisis_verifier_state.json \
  -ncols 16 \
  -lvcs-ncols 32 \
  -nleaves 4096 \
  -eta 8 \
  -rho 1 \
  -theta 1 \
  -ell 4 \
  -ell-prime 4
```

Current implementation note:

- the presentation artifact omits `c`, `T`, `M`, `m`, `k`, `s`, `e`, `mu_sig`, `x0`, `x1`, `Z`, and `u`;
- the verifier path no longer loads private credential state. It reconstructs `A` from the public `-verifier-key` artifact and rejects replayed nonce/tag pairs when `-verifier-state` is provided.

### 10. Row Inventory Benchmark

```bash
go run ./cmd/issuance benchmark-intgenisis \
  -profiles intgenisis_profile_b,intgenisis_profile_a \
  -s-sw 16 \
  -json-out credential/issuance/intgenisis_benchmark.json
```

What it does:

- computes the row inventory for selected IntGenISIS profiles;
- labels the two benchmark surfaces as:
  - `intgenisis_mlwe_presign`
  - `intgenisis_mlwe_showing`
- writes optional JSON output.

Flag meanings:

- `-profiles`: comma-separated IntGenISIS profile names.
- `-s-sw`: SmallWood packing factor. Default is `16`.
- `-json-out`: optional report path.

Important limitation:

- this command reports relation buckets and row counts for every requested profile. It is still primarily a row-inventory command; use `benchmark-intgenisis-e2e -96bit`, `-preset 120bitsf`, or `-preset n256-sw128` for live profile-A proof measurements.

### 11. End-To-End Transcript Benchmark

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -artifact-dir credential/issuance/intgenisis_e2e \
  -force \
  -preset fast-local \
  -keygen-trials 10000 \
  -attempts 4 \
  -max-trials 2048 \
  -json-out credential/issuance/intgenisis_e2e_report.json
```

What it does:

- generates profile-routed public params and matching NTRU key material;
- runs holder commit, holder prove, issuer verify/sign, and holder finalize;
- builds a standalone IntGenISIS presentation from the finalized state;
- verifies the presentation from public params plus verifier key only;
- checks that the verifier state rejects a replayed nonce/tag pair;
- prints and optionally writes JSON for proof bytes, paper transcript bytes, proving time, verification time, row counts, PRF rows, bound rows, shortness rows, hat rows, `d_Q`, and paper transcript buckets.
- supports separate issuance/showing knobs with `-issuance-ncols`, `-issuance-lvcs-ncols`, `-issuance-nleaves`, `-issuance-eta`, `-issuance-theta`, `-issuance-rho`, `-issuance-ell`, `-issuance-ell-prime` and the matching `-showing-*` flags. Unprefixed knobs are shared defaults.
- supports showing shortness-shape tuning with `-showing-sig-shortness-radix` and `-showing-sig-shortness-digits`. Supported tuning shapes are odd signed-radix decompositions that cover `beta`; R121/L2 is rejected for IntGenISIS.
- supports the experimental IntGenISIS-native replay projection with `-showing-replay-projection project_u_y_hat_v1` or `-showing-replay-projection project_u_y_hat_and_y_view_v2`. V1 commits `UView` and `YView`, removes committed `UHat/YHat`, and derives their lane-projected NTT contribution inside the aggregate signature residual. V2 also removes `YView` and derives the `YHat` contribution directly as `C_M(omega_t) Transform(M) + A_s(omega_t) Transform(s) + Transform(e)` from authenticated `M/s/e` roots or carriers. Projection descriptors are Fiat-Shamir-bound, verifier options must match them, and proofs carrying omitted rows in projection mode are rejected. The compact `sw96-lvcs64` default now uses V2 projection; the raw flag default remains `none` for explicit non-preset experiments.
- supports named presets with `-preset` and the `-96bit` shorthand. Current static names are `96bit`, `120bitsf`, `fast-local`, `sw96-lvcs32`, `sw96-lvcs64`, `sw96-lvcs128`, `sw128-lvcs32`, `sw128-lvcs64`, `sw128-lvcs128`, `n256-sw96`, and `n256-sw128`. Explicit flags override preset values.
- caps explicit-domain size with `-max-nleaves`, default `65536`; named presets can raise this cap when their measured tuple requires a larger domain. Use `-max-nleaves 0` only for intentionally uncapped research runs.

Current preset values promoted into the static registry:

```text
preset          ncols  lvcs  nleaves  eta  theta  rho  ell  ell'  kappa       prf          g  samples  shortness  comp  projection
96bit           16     48    262144   44   2      3    8    3     {0,0,0,0} direct_auth  2  2        R7/L5      1     project_u_y_hat_and_y_view_v2
120bitsf        32     36    618048   42   2      3    9    4     {0,0,0,0} direct_auth  2  2        R5/L6      0     project_u_y_hat_and_y_view_v2
sw96-lvcs32     32     32    32448    29   6      1    10   1     {0,0,0,0} direct_auth  2  2        R7/L5      1     none
sw96-lvcs64     32     70    42000    47   3      2    10   2     {0,0,0,6} direct_auth  2  2        R11/L4     1     project_u_y_hat_and_y_view_v2
sw96-lvcs128    32     128   64512    77   6      1    11   1     {0,0,0,0} direct_auth  2  2        R7/L5      1     none
sw128-lvcs32    32     32    41088    33   7      1    13   1     {0,0,0,0} direct_auth  2  2        R7/L5      1     none
sw128-lvcs64    32     70    262144   59   7      1    10   1     {6,0,0,11} direct_auth 2  2        R11/L4     1     project_u_y_hat_and_y_view_v2
sw128-lvcs128   32     128   57344    79   7      1    15   1     {0,0,0,0} direct_auth  2  2        R7/L5      1     none
n256-sw96       16     48    262144   44   2      3    8    3     {0,0,0,0} direct_auth  2  2        R7/L5      1     project_u_y_hat_and_y_view_v2
n256-sw128      32     32    917504   40   1      7    9    11    {0,0,0,0} direct_auth  2  2        R5/L6      0     project_u_y_hat_and_y_view_v2
```

`sw96-lvcs64` and `sw128-lvcs64` are historical names for the compact projected defaults. Their showing LVCS width is now `70`, and their pass condition is theorem-level SmallWood ROM soundness rather than raw Eq. (8): `sw96-lvcs64` uses `kappa4=6` with measured `theorem_total_bits≈96.50`; `sw128-lvcs64` uses `kappa={6,0,0,11}` with measured showing snapshot `paper_transcript_bytes=36938`, `d_Q=482`, `VTargets=5155`, `Pdecs=9325`, `Q=8404`, `R=10330`, and `theorem_total_bits≈128.01`. A smaller 36,694-byte 128-bit research variant used `nleaves=180000`, `eta=58`, and `kappa4=16`, but its proving time was substantially higher. The issuance side of the compact 96-bit preset stays on the previous measured issuance tuple (`lvcs_ncols=64`, `theta=6`, `rho=1`, `ell'=1`) because issuance is not the recurring presentation cost.

The general `96bit` preset and the profile-specific `n256-sw96` preset both use measured viable-frontier candidate `est_000514` from the corrected 88-to-100-bit profile-A sweep. Its measured showing snapshot is `paper_transcript_bytes=22116`, `d_Q=222`, `rows=332`, `committed_cols=48`, `theorem_total_bits≈96.33`, and raw Eq. (8) `≈96.33`; its measured issuance snapshot is `paper_transcript_bytes=13652`, `committed_cols=48`, and `theorem_total_bits≈98.27`. The combined measured paper transcript size is `35768` bytes.

The `120bitsf` preset promotes measured focused-sweep candidate `est_1246730` as a zero-kappa 120-bit small-field baseline. Its measured showing snapshot is `paper_transcript_bytes=25232`, `d_Q=231`, `rows=207`, `committed_cols=36`, `theorem_total_bits≈120.01`, and raw Eq. (8) `≈120.01`; its measured issuance snapshot is `paper_transcript_bytes=14822`, `committed_cols=36`, and `theorem_total_bits≈120.01`. The combined measured paper transcript size is `40054` bytes.

The `n256-sw128` preset promotes measured focused-sweep candidate `est_490949` as the zero-kappa 128-bit profile-A default. Its measured showing snapshot is `paper_transcript_bytes=23100`, `d_Q=231`, `rows=207`, `committed_cols=32`, `theorem_total_bits≈131.49`, and raw Eq. (8) `≈131.49`; its measured issuance snapshot is `paper_transcript_bytes=15438`, `committed_cols=32`, and `theorem_total_bits≈131.75`. The combined measured paper transcript size is `38538` bytes.

The current N=256 preset references are:

```text
n256-sw96  measured showing paper_transcript_bytes=22116, dQ=222, theorem_total_bits=96.33, raw Eq.(8)=96.33, combined_paper_transcript_bytes=35768
120bitsf   measured showing paper_transcript_bytes=25232, dQ=231, theorem_total_bits=120.01, raw Eq.(8)=120.01, combined_paper_transcript_bytes=40054
n256-sw128 measured showing paper_transcript_bytes=23100, dQ=231, theorem_total_bits=131.49, raw Eq.(8)=131.49, combined_paper_transcript_bytes=38538
```

Run them with:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -96bit \
  -artifact-dir /tmp/intgenisis_n256_sw96 \
  -force \
  -json-out /tmp/intgenisis_n256_sw96.json
```

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset 120bitsf \
  -artifact-dir /tmp/intgenisis_120bitsf \
  -force \
  -json-out /tmp/intgenisis_120bitsf.json
```

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n256-sw128 \
  -artifact-dir /tmp/intgenisis_n256_sw128 \
  -force \
  -json-out /tmp/intgenisis_n256_sw128.json
```

If `-artifact-dir` is omitted, the command creates a temporary artifact directory and leaves it in place for inspection. Use `-force` when reusing an existing artifact directory.

Generated benchmark and sweep artifacts are intentionally not source artifacts. The repository ignores transient `credential/issuance/intgenisis_bench_*`, `intgenisis_sweep_*`, `intgenisis_audit_*`, `intgenisis_e2e`, and preset-measurement artifact directories/reports. Keep only compact curated evidence files when they are used to promote static presets; regenerate full measured reports with the commands below when auditing a tuning decision.

### 12. Degree-256 Parameter Search

Profile A is wired as an executable candidate, but parameter promotion must start from the Sage search pipeline. The N=256 orchestrator runs fixed-q and fully-split q-scan tracks for commitment, signature, and NTRU security, using the live ternary `B=1` witness domain.

```bash
python3 parameter_search/run_intgenisis_degree256.sage \
  --targets 96,128 \
  --estimator-path /tmp/lattice-estimator-dklw \
  --bits-start 12 \
  --bits-end 24 \
  --qs-per-bit 2 \
  --full-top 20 \
  --out-dir parameter_search/results/intgenisis_n256
```

Outputs:

```text
parameter_search/results/intgenisis_n256/target_96/*.csv
parameter_search/results/intgenisis_n256/target_128/*.csv
parameter_search/results/intgenisis_n256/intgenisis_n256_summary.json
```

The summary records accepted commitment/signature/NTRU counts, combined candidates, live ternary bound, compatibility public bound, and suggested Go preset commands. Promote an N=256 tuple only after the search summary and measured Go e2e run agree on commitment hiding, commitment binding, signature security, NTRU security, issuance proof soundness, showing proof soundness, presentation verification, and replay rejection.

For behavior-preserving cleanup passes, use `docs/arc_spruce_intgenisis/INTGENISIS_CLEANUP_PROMPT.md`. It records the current live profile-B invariants, legacy quarantine rules, and the focused verification commands.

### 12. Eq. (8) Parameter Sweep

For large tuning passes that should not build proofs, use the estimate-only sweep. It covers both live IntGenISIS ring degrees, filters on SmallWood Theorem 9 with `candidate_bits=min(issuance,showing)`, keeps only candidates in the 94-to-135-bit band by default, and drops candidates whose estimated showing transcript exceeds 50 KB. The sweep estimates each proof geometry once with `kappa={0,0,0,0}` and then chooses the smallest allowed kappa top-up that places the candidate in the target band; it does not emit a duplicate row for every kappa tuple because kappa changes grinding/prover work, not row counts, `d_Q`, or paper transcript bytes. The default kappa grid treats grinding as a small top-up only: every `kappa_i` is capped at 6 bits, with single-round top-ups and the measured-useful `kappa1/kappa4` combinations included.

```bash
go run ./cmd/issuance sweep-intgenisis-estimate \
  -profiles intgenisis_profile_a,intgenisis_profile_b \
  -grid estimate-deep \
  -soundness-min 94 \
  -soundness-max 135 \
  -max-showing-bytes 50000 \
  -max-kappa-per-round 6 \
  -prf-companion-modes direct_auth \
  -prf-group-rounds 2 \
  -prf-checkpoint-samples 2 \
  -out-dir credential/issuance/intgenisis_estimate_sweeps/run_001 \
  -progress \
  -progress-interval 1000 \
  -checkpoint-interval 5000 \
  -force
```

For the long full-grid run on a separate machine, keep the same command and choose a fresh run directory:

```bash
go run ./cmd/issuance sweep-intgenisis-estimate \
  -profiles intgenisis_profile_a,intgenisis_profile_b \
  -grid estimate-deep \
  -soundness-min 94 \
  -soundness-max 135 \
  -max-showing-bytes 50000 \
  -max-kappa-per-round 6 \
  -prf-companion-modes direct_auth \
  -prf-group-rounds 2 \
  -prf-checkpoint-samples 2 \
  -out-dir credential/issuance/intgenisis_estimate_sweeps/run_$(date -u +%Y%m%d_%H%M%S)_low_kappa \
  -progress \
  -progress-interval 1000 \
  -checkpoint-interval 5000 \
  -force
```

The command streams accepted candidates to `accepted_candidates.jsonl`, periodically syncs the file, rewrites the frontier CSV/JSON files as checkpoints, and updates `progress.json` plus a terminal progress bar over the outer grid. It writes `summary.json`, `frontier_all.csv`, `frontier_96.{json,csv}`, `frontier_128.{json,csv}`, `rejected_counts.json`, and `grid_config.json` under the selected output directory. Set `-progress=false` to silence the terminal bar or `-checkpoint-interval 0` to keep only the streaming JSONL plus final frontier files. It estimates row geometry, paper-conservative Eq. (3) `d_Q`, Eq. (8)/Theorem 9 round bits, and paper transcript buckets without setup, NTRU keygen, proving, presentation verification, or replay-state mutation. The PRF companion geometry is not a constant: the estimator loads `prf/prf_params.json`, applies the selected `-prf-group-rounds`, and packs key, checkpoint, and final-tag scalars at the candidate `ncols`; candidates with `ncols < lenkey` are rejected. The CSV frontiers include `issuance_ncols`, `prf_mode`, `prf_group_rounds`, `prf_checkpoint_samples`, and `showing_prf_rows` so a selected row can be replayed directly through `benchmark-intgenisis-e2e`. The accepted JSONL can be hundreds of GB on the full grid; for preset selection, the frontier CSV/JSON files plus `summary.json`, `rejected_counts.json`, and `grid_config.json` are the practical artifacts to copy back. Use the measured `benchmark-intgenisis-e2e` command on the selected frontier rows before promoting presets.

All generated estimate/sweep directories are ignored by git. To remove local sweep data after copying the frontier files you need, run:

```bash
rm -rf credential/issuance/intgenisis_estimate_sweeps \
       credential/issuance/intgenisis_sweep_* \
       credential/issuance/intgenisis_preset_sweep*.json
```

The default `estimate-deep` grid is intentionally pre-pruned before any candidate scoring. It keeps only round-2-plausible `theta/rho/ell_prime` families, uses V2 replay projection by default, excludes `ncols >= 256`, excludes `lvcs_ncols > 256`, excludes `ell > 32`, caps default leaf bases at `262144`, and skips compression level `3`. The retained grid is wider around the compact measured regions: `lvcs_ncols` includes the neighborhood around `70`, `ell` includes every value from `16` through `28`, small leaf bases include `768..2048`, and low-theta families include `theta=2,rho=3/4,ell_prime=3/4` plus nearby `theta=3/4` comparisons. These axes are chosen to catch candidates that barely miss the 96-bit line and can be boosted by at most six grinding bits without jumping to the old large-kappa regime. Re-enable pruned axes only for research checks with explicit `-theta`, `-rho`, `-ell-prime`, `-ncols`, `-lvcs-ncols`, `-ell`, `-nleaves`, `-compression-levels`, `-projection-modes`, `-prf-companion-modes`, `-prf-group-rounds`, or `-prf-checkpoint-samples` overrides.

For preset generation, use the fixed-LVCS preset sweep first. It creates independent 96-bit and 128-bit tracks for `lvcs_ncols` equal to `32`, `64`, and `128`, keeps a compact analytic frontier per track, and optionally measures only the top candidates:

```bash
go run ./cmd/issuance sweep-intgenisis-presets \
  -security-levels 96,128 \
  -lvcs-targets 32,64,128 \
  -max-nleaves 65536 \
  -fallback-max-nleaves 262144 \
  -max-analytic-per-track 128 \
  -max-measured-per-track 5 \
  -force \
  -artifact-dir /tmp/intgenisis_preset_measured \
  -json-out /tmp/intgenisis_preset_sweep.json \
  -preset-json-out credential/issuance/intgenisis_selected_presets_measured.json
```

Use analytic-only mode before measuring:

```bash
go run ./cmd/issuance sweep-intgenisis-presets \
  -security-levels 96,128 \
  -lvcs-targets 32,64,128 \
  -max-nleaves 65536 \
  -fallback-max-nleaves 262144 \
  -max-analytic-per-track 128 \
  -max-measured-per-track 0 \
  -force \
  -json-out /tmp/intgenisis_preset_sweep_analytic.json \
  -preset-json-out /tmp/intgenisis_selected_presets_analytic.json
```

Preset tracks use only valid profile-B packing divisors:

```text
lvcs=32:  ncols in {16,32}
lvcs=64:  ncols in {32,64}
lvcs=128: ncols in {32,64,128}
```

The primary leaf cap is `65536`. If a fixed-LVCS track cannot clear the raw Eq. (8) threshold under that cap, the command retries only that track with `-fallback-max-nleaves`, default `262144`, and marks the selected preset as requiring the fallback cap.

```bash
go run ./cmd/issuance sweep-intgenisis \
  -artifact-dir credential/issuance/intgenisis_sweep \
  -force \
  -grid wide \
  -target-eq8 128 \
  -margin 2 \
  -max-nleaves 65536 \
  -max-analytic 64 \
  -max-measured 8 \
  -keygen-trials 10000 \
  -attempts 4 \
  -max-trials 2048 \
  -json-out credential/issuance/intgenisis_sweep.json
```

What it does:

- analytically filters SmallWood Eq. (8) candidates using relation-aware paper Eq. (3) `d_Q` estimates for ternary `M,s,e` and the selected `u` shortness radix;
- enumerates optional showing `M/s/e` carrier-compression levels (`compressed_rows=0..3`, depending on grid) and accounts for both carrier membership degree and decompression bridge degree;
- supports `-grid quick`, `-grid wide`, `-grid deep`, `-grid strata`, `-grid leafcap64k`, `-grid pack64`, `-grid pack128`, `-grid pack256`, and `-grid packwide`;
- generates public params, NTRU keys, holder witness, issuer response, finalized state, verifier key, and a replay-checked presentation once;
- reuses those artifacts while measuring real issuance and showing proofs for the analytic frontier;
- requires raw Eq. (8) soundness for both issuance and showing to clear `target + margin`;
- sorts passing candidates by showing paper transcript bytes, then total issuance+showing transcript bytes.

Use `-max-measured 0` for an analytic-only run that writes the frontier JSON without generating reusable issuance/showing artifacts. This is the fastest way to inspect the full grid before paying for real proofs.

The analytic sweep path caches `nleaves` feasibility per `(lvcs_ncols, ell, threshold, cap)`, computes the minimum feasible `eta` directly from the first Eq. (8) term, memoizes repeated binomial terms, and keeps only the requested frontier while enumerating. On the local development machine, analytic-only runs complete in seconds after Go compilation.

The default `wide` grid is intentionally broad:

```text
theta/rho/ell_prime:
  (7,1,1), (8,1,1), (9,1,1), (10,1,1)
  (4,2,1), (4,2,2), (5,2,1), (5,2,2), (6,2,1), (6,2,2)
  (3,3,1), (3,3,2), (4,3,1), (4,3,2), (2,4,2), (2,4,3)
  theta=1 baselines: (1,7,12), (1,7,13), (1,8,10), (1,8,11), (1,9,9)

ncols:
  8, 16, 32, 64, 128

lvcs_ncols:
  8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 112, 128, 160, 192, 224, 256

ell:
  8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28

PRF:
  output_audit and direct_auth, checkpoint samples 2, 4, 8

shortness:
  R11/L4, R7/L5, R5/L6
```

The `strata` grid is a narrower measurement grid for transcript-reduction work. It forces `ncols in {32,64}`, `lvcs_ncols in {32,48,64,80,96,128,160}`, `theta in {7,8,9}`, `rho=1`, `ell_prime=1`, direct-auth PRF with two checkpoint samples, and the three shortness shapes above.

The large-packing grids are deep-style focused sweeps for DECS layer-boundary tuning:

```text
pack64:
  ncols = 64
  lvcs_ncols = 64, 72, 80, 96, 112, 128, 144, 160, 192, 224, 256, 288, 320, 384, 448, 512

pack128:
  ncols = 128
  lvcs_ncols = 128, 144, 160, 192, 224, 256, 288, 320, 384, 448, 512

pack256:
  ncols = 256
  lvcs_ncols = 256, 288, 320, 384, 448, 512

packwide:
  ncols = 64, 128, 256
  lvcs_ncols = 64, 72, 80, 96, 112, 128, 144, 160, 192, 224, 256, 288, 320, 384, 448, 512
```

These grids inherit the `deep` theta/rho/ell-prime families, `ell` coverage through `32`, `eta_slack=4`, `max_eta=128`, PRF modes `direct_auth` and `output_audit`, checkpoint samples `2,4,8`, and the R11/L4, R7/L5, and R5/L6 shortness shapes. They intentionally omit `ncols=96`: the current IntGenISIS coefficient-view and hat layouts require `ncols` to divide the profile-B ring degree `N=512`, and `96` would require a padded-final-block row layout that is not implemented.

Analytic-only large-packing commands:

```bash
go run ./cmd/issuance sweep-intgenisis \
  -grid pack64 \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 256 \
  -max-measured 0 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_pack64_analytic.json

go run ./cmd/issuance sweep-intgenisis \
  -grid pack128 \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 256 \
  -max-measured 0 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_pack128_analytic.json

go run ./cmd/issuance sweep-intgenisis \
  -grid pack256 \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 256 \
  -max-measured 0 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_pack256_analytic.json

go run ./cmd/issuance sweep-intgenisis \
  -grid packwide \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 512 \
  -max-measured 0 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_packwide_analytic.json
```

Measured large-packing commands:

```bash
go run ./cmd/issuance sweep-intgenisis \
  -artifact-dir credential/issuance/intgenisis_sweep_pack64 \
  -grid pack64 \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 128 \
  -max-measured 12 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_pack64_measured.json

go run ./cmd/issuance sweep-intgenisis \
  -artifact-dir credential/issuance/intgenisis_sweep_pack128 \
  -grid pack128 \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 128 \
  -max-measured 12 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_pack128_measured.json

go run ./cmd/issuance sweep-intgenisis \
  -artifact-dir credential/issuance/intgenisis_sweep_pack256 \
  -grid pack256 \
  -target-eq8 128 \
  -margin 2 \
  -max-analytic 128 \
  -max-measured 12 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_pack256_measured.json
```

For every `(lvcs_ncols, ell)` pair, the sweep computes the smallest feasible `nleaves` for the fourth Eq. (8) term and adds nearby rounded values. The command-level default cap is now `-max-nleaves 65536`; this intentionally prevents the sweep from selecting very large Merkle domains such as `917504` leaves. Passing `-max-nleaves 0` restores the old uncapped research behavior, still bounded internally below the base-field size.

The reason `nleaves` looks high is the fourth Eq. (8) term:

```text
round4_bits = log2 binom(nleaves, ell) - log2 binom(lvcs_ncols + ell - 1, ell)
```

For fixed `lvcs_ncols`, small `ell` requires a very large explicit domain. At `lvcs_ncols=32`, the exact profile-B boundary for `round4_bits >= 130` is approximately:

```text
ell=8   infeasible under 2^20 leaves
ell=9   nleaves >= 800560
ell=10  nleaves >= 298084
ell=11  nleaves >= 133122
ell=12  nleaves >= 68136
ell=14  nleaves >= 23904
ell=16  nleaves >= 10959
ell=20  nleaves >= 3729
```

The paper tradeoff is:

- increasing `ell` sharply reduces the `nleaves` needed by round 4;
- lowering `lvcs_ncols` also reduces the round-4 denominator, but may increase row-block pressure elsewhere;
- increasing `eta` repairs round 1 when needed;
- increasing `theta*rho` repairs round 2 without increasing `nleaves`;
- increasing `ell_prime` or lowering `d_Q` repairs round 3 without increasing `nleaves`;
- `kappa4` only helps theorem-level ROM aggregation and does not improve raw Eq. (8) bits.

The useful region is therefore not "smallest nleaves"; it is the transcript minimum across the `ell`/`N`/`eta` boundary. For capped runs, start with the low-leaf grid:

```bash
go run ./cmd/issuance sweep-intgenisis \
  -grid leafcap64k \
  -target-eq8 128 \
  -margin 2 \
  -max-nleaves 65536 \
  -max-analytic 64 \
  -max-measured 0 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_leafcap64k_analytic.json
```

Stricter cap probe:

```bash
go run ./cmd/issuance sweep-intgenisis \
  -grid leafcap64k \
  -target-eq8 128 \
  -margin 2 \
  -max-nleaves 16384 \
  -max-analytic 64 \
  -max-measured 0 \
  -force \
  -json-out credential/issuance/intgenisis_sweep_leafcap16k_analytic.json
```

Precomputed analytic frontiers after the ternary/compression rewrite:

```text
cap=65536:
  first frontier shape:
    ncols=32 lvcs_ncols=32 nleaves≈40960 eta=33 theta=7 rho=1 ell=13 ell_prime=1
    showing: direct_auth, checkpoint_samples=2, shortness=R7/L5, compressed_rows=1
    analytic showing: d_Q=427, Eq8≈130.18 bits, rows≈605

cap=32768:
  first frontier shape:
    ncols=32 lvcs_ncols=32 nleaves≈25344 eta=32 theta=7 rho=1 ell=14 ell_prime=1
    showing: direct_auth, checkpoint_samples=2, shortness=R7/L5, compressed_rows=1
    analytic showing: d_Q=436, Eq8≈130.23 bits, rows≈605

cap=16384:
  first frontier shape:
    ncols=32 lvcs_ncols=32 nleaves=16384 eta=31 theta=7 rho=1 ell=15 ell_prime=1
    showing: direct_auth, checkpoint_samples=2, shortness=R7/L5, compressed_rows=1
    analytic showing: d_Q=445, Eq8≈130.04 bits, rows≈605

cap=4096:
  first frontier shape:
    ncols=32 lvcs_ncols=32 nleaves≈3904 eta=27 theta=7 rho=1 ell=20 ell_prime=1
    showing: direct_auth, checkpoint_samples=2, shortness=R7/L5, compressed_rows=1
    analytic showing: d_Q=490, Eq8≈130.22 bits, rows≈619
```

These are analytic frontiers, not promoted measured defaults. The next measurement pass should use the capped frontier and compare the first 3-5 candidates at `cap=4096`, `16384`, `32768`, and `65536`.

The prior sweep JSON predates the compact showing row surface. Regenerate measured sweeps before promoting a new default. A smoke measurement on April 29, 2026 at the previous best `theta>1` candidate after row pruning was:

```text
issuance/showing:
  ncols=32
  lvcs_ncols=32
  nleaves=917504
  eta=41
  theta=7
  rho=1
  ell=9
  ell_prime=1
  kappa=[0,0,0,0]
showing PRF:
  prf_companion_mode=direct_auth
  prf_checkpoint_samples=2
showing shortness:
  R11/L4

measured:
  issuance soundness_eq8_bits=130.29
  showing soundness_eq8_bits=130.29
  showing paper_transcript_bytes=50685
  issuance paper_transcript_bytes=26170
  total paper_transcript_bytes=76855
  showing proof_bytes=103824
  showing prove_ms≈67502
  showing verify_ms≈6941
  rows=407
  prf_rows=7
  coefficient_view_rows=96
  bound_rows=64
  shortness_rows=128
  hat_rows=176
  historical pre-Y-linear coeff_to_hat_bridge_constraints=3072
  d_Q=558
  round_bits=[158.35, 140.06, 130.93, 131.77]
```

This block is a historical pre-`YView/YHat` measurement. Current runs print separate `y_coefficient_view_rows`, `y_hat_rows`, and `y_linear_constraints`; re-run the benchmark after the Y-linear refactor before comparing transcript minima. At that same historical PCS point, R7/L5 produced `showing paper_transcript_bytes=51242`: lower shortness degree did not reduce `d_Q=558`, and the extra digit rows dominated. The `strata` grid is intended to find PCS widths or theta families where a lower-degree shortness shape actually helps.

The previous pre-pruning `theta=1` baseline should be remeasured under the compact row surface:

```text
ncols=32 lvcs_ncols=32 nleaves=196608 eta=37 theta=1 rho=7 ell=11 ell_prime=13
prf_companion_mode=direct_auth prf_checkpoint_samples=2
```

Current sweep status:

- `theta>1` SmallWood candidates are executable again. The small-field PCS path uses literal IntGenISIS row heads on Ω, preserves the logical witness row count for K-point replay, and commits split Q limb rows with `QOpening.R = rho * theta`.
- The compact row surface has not yet been fully swept. Use `-grid strata` for forced transcript-reduction measurements, then rerun `-grid deep` for a broad frontier.

## Verification Commands

Run all repository tests:

```bash
go test ./... -count=1
```

Focused IntGenISIS tests:

```bash
go test ./commitment ./credential ./issuance ./PIOP ./cmd/issuance -run 'IntGenISIS|Target' -count=1
```

Focused PIOP tests:

```bash
go test ./PIOP -run 'TestIntGenISIS(PreSignProofBuildsAndVerifies|ShowingProofBuildsAndVerifies)' -count=1
```

What the current tests cover:

- IntGenISIS public parameter/profile shape.
- Semantic message layout round trips, key extraction, reserved-slot rejection, and mutation rejection.
- Target-shaped commitment sampling, computation, and opening verification.
- IntGenISIS target computation and tampered-commitment rejection.
- v5 credential-state serialization and old-randomness omission.
- Pre-sign PIOP proof build/verify.
- Pre-sign rejection for tampered `c`, `C_M`, `A_s`, row layout, and proof root.
- Pre-sign policy binding for `noop` and the `m_eq` test policy.
- Showing PIOP proof build/verify for a synthetic profile-B witness.
- Showing rejection for forbidden public `c` and tampered `B`.
- CLI setup, NTRU keygen, holder commit, issuer-challenge guard, holder prove, issuer verify/sign, holder finalize, standalone show, standalone verify, and replay rejection.
- Issuer response privacy for omitted `T`/signature bundle and `A u = T` response verification.
- Presentation privacy and verifier replay-state rejection.
- Public verifier-key artifact round trip.

Known test gap:

- the full CLI integration tests cover profile B and an N=256 profile-A preset smoke, but final profile-A parameter promotion still depends on the Sage search summary and measured frontier review.

## Artifact Map

Recommended IntGenISIS artifacts:

```text
Parameters/credential_public.intgenisis.json
Parameters/Bmatrix.intgenisis.json
Parameters/Parameters.research_n512.json
ntru_keys/public.research_n512.json
ntru_keys/private.research_n512.json
Parameters/credential_public.intgenisis_profile_a.json
Parameters/Bmatrix.intgenisis_profile_a.json
Parameters/Parameters.research_n256.json
ntru_keys/public.research_n256.json
ntru_keys/private.research_n256.json
credential/issuance/intgenisis_holder_secret.json
credential/issuance/intgenisis_commit_request.json
credential/issuance/intgenisis_presign_submission.json
credential/issuance/intgenisis_issue_response.json
credential/issuance/intgenisis_verifier_key.json
credential/issuance/intgenisis_presentation.json
credential/issuance/intgenisis_verifier_state.json
credential/keys/credential_state.intgenisis.json
```

Artifact contents:

| Artifact | Secret? | Main contents | IntGenISIS notes |
|---|---:|---|---|
| public params | no | profile, `C_M`, `A_s`, `BPath`, dimensions | profile-routes new flow |
| B matrix | no | BB-tran `B` data | `ell_x0=2` |
| NTRU public key | no | issuer verification key row | used to build showing `A` |
| NTRU private key | yes | issuer trapdoor key | used only by issuer signing |
| holder secret | yes | `M`, `m`, `k`, `s`, `e` | local holder material |
| commit request | no | `c`, profile/proof geometry metadata | no `M/s/e`, no `T` |
| pre-sign submission | no | `pi_pre` | no `T` in IntGenISIS branch |
| issue response | holder-private transcript | `u`, `mu_sig`, `x0`, `x1`, issuer public row | no serialized `T` in live IntGenISIS schema |
| v5 credential state | yes | `u`, `M`, `m`, `k`, `s`, `e`, `mu_sig`, `x0`, `x1`, signature bound | no `c`, no `T`, no old randomness |
| verifier key | no | profile, public-params digest, issuer public row, signature bound | verifier-only showing input |
| presentation | no | profile, public-params digest, nonce, tag, proof | omits credential witness and issuance transcript |
| verifier state | verifier-private | seen nonce/tag keys | rejects replay when supplied |

## Correctness And Completeness Status

### Correct For The Implemented Prototype Surface

The following implementation claims are supported by code and tests:

- IntGenISIS profile B dimensions are represented and validated.
- `C_M` and `A_s` are generated and stored under the public-parameter schema.
- The target commitment computes `c = C_M M + A_s s + e` with live ternary `M,s,e` sampling on the IntGenISIS path.
- Profile-B semantic layout helpers encode and validate ternary `M=m||k`.
- The standalone commitment opening verifier checks dimensions, the public compatibility bound, and recomputation; the IntGenISIS proof relation enforces the stricter ternary domain.
- The issuer-side target computation uses `mu_sig`, `x0`, `x1`, `Z`, and `c`.
- The old issuer challenge command rejects IntGenISIS public params.
- The pre-sign PIOP verifier replay is implemented and no longer a placeholder.
- The IntGenISIS pre-sign replay rejects old public statement fields.
- The IntGenISIS pre-sign proof includes explicit `M`, `m`, and `k` rows and enforces `M-m-k=0`.
- The IntGenISIS pre-sign proof includes coefficient-view rows for `M,m,k,s,e`, ternary membership constraints, and a public policy descriptor.
- The showing PIOP branch verifies the blockwise hat-row signature equation and inverse equation.
- The showing branch uses a compact no-disclosure row surface: coefficient-view rows for `u,M,s,e` by default, optional SmallWood carrier rows for compressed `M,s,e`, a coefficient-view `Y = C_M M + A_s s + e`, direct hat rows for `mu_sig,x0,x1,Z`, NTT/replay hat rows for `u,Y`, R11/L4 digit rows for packed `u` views, ternary/carrier membership constraints for `M,s,e`, coeff-to-hat aggregate bridges for `u,Y`, and PRF key-source equality over semantic `M` key lanes.
- The showing public inputs reject `c`, `T`, `Ac`, `RI0`, and `RI1`.
- The issuer response omits serialized `T` and full signature bundles on the live IntGenISIS path.
- Presentation artifacts and verifier replay state are implemented for the IntGenISIS showing CLI.
- Presentation verification can run from public params plus the verifier-key artifact without loading private credential state.
- v5 credential state omits old shared-randomness and holder-computed-target fields.

### Not Complete Relative To The Paper

The implementation is not yet a complete ARC-SPRUCE IntGenISIS realization. The largest gaps are:

1. Pre-sign relation incompleteness:
   - implemented: `c = C_M M + A_s s + e`;
   - implemented: whole-row `M=m+k` binding under the ring-tail-key semantic layout;
   - implemented: coefficient-view ternary membership for `M,m,k,s,e`, including `K_key={-1,0,1}^8` in the live profile-B proof;
   - implemented: default `noop` policy and public `m_eq` test policy;
   - remaining review item: formalize the coefficient-view bridge in the paper-facing SmallWood model.

2. Showing relation incompleteness:
   - implemented: inverse equation;
   - implemented: signature equation with hidden commitment term;
   - implemented: compact no-disclosure showing surface with packed coefficient-view `M` rows and PRF key lanes derived from the final semantic slots of `M`;
   - implemented: PRF companion proof over key lanes derived by the honest builder from `M`;
   - implemented: verifier replay equality over configured PRF companion key-source slots sourced from semantic `M` coefficient-view lanes;
   - implemented: coefficient-view ternary membership for `M,s,e`;
   - implemented: coefficient-domain `Y = C_M M + A_s s + e`, coeff-to-hat aggregate bridges for `u,Y`, and blockwise hat-row signature/inverse equations over direct or bridged hats for `u,Y,mu_sig,x0,x1,Z`;
   - implemented: live NTRU signature-bound validation for `u`, with Fiat-Shamir-bound signed-radix packed-view shortness proving capacity `7320` under the default R11/L4 shape and direct PIOP range membership for small synthetic bounds;
   - implemented: transcript-tuning shortness variants R7/L5 and R5/L6; R121/L2 remains rejected for IntGenISIS;
   - missing: presentation-policy rows for disclosures that require explicit `m` projections;
   - missing: final distribution/range constraints for `mu_sig,x0,x1` if the concrete DKLW domain requires them;
   - remaining review item: add the theorem-grade exact-beta comparison inside the proof.

3. Issuer response minimization:
   - implemented: no serialized `T` or full signature bundle in the live IntGenISIS response;
   - implemented: optional standalone verifier-key artifact for presentation verification;
   - remaining cleanup: holder finalization still receives the issuer public row in the response so it can check `A u = T`.

4. Standalone showing presentation:
   - implemented: presentation JSON with nonce, tag, proof, profile, and public-parameter digest;
   - implemented: verifier-state replay rejection for repeated nonce/tag pairs when `-verifier-state` is provided;
   - implemented: verifier mode accepts public params plus verifier key and does not load credential state.

5. Soundness/proof-size finality:
   - row inventory is implemented;
   - final proof sizes, proving time, verification time, and full SmallWood optimizer outputs are not final;
   - the security proof remains conditional in the paper and the implementation has not completed all relation gadgets needed for that proof surface.

6. Profile A:
   - represented in profile and row-inventory code;
   - not verified as an end-to-end protocol because `N=256` NTRU/ring support is not proven through setup, issuance, signing, showing, and tests.

## Relationship To The Old Legacy Flow

The old flow remains for legacy tests and old public params:

```text
holder-commit -> issuer-challenge -> holder-prove -> issuer-verify-sign -> holder-finalize
```

The IntGenISIS flow is:

```text
holder-commit -> holder-prove -> issuer-verify-sign -> holder-finalize
```

There is no IntGenISIS issuer challenge.

The old flow signs a holder-derived target involving old shared-randomness material. The new flow signs an issuer-derived target:

```text
T = B0 + B1 mu_sig + B2 x0 + Z + c
```

In the new flow:

- the holder sends `c` and `pi_pre`;
- the issuer computes `T`;
- the holder stores the credential witness;
- showing does not reveal `c`.

## Remaining Work

Recommended implementation order:

1. Formalize coefficient-view gadgets:
   - document the exact coefficient-view bridge in the SmallWood model;
   - review the current live `K_key={-1,0,1}^8` profile-B assumption if a wider PRF key space is required.

2. Complete the final showing relation:
   - replace or justify the current large-beta `u` shortness handling with the theorem-grade IntGenISIS signature-shortness gadget;
   - add any required `mu_sig,x0,x1` distribution/range constraints.

3. Finish issuer/public-key artifact cleanup:
   - keep verifier-only mode on the standalone verifier key;
   - decide whether holder finalization should also load the verifier key instead of reading the issuer public row from the response.

4. Finish CLI integration tests:
   - setup public params;
   - setup NTRU keys;
   - holder commit;
   - holder prove;
   - issuer verify/sign with `-verifier-key-out`;
   - holder finalize;
   - showing build/verify;
   - verifier-only presentation verification and replay rejection.

5. Rerun measurement harness:
   - proof size;
   - proving time;
   - verification time;
   - PRF auxiliary rows;
   - total SmallWood rows;
   - `d_Q` or equivalent degree parameter;
   - QR, RowOpening, BarSets, and VTargets sizes if present.
   - start with `sweep-intgenisis -grid strata` for forced `theta>1`/PCS-width/shortness-shape measurements, then rerun `-grid deep` for the broad frontier.

6. Decide and document DKLW sampling domains:
   - either justify full-ring uniform `mu_sig,x0,x1`;
   - or replace the placeholder sampler with the exact distribution required by the concrete theorem.

7. Quarantine legacy artifacts:
   - keep old challenge-based CLI behavior only for old public params;
   - move old JSON samples and tests under explicit legacy names;
   - ensure generated docs and examples default to IntGenISIS once the missing gadgets are complete.

## Practical Recommendation

Use the current implementation for prototype development and relation debugging, not as a complete cryptographic implementation. The implemented algebraic core is the right IntGenISIS direction: `M` is hidden by the target-shaped MLWE commitment, `mu_sig/x0/x1` are issuer-side BB-tran values, packed `u` coefficients are shortness-checked and bridged or projected into the signature equation, issuer-side BB-tran rows are hat-only in the default showing surface, and showing no longer uses old `r0/r1` target-hiding randomness. The remaining caveats are now narrower: the default R11/L4 `u` shortness surface proves the `7320` capacity rather than exact `6142` inside the proof, presentation policies that need disclosed `m` slots need explicit projection rows, `mu_sig/x0/x1` sampling domains remain placeholders, and profile A still requires estimator-backed parameter promotion before it should be treated as final.
