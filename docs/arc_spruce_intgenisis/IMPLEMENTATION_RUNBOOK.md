# ARC-SPRUCE IntGenISIS Implementation Runbook

This document describes the IntGenISIS-style ARC-SPRUCE implementation currently present in this repository. It covers:

- what routines were added or rerouted;
- how those routines correspond to the IntGenISIS paper construction under `docs/arc_spruce_intgenisis`;
- how to run setup, issuance, showing, tests, and row-inventory benchmarks;
- which command flags matter for the IntGenISIS path;
- what is correct today;
- what is still incomplete relative to the paper.

The short status is:

The repository now has a working IntGenISIS prototype path for profile B. It supports target-shaped commitments, issuer-side target computation, a real PIOP verifier replay for the new pre-sign commitment-opening rows, an IntGenISIS showing relation branch, profile-routed CLI issuance, and an in-process showing command. The implementation is not paper-complete yet. The remaining gaps are listed in [Correctness And Completeness Status](#correctness-and-completeness-status) and [Remaining Work](#remaining-work).

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
  - primary profile B row arithmetic: 4 pre-sign ring polynomials, 11 showing ring polynomials, 128 and 352 non-PRF rows at `s_SW=16`.

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

Primary profile B is the active target:

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

Compact profile A is represented for row inventory:

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
```

Profile A is not yet an end-to-end supported protocol profile because the `N=256` NTRU/ring path has not been verified as a full issuance and showing stack.

Important public parameter fields:

- `Profile`: selects `intgenisis_profile_b` or `intgenisis_profile_a`.
- `RingDegree`: profile ring degree.
- `CM`: coefficient-domain serialized `C_M`.
- `AS`: coefficient-domain serialized `A_s`.
- `BPath`: file containing the BB-tran public `B` matrix.
- `BoundB` and `CommitmentBound`: currently profile bound `B=8`.
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
commitment.SampleCommitmentRandomness(params, rng)
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
- `SampleCommitmentRandomness` samples `s` and `e` coefficient-wise from `[-B,B]`.
- `VerifyCommitmentOpening` checks dimensions, centered coefficient bounds for `M`, `s`, and `e`, recomputes `c`, and compares it to the supplied public commitment.

What this corresponds to in the paper:

- `docs/arc_spruce_intgenisis/sections/02_preliminaries.tex`, commitment preliminaries.
- `docs/arc_spruce_intgenisis/sections/03_blind_signature.tex`, pre-sign issuance relation.

Current limitation:

- The standalone commitment verifier checks bounds directly, but the current PIOP pre-sign proof only enforces the commitment-opening equation. It does not yet prove all bound checks in zero knowledge.

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
s rows next: k_s
e rows next: n_c
```

For profile B this is:

```text
M: 1
s: 2
e: 1
total: 4 ring polynomials
```

Verified relation:

```text
C_M M + A_s s + e - c = 0
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
- Fiat-Shamir binding includes the IntGenISIS marker, `Com`, `C_M`, `A_s`, profile-relevant dimensions, and the bound.

What this corresponds to in the paper:

- `docs/arc_spruce_intgenisis/sections/03_blind_signature.tex`, `R_IssueBS`.
- `docs/arc_spruce_intgenisis/sections/04_arc_construction.tex`, `R_IssueARC`.
- `docs/arc_spruce_intgenisis/sections/05_smallwood_model.tex`, issuance as a SmallWood statement.

Current limitation:

- The current PIOP pre-sign surface proves the commitment equation only.
- It does not yet prove `M = m || k`.
- It does not yet prove PRF key-space membership.
- It does not yet prove issuance policy constraints on `m`.
- It does not yet prove coefficient bounds for `M`, `s`, and `e` inside the PIOP.

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

Witness row order before PRF auxiliary rows:

```text
u:        2
M:        1
s:        2
e:        1
mu_sig:   1
x0:       2
x1:       1
Z:        1
total:   11 ring polynomials
```

Verified algebraic relations:

```text
(B3 - x1) * Z = 1
A u = B0 + B1 mu_sig + B2 x0 + Z + C_M M + A_s s + e
```

PRF handling:

- The showing branch derives the PRF key lanes from the new `M` layout.
- It builds a PRF companion witness and verifies the public `(nonce, tag)` relation through the existing PRF companion machinery.

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

- The current showing proof verifies the signature/inverse equations and PRF companion relation, but it is not yet the full paper relation.
- It does not yet include explicit `m` rows or a full `M = m || k` encoding proof.
- It does not yet prove coefficient bounds for `M`, `s`, and `e` inside the PIOP.
- It does not yet prove `mu_sig`, `x0`, or `x1` distribution/range constraints if those are required by the final concrete DKLW domain.
- It does not yet wire the full signature shortness proof for the IntGenISIS row layout.
- The PRF companion is generated from `M`, but the current companion layout records `KeySourceIndependentWitness`; a rigorous final version should add explicit row-equality constraints tying the companion key rows back to the key slots inside `M`.

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

Profile B at `s_SW=16`:

```text
rows per ring polynomial = 512 / 16 = 32
pre-sign ring polynomials = 4
pre-sign rows = 128
showing non-PRF ring polynomials = 11
showing non-PRF rows = 352
```

Profile A at `s_SW=16`:

```text
rows per ring polynomial = 256 / 16 = 16
pre-sign ring polynomials = 6
pre-sign rows = 96
showing non-PRF ring polynomials = 13
showing non-PRF rows = 208
```

This is row-inventory arithmetic only. It is not a final proof-size benchmark.

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
- `-profile`: IntGenISIS profile name. Use `intgenisis_profile_b` for the primary implementation. `intgenisis_profile_a` is inventory-only unless `N=256` is verified end to end.
- `-force`: overwrite existing `-out` and `-b-path` files.

Paper correspondence:

- setup for `C_M`, `A_s`, and `B` in `Setup`.

### 2. Generate NTRU/SampPre Keys For Profile B

```bash
go run ./cmd/issuance setup-ntru-keys \
  -research-ring-degree 512 \
  -params-out Parameters/Parameters.research_n512.json \
  -public-out ntru_keys/public.research_n512.json \
  -private-out ntru_keys/private.research_n512.json \
  -force
```

What it does:

- generates NTRU parameters for `N=512`;
- generates issuer public/private key material;
- produces the trapdoor-backed signing material used by `issuer-verify-sign`.

Flag meanings:

- `-research-ring-degree`: must be `512` for profile B. If omitted, the command uses legacy defaults that are not profile-B aligned.
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

- samples a PRF key `k`;
- packs the key into the semantic message polynomial `M`;
- samples `s` and `e` from `[-B,B]`;
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
- `-ncols`: witness packing width used by the pre-sign PIOP. Profile-B examples use `16`.
- `-lvcs-ncols`: LVCS width. Profile-B examples use `32`, though the pre-sign builder internally narrows the prepared commitment rows to the witness width where needed.
- `-nleaves`: explicit-domain size. Profile-B examples use `4096`.
- `-research-ring-degree`: optional override. Normally omitted because the public params already say `N=512`.

Paper correspondence:

- holder step: sample `k`, form `M=m||k`, sample `s,e`, send `(c, pi_pre)` later.

Current implementation note:

- the prototype currently uses an empty attribute component `m` and stores the PRF key in a fixed region of the single `M` polynomial. The full `M=m||k` policy encoding is not complete.

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

- reloads the holder opening `(M,s,e)`;
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

- creates `pi_pre` for `c = C_M M + A_s s + e`.

Current implementation note:

- the proof currently covers only the commitment-opening equation. The full paper relation additionally needs `M=m||k`, key membership, policy, and bounds.

### 6. Issuer Verification And Signing

```bash
go run ./cmd/issuance issuer-verify-sign \
  -commit-request credential/issuance/intgenisis_commit_request.json \
  -presign-submission credential/issuance/intgenisis_presign_submission.json \
  -issue-response credential/issuance/intgenisis_issue_response.json \
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

Flag meanings:

- `-commit-request`: public holder request containing `c`.
- `-presign-submission`: holder proof artifact.
- `-issue-response`: output issuer response.
- `-max-trials`: maximum NTRU signing trials. Defaults to `2048`.
- `-ntru-params`: NTRU parameter path for the profile-B signer/verifier.
- `-ntru-public-key`: issuer public key path.
- `-ntru-private-key`: issuer private key path.
- `-ntru-signature-out`: optional extra issuer-side signature artifact path.
- `-issue-challenge`: still exists for legacy compatibility. It is not read on the IntGenISIS path.

Artifact privacy and compatibility:

- the paper response is conceptually `(u, mu_sig, x0, x1)`;
- this implementation response contains `sig_s1`, `sig_s2`, `mu_sig`, `x0`, `x1`, plus a serialized `T` and signature bundle for compatibility with the existing target verification/signature artifact format;
- `T` is not saved into the final v5 credential state and is not revealed during showing.

Paper correspondence:

- issuer steps in `Issue`: verify `pi_pre`, sample `mu_sig,x0,x1`, compute `Z,T`, run `SampPre`.

Current implementation note:

- if strict transcript minimization is required, the response artifact should be revised to omit `T` and keep only the data needed by the holder to verify and store the credential.

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
- verifies the issuer's signed target bundle if present;
- recomputes `T` from `c,mu_sig,x0,x1`;
- checks the issuer response target;
- writes v5 IntGenISIS credential state.

Flag meanings:

- `-holder-secret`: local holder opening from `holder-commit`.
- `-commit-request`: public request containing `c`.
- `-issue-response`: issuer response from `issuer-verify-sign`.
- `-state-out`: output v5 credential state.
- `-signature-out`: optional compatibility signature artifact path.
- `-ntru-params`: NTRU parameter path used when verifying the signed target bundle.
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
  -ncols 16 \
  -lvcs-ncols 32 \
  -nleaves 4096 \
  -eta 8 \
  -rho 1 \
  -theta 1 \
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
- `-ell-prime`: DECS/LVCS extension parameter. The prototype default is `4`.
- `-kappa1`, `-kappa2`, `-kappa3`, `-kappa4`: optional grinding/soundness knobs. Defaults are zero in this branch unless provided.
- `-prf-companion-mode`: PRF companion mode. Use `output_audit` for the current default.
- `-prf-checkpoint-samples`: number of checkpoint audits. Defaults to `8`.

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

Current implementation note:

- this command builds and verifies the presentation in one process;
- it does not yet write a standalone presentation JSON;
- it does not yet implement persistent verifier replay-state storage for accepted `(nonce, tag)` pairs.

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

- this command does not measure final proof sizes, proving time, or verification time for the full proof stack. It records row inventory only.

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
- Target-shaped commitment sampling, computation, and opening verification.
- IntGenISIS target computation and tampered-commitment rejection.
- v5 credential-state serialization and old-randomness omission.
- Pre-sign PIOP proof build/verify.
- Pre-sign rejection for tampered `c`, `C_M`, `A_s`, row layout, and proof root.
- Showing PIOP proof build/verify for a synthetic profile-B witness.
- Showing rejection for forbidden public `c` and tampered `B`.
- CLI setup, holder commit, issuer-challenge guard, and holder prove.

Known test gap:

- there is not yet a full CLI integration test that runs setup, NTRU keygen, holder commit, holder prove, issuer verify/sign, holder finalize, and showing end to end.

## Artifact Map

Recommended IntGenISIS artifacts:

```text
Parameters/credential_public.intgenisis.json
Parameters/Bmatrix.intgenisis.json
Parameters/Parameters.research_n512.json
ntru_keys/public.research_n512.json
ntru_keys/private.research_n512.json
credential/issuance/intgenisis_holder_secret.json
credential/issuance/intgenisis_commit_request.json
credential/issuance/intgenisis_presign_submission.json
credential/issuance/intgenisis_issue_response.json
credential/keys/credential_state.intgenisis.json
credential/keys/signature.intgenisis.json
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
| issue response | holder-private transcript | `u`, `mu_sig`, `x0`, `x1`, compatibility `T` and signature bundle | `T` should be removed in final minimized response |
| v5 credential state | yes | `u`, `M`, `m`, `k`, `s`, `e`, `mu_sig`, `x0`, `x1` | no `c`, no `T`, no old randomness |
| showing output | currently not persisted | proof is built and verified in process | standalone presentation artifact still needed |

## Correctness And Completeness Status

### Correct For The Implemented Prototype Surface

The following implementation claims are supported by code and tests:

- IntGenISIS profile B dimensions are represented and validated.
- `C_M` and `A_s` are generated and stored under the public-parameter schema.
- The target commitment computes `c = C_M M + A_s s + e`.
- The standalone commitment opening verifier checks dimensions, bounds, and recomputation.
- The issuer-side target computation uses `mu_sig`, `x0`, `x1`, `Z`, and `c`.
- The old issuer challenge command rejects IntGenISIS public params.
- The pre-sign PIOP verifier replay is implemented and no longer a placeholder.
- The IntGenISIS pre-sign replay rejects old public statement fields.
- The showing PIOP branch verifies the new signature equation and inverse equation.
- The showing public inputs reject `c`, `T`, `Ac`, `RI0`, and `RI1`.
- v5 credential state omits old shared-randomness and holder-computed-target fields.

### Not Complete Relative To The Paper

The implementation is not yet a complete ARC-SPRUCE IntGenISIS realization. The largest gaps are:

1. Pre-sign relation incompleteness:
   - implemented: `c = C_M M + A_s s + e`;
   - missing: `M = m || k`;
   - missing: PRF key-space membership;
   - missing: issuance policy constraints;
   - missing: PIOP-enforced coefficient bounds on `M,s,e`.

2. Showing relation incompleteness:
   - implemented: inverse equation;
   - implemented: signature equation with hidden commitment term;
   - implemented: PRF companion proof over key lanes derived by the honest builder from `M`;
   - missing: explicit `m` rows and full `M = m || k` proof;
   - missing: explicit row-equality constraints binding companion PRF key rows back to the key slots inside `M`;
   - missing: PIOP-enforced bounds for `M,s,e`;
   - missing: final distribution/range constraints for `mu_sig,x0,x1` if the concrete DKLW domain requires them;
   - missing: IntGenISIS-specific signature shortness proof wiring.

3. Issuer response minimization:
   - paper response is `(u, mu_sig, x0, x1)`;
   - implementation response still serializes `T` and a signature bundle for compatibility with existing verifier/finalizer tooling.

4. Standalone showing presentation:
   - showing currently builds and verifies in one CLI process;
   - no presentation JSON is written;
   - no verifier-state database enforces replay rejection across runs.

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

1. Complete the pre-sign relation:
   - add explicit `m` and `k` witness rows;
   - prove `M = m || k` for the actual packing convention;
   - prove key-space membership for `k`;
   - add coefficient-bound gadgets for `M,s,e`;
   - add policy hooks for `m`.

2. Complete the showing relation:
   - add explicit `m` and `k` witness rows or a formal key-slot binding gadget from `M`;
   - enforce `M = m || k`;
   - bind PRF companion key rows to the key slots inside `M`;
   - wire IntGenISIS-compatible signature shortness proof;
   - add bound/range gadgets for `M,s,e` and any required `mu_sig,x0,x1` constraints.

3. Minimize the issuer response:
   - remove serialized `T` from the final IntGenISIS issuer response schema;
   - keep holder verification by recomputing `T` internally from `c,mu_sig,x0,x1`;
   - update tests so response privacy matches the paper exactly.

4. Add standalone presentation artifacts:
   - write `(nonce, tag, proof)` as a showing presentation JSON;
   - add a verifier CLI that accepts public params, presentation, and verifier-state path;
   - persist replay-state checks for `(nonce, tag)`.

5. Finish CLI integration tests:
   - setup public params;
   - setup NTRU keys;
   - holder commit;
   - holder prove;
   - issuer verify/sign;
   - holder finalize;
   - showing build/verify;
   - stale-field checks on all JSON artifacts.

6. Rerun measurement harness:
   - proof size;
   - proving time;
   - verification time;
   - PRF auxiliary rows;
   - total SmallWood rows;
   - `d_Q` or equivalent degree parameter;
   - QR, RowOpening, BarSets, and VTargets sizes if present.

7. Decide and document DKLW sampling domains:
   - either justify full-ring uniform `mu_sig,x0,x1`;
   - or replace the placeholder sampler with the exact distribution required by the concrete theorem.

8. Quarantine legacy artifacts:
   - keep old challenge-based CLI behavior only for old public params;
   - move old JSON samples and tests under explicit legacy names;
   - ensure generated docs and examples default to IntGenISIS once the missing gadgets are complete.

## Practical Recommendation

Use the current implementation for prototype development and relation debugging, not as a complete cryptographic implementation. The implemented algebraic core is the right IntGenISIS direction: `M` is hidden by the target-shaped MLWE commitment, `mu_sig/x0/x1` are issuer-side BB-tran values, and showing no longer uses old `r0/r1` target-hiding randomness. However, the proof relation is not yet complete enough to support the full paper claims because message packing, key binding, bounds, policy constraints, signature shortness, and persistent presentation verification still need to be finished.
