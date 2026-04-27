# Degree-512 V18 Research Flag Plan And Status

## Scope

The maintained public showing path is now profile-driven, and all maintained
profiles use the optimized V18 relation:

- showing preset: `aggregate_inline_target_replay_compact_research`
- statement: `theorem_clean_direct_target_full_replay`
- shortness mode: `sig_shortness_inline_target_replay_compact_hiding`
- proof: `SigShortnessProofV18`, version 18
- maintained profile names: `showing_n512_x0len70_100`,
  `showing_n512_x0len70_128`, and `showing_n1024_x0len70_100`

The degree-512 path is still a research statement fork, but
`showing_n512_x0len70_100` is intentionally the no-flag default profile for the
current research repository state. Production validity remains blocked on the
security review noted below.

## Statement Change

`N=512` is a research statement fork, not an equivalent public V18 statement.
It runs the same V18 optimized relation shape over `R_q[X]/(X^512+1)`, but the
private full-capacity `mu` ring element has only 512 coefficients. With the
current full-capacity halves layout, the message window remains in the lower
half and the PRF key window starts at coefficient `256`.

The implementation must reject silent truncation. Any public parameter row,
credential row, NTRU key row, B-matrix row, or signature component whose
coefficient count is not exactly the selected ring degree is incompatible with
that run.

## Compatibility Story

Artifacts are ring/layout-specific. `N=1024` artifacts are not compatible with
an `N=512` showing run, and `N=512` artifacts are not compatible with an
`N=1024` showing run. The profile-selected showing command fails clearly on any
degree, `x0_len`, or coefficient-length mismatch.

Fresh matching public parameters, B matrix, credential state, NTRU key material,
and signature material are required before a complete end-to-end showing can be
produced for any maintained profile.

## Degree-512 Artifact Generation

The committed canonical N=512/x0_len=70 artifacts are:

- `Parameters/credential_public.n512_x0len70.json`
- `Parameters/Bmatrix_bb_tran_n512_x0len70.json`
- `credential/keys/credential_state.n512_x0len70.json`
- `credential/keys/signature.n512_x0len70.json`

They were generated through the issuance CLI with explicit paths:

```sh
go run ./cmd/issuance setup-demo-public \
  -research-ring-degree 512 \
  -out Parameters/credential_public.n512_x0len70.json \
  -b-path Parameters/Bmatrix_bb_tran_n512_x0len70.json \
  -x0-profile lhl_default \
  -x0-len 70 \
  -force

go run ./cmd/issuance demo-local \
  -research-ring-degree 512 \
  -public-params Parameters/credential_public.n512_x0len70.json \
  -artifact-dir credential/issuance/n512_x0len70 \
  -state-out credential/keys/credential_state.n512_x0len70.json \
  -signature-out credential/keys/signature.n512_x0len70.json \
  -ntru-params Parameters/Parameters.research_n512.json \
  -ntru-public-key ntru_keys/public.research_n512.json \
  -ntru-private-key ntru_keys/private.research_n512.json \
  -ntru-signature-out credential/issuance/n512_x0len70/ntru_signature.json

go run ./cmd/showing \
  -showing-profile showing_n512_x0len70_100
```

The default `demo-local`, `issuer-verify-sign`, and `holder-finalize` commands
continue to use the canonical `N=1024` params and NTRU key paths unless the
research paths are supplied explicitly.

## Privacy Argument

The `N=512` fork keeps the V18 optimized privacy surface:

- no public `mu`, message, key, `r0`, `r1`, `Z`, or signature digits;
- no `T`, `THat`, or `THatHeads`;
- no `TargetMR0Hat`;
- no hidden proof;
- no sidecar root;
- `RHat1` and `ZHat` remain committed replay rows;
- signature shortness remains inside the main PACS transcript.

The smaller degree reduces private payload capacity, so it must not be marketed
as an equivalent credential statement.

## Soundness Argument

The implementation reports theorem and transcript values from the existing
proof-reporting code. It must not assume `total_bits >= 100` for `N=512`.

Even if the computed Fiat-Shamir/theorem accounting remains above a target
threshold, production validity remains blocked until the degree-512 lattice
assumptions, hiding margins, and parameter-generation story are reviewed
externally. Any measured `total_bits < 100` marks the mode invalid for
production.

## Measured Transcript Impact

Current measured `N=512,x0_len=70` 100-bit default:

- blocks: `32`
- `mu_rows`: `16`
- signature shortness rows: `256`
- `RHat1`: `32`
- `ZHat`: `32`
- actual witness: `490`
- committed witness: `133`
- `nrows`: `169`
- `m`: `42`
- `dQ`: `356`
- theorem bits: `103.05`
- optimized paper transcript: `34843` bytes

Current measured `N=512,x0_len=70` 128-bit profile:

- blocks: `32`
- `mu_rows`: `16`
- `mu_blocks`: `32`
- `RHat1`: `32`
- `ZHat`: `32`
- signature shortness rows: `256`
- logical witness: `419`
- actual witness: `490`
- committed witness: `126`
- mask rows: `36`
- `rowsBlock`: `7`
- `nrows`: `162`
- `m`: `56`
- `dQ`: `356`
- theorem bits: `128.06`
- optimized paper transcript: `37540` bytes
- buckets: `Pdecs=8963`, `VTargets=10300`, `R=7704`, `Q=5268`,
  `Auth=2635`, `BarSets=2362`, `SigShortness=39`

The current maintained default table is tracked in
[`current_showing_defaults.md`](current_showing_defaults.md). Older degree-512
retuning notes are historical and may refer to the prior x0_len=6 research
artifact set.

## Exact Files To Change

- `cmd/showing/main.go`
  - profile resolution for the three maintained x0_len=70 profiles
  - load the selected ring degree and profile state path
  - reject incompatible degree or x0 artifacts clearly
- `cmd/issuance/main.go`
  - add `setup-ntru-keys`
  - add `-research-ring-degree` to issuance artifact generation paths
  - add explicit NTRU params/public/private/signature paths for signing
- `cmd/issuance/flow_helpers.go`
  - generate separate `N=512` credential public params/B matrices
  - pass selected ring degree into issuance proof construction
  - reject mismatched NTRU params, public keys, private keys, B rows, and
    issuance artifact rows before converting them to ring polynomials
- `issuance/flow.go`
  - bind ring degree in pre-sign public inputs
  - allow target signing with explicit NTRU params/key/signature paths
- `ntru/signverify/signverify.go`
  - expose direct-target signing with explicit key paths
  - expose key generation to explicit output paths
- `ntru/io/io.go`
  - save separate NTRU parameter files
- `PIOP/run.go`
  - add `SimOpts.RingDegree`
  - thread the selected degree through proof construction
  - keep default `N=1024`
- `PIOP/params_helpers.go`
  - load repository `q`/`beta` while allowing explicit `N=512`
  - validate supported research degrees
- `PIOP/masking_fs_helper.go`
  - ensure Fiat-Shamir masking helpers use the selected ring degree
- `PIOP/VerifyNIZK.go`
  - reject proof/layout/ring-degree mismatches
- `PIOP/fs_binding.go`
  - bind ring degree and x0_len into public-input labels
- `PIOP/sig_shortness_replay.go`
  - include ring degree and x0_len in V18 layout digest material
  - add ring degree to `SigShortnessProofV18`
- `PIOP/proof_report.go`
  - include `ring_degree` and `x0_len` in proof reports
- `PIOP/canonical_transcript.go`
  - include `ring_degree` and `x0_len` in transcript reports
- `PIOP/witness_geometry.go`
  - surface ring-degree geometry where reports are assembled
- `credential/public_params.go`
  - store or infer public-parameter ring degree
- `credential/state.go`
  - store or infer credential-state ring degree
- B-matrix and coefficient-loading call sites
  - validate exact coefficient counts before converting to ring polynomials

## Tests Required

- existing baseline tests still pass
- no-flag showing resolves to `showing_n512_x0len70_100`
- all maintained profiles use and report `x0_len=70`
- `RingDegree=512` can build a V18 proof in a fresh or synthetic `N=512`
  fixture
- `N=512` proof is rejected under an `N=1024` verifier context
- `N=1024` proof is rejected under an `N=512` verifier context
- V18 layout digest changes when ring degree or x0_len changes
- checked-in `N=1024` credential artifacts fail clearly when forced through an
  `N=512` showing profile or verifier context
- proof and transcript reports include `ring_degree` and `x0_len`
- no private witness material appears in an `N=512` proof
- theorem bits are reported, and `total_bits < 100` marks the mode invalid for
  production

## Known Blockers

- `q=1054721` supports the needed NTT shape for `N=512`, but this does not
  establish lattice/security equivalence.
- This working tree contains generated `research_n512` artifacts. They are
  demonstration/research artifacts, not production parameters.
- Production validity is blocked on security review of degree-512 lattice
  assumptions and measured theorem/security results.
