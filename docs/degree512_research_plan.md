# Degree-512 V18 Research Flag Plan And Status

## Scope

The maintained public showing path remains the optimized V18 profile:

- showing preset: `aggregate_inline_target_replay_compact_research`
- statement: `theorem_clean_direct_target_full_replay`
- shortness mode: `sig_shortness_inline_target_replay_compact_hiding`
- proof: `SigShortnessProofV18`, version 18
- default ring degree: `N=1024`

The degree-512 path is opt-in research plumbing only. It does not change the
default command, the public preset, or the optimized V18 parameters at
`N=1024`.

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

The canonical/default repository artifacts are `N=1024` artifacts. They are not
compatible with an `N=512` showing run. A command such as:

```sh
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research -research-ring-degree 512
```

using the default checked-in state is expected to fail clearly with a degree or
coefficient-length mismatch.

Fresh `N=512` public parameters, B matrix, credential state, NTRU key material,
and signature material are required before a complete end-to-end `N=512`
showing can be produced.

## Degree-512 Artifact Generation

The issuance CLI has explicit paths for separate `N=512` artifacts. A complete
research run should generate public parameters/B matrix and NTRU params/keys
under `research_n512` names, then run issuance with those paths:

```sh
go run ./cmd/issuance setup-demo-public \
  -research-ring-degree 512 \
  -out Parameters/credential_public.research_n512.json \
  -b-path Parameters/Bmatrix_bb_tran_x0len6.research_n512.json \
  -x0-profile lhl_default \
  -force

go run ./cmd/issuance setup-ntru-keys \
  -research-ring-degree 512 \
  -params-out Parameters/Parameters.research_n512.json \
  -public-out ntru_keys/public.research_n512.json \
  -private-out ntru_keys/private.research_n512.json \
  -force

go run ./cmd/issuance demo-local \
  -research-ring-degree 512 \
  -public-params Parameters/credential_public.research_n512.json \
  -artifact-dir credential/issuance/research_n512 \
  -state-out credential/keys/credential_state.research_n512.json \
  -signature-out credential/keys/signature.research_n512.json \
  -ntru-params Parameters/Parameters.research_n512.json \
  -ntru-public-key ntru_keys/public.research_n512.json \
  -ntru-private-key ntru_keys/private.research_n512.json \
  -ntru-signature-out credential/issuance/research_n512/ntru_signature.json

go run ./cmd/showing \
  -showing-preset aggregate_inline_target_replay_compact_research \
  -research-ring-degree 512 \
  -state-path credential/keys/credential_state.research_n512.json
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

Measured `N=1024` baseline:

- blocks: `64`
- `mu_rows`: `32`
- signature shortness rows: `512`
- `RHat1`: `64`
- `ZHat`: `64`
- actual witness: `698`
- committed witness: `171`
- `nrows`: `201`
- `m`: `54`
- `dQ`: `356`
- theorem bits: `100.27`
- optimized paper transcript: `43163` bytes

Measured `N=512` shape with `ncols=16` and `mu_pack=2`:

- blocks: `32`
- `mu_rows`: `16`
- `mu_blocks`: `32`
- `RHat1`: `32`
- `ZHat`: `32`
- signature shortness rows: `256`
- logical witness: `355`
- actual witness: `362`
- committed witness: `95`
- mask rows: `30`
- `rowsBlock`: `5`
- `nrows`: `125`
- `m`: `30`
- `dQ`: `356`
- theorem bits: `100.27`
- optimized paper transcript: `32526` bytes
- verifier payload: `61187` bytes
- buckets: `Pdecs=8013`, `VTargets=6625`, `R=8614`, `Q=5298`,
  `Auth=2401`, `BarSets=1270`, `SigShortness=39`

## Exact Files To Change

- `cmd/showing/main.go`
  - add `-research-ring-degree`
  - add `-state-path`
  - load the selected ring degree
  - reject incompatible default artifacts clearly
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
  - bind ring degree into public-input labels
- `PIOP/sig_shortness_replay.go`
  - include ring degree in V18 layout digest material
  - add ring degree to `SigShortnessProofV18`
- `PIOP/proof_report.go`
  - include `ring_degree` in proof reports
- `PIOP/canonical_transcript.go`
  - include `ring_degree` in transcript reports
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
- default optimized V18 still uses and reports `ring_degree=1024`
- `RingDegree=512` can build a V18 proof in a fresh or synthetic `N=512`
  fixture
- `N=512` proof is rejected under an `N=1024` verifier context
- `N=1024` proof is rejected under an `N=512` verifier context
- V18 layout digest changes when ring degree changes
- checked-in `N=1024` credential artifacts fail clearly under
  `-research-ring-degree 512`
- proof and transcript reports include `ring_degree`
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
