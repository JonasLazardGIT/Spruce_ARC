# Commands

## Showing

Live commands:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

`go run ./cmd/showing` is the reduced `soundness_balanced` path.

`go run ./cmd/showing -full` is the maintained V6 hidden-shortness full replay
baseline.

`aggregate_v6_research` is the aggregate V6 control.

`aggregate_inline_target_replay_compact_research` is the canonical optimized
profile. It uses internal proof version `18`, mode
`sig_shortness_inline_target_replay_compact_hiding`, `R11,L4`, `lvcs_ncols=84`,
`nleaves=5760`, `ell=16`, `eta=41`, `theta=3`, `rho=2`, `ell'=2`, and
`kappa={10,0,0,6}`. The default optimized path uses `ring_degree=1024`. Its
showing-time `mu` carrier is packed with internal
`mu_pack=2`, so the 64 logical full-capacity `mu` blocks use 32 private
carrier rows. The public proof statement is still direct `bb_tran`; no public
`mu`, message, or PRF-key coefficient is emitted.

Current optimized reference output is about:

```text
paper transcript = 43163 bytes
verifier payload = 71740 bytes
dQ               = 356
theorem bits     = 100.27
selected rows    = 51
active blocks    = 3
```

## Degree-512 Research Artifacts

The degree-512 path is an explicit research statement fork. It requires
separate public params, B matrix, NTRU params/key material, credential state,
and signature artifacts.

```bash
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

The measured research output is `32526` bytes paper transcript, `61187` bytes
verifier payload, `dQ=356`, and `100.27` theorem bits. It is not production
valid without a degree-512 security review.

## Tests

```bash
go test ./credential ./cmd/issuance ./cmd/showing ./PIOP
go test ./PIOP
go test ./cmd/showing
```

## Pruned Presets

Removed research labels are invalid and are not mapped to the optimized profile.
This includes the old V11, V14, V15, V16, V17, legacy V18/W84, V19,
`compact_l1_research`, `transcript_first`, and `production_balance` strings.
