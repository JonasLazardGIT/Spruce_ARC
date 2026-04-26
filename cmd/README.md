# Command Programs

## `cmd/showing`

Live showing surface:

```bash
go run ./cmd/showing
go run ./cmd/showing -full
go run ./cmd/showing -showing-preset aggregate_v6_research
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research
```

The optimized preset is the clean V18 profile:

- preset: `aggregate_inline_target_replay_compact_research`
- mode: `sig_shortness_inline_target_replay_compact_hiding`
- payload: `SigShortnessProofV18`, version `18`
- tuple: `lvcs_ncols=84`, `nleaves=5760`, `ell=16`, `eta=41`,
  `theta=3`, `rho=2`, `ell'=2`, `kappa={10,0,0,6}`, `R11,L4`
- default ring degree: `1024`
- `mu` carrier: full-capacity ternary `mu` is packed with internal
  `mu_pack=2`, giving 32 private carrier rows for 64 logical `mu` blocks
- replay shape: no `TargetMR0Hat`, keep `RHat1=64` and `ZHat=64`,
  no `THat`, hidden proof, sidecar root, lookup proof, or pullback proof

Unknown or pruned showing preset strings fail explicitly.

The same preset has an explicit unsafe research fork at `ring_degree=512`:

```bash
go run ./cmd/showing -showing-preset aggregate_inline_target_replay_compact_research \
  -research-ring-degree 512 \
  -state-path credential/keys/credential_state.research_n512.json
```

This fork requires separately generated `research_n512` issuance and NTRU
artifacts. It preserves the private optimized surface but changes the semantic
payload capacity to 512 coefficients, so it is not equivalent to public V18.

## `cmd/issuance`

Default issuance uses the canonical `N=1024` public params and NTRU paths. For
degree-512 research artifacts, use `setup-demo-public`, `setup-ntru-keys`, and
`demo-local` with explicit `research_n512` paths. The issuer signing command
validates that NTRU params, public key, private key, and target length all
match the selected ring degree before signing.

## Transcript Sweep

The transcript sweep keeps reduced/full V6 controls and the clean inline-target
replay-compact control. Removed V11/V14/V15/V16/V17/V19 controls are not live
sweep tracks.
