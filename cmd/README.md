# Command Programs

## `cmd/showing`

Live showing surface:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

`go run ./cmd/showing` resolves to `showing_n512_x0len70_100`. All maintained
profiles use the clean V18 relation:

- preset: `aggregate_inline_target_replay_compact_research`
- mode: `sig_shortness_inline_target_replay_compact_hiding`
- payload: `SigShortnessProofV18`, version `18`
- profile tuples: see `docs/current_showing_defaults.md`
- x0 layout: `x0_len=70`
- `mu` carrier: full-capacity ternary `mu` is packed with internal
  `mu_pack=2`
- replay shape: no `TargetMR0Hat`, keep `RHat1` and `ZHat`,
  no `THat`, hidden proof, sidecar root, lookup proof, or pullback proof

Unknown profile strings fail explicitly. There is no maintained preset alias
surface; profile names are the public selector.

## `cmd/issuance`

Canonical showing artifacts are committed for `N=512,x0_len=70` and
`N=1024,x0_len=70`. To regenerate them, use `setup-demo-public`,
`setup-ntru-keys` if new NTRU material is needed, and `demo-local` with explicit
public-params, B-matrix, NTRU, state, and signature paths. The issuer signing
command validates that NTRU params, public key, private key, and target length
all match the selected ring degree before signing.

## Transcript Sweep

Transcript tuning is profile-driven around the three maintained optimized V18
profiles. Obsolete research controls are not live sweep tracks.
