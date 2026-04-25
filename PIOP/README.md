# PIOP Notes

The live showing implementation keeps two maintained families:

- V6 hidden-shortness controls, reached by `-full` and `aggregate_v6_research`.
- The optimized inline-target replay-compact family, exposed as
  `aggregate_inline_target_replay_compact_research`.

The optimized family stores `SigShortnessProofV18` with version `18` and reports
mode `sig_shortness_inline_target_replay_compact_hiding`. It is single-root,
uses the existing 16-column main row oracle, keeps private `R11,L4` signature
digit rows, omits committed `TargetMR0Hat`, and keeps `RHat1` and `ZHat` rows.

The current canonical tuple is:

```text
lvcs_ncols=84
nleaves=4096
eta=39
ell'=2
theta=3
rho=2
kappa={10,0,0,5}
sig_profile=r11_l4_production
```

Old research payloads are no longer public proof surfaces. Their preset labels
must fail closed when requested through the CLI. Archived internal helpers may
remain only where they are needed for old artifact rejection or shared layout
code; they are not live profiles.
