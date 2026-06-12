# PIOP

`PIOP/` contains the maintained proof system used by issuance and showing. It
builds the row layout, transcript, Fiat-Shamir challenges, soundness reports,
and verifier checks for the committed-message IntGenISIS relation.

## Package Role

- Compose the single-root LVCS/DECS row-oracle proof.
- Build the inline target relation for `bb_tran`.
- Replay the compact signature, PRF, and commitment constraints used by the
  maintained presets.
- Produce proof and transcript reports with preset-derived accounting.
- Verify layout digests, public-input labels, ring degree, and transcript
  binding.

## Main Entry Points

- `BuildIntGenISISPreSign`
- `VerifyIntGenISISPreSign`
- `BuildIntGenISISShowingCombined`
- `VerifyIntGenISISShowing`
- `ResolveDECSCollisionBits`
- `ComposeFullGameSoundness`
- `BuildProofReport`
- `BuildOpeningPaperReport`

## Current Invariants

- The public showing surface is the optimized inline-target replay-compact
  relation selected by maintained presets.
- Proof payloads use `SigShortnessProofV18` with mode
  `sig_shortness_inline_target_replay_compact_hiding`.
- The live row-oracle tuple is `lvcs_ncols=84`, `nleaves=5760`, `ell=16`,
  `eta=41`, `ell'=2`, `theta=3`, `rho=2`, and `kappa={10,0,0,6}`.
- The active signature profile is `r11_l4_production`.
- Public labels bind `ring_degree`, proof reports, transcript reports, row
  layouts, and V18 layout digests.
- Internal `mu` packing uses width `2`, `32` carrier rows, and `64` virtual
  blocks. The public statement remains direct `bb_tran`; decode and membership
  checks are private PACS constraints.
- The p=4 `mu` packing path is an internal degree-study override and is not
  selected by any public preset.

## Read Next

- [Protocol](../docs/PROTOCOL.md)
- [Security](../docs/SECURITY.md)
- [DECS](../DECS/README.md)
- [LVCS](../LVCS/README.md)
