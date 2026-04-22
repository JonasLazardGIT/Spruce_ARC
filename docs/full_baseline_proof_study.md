# Full Baseline Proof Study

This note is the current-state study for the live theorem-clean full baseline only:

- `go run ./cmd/showing -showing-preset compact_l1_research -full`
- default `PRFCompanionMode=output_audit`

It is a feasibility map, not an optimization patch. Reduced replay and `aux_instance` remain comparison controls only and do not drive the lever classifications below.

## Baseline Snapshot

- Statement: `theorem_clean_full_replay`
- Replay mode: `full`
- PRF mode: `output_audit`
- Optimized transcript: `66465` bytes
- Buckets: `SigShortness=23543`, `Pdecs=18130`, `VTargets=9838`, `BarSets=5539`, `Q=4622`
- Soundness: `128.11` bits
- Replay selector: `16/400` rows, `3` active blocks, replay blocks `64`
- Hidden shortness: opening `14469` bytes, hidden proof `9051` bytes

## Main Witness Families

| Family | Rows | Selected | Blocks | Authenticated By | Notes |
| --- | ---: | ---: | ---: | --- | --- |
| `carrier_m` | 1 | 1 | 1 | `main_root`, `main_pcs_row_opening` | Packed message carrier row; decoded into `m1/m2` and consumed directly by the main transform-bridge replay. |
| `carrier_ctr` | 1 | 1 | 1 | `main_root`, `main_pcs_row_opening` | Packed counter carrier row; decoded into `r0/r1` and consumed directly by the main transform-bridge replay. |
| `t_source` | 0 | 0 | 0 | `main_root`, `main_pcs_row_opening` | Committed `T`-source rows are already absent on the live theorem-clean full baseline; `THat` is derived directly from signature replay heads. |
| `mhat_sigma` | 64 | 0 | 12 | `main_root`, `main_pcs_row_opening` | Replay-image row family for `M1+M2` over every full replay block. |
| `rhat0` | 64 | 0 | 12 | `main_root`, `main_pcs_row_opening` | Replay-image row family for `R0` over every full replay block. |
| `rhat1` | 64 | 0 | 13 | `main_root`, `main_pcs_row_opening` | Replay-image row family for `R1` over every full replay block. |
| `msigmar1_source` | 1 | 1 | 1 | `main_root`, `main_pcs_row_opening` | Committed omega-interpolated source-product row for `(M1+M2)*R1`. Still live in the baseline full proof. |
| `r0r1_source` | 1 | 1 | 1 | `main_root`, `main_pcs_row_opening` | Committed omega-interpolated source-product row for `R0*R1`. Still live in the baseline full proof. |
| `msigmar1_hat` | 64 | 0 | 13 | `main_root`, `main_pcs_row_opening` | Replay-image row family for `(M1+M2)*R1` over all replay blocks. |
| `r0r1_hat` | 64 | 0 | 13 | `main_root`, `main_pcs_row_opening` | Replay-image row family for `R0*R1` over all replay blocks. |
| `t_hat` | 64 | 0 | 13 | `main_root`, `main_pcs_row_opening`, `sig_shortness_t_hat_subset_opening` | Replay-image `THat` rows over all replay blocks. They are also re-opened through the outer sig-shortness same-root subset opening. |
| `prf_key` | 1 | 1 | 1 | `main_root`, `main_pcs_row_opening` | Packed PRF key row retained for key binding and scalar opening checks in the baseline path. |
| `prf_checkpoint` | 10 | 10 | 1 | `main_root`, `main_pcs_row_opening` | Packed PRF checkpoint rows consumed by the live `Q`-bridge and scalar opening checks. |
| `prf_final_tag` | 2 | 2 | 1 | `main_root`, `main_pcs_row_opening` | Packed PRF final-tag rows consumed by the live `Q`-bridge and scalar opening checks. |
| `prf_helper` | 1 | 1 | 1 | `main_root`, `main_pcs_row_opening` | Packed PRF helper rows still live in the baseline `Q`-bridge mix. |
| `outer_sig_shortness_support` | 64 | 0 | 13 | `main_root`, `sig_shortness_t_hat_subset_opening` | Outer sig-shortness support rows authenticated by the same-root `THat` subset opening; on V6 these coincide with `THat` rows. |

## Hidden Sig Shortness

- Witness geometry: `ncols=16`, `lvcs_ncols=256`, `nleaves=512`
- Outer support slots: `16`
- Hidden proof bytes: `9071`, outer opening bytes: `14469`
- Hidden footprint: `Fpar=0`, `Fagg=0`, `Q=1001`, `Pdecs=364`, `VTargets=2698`, `BarSets=30`
- Binding: The outer proof authenticates `THat` under the main root via a same-root subset opening. The hidden proof then receives the encoded `THat` heads, the main root, and the shortness spec as public inputs and proves the `linf` statement under its own root.

## Constraint Families

| Constraint | Layer | Witness Families | Authenticated By | Notes |
| --- | --- | --- | --- | --- |
| `transform_hash_residual_all_blocks` | `Fpar` | `mhat_sigma`, `rhat0`, `rhat1`, `msigmar1_hat`, `r0r1_hat`, `t_hat` | `main_pcs_row_opening`, `q_opening`, `main_root` | All-block replay residual over the exact replay-image hats. This is the theorem-clean full replay core. |
| `carrier_decode_and_membership` | `Fpar` | `carrier_m`, `carrier_ctr` | `main_pcs_row_opening`, `q_opening`, `main_root` | Decodes carrier rows into message/counter source polynomials and enforces membership on the packed carriers. |
| `non_sign_source_to_hat_bridge` | `Fagg` | `carrier_m`, `carrier_ctr`, `mhat_sigma`, `rhat0`, `rhat1` | `main_pcs_row_opening`, `q_opening`, `main_root` | Bridges carrier-derived non-sign source polynomials to the exact replay-image hats on every replay block. |
| `bb_tran_source_product_source_residual` | `Fpar` | `carrier_m`, `carrier_ctr`, `msigmar1_source`, `r0r1_source` | `main_pcs_row_opening`, `q_opening`, `main_root` | Checks that the committed source-product rows equal the omega-interpolated products reconstructed from the carrier rows. |
| `bb_tran_source_product_source_to_hat_bridge` | `Fagg` | `msigmar1_source`, `r0r1_source`, `msigmar1_hat`, `r0r1_hat` | `main_pcs_row_opening`, `q_opening`, `main_root` | Bridges committed source-product rows to their replay-image hats over every replay block. |
| `prf_companion_q_bridge` | `Q` | `prf_key`, `prf_checkpoint`, `prf_final_tag`, `prf_helper` | `main_pcs_row_opening`, `q_opening`, `main_root` | Packed PRF bridge families aggregated into the main `Q` path under the baseline `output_audit` mode. |
| `prf_companion_scalar_openings` | `outer_verification` | `prf_key`, `prf_checkpoint`, `prf_final_tag` | `prf_companion_scalar_payload`, `main_root` | Scalar direct-auth openings over checkpoint outputs, final tag, and key truncation. These validate scalar semantics but do not replace the packed `Q`-bridge on `Ω_s`. |
| `sig_shortness_outer_subset_opening` | `outer_shortness_verification` | `t_hat`, `outer_sig_shortness_support` | `sig_shortness_t_hat_subset_opening`, `main_root` | Same-root subset opening that authenticates `THat` support rows for the outer V6 shortness binding. |
| `sig_shortness_hidden_t_hat_bridge` | `hidden_shortness_subproof` | `hidden_linf_digit_rows` | `sig_shortness_hidden_public_digest`, `sig_shortness_hidden_root` | Bridges hidden digit rows to the public `THat` rows inside the nested hidden shortness proof. |
| `sig_shortness_hidden_linf` | `hidden_shortness_subproof` | `hidden_linf_digit_rows` | `sig_shortness_hidden_root` | Hidden `linf` certificate over packed signature digits inside the nested V6 proof. |

## Authenticated Surfaces

| Surface | Kind | Active | Bytes | Witness Families | Notes |
| --- | --- | --- | ---: | --- | --- |
| `main_pcs_row_opening` | `row_opening` | yes | 20617 | `carrier_m`, `carrier_ctr`, `t_source`, `mhat_sigma`, `rhat0`, `rhat1`, `msigmar1_source`, `r0r1_source`, `msigmar1_hat`, `r0r1_hat`, `t_hat`, `prf_key`, `prf_checkpoint`, `prf_final_tag`, `prf_helper` | Authenticated main PCS row opening reconstructed at mask/tail indices. It binds the main witness rows under the main root, but it does not expose exact witness-`Ω_s` values for every potential extraction lever. |
| `q_opening` | `q_opening` | yes | 6372 | `` | Authenticated `Q` opening for the aggregated formal constraint families in the main theorem-clean proof. |
| `main_root` | `root` | yes | 16 | `carrier_m`, `carrier_ctr`, `t_source`, `mhat_sigma`, `rhat0`, `rhat1`, `msigmar1_source`, `r0r1_source`, `msigmar1_hat`, `r0r1_hat`, `t_hat`, `prf_key`, `prf_checkpoint`, `prf_final_tag`, `prf_helper` | Main proof root authenticating the one-root baseline witness surface and the same-root subset openings derived from it. |
| `sig_shortness_t_hat_subset_opening` | `same_root_subset_opening` | yes | 14469 | `t_hat`, `outer_sig_shortness_support` | Same-root subset opening over `THat` support rows used by the outer hidden shortness binding. |
| `sig_shortness_hidden_public_digest` | `public_input_digest` | yes | 32 | `t_hat`, `hidden_linf_digit_rows` | Hidden-shortness public extras digest carrying the encoded `THat` heads, main root, and shortness spec into the nested proof. |
| `sig_shortness_hidden_root` | `root` | yes | 16 | `hidden_linf_digit_rows` | Root of the nested hidden shortness proof; verified independently and bound back to the outer proof through the hidden public-input digest. |
| `prf_companion_scalar_payload` | `masked_scalar_openings` | yes | 1102 | `prf_key`, `prf_checkpoint`, `prf_final_tag` | Masked scalar opening payload for PRF direct-auth checks. It validates scalar semantics but does not authenticate the packed bridge rows on `Ω_s`. |
| `prf_aux_same_root_bridge` | `same_root_subset_bridge` | no (control) | 0 | `prf_key`, `prf_checkpoint`, `prf_final_tag`, `prf_helper` | Research-only control surface from the `aux_instance` path. It is sound, but the same-root bridge and stripe still make the total transcript larger than the baseline. |

## Lever Matrix

| Lever | Status | Feasibility | Byte Leverage | Witness Families | Rationale |
| --- | --- | ---: | --- | --- | --- |
| `hidden_sig_shortness_geometry_tuning` | `doable_with_current_openings` | 1 | `medium` | `hidden_linf_digit_rows` | The hidden V6 subproof is already separately factorized, independently authenticated, and tunable through its own SmallWood geometry without changing the main theorem-clean statement. |
| `hidden_sig_shortness_outer_t_hat_opening` | `needs_same_root_subset_bridge` | 2 | `high` | `t_hat`, `outer_sig_shortness_support` | The outer `THat` opening is a large authenticated object on the current baseline. Shrinking it requires a new same-root subset-bridge shape, not local evaluator reuse. |
| `source_product_extraction` | `needs_same_root_subset_bridge` | 3 | `medium_high` | `carrier_m`, `carrier_ctr`, `msigmar1_source`, `r0r1_source`, `msigmar1_hat`, `r0r1_hat` | The current main-opening recovery path does not authenticate the omega-interpolated source-product polynomials strongly enough for live extraction. The failed direct-auth attempt shows this lever needs a dedicated same-root bridge object. |
| `prf_packed_rows_master_root_bridge` | `needs_separate_oracle_or_master_root` | 5 | `medium` | `prf_key`, `prf_checkpoint`, `prf_final_tag`, `prf_helper` | PRF packed rows can only become economically separate if their bridge geometry is decoupled from the main PCS. That requires a separate PRF oracle/subroot under one protocol-level master root. |
| `carrier_row_extraction` | `changes_statement` | 6 | `high_but_statement_changing` | `carrier_m`, `carrier_ctr` | Carrier rows are still the live source of decoded message/counter semantics in the theorem-clean baseline. Removing them would change the implemented statement, not just the authenticated surface. |
| `prf_same_root_aux_instance` | `not_worth_it_after_measurement` | 4 | `negative_after_measurement` | `prf_key`, `prf_checkpoint`, `prf_final_tag`, `prf_helper` | The same-root PRF aux split is sound but still larger than the baseline after measurement. It should remain a control path, not the next optimization target. |
| `t_source_derivation` | `already_derived_now` | 1 | `none` | `t_source`, `t_hat` | The theorem-clean full baseline already derives `THat` directly from signature replay heads and no longer commits `T`-source rows. This lever is complete on the current baseline. |

## Ranked Recommendation

- Next baseline-doable lever: `hidden_sig_shortness_geometry_tuning`
- Next bridge-required lever: `hidden_sig_shortness_outer_t_hat_opening`
- Next architecture-required lever: `prf_packed_rows_master_root_bridge`

The resulting feasibility order is:

1. Retune the already-factorized hidden V6 proof geometry.
2. Redesign the outer `THat` same-root opening if the hidden tuning is exhausted.
3. Only then revisit `source_product` with a real same-root bridge object.
4. Keep PRF master-root split as the next architecture step, not the next baseline-only step.

## Full Replay Repair Summary

The live theorem-clean full path is stable because the outer `SigShortnessV6`
same-root `THat` opening now treats reduced and full replay differently:

- reduced one-block openings may omit serialized `M` values
- full multi-slot openings keep explicit authenticated `M` values

That repair lives in
[PIOP/sig_shortness_replay.go](../PIOP/sig_shortness_replay.go). It fixed the
earlier full-replay verifier divergence without weakening hidden shortness or
reintroducing exact-head disclosure.

## PRF Aux Research Summary

The same-root PRF auxiliary split remains a retained research control, not a
promotion candidate for the live baseline.

Measured on the compact theorem-clean full path:

- baseline full `output_audit`: about `64.7 KB`
- same-root striped `aux_instance`: about `83.5 KB`
- PRF bridge opening: about `12.9 KB`
- aux PRF proof: about `10.0 KB`

The important conclusion is that the same-root PRF split is sound but still not
economically positive. Even after shrinking the bridge opening, the extra
same-root stripe rows inflate the main PCS witness too much. The next PRF
architecture step is therefore a master-root multi-oracle design, not another
local same-root tuning pass.

## Hidden Retuning Follow-Up

The hidden-shortness retuning cycle landed one lasting change:

- the live proof/report path now surfaces the selected hidden shortness shape explicitly as profile, radix, digits, `lvcs_ncols`, and `nleaves`

The exact-search experiment did not earn a place in the default code path and
was removed during cleanup. The current measured outcome remains:

- the shipped theorem-clean full baseline still uses the legacy first-fit hidden selector
- that live hidden shape is `r11_l4_production` with hidden geometry `256/512`
- the resulting hidden contribution is about `9051` hidden-proof bytes plus `14469` outer `THat` opening bytes

So the ranked next steps remain unchanged:

1. `hidden_sig_shortness_outer_t_hat_opening`
2. `source_product_extraction`
3. `prf_packed_rows_master_root_bridge`
