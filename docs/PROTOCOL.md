# SPRUCE Protocol And Code Map

This document describes the hard v2 protocol implemented by SPRUCE. It is the
executable companion to `/home/jonas/Bureau/GIT_Paper`: the manuscript defines
the ARC-SPRUCE construction and its proof arguments, while this repository
fixes one concrete encoding, transcript, artifact identity, and state machine.

Every maintained manifest has `claim_scope=proof_only`. The code proves and
verifies the relations below; profile labels and successful execution do not
assert security of an assembled deployment.

## Canonical Protocol Epoch

Only these nine preset IDs select a protocol:

| Canonical preset ID | Profile | Lifecycle | PRF profile | Showing projection |
| --- | --- | --- | --- | --- |
| `poc-n512-sc96-v2` | `intgenisis_profile_b` | `poc` | tag 7 | `project_u_digits_and_y_view_v3` |
| `artifact-n1024-sc125-v2` | `intgenisis_profile_c` | `artifact` | tag 7 | `project_u_digits_y_bounded_sources_v6` |
| `artifact-n1024-bq10-r96-v2` | `intgenisis_profile_c` | `artifact` | tag 7 | `project_u_digits_y_bounded_sources_v6` |
| `artifact-n1024-bq16-r96-v2` | `intgenisis_profile_c` | `artifact` | tag 7 | `project_u_digits_y_bounded_sources_v6` |
| `pilot-n1024-bq32-r96-v2` | `intgenisis_profile_c` | `candidate` | tag 9 | `project_u_digits_y_bounded_sources_v6` |
| `poc-n1024-bq64-r128-v2` | `intgenisis_profile_c` | `poc` | tag 10 | `project_u_digits_y_bounded_sources_v6` |
| `poc-n1024-bq96-r128-v2` | `intgenisis_profile_c` | `poc` | tag 10 | `project_u_digits_y_bounded_sources_v6` |
| `poc-n1024-bq128-r128-v3` | `intgenisis_profile_c` | `poc` | tag 10 | `project_u_digits_y_bounded_sources_v6` |
| `system-n1024-wf128-crom-v2` | `intgenisis_profile_c` | `candidate` | tag 13 | `project_u_digits_y_bounded_sources_v6` |

The revision suffix in a canonical ID is part of that ID. All nine manifests
currently carry preset schema version `2`, including the BQ128 ID whose own
revision suffix is `v3`.

There is no migration layer. A selector must be a canonical ID, and every
persisted object must have the current exact schema and manifest binding.
Changing a preset, public-parameter digest, PRF parameter digest, verifier-key
digest, transcript tuple, or rate-limit policy creates a different protocol
identity.

## Algebraic Setting

The main relations are over

```text
R_q = Z_q[X] / (X^N + 1)
q   = 1,017,857
N   = 512 or 1024, as fixed by the preset profile
```

The holder's semantic message `M` contains ordinary credential coordinates and
a 48-coefficient secret seed. The seed coefficients lie in `[-4,4]` and are
packed into eight field elements for the Poseidon2 PRF. Ordinary message,
commitment-randomness, and commitment-error coefficients use bound one.

The public commitment matrices define

```text
c = C_M * M + A_s * s_com + e.
```

For BB-tran, setup samples the public vector

```text
B = (B0, B1, B2[0], ..., B2[ell_x0-1], B3).
```

Every component, including `B0`, is an independent uniform draw. `B0` is not
fixed to zero, but the relation imposes no nonzero or invertibility condition
on it; zero remains a valid (negligibly likely) uniform outcome.

The NTRU/vSIS public verification row is

```text
A = (-h, 1),
```

and a valid short preimage `u=(s1,s2)` satisfies `A*u=T`.

## Issuance

The executable issuance flow is:

1. `setup-intgenisis-public` creates the commitment and BB-tran public
   parameters for one canonical manifest.
2. `setup-ntru-keys` creates separately identified NTRU parameters and issuer
   signing/verifying material.
3. The holder samples `M`, `s_com`, and `e`, computes `c`, and persists a holder
   secret plus commitment request.
4. `holder-prove` proves knowledge of a valid bounded opening of `c` without
   exposing the message, seed, `s_com`, or `e`.
5. The issuer verifies the pre-sign proof. It independently samples
   `mu_sig`, every row of `x0`, and `x1` coefficient-wise and uniformly from
   `{-1,0,1}`. It resamples `x1` until `B3-x1` is invertible and computes

   ```text
   Z = (B3 - x1)^(-1)
   T = c + B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z.
   ```

6. The issuer samples a short NTRU preimage `u` of `T` and returns the response
   and public verifier key.
7. `holder-finalize` checks the bounded BB-tran data, inverse, target, NTRU
   signature, and all manifest bindings before persisting credential state.

`mu_sig` is the BB-tran message input. It is distinct from the credential's
secret PRF seed. The inverse witness `Z` is algebraically constrained but is
not assigned the ternary source bound.

All source sampling uses an injected entropy reader and unbiased rejection.
The public parameters store `hash_input_bound=1`, so the prover, verifier, and
artifact identity agree on the accepted coefficient domain.

## Public Context And Hidden Slot

The v2 rate policy has the exact identity:

```text
mode                = public_context_hidden_slot_v2
context_lanes       = 11
hidden_slot_lanes   = 1
quota_slots         = 16
slot_bits           = 4
context_encoding    = shake256_reject11_v2
holder_counter_mode = monotonic_burn_v2
verifier_state_mode = atomic_context_tag_set_v2
```

Let `raw_context` be non-empty opaque bytes supplied by the service. The holder
derives a context binding from:

- a domain label;
- the raw bytes;
- the field modulus and quota size;
- the preset-manifest digest;
- the public-parameter digest; and
- the verifier-key digest.

Separate SHAKE256 domains derive a 32-byte context digest and exactly 11 field
elements. Field elements use unbiased 128-bit rejection sampling rather than
modular reduction. The raw service input is bounded to 4096 bytes and is not
copied into the presentation.

For each credential and derived context, the holder reserves

```text
s in {0, 1, ..., 15}.
```

The reservation is atomically persisted and burned before proof construction.
The PRF receives 12 input lanes:

```text
(context[0], ..., context[10], s),
```

and publishes

```text
tag = PRF(k, context || s).
```

The 11 context lanes are public statement values. The slot and its four bits
are witness values. The proof enforces Boolean membership of every bit,
reconstructs `s` from those bits, enforces `0 <= s < 16`, and proves the full
PRF trace using the same secret seed `k` embedded in `M`. The presentation
never serializes the slot or slot bits.

This is an exact `L=16` policy, not a probabilistic choice from a larger
domain. A holder state records the next slot by credential fingerprint and
context digest. Failed proof construction does not refund a reserved slot.

## Showing Statement

The showing proof recomputes the hidden commitment and proves, in one bound
statement:

```text
c = C_M*M + A_s*s_com + e
Z * (B3 - x1) = 1
T = c + B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z
A*u = T
tag = PRF(k, context || hidden_slot)
hidden_slot = bit0 + 2*bit1 + 4*bit2 + 8*bit3
bitj in {0,1}
```

It also proves:

- coefficient membership of `mu_sig`, every `x0`, and `x1` in
  `{-1,0,1}`;
- the ordinary message/opening bounds and the wider seed bound;
- consistency between coefficient-source rows and every transformed source
  consumed by the signature equation;
- signed-radix reconstruction and shortness of `u`;
- consistency between the committed seed, packed PRF key, PRF checkpoints,
  final round, and public tag; and
- the canonical preset, context, transcript, and public-artifact bindings.

The bounded BB-tran sources remain individually extractable. The proof does
not replace them with a single unconstrained full-image residual.

## Bounded-Source Row Encodings

The current showing layouts are:

```text
intgenisis_showing_y_linear_bounded_sources_v2
intgenisis_showing_project_u_digits_y_view_bounded_sources_v4
intgenisis_showing_project_u_digits_y_bounded_sources_v6
```

The compact degree-512 preset uses the bounded-source `y_view` layout with
projection mode `project_u_digits_and_y_view_v3`. The degree-1024 presets use
`project_u_digits_y_bounded_sources_v6`. Both preserve explicit coefficient
views for `mu_sig`, `x0`, and `x1`, their transformed hats, ternary membership,
and source-to-hat bridges.

The projection descriptor is `intgenisis_replay_projection_v2`. A proof binds
the exact descriptor and row-layout version in its Fiat-Shamir public inputs.
Unknown projections, layout/projection mismatches, and any encoding that omits
the individual bounded sources are rejected.

## Independent Salted Tapes

Every maintained issuance and showing proof uses this exact transcript tuple:

```text
protocol = smallfield_2025_1085_salted_tapes_v2
version  = smallwood_2025_1085_salted_decs_v2
gate     = smallwood_2025_1085_salted_tapes_v2_live
```

The proof has schema version `2`. Its proof-global salt is sampled freshly and
is an explicit input to Fiat-Shamir and every DECS v2 commitment context. A
commitment context also carries version `2` and a role such as `main`,
`q-payload`, `companion`, `replay`, or `sig-shortness`.

For each logical leaf, DECS samples an independent fixed-width tape. The leaf
hash binds the context, leaf index, evaluation point, modulus, canonical
residues, and that leaf's tape. Internal nodes and padding bind the same
context, level, index, and framed children. An opening transmits exactly the
tape belonging to each distinct opened leaf.

Verification checks the exact salt, role, version, tape count and width,
canonical residues, distinct indices, authentication paths, and low-degree
relations. The v2 format has no accepted seed-compressed fallback, and an
opening that carries earlier-format material is rejected rather than
normalized.

## Presentation Verification And State

Presentation creation requires:

```text
-state-path
-verifier-key
-context-file
-holder-usage-state
-presentation-out
```

The resulting `intgenisis_presentation_v2` envelope contains the manifest,
public-parameter, verifier-key, and context digests; the 11 derived public
context lanes; the public tag; and the proof. It excludes raw context bytes and
hidden-slot material.

Rate-limited verification requires:

```text
-public-params
-verifier-key
-verify-presentation
-expected-context-file
-verifier-state
```

The verifier:

1. strictly decodes the v2 presentation, public parameters, and verifier key;
2. validates their manifest and content-digest bindings;
3. derives the expected digest and 11 lanes from independently supplied raw
   service context bytes;
4. compares that binding with the presentation;
5. verifies the SmallWood proof and public tag relation; and
6. under an exclusive lock, rejects a tag already accepted in that context or
   atomically records the new `(context, tag)` acceptance.

The verifier state is namespaced by public-parameter digest, verifier-key
digest, and context digest. Deployments that intend a shared quota must share
one consistent verifier-state namespace; isolated state files enforce isolated
acceptance histories.

With `-proof-only`, step 6 is deliberately skipped. The flag is valid only for
verification, cannot be combined with `-verifier-state`, and does not represent
rate-limit acceptance.

## Artifact Identity And No Migration

| Object | Exact current identity |
| --- | --- |
| preset manifest | preset version `2` plus one canonical ID above |
| public parameters | schema version `8` and `public_context_hidden_slot_v2` policy |
| credential state | schema version `7` |
| verifier key | version `2` |
| presentation | version `2`, `intgenisis_presentation_v2` |
| holder usage state | version `2` |
| verifier state | version `2` |
| proof | schema version `2` and transcript tuple above |
| DECS commitment/opening | version `2` with explicit commitment context |
| NTRU parameters | `ntru-params-v2` |
| NTRU key | `ntru-key-v2` |
| NTRU signature | `ntru-signature-v2` |

These formats use strict decoding and canonical values. An exact current
schema number is required; it is not interpreted as a request to upgrade an
older object. There is no cross-epoch verifier or conversion command.

## Relationship To The Manuscript

The main correspondence with `/home/jonas/Bureau/GIT_Paper` is:

| Manuscript area | SPRUCE implementation |
| --- | --- |
| `sections/03_blind_signature.tex` | `issuance/intgenisis.go`, `cmd/issuance/flow_helpers.go`, `ntru/` |
| `sections/04_arc_construction.tex` | `credential/presentation_context.go`, `credential/intgenisis_usage_state.go`, `credential/intgenisis_presentation.go`, `cmd/showing/` |
| `sections/05_smallwood_model.tex` | `PIOP/`, `LVCS/`, `DECS/` |
| `sections/06_parameters.tex` | `credential/intgenisis_profile.go`, `credential/intgenisis_presets.go`, `credential/preset_manifest.go` |
| `appendix/B_gaussian_sampler.tex` | `ntru/` sampler and trapdoor implementation |
| `appendix/C_smallwood_details.tex` and `appendix/D_extended_parameters.tex` | transcript construction, row geometry, projection, and proof reporting in `PIOP/` |
| `appendix/E_prf_and_misc.tex` | `prf/` and the PRF companion relation in `PIOP/` |

The manuscript is the mathematical narrative; the Go manifest is the
executable parameter authority. Generated sizes and timings must come from a
v2 benchmark run and then be reflected deliberately in the manuscript. The
repositories are not synchronized automatically.

## Code Map

| Area | Main paths |
| --- | --- |
| CLI orchestration | `cmd/issuance/`, `cmd/showing/` |
| canonical presets and policy | `credential/intgenisis_presets.go`, `credential/preset_manifest.go`, `credential/v2_policy.go` |
| strict public/state artifacts | `credential/public_params.go`, `credential/intgenisis_state.go`, `credential/intgenisis_verifier_key.go`, `credential/intgenisis_presentation.go` |
| context and holder quota state | `credential/presentation_context.go`, `credential/intgenisis_usage_state.go`, `credential/atomic_state.go` |
| committed-message issuance | `issuance/intgenisis.go`, `cmd/issuance/flow_helpers.go` |
| bounded BB-tran public hash | `internal/hash/vsis_bbs.go` |
| SmallWood/PACS proof | `PIOP/` |
| row commitment stack | `LVCS/`, `DECS/` |
| Ajtai commitment | `commitment/` |
| NTRU/vSIS | `ntru/` |
| Poseidon2 PRF | `prf/` |

See [../ARTIFACT.md](../ARTIFACT.md) for executable commands and
[SECURITY.md](SECURITY.md) for the proof-only security boundary.
