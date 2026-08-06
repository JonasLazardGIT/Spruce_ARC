# SPRUCE Protocol And Code Map

This document describes the mixed protocol epochs implemented by SPRUCE. It is
the executable companion to `../Better-Lattice-based-Blind-Signatures`: the
manuscript defines the ARC-SPRUCE construction and its proof arguments, while
this repository fixes concrete relations, transcripts, artifact identities,
and state machines.

Seven canonical presets retain their historical hard-v2 implementation and
evidence. Exactly two N=1024 targets use the strict-v3 proof and codec path:
`poc-n1024-bq128-r128-v3` (BQ128-128) and
`system-n1024-wf128-crom-v2` (WF128). The latter's `-v2` suffix is a stable
public selector, not its current manifest or proof version. The detailed v3
implementation and measurement record is
[CREDENTIAL_SIZE_OPTIMIZATION.md](CREDENTIAL_SIZE_OPTIMIZATION.md).

Every maintained manifest has `claim_scope=proof_only`. The code proves and
verifies the relations below; profile labels and successful execution do not
assert security of an assembled deployment.

## Canonical Protocol Epoch

Only these nine preset IDs select a protocol:

| Canonical preset ID | Profile | Lifecycle | PRF profile | Proof epoch / showing relation |
| --- | --- | --- | --- | --- |
| `poc-n512-sc96-v2` | `intgenisis_profile_b` | `poc` | tag 7 | historical v2; `project_u_digits_and_y_view_v3` |
| `artifact-n1024-sc125-v2` | `intgenisis_profile_c` | `artifact` | tag 7 | historical v2; `project_u_digits_y_bounded_sources_v6` |
| `artifact-n1024-bq10-r96-v2` | `intgenisis_profile_c` | `artifact` | tag 7 | historical v2; `project_u_digits_y_bounded_sources_v6` |
| `artifact-n1024-bq16-r96-v2` | `intgenisis_profile_c` | `artifact` | tag 7 | historical v2; `project_u_digits_y_bounded_sources_v6` |
| `pilot-n1024-bq32-r96-v2` | `intgenisis_profile_c` | `candidate` | tag 9 | historical v2; `project_u_digits_y_bounded_sources_v6` |
| `poc-n1024-bq64-r128-v2` | `intgenisis_profile_c` | `poc` | tag 10 | historical v2; `project_u_digits_y_bounded_sources_v6` |
| `poc-n1024-bq96-r128-v2` | `intgenisis_profile_c` | `poc` | tag 10 | historical v2; `project_u_digits_y_bounded_sources_v6` |
| `poc-n1024-bq128-r128-v3` | `intgenisis_profile_c` | `poc` | tag 10 | strict v3; input trace, two-lane carriers, and public-linear hat fusion |
| `system-n1024-wf128-crom-v2` | `intgenisis_profile_c` | `candidate` | tag 13 | strict v3; input trace, two-lane carriers, and public-linear hat fusion |

The revision suffix in a canonical ID is part of that ID. The first seven rows
retain preset manifest version `2`, proof schema `2`, their historical
relation/layout values, and their historical evidence. The two strict targets
carry this exact tuple:

```text
preset manifest             3
proof schema                3
canonical proof codec       6 / SPRUCEP6
field encoding              radix-q-v1;group=1024
Q kernel                    ker-sum-omega-constant-v1
Merkle topology             exact-n-largest-lower-power-v3
transcript/domain           smallfield_2025_1085_salted_tapes_v3 /
                            smallwood_2025_1085_salted_decs_v3
relation / layout           3 / 3
credential-state format     8
presentation format         3
issuance-artifact format    4
holder-usage format         3
claim_scope                 proof_only
```

Codec 6 derives the exact positional Merkle frontier from the Fiat–Shamir
tail and transmits only those sibling hashes. It carries no node count,
positions, path references, or worst-case zero padding. Codec 5 is a rejected
legacy grammar. BQ128 showing also uses the manifest-bound R11/L4 shortness
relation; WF128 remains R11/L4. No grinding, leaf count, query cap, κ, or
cryptographic width changed.

There is no migration layer. A selector must be a canonical ID, and every
persisted object must have the exact schema and manifest binding required by
that ID. Strict-v3 targets reject legacy JSON state, v2/debug proofs,
presentation-v2, issuance-v3, and holder/verifier usage-v2 artifacts rather
than normalizing them. Changing a preset, public-parameter digest, PRF
parameter digest, verifier-key digest, transcript tuple, field profile, or
rate-limit policy creates a different protocol identity.

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

All source sampling uses an injected entropy reader; entropy failure aborts.
The public parameters store `hash_input_bound=1`, so the prover, verifier, and
artifact identity agree on the accepted coefficient domain. On the two strict
targets, every Fiat--Shamir challenge, witness randomizer, mask randomizer,
bounded integer, distinct tail index, base-field point, and point in
`K \ Omega` is sampled by exact rejection from a domain-separated SHAKE-256
stream. No v3 path uses `% q` or `% length` as its distribution rule. The
legacy v2 sampler remains unchanged for the seven historical presets.

## Public Context And Hidden Slot

The algebraic rate policy is unchanged across the historical and strict target
paths and has the exact identity:

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
Historical presets persist the v2 holder ledger. Strict targets use
holder-usage format 3, whose credential fingerprint is derived from canonical
state-v8 bytes and configured-width public/key bindings; a v2 ledger at the
same path is an error, not migration input.

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

## Historical Bounded-Source Row Encodings

The seven historical v2 presets retain these showing layouts:

```text
intgenisis_showing_y_linear_bounded_sources_v2
intgenisis_showing_project_u_digits_y_view_bounded_sources_v4
intgenisis_showing_project_u_digits_y_bounded_sources_v6
```

The compact degree-512 preset uses the bounded-source `y_view` layout with
projection mode `project_u_digits_and_y_view_v3`. The six historical
degree-1024 presets use `project_u_digits_y_bounded_sources_v6`. Both preserve
explicit coefficient views for `mu_sig`, `x0`, and `x1`, their transformed
hats, ternary membership, and source-to-hat bridges.

The projection descriptor is `intgenisis_replay_projection_v2`. A proof binds
the exact descriptor and row-layout version in its Fiat-Shamir public inputs.
Unknown projections, layout/projection mismatches, and any encoding that omits
the individual bounded sources are rejected.

## Strict-v3 Relation Reformulation

The BQ128/WF128 showing relation preserves the same public equations but uses
three locally checked algebraic reformulations to reduce committed rows.

First, Poseidon input-trace v3 commits the 179 S-box inputs in canonical
round/lane order and derives each cube in the relation. Selector-weighted
cubic terms are `L*P^3`, not `(L*P)^3`. The authenticated seed, 11 public
context lanes, hidden slot, and slot bits are reused at their existing source
locations. The final MDS/feed-forward equations derive the public tag directly.
The retained payload is 189 scalars for BQ/tag-10 and 192 for WF/tag-13; each
fits six 32-column rows. The six old PRF bridge matrices and all bridge
metadata are forbidden on v3.

For fixed parameters and authenticated sources, induction over the Poseidon
rounds maps every valid output trace to one valid input trace and conversely;
the terminal equations derive the same tag. This is a local algebraic
equivalence lemma, not a new statement from the manuscript. Compiler-derived
showing degrees remain `(d,d')=(9,8)` for BQ and `(11,8)` for WF.

Second, the 96 logical ternary source rows for `mu_sig`, `x0`, and `x1` are
paired as

```text
Enc(a,b) = (a+1) + 3*(b+1),  a,b in {-1,0,1}.
```

Membership in `{0,...,8}` is enforced by a degree-9 polynomial. Two fixed
degree-at-most-8 decoders recover the lanes, which feed the same coefficient,
CRT, NTT, and signature semantics as the historical raw rows. The retained
nonlinear hats remain source-bridged. No duplicate raw source rows remain. This
changes 96 rows to 48; together with the six-row PRF payload, the first
strict-v3 pass reduced each target showing relation by 49 logical rows.

Third, strict v3 now substitutes the public-linear transforms of `mu_sig` and
`x0` directly into the projected signature aggregate. For decoded carrier rows
`C_r`, every eliminated target hat is a fixed expression

```text
hat(a)[t] = sum_{x in Omega} H_t(x) *
            sum_r alpha[t,r] * Decode(C_r(x)).
```

The old relation used this value only as `B[t]*hat(a)[t]`, where `B[t]` is
public. Distributing `B[t]` through the expression gives the fused aggregate.
Every old satisfying witness therefore satisfies the fused relation, and the
committed bounded sources uniquely reconstruct the eliminated hats in the
opposite direction. The paper's hats are expressions, not a requirement to
commit a separate row for every public-linear expression. This removes 32
`mu_sig` and 32 `x0` hat rows without changing the extracted source tuple.

The `x1` and `Z` hats remain materialized and source-bound because
`(B3[t]-hat(x1)[t])*hat(Z)[t]=1` is nonlinear in two witness images. Fusing that
chain would require a new relation and degree proof; this implementation does
not do so. The public-linear substitution uses only the existing
degree-at-most-8 lane decoders. Compiler-derived degrees therefore remain
`(d,d')=(9,8)` for BQ and `(11,8)` for WF, and `dQ` remains 472 and 471.

The eliminated expressions are not sent publicly: their commitments disappear.
Every surviving carrier/witness row retains its independent `omegaExtra`
randomizer, DECS tapes remain independent, and the compiler recomputes all
layers, masks, queries, and theorem terms for the reduced geometry.

The complete current progression is:

| Target | Historical rows | First-v3 rows | Current rows | Witness layers | Replay rows | Mask rows | Physical rows | Queries | Opening rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BQ128, `L=43` | 600 | 551 | 487 | 12 | 540 | 156 | 696 | 169 | 527 |
| WF128, `L=41` | 536 | 487 | 423 | 11 | 429 | 91 | 520 | 84 | 436 |

## Strict-v3 SmallWood Foundation

The target proof path implements the following paper-facing invariants before
any compression is accepted.

- Each logical witness row receives a fresh independent `rho_i in K`. Its
  degree-at-most-`s` interpolant preserves every value on `Omega` and satisfies
  `P_i(omegaExtra)=rho_i`; the split coordinates occupy the existing tail
  rows. Reusing the same logical witness therefore does not reuse its
  extra-point value.
- For mask degree `dQ` and LVCS width `L`, the Equation (2) encoding uses
  `mu=ceil(dQ/L)` and exactly `(mu+1)*theta` rows. It includes the shifted final
  column and fresh independent `+tau/-tau` boundary randomizers. Semantic mask
  queries reconstruct and authenticate `M(e)` through `VTargets`; the former
  identity/rank-padding queries are not part of v3.
- Equation (4) is built and checked through one semantic relation evaluator:

  ```text
  Q_i(e) = M_i(e)
         + sum_j GammaPrime_i,j(e) * F_j(e)
         + sum_j gamma_i,j * FPrime_j(e).
  ```

  The prover evaluates that relation at `dQ+1` fixed distinct base-field
  points and interpolates limbwise. The verifier consumes the same relation
  IR at its challenge point. `BuildQK` and the debug/formal coefficient replay
  path are not accepted on v3. The canonical wire may omit only each limb's
  constant coefficient, uniquely reconstructing it from
  `sum_{omega in Omega} Q(omega)=0`; the full executed `QPayload` is restored
  before the third Fiat--Shamir round.
- The verifier derives `dQ` from compiler degrees and derives the DECS row
  degree as `LVCSNCols+ell-1`. No wire field can raise either bound. The value
  is 60 for BQ, 50 for WF issuance, and 49 for the adopted WF showing width.

The fixed public extension fields are:

| Target | `theta` | Profile | `omegaExtra` | Binding width |
| --- | ---: | --- | --- | ---: |
| WF128 | 7 | `spruce-smallwood-kfield-q1017857-theta7-v3` | `X mod Chi` | 264 bits |
| BQ128 | 13 | `spruce-smallwood-kfield-q1017857-theta13-v3` | `X mod Chi` | 392 bits |

Each profile fixes and validates a monic irreducible `Chi`, support separation,
and interpolation inverses. Its canonical bytes and SHAKE digest are manifest-
and transcript-bound. Neither `Chi` nor `omegaExtra` is transmitted.

WF128 showing uses `LVCSNCols=41`, with frozen
`kappa=[1,0,2,13]`, `NLeaves=327680`, `eta=43`, `theta=7`, and `ell=9`.
After public-linear hat fusion it has 423 logical rows, 11 witness layers, 13
mask chunks, 520 physical rows, 84 queries, and 436 opening rows. BQ retains
`LVCSNCols=43` and `kappa=[5,6,12,13]`, with 487 logical rows, 12 witness layers,
696 physical rows, 169 queries, and 527 opening rows. This work does not
increase grinding, domain size, query caps, salt/hash/tape widths, or work.

## Independent Salted Tapes

The seven historical presets retain this exact tuple and proof schema 2:

```text
protocol = smallfield_2025_1085_salted_tapes_v2
version  = smallwood_2025_1085_salted_decs_v2
gate     = smallwood_2025_1085_salted_tapes_v2_live
```

The two strict targets instead require proof schema 3 and:

```text
protocol = smallfield_2025_1085_salted_tapes_v3
version  = smallwood_2025_1085_salted_decs_v3
gate     = smallwood_2025_1085_salted_tapes_v3_live
omission = canonical_reconstruction_v3
```

Every epoch samples a fresh proof-global salt and makes it an explicit input
to Fiat--Shamir and every DECS commitment context. A commitment context carries
a version and role such as `main`, `q-payload`, `companion`, `replay`, or
`sig-shortness`; strict v3 uses only the roles required by its reconstructed
single-opening path.

For each logical leaf, DECS samples an independent fixed-width tape. The leaf
hash binds the context, leaf index, evaluation point, modulus, canonical
residues, and that leaf's tape. Internal nodes and padding bind the same
context, level, index, and framed children. An opening transmits exactly the
tape belonging to each distinct opened leaf.

Verification checks the exact salt, role, version, tape count and width,
canonical residues, distinct indices, authentication paths, and low-degree
relations. Neither epoch has an accepted master-tape seed or seed-compressed
fallback.

Strict v3 additionally uses a 64-byte SHAKE-256 digest for each of four chained
rounds and injectively frames the round, prior digest, material count, each
message, and the unchanged `uint64` grinding counter. The first round absorbs
the canonical complete `PublicInputs` frame directly, including every matrix,
tag, context, bound, relation field, complete preset-manifest bytes, complete
field-profile bytes, and the verifier-reconstructed complete `RowLayout`. The
layout encoder is injective over the closed layout type graph: it frames field
names, zero values, nil/present markers, slice lengths, row locations, and the
hat-source mode. A stale materialized-hat layout is therefore a different
statement and is rejected. Subsequent rounds bind `R` plus the fixed profile,
the full reconstructed `QPayload`, and dense reconstructed
`VTargets`/`BarSets` before deriving the distinct tail. Challenges expand from
the full SHAKE round digest. `LabelsDigest` is forbidden in a v3 proof, and no
SHA-256 intermediate is the sole binding for a target public statement.

The v3 opening keeps independent tapes but encodes Merkle authentication as a
canonical positional frontier multiproof. Tail-derived sibling positions are
not transmitted. The fixed-size wire zero-pads to the public worst-case node
bound; nonzero padding, duplicate/missing siblings, alternate encodings,
truncation, and trailing bytes reject. DECS commitment/opening structures
remain version 2 internally, but a strict-v3 canonical proof admits only the
one authoritative opening reconstructed under its trusted v3 context.

## Presentation Verification And State

Presentation creation requires:

```text
-state-path
-verifier-key
-context-file
-holder-usage-state
-presentation-out
```

For the seven historical presets, the resulting
`intgenisis_presentation_v2` JSON envelope contains the manifest,
public-parameter, verifier-key, and context digests; the 11 derived public
context lanes; the public tag; and the schema-2 proof. It excludes raw context
bytes and hidden-slot material.

For the two targets, presentation format 3 is binary and contains exactly:

```text
magic/version || packed public tag || canonical schema-3 showing proof.
```

Preset, public parameters, verifier key, and context are supplied independently
by the verifier and are bound directly into Fiat--Shamir. A JSON file beside a
v3 presentation is only a non-verifying digest/length/report sidecar; it is not
a lossless proof format.

Rate-limited verification requires:

```text
-public-params
-verifier-key
-verify-presentation
-expected-context-file
-verifier-state
```

The verifier selects the path from the validated manifest, then:

1. strictly decodes the epoch-specific presentation, public parameters, and
   verifier key;
2. validates their manifest and content-digest bindings;
3. derives the expected digest and 11 lanes from independently supplied raw
   service context bytes;
4. on v2, compares that binding with the envelope; on v3, supplies it as the
   trusted canonical-proof context;
5. verifies the SmallWood proof and public tag relation, with no cross-epoch
   fallback; and
6. under an exclusive lock, rejects a tag already accepted in that context or
   atomically records the new `(context, tag)` acceptance.

The verifier state is namespaced by public-parameter, verifier-key, and context
bindings. Historical replay state is format 2; target replay state is format 3
and uses configured-width SHAKE bindings. A v2 replay file presented to the v3
transition is rejected. Deployments that intend a shared quota must share one
consistent verifier-state namespace; isolated state files enforce isolated
acceptance histories.

With `-proof-only`, step 6 is deliberately skipped. The flag is valid only for
verification, cannot be combined with `-verifier-state`, and does not represent
rate-limit acceptance.

### Strict-v3 source-only issuance

The two targets commit 49 issuance source rows: 15 paired carriers for the 30
ordinary-message blocks, two raw reserved/seed-tail blocks, 16 paired `S`
carriers, and 16 paired `E` carriers. Degree-9 membership and fixed
degree-at-most-8 lane decoders recover every source coordinate. The verifier's
`m_eq` statement is strictly decoded: attribute slots are exactly signed
ternary and every key/reserved slot is zero; public integers are never reduced
modulo `q`.

The relation reconstructs all 1,024 transform coordinates and retains every
commitment residual `CM[t]M[t]+AS[t]S[t]+E[t]-Com[t]`. Production evaluates the
Fiat--Shamir-weighted aggregate by distributive reassociation in the canonical
`gamma[out*N+t]` order, over all K limbs. It does not omit a constraint. The
formal 1,024-residual evaluator is retained as an independent oracle, and both
BQ128 and WF128 tests require the complete `Q` polynomials to be
coefficient-for-coefficient identical. Issuance geometry is BQ 49 logical / 90
replay / 156 mask / 246 physical rows with `(d,d',dQ)=(9,8,472)`, and WF
49 / 78 / 77 / 155 with `(9,8,391)`.

### Strict-v3 canonical codecs

The canonical proof wire carries only magic/version/kind, configured-width
root, exact salt, four minimally encoded counters, packed full `R`, the packed
nonconstant coefficients of `QPayload`, trusted-ragged `VTargets`, packed
`BarSets`, and the authoritative DECS opening. All dimensions, layouts,
profiles, challenges, tail indices, coefficient plans, and omission metadata
are reconstructed from trusted context. Field elements use fixed-width grouped
radix-`q` encoding (at most 1,024 digits per group); values outside `[0,q^r)`,
nonzero spare bits, nonminimal counters, wrong kind/context, retired padding,
or trailing data reject.

For `Q(X)=sum_i q_i X^i`, the verifier derives the omitted constant from the
enforced relation

```text
q_0 = -|Omega|^(-1) * sum_{i=1}^{dQ} q_i *
                         sum_{omega in Omega} omega^i.
```

The encoder rejects a full in-memory `Q` that violates this identity; decoding
restores the dense matrix before round-three Fiat--Shamir replay. `VTargets`
omits only trusted zero suffixes: final issuance witness layers are 6 columns
for BQ and 7 for WF, while final showing layers are 36 and 13. The Equation
(2) mask-query widths are 41 for BQ showing and 40 for WF showing. Nonzero
omitted suffixes reject, and dense rows are restored before transcript and
semantic-mask checks. Neither omission depends on a challenge value. Merkle
authentication separately uses the exact tail-derived unpadded frontier.

The implemented paper projection uses full `R` and omits standalone `M(e)`.
The paper's equivalent alternative shortens `R` by `ell` columns but must then
carry `M(e)`; both representations account for
`eta*(dDECS+1)` base-field elements. Combining shortened `R` with omitted `M`
is invalid. Paper accounting charges exactly `rho*dQ*theta` field elements for
`Q`; it omits only the same pre-challenge support-sum constant as codec 6.

Across the three final runs in
`artifacts/smallwood-v3/final-size-optimization-v2`, the exact medians are:

| Target | State | Issuance proof | Showing proof | Presentation | Paper issuance/showing |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B |
| WF128 | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B |

The immediately preceding codec-5 medians were BQ
52,385 / 86,801 / 86,834 B and WF 22,050 / 38,068 / 38,109 B, with paper
57,271 / 91,756 B and 23,790 / 39,837 B. That evidence remains immutable.

The corrected first-v3 paper baselines are 65,296 / 96,098 B for BQ128 and
27,655 / 41,933 B for WF128. Earlier 62,614 / 93,416 B and
26,672 / 40,950 B values used the invalid shortened-`R`/omitted-`M`
combination and are historical only.

State format 8 is a canonical binary secret-only encoding. It packs ordinary
ternary attributes and witnesses in base 243, the 48 seed symbols in base 9,
and bound-shifted signature coefficients four per fixed-width group. Public
matrices, `MAttr`, packed key `K`, reserved zeros, paths, NTRU public data, and
the signature bound are reconstructed from the trusted public/key context.
Saves are atomic mode `0600`. The fixed target sizes are 4,926 bytes for BQ and
4,894 bytes for WF.

The codec boundary is deliberately fail closed at codec 6 (`SPRUCEP6`):
`MarshalCanonicalProof` and
`UnmarshalCanonicalProof` accept only schema 3 and an explicit `PreSign` or
`Showing` context; state-v8 and presentation-v3 do not probe JSON; issuance
format 4 carries canonical pre-sign bytes and rejects a JSON proof; and no v3
wire representation exists for `MaskCoeffDebug`, `FparCoeffDebug`,
`FaggCoeffDebug`, `QCoeffDebug`, `MKData`, or `QKData`. Codecs 3, 4, and 5 are
explicitly rejected; codec 4's provisional second `Q` reconstruction depended
on the later evaluation challenge, while codec 5 used the retired padded
frontier grammar.

## Artifact Identity And No Migration

| Object | Seven historical presets | BQ128/WF128 strict targets |
| --- | --- | --- |
| preset manifest | version `2` | version `3` |
| public parameters | schema `8`, v2 policy | unchanged container schema `8`, manifest-v3 binding |
| credential state | JSON schema `7` | canonical binary format `8` |
| verifier key | version `2` | unchanged container version `2`, manifest-v3 binding |
| presentation | version `2`, `intgenisis_presentation_v2` | binary format `3` |
| issuance artifacts | version `3`, JSON proof | version `4`, canonical pre-sign proof only |
| holder usage state | version `2` | version `3` |
| verifier state | version `2` | version `3` |
| proof | schema `2`, v2 transcript tuple | schema `3`, strict-v3 tuple |
| relation / layout | historical v2 values | `3 / 3` |
| DECS commitment/opening | version `2`, explicit context | version `2`, one canonical authoritative opening under v3 transcript |
| NTRU parameters | `ntru-params-v2` | unchanged |
| NTRU key | `ntru-key-v2` | unchanged |
| NTRU signature | `ntru-signature-v2` | unchanged |

These formats use strict decoding and canonical values. The manifest selects
one column; a schema number is never interpreted as a request to upgrade an
older object. There is no cross-epoch verifier or conversion command. The
other seven presets' files and historical results are not rewritten through
the target codecs.

## Relationship To The Manuscript

The main correspondence with `../Better-Lattice-based-Blind-Signatures` is:

| Manuscript area | SPRUCE implementation |
| --- | --- |
| `sections/03_blind_signature.tex` | `issuance/intgenisis.go`, `cmd/issuance/flow_helpers.go`, `ntru/` |
| `sections/04_arc_construction.tex` | `credential/presentation_context.go`, v2 and v3 presentation/usage codecs, `cmd/showing/` |
| `sections/05_smallwood_model.tex` | `PIOP/`, `LVCS/`, `DECS/` |
| `sections/06_parameters.tex` | `credential/intgenisis_profile.go`, `credential/intgenisis_presets.go`, `credential/preset_manifest.go` |
| `appendix/B_gaussian_sampler.tex` | `ntru/` sampler and trapdoor implementation |
| `appendix/C_smallwood_details.tex` and `appendix/D_extended_parameters.tex` | v2 transcript plus v3 exact sampling, Equation (2) masks, semantic Equation (4), full-R/omitted-M accounting, trusted canonical reconstruction, row geometry, and proof reporting in `PIOP/` |
| `appendix/E_prf_and_misc.tex` | `prf/`, historical companion relation, and strict-v3 input-trace/carrier/public-linear-hat relation in `PIOP/` |

The manuscript is the mathematical narrative; the Go manifest is the
executable parameter authority. Generated sizes and timings must come from a
benchmark of the same manifest/proof epoch: historical v2 evidence for the
first seven presets and canonical v3 evidence for BQ128/WF128. The paper was
not modified by the v3 work, and the repositories are not synchronized
automatically. The exact paper-to-code mapping, local equivalence lemma, byte
accounting, and remaining assumptions are recorded in
[CREDENTIAL_SIZE_OPTIMIZATION.md](CREDENTIAL_SIZE_OPTIMIZATION.md).

## Code Map

| Area | Main paths |
| --- | --- |
| CLI orchestration | `cmd/issuance/`, `cmd/showing/` |
| canonical presets and policy | `credential/intgenisis_presets.go`, `credential/preset_manifest.go`, `credential/v2_policy.go` |
| public/key and credential-state artifacts | `credential/public_params.go`, `credential/intgenisis_state.go`, `credential/intgenisis_state_v8.go`, `credential/intgenisis_verifier_key.go` |
| presentation and quota state | `credential/intgenisis_presentation.go`, `credential/intgenisis_presentation_v3.go`, `credential/intgenisis_usage_state.go`, `credential/intgenisis_usage_v3.go`, `credential/presentation_operations_v3.go` |
| committed-message issuance | `issuance/intgenisis.go`, `cmd/issuance/flow_helpers.go` |
| bounded BB-tran public hash | `internal/hash/vsis_bbs.go` |
| canonical proof/transcript | `PIOP/canonical_proof_codec_v3.go`, `PIOP/canonical_transcript.go`, `PIOP/public_statement_v3.go`, `PIOP/fs_helpers.go` |
| mask and semantic Equation (4) | `PIOP/smallfield_mask_v3.go`, `PIOP/semantic_q_v3.go` |
| strict-v3 relation reformulation | `PIOP/prf_input_trace_v3.go`, `PIOP/prf_input_trace_v3_relation.go`, `PIOP/intgenisis_showing_eval.go`, `PIOP/mu_x0_hat_fusion_test.go`, and ternary-carrier helpers in `PIOP/` |
| SmallWood/PACS proof | `PIOP/` |
| fixed extension fields | `internal/kfield/profile.go` |
| row commitment stack | `LVCS/`, `DECS/` |
| Ajtai commitment | `commitment/` |
| NTRU/vSIS | `ntru/` |
| Poseidon2 PRF | `prf/` |

See [../ARTIFACT.md](../ARTIFACT.md) for executable commands,
[SECURITY.md](SECURITY.md) for the proof-only security boundary, and
[CREDENTIAL_SIZE_OPTIMIZATION.md](CREDENTIAL_SIZE_OPTIMIZATION.md) for the two
strict targets' implementation/evidence report.
