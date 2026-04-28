# ARC-SPRUCE IntGenISIS Full Alignment Plan

This plan describes how to move from the current IntGenISIS prototype described in `IMPLEMENTATION_RUNBOOK.md` to a protocol implementation that is aligned with the construction in `docs/arc_spruce_intgenisis`.

The current code has the right algebraic direction:

```text
M := m || k
c = C_M M + A_s s + e
T = B0 + B1 mu_sig + B2 x0 + Z + c
Z = (B3 - x1)^(-1)
A u = T
tag = PRF(k, nonce)
```

But it is not yet paper-complete. The main missing pieces are:

- full `M = m || k` binding;
- PRF key-space membership;
- issuance policy constraints;
- PIOP-enforced bounds;
- explicit PRF companion key binding back to `M`;
- IntGenISIS-compatible signature shortness;
- minimized issuer response without public `T`;
- standalone presentation/proof artifacts;
- persistent verifier replay-state;
- final benchmark and soundness regeneration;
- full legacy quarantine.

This document is an implementation roadmap with file-level actions, larger refactors, acceptance gates, and test requirements.

## Target Definition

The fully aligned live protocol must implement the following interfaces.

### Setup

Public parameters include:

```text
N, q
ring/NTT context metadata
n = n_c
B0, B1, B2, B3
A or equivalent NTRU public key for SampPre verification
C_M in R_q^{n_c x ell_M}
A_s in R_q^{n_c x k_s}
ell_M
k_s
n_c
B
ell_mu_sig = 1
ell_x0 = 2
ell_x1 = 1
signature_preimage_len = 2
PRF params/key-space description
SmallWood packing/profile metadata
schema/profile labels
```

Primary profile:

```text
intgenisis_profile_b
N = 512
q = 1054721
ell_M = 1
k_s = 2
n_c = 1
B = 8
```

Compact candidate:

```text
intgenisis_profile_a
N = 256
q = 1054721
ell_M = 1
k_s = 4
n_c = 1
B = 8
```

Profile A should remain disabled for live protocol commands until `N=256` NTRU/SampPre, PIOP, showing, and benchmarks pass end to end.

### Issuance

Holder sends only:

```text
IssuanceRequest = {
  c,
  pi_pre
}
```

Issuer response is:

```text
IssuanceResponse = {
  u,
  mu_sig,
  x0,
  x1
}
```

The issuer response must not serialize `T` in the final aligned schema. The holder can recompute `T` locally during finalization from `c`, `mu_sig`, `x0`, `x1`, and public params.

### Credential State

The holder stores:

```text
u
M
m
k
s
e
mu_sig
x0
x1
profile metadata
public parameter references
```

The holder does not store old shared-randomness fields, and the live showing path does not depend on:

```text
r0, r1, r0H, r1H, r0I, r1I, RI0, RI1, T, c
```

`c` may remain in issuance artifacts, but not in final showing public inputs.

### Showing

Presentation public data:

```text
nonce
tag
proof
```

The verifier reconstructs public statement data from public parameters and verifier state. It must not receive:

```text
c
T
M
m
k
s
e
mu_sig
x0
x1
Z
u
```

The showing proof relation proves:

```text
(B3 - x1) * Z = 1
A u = B0 + B1 mu_sig + B2 x0 + Z + C_M M + A_s s + e
M = m || k
tag = PRF(k, nonce)
k in K_key
policy/presentation constraints
bounds on M,s,e,u and any bounded sampled values required by the concrete profile
```

## Architectural Refactors

The current implementation added IntGenISIS beside old code. The next step should stop treating IntGenISIS as a patch branch inside legacy types and introduce explicit protocol layers.

### Refactor 1: Split Live IntGenISIS Types From Legacy Types

Current affected files:

- `credential/public_params.go`
- `credential/params.go`
- `credential/intgenisis_profile.go`
- `credential/intgenisis_state.go`
- `cmd/issuance/flow_helpers.go`
- `cmd/showing/main.go`
- `PIOP/builder_types.go`

Problems:

- `credential.PublicParams` still contains both legacy and IntGenISIS fields.
- CLI artifact structs still serve both protocols.
- `PIOP.PublicInputs` is shared between old showing, old pre-sign, IntGenISIS pre-sign, and IntGenISIS showing.
- Several legacy flags remain accepted by IntGenISIS commands even when ignored.

Plan:

1. Add a typed IntGenISIS parameter layer:

   ```text
   credential.IntGenISISPublicParams
   credential.IntGenISISCommitmentParams
   credential.IntGenISISProofParams
   credential.IntGenISISProfile
   ```

2. Keep `credential.PublicParams` as a backward-compatible loader only. Convert loaded values into one of:

   ```text
   credential.LegacyPublicParams
   credential.IntGenISISPublicParams
   ```

3. Add typed PIOP public statements:

   ```text
   PIOP.IntGenISISPreSignPublic
   PIOP.IntGenISISShowingPublic
   PIOP.LegacyPreSignPublic
   PIOP.LegacyShowingPublic
   ```

4. Make `PIOP.PublicInputs` either an internal compatibility adapter or split it entirely. The final IntGenISIS prover/verifier should not accept legacy fields by construction.

5. Add schema versions:

   ```text
   intgenisis_public_params_v2
   intgenisis_issuance_request_v1
   intgenisis_presign_submission_v1
   intgenisis_issuance_response_v1
   intgenisis_credential_state_v6
   intgenisis_presentation_v1
   intgenisis_verifier_state_v1
   ```

Acceptance:

- IntGenISIS commands cannot accidentally deserialize old challenge artifacts as valid new artifacts.
- IntGenISIS PIOP statements have no `Ac`, `RI0`, `RI1`, or `T` fields.
- Legacy tests still pass through explicitly named legacy paths.

### Refactor 2: Centralize Message Encoding

Current affected files:

- `cmd/issuance/flow_helpers.go`
- `cmd/showing/main.go`
- `PIOP/signed_key_extraction.go`
- `issuance/intgenisis.go`
- `credential/intgenisis_state.go`

Problem:

- The current prototype constructs `M` directly in `holderCommitIntGenISIS` and places the PRF key into a fixed region of the ring polynomial.
- `MAttr` and `K` are stored, but the PIOP does not prove `M = m || k`.
- PRF key extraction during showing relies on helper conventions rather than a protocol-level message layout object.

Plan:

1. Add a dedicated message encoding module:

   ```text
   credential/message_encoding.go
   credential/message_encoding_test.go
   ```

2. Define:

   ```go
   type SemanticMessageLayout struct {
       RingDegree int
       EllM int
       AttributeSlots []CoeffSlot
       KeySlots []CoeffSlot
       ReservedSlots []CoeffSlot
       Bound int64
       PRFKeyLen int
   }
   ```

3. Implement:

   ```go
   EncodeSemanticMessage(layout, m, k) -> M
   DecodeSemanticMessage(layout, M) -> (m,k)
   ValidateSemanticMessage(layout, M, m, k) error
   PRFKeyFromSemanticMessage(layout, M) -> []prf.Elem
   ```

4. Store the layout in public params or derive it from the selected profile plus PRF params.

5. Make every caller use this module:

   - `holderCommitIntGenISIS`
   - `holderProveIntGenISIS`
   - `holderFinalizeIntGenISIS`
   - `runIntGenISISShowingCLI`
   - PIOP relation builders
   - tests

6. Remove ad hoc key-slot constants from CLI code.

Acceptance:

- Changing message packing in one place updates issuance, showing, PRF extraction, and PIOP constraints.
- A test can mutate one key slot in `M` and show that the PRF/tag relation fails.
- A test can mutate `m` or `k` while keeping `M` fixed and show that the encoding relation fails.

### Refactor 3: Protocol Artifact Boundary

Current affected files:

- `cmd/issuance/flow_helpers.go`
- `cmd/issuance/benchmark_x0.go`
- `cmd/showing/main.go`
- `credential/intgenisis_state.go`

Problem:

- IntGenISIS issuance uses legacy artifact structs with extra fields, including compatibility `T`.
- Showing does not persist a presentation artifact.
- Verifier replay-state does not exist as a durable artifact.

Plan:

1. Add a small protocol artifact package or local files under `credential/`:

   ```text
   credential/intgenisis_artifacts.go
   credential/intgenisis_presentation.go
   credential/verifier_state.go
   ```

2. Define strict structs:

   ```go
   type IntGenISISIssuanceRequest struct {
       Version int
       Profile string
       CredentialPublicPath string
       Com [][]int64
       PreSignProof *PIOP.Proof
       ProofGeometry ...
   }

   type IntGenISISIssuanceResponse struct {
       Version int
       Profile string
       MuSig [][]int64
       X0 [][]int64
       X1 [][]int64
       SigS1 []int64
       SigS2 []int64
       NTRUPublic [][]int64
       SignatureCertificate optional
   }

   type IntGenISISPresentation struct {
       Version int
       Profile string
       PublicParamsDigest []byte
       Nonce [][]int64
       Tag [][]int64
       Proof *PIOP.Proof
   }

   type IntGenISISVerifierState struct {
       Version int
       SeenTags map[string]SeenTagEntry
   }
   ```

3. Remove `T` from the final response struct.

4. If a signature certificate still needs target information for local debugging, store it under an explicit debug artifact:

   ```text
   intgenisis_issue_response.debug_target.json
   ```

   The live response must not require it.

Acceptance:

- JSON privacy tests fail if response contains `T`.
- JSON privacy tests fail if presentation contains witness material.
- Verifier CLI can persist and reject repeated `(nonce, tag)`.

## Phase 1: Complete Message Encoding And Key Binding

### Scope

Implement the canonical `M = m || k` layout and make all protocol layers consume it.

Files to modify:

- `credential/intgenisis_profile.go`
- `credential/public_params.go`
- `credential/intgenisis_state.go`
- `credential/message_encoding.go` new
- `cmd/issuance/flow_helpers.go`
- `cmd/showing/main.go`
- `PIOP/intgenisis_presign.go`
- `PIOP/intgenisis_showing.go`
- `PIOP/intgenisis_layout.go`
- `PIOP/signed_key_extraction.go`

### Work Items

1. Define exact slot layout for profile B:

   - attribute slots;
   - key slots;
   - reserved zero slots;
   - signed-lift convention;
   - coefficient bound convention.

2. Decide how attributes `m` are represented in the demo:

   - if no attributes are supported yet, define `m` as an explicit zero-width or zero-valued policy row;
   - do not leave it as an implicit empty side channel.

3. Add message layout to public params:

   ```text
   message_layout.version
   message_layout.ell_M
   message_layout.attribute_slots
   message_layout.key_slots
   message_layout.bound
   ```

4. Replace direct `M` construction in `holderCommitIntGenISIS`.

5. Replace direct key extraction in showing with `PRFKeyFromSemanticMessage`.

6. Add PIOP row components for `m` and `k`.

7. Add encoding residuals:

   ```text
   M_slot_i - m_i = 0
   M_key_slot_j - k_j = 0
   M_reserved_slot_l = 0
   ```

   These should be expressed in the same replay basis as the rest of the IntGenISIS rows.

8. Make `M`, `m`, and `k` row positions part of `IntGenISISPreSignRowLayout` and `IntGenISISShowingRowLayout`.

### Tests

- `EncodeSemanticMessage` round trip.
- PRF key extraction from `M` matches original `k`.
- Mutating a key slot in `M` changes the derived tag.
- Pre-sign proof rejects mismatched `M` and `k`.
- Showing proof rejects mismatched `M` and `k`.
- Reserved slots must be zero if the layout requires them.

### Acceptance

The implementation has a single source of truth for `M=m||k`, and both pre-sign and showing proofs enforce it.

## Phase 2: Complete Pre-Sign Relation

### Target Relation

Public:

```text
c
C_M
A_s
issuance policy public data
profile/message layout
```

Witness:

```text
M
m
k
s
e
```

Constraints:

```text
c = C_M M + A_s s + e
M = m || k
k in K_key
m satisfies issuance policy
M,s,e bounded by B
```

### Files To Modify

- `PIOP/intgenisis_presign.go`
- `PIOP/intgenisis_presign_eval.go`
- `PIOP/intgenisis_layout.go`
- `PIOP/generic_builder.go`
- `PIOP/bound_spec.go`
- `PIOP/non_sig_bounds.go`
- `PIOP/fpar_membership.go`
- `PIOP/norm_wire_linf.go`
- `PIOP/run.go`
- `cmd/issuance/flow_helpers.go`
- `cmd/issuance/main_test.go`

### Work Items

1. Extend pre-sign row order:

   ```text
   M
   m
   k
   s
   e
   bound auxiliaries
   policy auxiliaries
   masks
   ```

2. Preserve a deterministic row order and include it in proof metadata.

3. Add replay constraints:

   - commitment equation;
   - message encoding;
   - key-slot binding;
   - reserved-slot zero constraints.

4. Add bound gadgets:

   - `M` coefficients in `[-B,B]`;
   - `s` coefficients in `[-B,B]`;
   - `e` coefficients in `[-B,B]`;
   - `k` key-space bound or membership convention.

5. Add issuance policy extension point:

   ```go
   type IssuancePolicy interface {
       PublicData() ...
       BuildRows(...)
       BuildConstraints(...)
       VerifyPublic(...)
   }
   ```

   Start with a no-op policy and one simple test policy, for example an attribute equality or range predicate.

6. Update Fiat-Shamir binding to include:

   - message layout digest;
   - policy identifier;
   - policy public data;
   - bounds;
   - profile name and schema version.

7. Keep rejection of old public fields, but move that from runtime checks to type boundaries where possible.

### Tests

- valid profile-B pre-sign verifies.
- tampered `c` fails.
- tampered `C_M` fails.
- tampered `A_s` fails.
- tampered `M=m||k` layout fails.
- wrong `k` fails.
- out-of-bound `M`, `s`, or `e` fails.
- wrong policy public data fails.
- proof serialized with legacy fields fails validation.

### Acceptance

`pi_pre` proves the full issuance relation from the paper, not only the commitment equation.

## Phase 3: Complete Issuer-Side Sampling And Target Handling

### Target

Issuer samples:

```text
mu_sig in R_q^1
x0 in R_q^2
x1 in R_q
```

Then:

```text
Z = (B3 - x1)^(-1)
T = B0 + B1 mu_sig + B2 x0 + Z + c
u <- SampPre(td, T)
```

### Files To Modify

- `issuance/intgenisis.go`
- `vSIS-HASH/vSIS-BBS.go`
- `credential/intgenisis_profile.go`
- `cmd/issuance/flow_helpers.go`
- `ntru/signverify/*`
- `ntru/keys/*`

### Work Items

1. Decide final distributions for `mu_sig`, `x0`, and `x1`.

   Current code uses uniform `R_q` sampling. This must be either:

   - explicitly justified by the IntGenISIS/DKLW concrete profile; or
   - replaced with the exact prescribed domain sampler.

2. Add typed sampler configuration:

   ```go
   type SignatureHashSamplerProfile struct {
       MuSigDistribution ...
       X0Distribution ...
       X1Distribution ...
       MaxInvertibilityTrials int
       InadmissibilityErrorBound ...
   }
   ```

3. Add deterministic test samplers for negative tests.

4. Make invertibility check explicit and auditable:

   ```go
   IsInvertibleB3MinusX1(...)
   ComputeZ(...)
   ```

5. Refactor issuer response so the live schema contains no `T`.

6. Let holder finalization recompute target internally and verify:

   ```text
   A u = B0 + B1 mu_sig + B2 x0 + Z + c
   ```

   without relying on serialized `T`.

7. Keep optional debug target output behind an explicit `-debug-target-out` flag if useful.

### Tests

- sampled `x1` always produces invertible `B3-x1`.
- forced non-invertible `x1` triggers resampling.
- target recomputation is deterministic.
- final response omits `T`.
- modified `mu_sig`, `x0`, `x1`, or `u` fails finalization.
- issuer cannot sign before pre-sign proof verification.

### Acceptance

Issuer-side issuance matches the paper transcript shape. `T` is an internal computation, not a live artifact field.

## Phase 4: Complete Showing Relation

### Target Relation

Public:

```text
public params
nonce
tag
verifier state context
```

Witness:

```text
u
M
m
k
s
e
mu_sig
x0
x1
Z
PRF auxiliary witness
signature shortness auxiliary witness
bound auxiliary witness
```

Constraints:

```text
(B3 - x1) * Z = 1
A u = B0 + B1 mu_sig + B2 x0 + Z + C_M M + A_s s + e
M = m || k
tag = PRF(k, nonce)
k in K_key
u short
M,s,e bounded
presentation policy constraints
```

### Files To Modify

- `PIOP/intgenisis_showing.go`
- `PIOP/intgenisis_showing_eval.go`
- `PIOP/intgenisis_layout.go`
- `PIOP/generic_builder.go`
- `PIOP/showing_builder.go`
- `PIOP/prf_companion_types.go`
- `PIOP/prf_companion_aux.go`
- `PIOP/prf_companion_residuals.go`
- `PIOP/sig_shortness_replay.go`
- `PIOP/signature_shortness_*`
- `PIOP/proof_report.go`
- `PIOP/witness_geometry.go`
- `cmd/showing/main.go`

### Work Items

1. Extend showing row layout:

   ```text
   u
   M
   m
   k
   s
   e
   mu_sig
   x0
   x1
   Z
   bounds auxiliaries
   signature shortness auxiliaries
   PRF companion auxiliaries
   masks
   ```

2. Add encoding constraints for `M=m||k`.

3. Refactor PRF companion key source.

   Current issue:

   ```text
   KeySourceIndependentWitness
   ```

   This means the companion rows are generated honestly from `M`, but the proof metadata does not yet force the verifier to tie those rows back to `M`.

   Required new model:

   ```text
   KeySourceSemanticMessageSlots
   ```

   It must record:

   - source row: `M`;
   - source slots: key slots from `SemanticMessageLayout`;
   - destination PRF companion key slots;
   - equality constraints between them.

4. Add PRF key-source equality constraints to replay.

5. Wire IntGenISIS-compatible signature shortness.

   Current shortness logic is tied to legacy coeff-native showing layouts. Add support for `IntGenISISShowingRowLayout`:

   - identify `u` rows;
   - produce shortness metadata over those rows;
   - bind shortness proof digest into Fiat-Shamir;
   - verify shortness proof with IntGenISIS layout digest.

6. Add bounds for non-signature rows:

   - `M,s,e` bounded by `B`;
   - `k` in key space;
   - `mu_sig,x0,x1` bounded only if required by final sampler profile.

7. Keep showing public statement clean:

   - reject `c`;
   - reject `T`;
   - reject old challenge fields.

8. Add presentation policy hook.

   Start with no hidden attributes revealed, then add an explicit policy interface for selective predicates later.

### Tests

- valid end-to-end IntGenISIS showing verifies.
- wrong `k` fails PRF relation.
- wrong `M` fails encoding or signature equation.
- wrong PRF companion key rows fail key-source equality.
- wrong `s` or `e` fails signature equation.
- wrong `mu_sig` or `x0` fails signature equation.
- wrong `x1` or `Z` fails inverse relation.
- modified `u` fails signature equation or shortness.
- out-of-bound `u` fails shortness.
- out-of-bound `M,s,e` fails bounds.
- public showing input containing `c` or `T` fails.
- serialized presentation does not contain witness material.

### Acceptance

The showing proof proves the full `R_ShowARC` relation from the paper and reveals only `(nonce, tag, proof)` plus public parameters.

## Phase 5: Presentation And Verifier State

### Files To Modify

- `cmd/showing/main.go`
- `credential/intgenisis_presentation.go` new
- `credential/verifier_state.go` new
- `cmd/showing/main_test.go`
- `cmd/showing/integration_test.go`

### Work Items

1. Split showing CLI into subcommands or modes:

   ```bash
   go run ./cmd/showing prove-intgenisis ...
   go run ./cmd/showing verify-intgenisis ...
   ```

   Or keep one binary with explicit flags:

   ```text
   -mode prove
   -mode verify
   ```

2. Prover command inputs:

   ```text
   state path
   public params
   nonce or nonce policy
   output presentation path
   proof knobs
   ```

3. Verifier command inputs:

   ```text
   public params
   presentation path
   verifier-state path
   replay policy
   proof knobs or profile label
   ```

4. Presentation JSON:

   ```text
   nonce
   tag
   proof
   public parameter digest/profile
   no witness fields
   ```

5. Verifier-state JSON:

   ```text
   accepted nonce/tag pairs
   timestamps or counters if useful
   public parameter digest
   ```

6. Add replay policy:

   - reject repeated `(nonce, tag)` under the same verifier state;
   - define whether repeated nonce with different tag is accepted or rejected according to ARC policy;
   - make policy explicit in docs and tests.

### Tests

- prover writes presentation.
- verifier accepts fresh presentation.
- verifier rejects replayed presentation.
- verifier rejects presentation with wrong public parameter digest.
- presentation JSON privacy tests.

### Acceptance

Showing and verification are separate protocol stages, and verifier replay-state exists outside the proof as described by the paper.

## Phase 6: CLI Restructure And Legacy Quarantine

### Current CLI State

`cmd/issuance/main.go` supports:

```text
setup-intgenisis-public
setup-demo-public
setup-ntru-keys
holder-commit
issuer-challenge
holder-prove
issuer-verify-sign
holder-finalize
demo-local
benchmark-x0
benchmark-intgenisis
```

The same command names route by public parameter profile.

### Target CLI State

IntGenISIS commands should be first-class and unambiguous:

```text
setup-intgenisis-public
setup-intgenisis-ntru-keys
intgenisis-holder-request
intgenisis-issuer-sign
intgenisis-holder-finalize
intgenisis-show
intgenisis-verify
benchmark-intgenisis
```

Legacy commands should be visibly legacy:

```text
legacy-setup-demo-public
legacy-holder-commit
legacy-issuer-challenge
legacy-holder-prove
legacy-issuer-verify-sign
legacy-holder-finalize
legacy-benchmark-x0
```

This can be done gradually. The first step is to keep existing commands but add explicit aliases and deprecation warnings for legacy paths.

### Files To Modify

- `cmd/issuance/main.go`
- `cmd/issuance/flow_helpers.go`
- `cmd/showing/main.go`
- `cmd/README.md`
- `Commands.md`
- `README.md`

### Work Items

1. Add explicit IntGenISIS command names.

2. Keep profile-based routing only as a compatibility layer.

3. Make `issuer-challenge` fail for IntGenISIS as it does now, but mark it legacy in help text.

4. Add command help examples for profile B.

5. Remove ignored legacy flags from IntGenISIS subcommands where possible.

6. Add strict artifact loaders:

   - IntGenISIS commands only accept IntGenISIS schemas;
   - legacy commands only accept legacy schemas.

7. Move generated legacy samples into clearly named paths:

   ```text
   credential/issuance/legacy/
   credential/keys/legacy/
   Parameters/legacy/
   ```

### Tests

- IntGenISIS commands reject legacy artifacts.
- Legacy commands reject IntGenISIS artifacts unless explicitly allowed for migration.
- `issuer-challenge` fails for IntGenISIS params.
- CLI help lists IntGenISIS commands clearly.

### Acceptance

Users can run the aligned protocol without knowing about the old challenge-based architecture.

## Phase 7: Benchmarks, Reports, And Soundness Parameters

### Current State

`benchmark-intgenisis` reports row inventory only. It does not measure proof sizes or timings.

### Target

Benchmark outputs should include:

```text
profile
pre-sign proof size
showing proof size
pre-sign proving time
pre-sign verification time
showing proving time
showing verification time
row inventory
PRF auxiliary rows
signature shortness rows
bound rows
total SmallWood rows
d_Q or equivalent degree parameter
DECS/LVCS/PCS geometry
QR / RowOpening / BarSets / VTargets sizes if present
Fiat-Shamir/security knobs
```

### Files To Modify

- `cmd/issuance/benchmark_intgenisis.go`
- `cmd/issuance/benchmark_x0.go`
- `PIOP/proof_report.go`
- `PIOP/witness_geometry.go`
- `PIOP/replay_family_audit.go`
- `PIOP/replay_subfamily_audit.go`
- `docs/arc_spruce_intgenisis/sections/06_parameters.tex`
- `docs/arc_spruce_intgenisis/appendix/D_extended_parameters.tex`

### Work Items

1. Extend benchmark command to run actual proof builders:

   - pre-sign proof;
   - showing proof.

2. Generate deterministic fixture witnesses.

3. Measure serialized proof size.

4. Measure proving and verification wall time.

5. Extract proof report fields.

6. Add JSON schema for benchmark reports.

7. Update LaTeX parameter sections only after measurements are regenerated.

8. Keep old x0 benchmarks under legacy labels only.

### Tests

- benchmark JSON schema test.
- profile-B row inventory equals expected values after adding new rows, with updated expectations.
- benchmark command does not silently compare against legacy x0 profiles.

### Acceptance

All reported IntGenISIS sizes and timings come from the actual aligned relation, not from row arithmetic or legacy proof surfaces.

## Phase 8: Documentation And Security Alignment

### Files To Modify

- `docs/arc_spruce_intgenisis/IMPLEMENTATION_RUNBOOK.md`
- `docs/arc_spruce_intgenisis/FULL_ALIGNMENT_PLAN.md`
- `docs/arc_spruce_intgenisis/sections/*.tex`
- `docs/arc_spruce_intgenisis/appendix/*.tex`
- `README.md`
- `Commands.md`
- `commitment/README.md`
- `credential/README.md`
- `PIOP/README.md`
- `prf/README.md`

### Work Items

1. Keep runbook as current-state operational documentation.

2. Update it after each phase with:

   - implemented status;
   - exact commands;
   - completeness caveats.

3. Add an implementation-status table:

   | Paper relation item | Code module | Status | Tests |
   |---|---|---|---|

4. Document exact message layout.

5. Document exact sampler distributions.

6. Document proof-size measurements only after the final benchmark phase.

7. Mark old docs as legacy:

   - `docs/arc_spruce_old/**` remains reference-only;
   - shared-randomness migration notes should not be linked as the live protocol.

### Acceptance

The docs no longer leave readers guessing which parts are prototype-only and which parts are paper-aligned.

## Phase 9: Test Matrix

The final protocol should have tests in these groups.

### Unit Tests

- message layout encode/decode;
- commitment sampling and verification;
- BB-tran sampler and invertibility;
- target recomputation;
- credential state validation;
- artifact schema privacy;
- presentation replay-state.

### PIOP Tests

- pre-sign valid proof;
- pre-sign negative cases:
  - wrong `c`;
  - wrong `C_M`;
  - wrong `A_s`;
  - wrong `M=m||k`;
  - wrong key-space membership;
  - wrong policy;
  - out-of-bound witness.
- showing valid proof;
- showing negative cases:
  - wrong `k`;
  - wrong `M`;
  - wrong `s/e`;
  - wrong `mu_sig/x0`;
  - wrong `x1/Z`;
  - wrong `u`;
  - wrong PRF companion key-source binding;
  - out-of-bound witness;
  - public `c`/`T` included.

### CLI Integration Tests

One full profile-B test should run:

```text
setup-intgenisis-public
setup-intgenisis-ntru-keys
intgenisis-holder-request
intgenisis-issuer-sign
intgenisis-holder-finalize
intgenisis-show
intgenisis-verify
intgenisis-verify replay rejection
```

### Privacy/Stale-Architecture Tests

Assert that live IntGenISIS artifacts do not contain:

```text
r0
r1
r0H
r1H
r0I
r1I
RI0
RI1
T
Ac
holder-side randomness
issuer-side randomness
shared randomness
centered sums
LHL
```

Exceptions:

- `T` may appear only in explicitly marked debug artifacts.
- legacy tests/artifacts may contain old fields only under `legacy` names.

### Benchmark Tests

- benchmark command writes valid JSON.
- row counts match current aligned layout.
- proof sizes are nonzero and stable within expected ranges.

## Phase 10: Cleanup And Removal

After all aligned tests pass:

1. Move old command paths under legacy names.

2. Delete or quarantine old generated artifacts from live paths:

   ```text
   credential/issuance/*.json
   credential/keys/*.json
   Parameters/*.json
   ntru_keys/*.json
   ```

   Keep only explicit IntGenISIS or legacy names.

3. Remove old fields from live IntGenISIS structs.

4. Remove compatibility `T` in issuer response.

5. Search for stale terms:

   ```bash
   rg -n "r0|r_0|r1|r_1|r0H|r1H|r0I|r1I|RI0|RI1|ACom|LHL|centered|target hiding|holder-side|issuer-side|shared randomness|ell_r0|beta_r0|C_s" .
   ```

6. Classify hits:

   - legacy-only;
   - false positive;
   - remove from live path.

7. Add a CI test that fails if stale terms appear outside allowed legacy paths.

## Dependency Order

Recommended execution order:

1. Message encoding refactor.
2. Typed IntGenISIS artifacts and public statements.
3. Full pre-sign relation.
4. Issuer sampler and minimized response.
5. Showing relation key binding and bounds.
6. IntGenISIS signature shortness.
7. Presentation/verifier-state CLI.
8. Full end-to-end CLI tests.
9. Benchmarks and reports.
10. Docs/security updates.
11. Legacy quarantine and stale-code gate.

Do not start final benchmarks before phases 1 through 7 are complete. Row counts and proof sizes will change when encoding, bounds, PRF key binding, and signature shortness are added.

## Major Risks

### Message Packing

`ell_M=1` forces `m` and `k` into one ring polynomial. The implementation needs a precise slot layout, not ad hoc coefficient placement. This is the highest-priority refactor because it affects issuance, showing, PRF, and proofs.

### PRF Key Binding

The current honest builder derives PRF companion rows from `M`, but final soundness needs verifier-enforced equality between the PRF key rows and the key slots inside `M`.

### Bound Gadgets

The standalone commitment verifier checks bounds, but the PIOP currently does not prove them. Bound gadgets can increase rows and degrees, so benchmarks must be delayed until they are implemented.

### Signature Shortness

The existing shortness machinery is tied to legacy showing layouts. Reusing it requires a layout-digest refactor so the proof binds to IntGenISIS `u` rows.

### Sampler Distribution

Uniform `R_q` sampling for `mu_sig,x0,x1` may or may not be the intended concrete DKLW distribution. This decision must be resolved before final security claims.

### Artifact Privacy

The issuer response still contains `T` for compatibility. That is not aligned with the minimized paper response. Removing it requires finalizer and tests to recompute targets internally.

### Legacy Cross-Contamination

The repo still has many old shared-randomness code paths. Typed schemas and command names are needed to prevent old artifacts from being accepted silently in the new flow.

## Final Acceptance Criteria

The protocol can be called fully aligned only when all of the following are true:

1. Profile-B setup produces public params with no live old LHL/shared-randomness fields.

2. Issuance request contains only `c` and `pi_pre`.

3. Pre-sign proof enforces:

   ```text
   c = C_M M + A_s s + e
   M = m || k
   k in K_key
   issuance policy
   bounds on M,s,e
   ```

4. Issuer response contains only:

   ```text
   u
   mu_sig
   x0
   x1
   ```

5. Credential state contains only live witness fields and no `c`, `T`, or old randomness.

6. Showing proof enforces:

   ```text
   (B3 - x1) * Z = 1
   A u = B0 + B1 mu_sig + B2 x0 + Z + C_M M + A_s s + e
   M = m || k
   tag = PRF(k, nonce)
   key membership
   signature shortness
   required bounds
   ```

7. Presentation contains only:

   ```text
   nonce
   tag
   proof
   public metadata/digests
   ```

8. Verifier replay-state rejects repeated `(nonce, tag)`.

9. Full profile-B CLI integration passes end to end.

10. All stale old terms are removed from live IntGenISIS paths or quarantined under explicit legacy paths.

11. Benchmarks report actual proof size, proving time, verification time, row inventory, PRF rows, shortness rows, bound rows, total rows, and degree/soundness parameters for the final relation.

12. Documentation states that the implementation is paper-aligned and lists any remaining conditional assumptions, especially around DKLW sampling and security reductions.

