# ARC-SPRUCE Preset Implementation Plan

> Historical design record. The implemented preset registry, threat manifests,
> measured values, and claim statuses are documented in `docs/SECURITY.md` and
> `docs/PROTOCOL.md`; where this plan differs, those documents and executable
> reports are authoritative.

This plan turns the ARC-SPRUCE adversary and parameterization report into a
repo-fitted implementation path. It is a plan only: no preset should be
promoted, renamed, or treated as a complete system-security claim until the
ledger, primitive feasibility checks, transcript gates, and tamper tests below
all pass.

Source report:
`/home/jonas/Desktop/arc_spruce_adversary_and_parameterization_report.pdf`

## 0. Status As Of 2026-07-01

Status includes the ARC-SPRUCE scaffold commits and the 2026-07-01 commit
wave inputs:

- `929efd9 arc-spruce: add security profiles and bq32 candidate scaffold`
- `3aa6da0 arc-spruce: expand ledger and profile sweep scaffolding`

Completed foundation work:

- Security-profile registry exists and classifies current presets under
  `single_candidate`, `query_work_factor`, and `residual_at_budget` semantics.
- CROM is the only registered ROM model; no QROM path has been added.
- Split width plumbing exists for DECS hash width, DECS tape/nonce width,
  Fiat-Shamir collision width, and salt width.
- `prf/prf_params_tag9.json` exists and `n1024-bq32-96` pins the tag-9 PRF
  profile.
- `n1024-bq32-96` exists as an explicit bounded-budget candidate preset with
  `DECSHashBits=168`, `DECSTapeBits=128`, `FSCollisionBits=168`, `SaltBits=128`,
  equal `2^32` RO caps, Profile C core, and `CompleteSystemClaim=false`.
- `n1024-bq32-96` has been tuned from the live BQ32 sweep to
  `LVCSNCols=40`, `NLeaves=557056`, `Eta=44`, `Ell=9`. This recovers the
  missing full-game slack and reduces live showing paper transcript bytes from
  `37244` to `36764`.
- A fail-closed system-ledger scaffold exists with log-domain helpers, explicit
  ledger terms, term provenance (`exact`, `conservative`, `missing`), adversary
  resource structs, flattened benchmark JSON fields, and profile-aware internal
  sweep scaffolding.
- PIOP one-proof and full-game soundness accounting now carry effective
  log-scale RO query caps alongside the legacy `[5]int` caps. This prevents
  `2^64` and `2^128` research lanes from being silently truncated or left
  unencoded by the old integer cap path.
- Negative tests now cover required ledger term rejection, tag-7/tag-9 BQ32
  behavior, DECS hash/tape mismatch rejection, Fiat-Shamir domain separation,
  and IntGenISIS public tag/nonce/context tamper rejection.
- Two BQ64 theorem-trail presets are registered as selectable research presets:
  `n1024-bq64-96-theta11` and `n1024-bq64-128-theta13-h256`. They use
  `ROQueryCapBits=[64,64,64,64,64]`, keep legacy `ROQueryCaps` unset, use the
  current executable tag-9 PRF plumbing, and remain `CompleteSystemClaim=false`.

Current preset registry snapshot:

| Preset | Profile / registry status | Query cap model | Key SmallWood knobs | PRF lane | Current claim level |
| --- | --- | --- | --- | --- | --- |
| `n512-compact96` | `SC-96` / `proof_only` | Current theorem proof-only caps | `LVCS=36`, `N=262144`, `eta=36`, `theta=5`, `ell=7`, `kappa={0,0,6,8}` | default tag-7 | Maintained proof-only compact preset, not complete system security. |
| `n1024-compact96` | `SC-96` / `proof_only` | Current theorem proof-only caps | `LVCS=43`, `N=230208`, `eta=40`, `theta=5`, `ell=7`, `kappa={0,0,6,11}` | default tag-7 | Maintained proof-only compact preset, not complete system security. |
| `n1024-compact125` | `SC-125` / `proof_only` | Current theorem proof-only caps | `LVCS=46`, `N=608192`, `eta=48`, `theta=7`, `ell=9`, `kappa={0,0,0,5}` | default tag-7 | Maintained proof-only compact preset; explicitly not a 128-bit residual-budget claim. |
| `n1024-q10-128` | `BQ32-128` / `requires_new_primitives` | Legacy raw caps `[2^10]*5` | `LVCS=36`, `N=983040`, `eta=44`, `theta=7`, `ell=9`, `kappa={0,4,9,9}` | default tag-7 | Maintained q-budget proof trail only; not a complete 128-bit system claim. |
| `n1024-q16-128` | `BQ32-128` / `requires_new_primitives` | Legacy raw caps `[2^16]*5` | `LVCS=37`, `N=524288`, `eta=43`, `theta=8`, `ell=10`, `kappa={0,0,0,8}` | default tag-7 | Maintained q-budget proof trail only; not a complete 128-bit system claim. |
| `n1024-q32-128` | `BQ32-128` / `requires_new_primitives` | Legacy raw caps `[2^32]*5` | `LVCS=37`, `N=655360`, `eta=45`, `theta=9`, `ell=11`, `kappa={1,0,0,8}` | default tag-7 | Maintained q-budget proof trail only; not a complete 128-bit system claim. |
| `n1024-q10-96` | `BQ32-96` / `candidate` | Legacy raw caps `[2^10]*5` | `LVCS=37`, `N=720896`, `eta=40`, `theta=6`, `ell=7`, `kappa={0,0,0,8}` | default tag-7 | Maintained q-budget proof trail only. |
| `n1024-q16-96` | `BQ32-96` / `candidate` | Legacy raw caps `[2^16]*5` | `LVCS=38`, `N=393216`, `eta=40`, `theta=6`, `ell=8`, `kappa={0,0,3,7}` | default tag-7 | Maintained q-budget proof trail only. |
| `n1024-q32-96` | `BQ32-96` / `candidate` | Legacy raw caps `[2^32]*5` | `LVCS=37`, `N=458752`, `eta=44`, `theta=7`, `ell=9`, `kappa={0,0,2,7}` | default tag-7 | Maintained q-budget proof trail only. |
| `n1024-bq32-96` | `BQ32-96` / `candidate` | Legacy raw caps `[2^32]*5` | `LVCS=40`, `N=557056`, `eta=44`, `theta=7`, `ell=9`, `kappa={0,0,2,7}` | tag-9 | Candidate preset with measured `36764` showing bytes and `96.38` full-game bits; not promoted. |
| `n1024-bq64-96-theta11` | `BQ64-96` / `requires_new_primitives` | Log caps `[64]*5` | `LVCS=43`, `N=983040`, `eta=58`, `theta=11`, `ell=16`, `kappa={0,11,13,2}` | tag-9 executable placeholder for future tag-12 | Research-only theorem trail with measured `66478` showing bytes; primitive and theorem blocked. |
| `n1024-bq64-128-theta13-h256` | `BQ64-128` / `requires_new_primitives` | Log caps `[64]*5` | `LVCS=48`, `N=983040`, `eta=65`, `theta=13`, `ell=18`, `kappa={0,7,13,13}` | tag-9 executable placeholder for future tag-13 | Research-only theorem trail with measured `78438` showing bytes; primitive and theorem blocked. |

Most recent `n1024-bq32-96` live benchmark:

```text
issuance paper transcript bytes: 25721
showing paper transcript bytes: 36764
issuance theorem bits:          97.46
showing theorem bits:           97.46
collision bits:                 101.68
full-game bits:                 96.38
tag collision bits:             116.61
programming conflict bits:      134.00
zero-knowledge bits:            ~96.00
replay rejected:                true
ledger status:                  candidate
ledger blockers:                profile status only
```

Current conclusion:

- `BQ32-96` now clears the numeric 96-bit ledger terms in the default
  one-user, one-context benchmark scope, but is not promotable yet.
- The previous full-game/system-composition blocker
  (`full_game_bits=94.97 < 96`) was addressed by the row-block tuning above;
  the current live run has `full_game_bits=96.38` and
  `phase_algebraic_slack_bits=0.42`.
- The component ledger now shows exact issuance/showing extraction terms pass
  at about `97.54` algebraic bits, the composed full-game term passes at
  `96.38` bits, and tag collision passes at `116.61` bits.
- The programming-conflict failure was a conservative placeholder. It is now
  accounted separately as `sum Q_prog * 2^-c_i` from the report resource
  vector; for the BQ32-96 split-width candidate this term is about `134` bits
  and is not the current blocker. It remains marked as
  `requires_theorem_accounting` until the paper theorem path is finalized.
- The tape-guessing and programming-conflict terms are classified as
  `zero_knowledge` / proof-simulation terms, not soundness terms. This follows
  report section 7.4, which treats hidden-tape guessing as zero-knowledge
  accounting. The soundness aggregate therefore tracks the full-game
  extraction/collision composition instead of being depressed by tape
  accounting.
- Multi-user and multi-context lifts are inactive for the default one-user,
  one-context benchmark scope. They remain conservative terms for any
  non-default scope and must be backed by explicit theorem/accounting before a
  broader deployment claim.
- The full-game/multi-proof loss is real under the current implemented theorem
  accounting: `PIOP.ComposeFullGameSoundness` counts one accepted issuance
  proof, one accepted showing proof, and global RO collision in the same
  log-domain union. Removing that roughly one-bit loss requires a genuine
  simultaneous-extraction/composition theorem, not a metadata relabel. The
  tuned BQ32-96 preset therefore pays this loss with parameter margin instead
  of assuming it away.
- The profile also remains deliberately fail-closed because its registry status
  is still `candidate`.
- No maintained gate, byte target, public CLI behavior, or complete-system
  security claim has been promoted.

Current BQ64 theorem-trail presets:

| Preset | Profile | Status | Core blocker | Width lane | SmallWood shape | Theorem note |
| --- | --- | --- | --- | --- | --- | --- |
| `n1024-bq64-96-theta11` | `BQ64-96` | `requires_new_primitives` | 160-bit lattice/PRF family plus tag-12 lane | hash/FS `232`, tape `160`, salt `224`, log RO caps `2^64` | `LVCSNCols=43`, `NLeaves=983040`, `eta=58`, `theta=11`, `ell=16`, `kappa={0,11,13,2}` | Requires an external valid-prefix or equivalent accounting theorem before the theta11 algebraic margin can be treated as current-theorem security. |
| `n1024-bq64-128-theta13-h256` | `BQ64-128` | `requires_new_primitives` | 192-bit lattice/PRF family plus tag-13 lane | hash/FS `256`, tape `192`, salt `256`, log RO caps `2^64` | `LVCSNCols=48`, `NLeaves=983040`, `eta=65`, `theta=13`, `ell=18`, `kappa={0,7,13,13}` | Requires an external theorem/accounting argument that charges SmallWood algebraic extraction to valid round-prefix caps while keeping collision/programming/challenge-bias on raw `2^64` caps. |

These presets are intentionally not maintained gates. They are executable
research trails for theorem work and serializer measurement, not public
complete-system security claims.

## 1. Current Codebase Map

The maintained preset surface is currently concentrated in
`credential/intgenisis_presets.go`. Presets are loaded by issuance and showing
commands, converted into `PIOP.SimOpts`, and then measured by the issuance
benchmark and degree gates.

Important files and current responsibilities:

| Area | Files | Current role |
| --- | --- | --- |
| Preset registry | `credential/intgenisis_presets.go`, `credential/intgenisis_presets_test.go` | Names, tuning knobs, expected bytes, query caps, and profile labels. |
| Lattice/profile core | `credential/intgenisis_profile.go`, `credential/intgenisis_security.go` | Profile B/C public parameters and current MLWE/MSIS/PRF security estimates. |
| Security profile registry | `credential/security_profiles.go`, `credential/security_profiles_test.go` | CROM-only SC/WF/BQ profile semantics, profile statuses, target/core bits, width/tag metadata. |
| Message/PRF binding | `credential/intgenisis_message.go`, `prf/prf.go`, `prf/prf_params.json`, `prf/prf_params_tag9.json` | Current seed packing plus default tag-7 and BQ32 tag-9 PRF profiles. |
| PIOP options | `PIOP/run.go` | `SimOpts` carries tuning knobs, `ROQueryCaps`, compatibility `DECSCollisionBits`, split hash/tape/FS/salt widths, and PRF params path. |
| Soundness accounting | `PIOP/soundness_accounting.go` | Query-budget composition, split DECS width resolution, collision and algebraic theorem bits. |
| DECS parameters | `DECS/decs_types.go` | `Params.NonceBytes`, `Params.HashBytes`, supported hash width range `16..64`, and nonce/tape range `12..64`. |
| Security ledger | `credential/security_ledger.go`, `credential/log_math.go`, `credential/security_ledger_test.go` | Fail-closed system ledger scaffold with explicit terms, resource scope, and log-domain composition helpers. |
| Issuance benchmark | `cmd/issuance/benchmark_intgenisis_e2e.go`, `cmd/issuance/benchmark_metrics.go` | JSON reports, transcript buckets, theorem bits, replay result, ledger terms, relation candidate reports, runtime metrics. |
| Issuance/showing flows | `cmd/issuance/flow_helpers.go`, `cmd/showing/main.go` | State files, holder secret files, PRF params path loading, showing verifier options. |
| Gates and docs | `cmd/issuance/gate_degree1024_presets.go`, `ARTIFACT.md`, `docs/PROTOCOL.md`, `docs/SECURITY.md` | Maintained byte/security gates and public documentation. |
| Research harness | `cmd/issuance/qbudget128_sweep_internal_test.go` | Env-gated internal sweep for q-budget 128 transcript reduction. |

Current implementation gap: the code now has a fail-closed ledger scaffold,
profile-aware benchmark output, and a numerically passing BQ32-96 candidate,
but the ledger terms are not yet a fully validated paper-grade master
advantage bound and no complete-profile gate exists. `BQ32-96` remains
candidate-only until promotion-grade theorem review, serializer regression
checks, complete-profile gates, and public docs are reviewed together.

## 2. Report-Aligned Target Profiles

The report separates single-candidate security, query work factor security,
and residual security after bounded adversary budgets. The code should model
that distinction explicitly instead of overloading existing preset names.

| Profile | Semantics | Current primitive feasibility | Implementation status |
| --- | --- | --- | --- |
| `SC-96` | Single-candidate 96-bit baseline | Current Profile B/C can support. | Registered and mapped to current compact 96 presets as proof-only. |
| `SC-125` | Single-candidate 125+ baseline | Current Profile C can support. | Registered and mapped to `n1024-compact125` as proof-only; not full 128. |
| `WF-128` | 128-bit query work factor in CROM | Possibly supportable only if full ledger passes with current core floor. | Registered as candidate; do not start until BQ32-96 is resolved. |
| `BQ32-96` | 96-bit residual after equal `2^32` RO budgets | Current Profile C can support if tag/hash/tape ledger passes. | Candidate preset `n1024-bq32-96` now clears the numeric default-scope ledger at `96.38` full-game bits and `36764` showing bytes, but remains candidate-only. |
| `BQ32-128` | 128-bit residual after equal `2^32` RO budgets | Needs about 160-bit primitive family. | Registered as `requires_new_primitives`. |
| `BQ64-96` | 96-bit residual after equal `2^64` RO budgets | Needs about 160-bit primitive family. | Registered as `requires_new_primitives`; research preset `n1024-bq64-96-theta11` now carries log caps and theorem-trail notes. |
| `BQ64-128` | 128-bit residual after equal `2^64` RO budgets | Needs about 192-bit primitive family. | Registered as `requires_new_primitives`; research preset `n1024-bq64-128-theta13-h256` now carries log caps and theorem-trail notes. |
| `BQ128-128` | 128-bit residual after equal `2^128` RO budgets | Needs about 256-bit redesign. | Registered as `requires_new_primitives`. |

The existing `n1024-q10-128`, `n1024-q16-128`, and `n1024-q32-128` names should
remain stable, but should be described as proof-level q-budget presets until
the complete ledger says otherwise.

### 2.1 Report coverage matrix

The implementation is complete only when each report block below has a matching
code path, test path, and documentation path.

| Report block | Required repo coverage |
| --- | --- |
| Current baseline | Regression gates reproduce current preset bytes, theorem bits, `dQ`, `dDECS`, row blocks, and transcript buckets. |
| Adversary resource model | Add a resource vector, not one scalar `Q`: RO caps, valid-prefix caps, issuance queries, presentations, verifications, PRF attempts, users, contexts, tags, proofs. |
| Security semantics | Encode `single_candidate`, `query_work_factor`, and `residual_at_budget` as distinct modes. |
| Query-budget ladder | Register all SC/WF/BQ labels, but fail closed for profiles whose primitive core is unavailable. |
| Required logic fixes | Split hash/tape/salt/tag/key widths; add tag, salt, tape, challenge-bias, multi-user, and extraction/simulation accounting. |
| Master advantage bounds | Implement a log-domain ledger with separate soundness, unlinkability, correctness, primitive, and composition terms. |
| Logical parameterization | Build an ordered parameter engine: profile, primitives, relation encoding, `n,d,d_prime,dQ`, SmallWood, serializer, benchmark, ledger. |
| Relation strategies | Enumerate signed radix, mixed radix, compression, direct membership, seed packing, CRT helper removal, PRF trace packing, norm proofs, and split proofs. |
| `dQ` optimization | Store both `dQ` branches, dominant constraint source, row-degree exchange score, and ceiling breakpoints. |
| Transcript model | Instrument exact serializer buckets and Merkle multiproof distributions; formulas are checks, not the source of truth. |
| SmallWood tuning | Derive `eta` and `kappa`, sweep `theta`, `ell_DECS`, `N_DECS`, `n_cols`, and keep `rho`/`ell_PIOP` explicit. |
| Optimizer architecture | Generalize the internal sweep into a profile-aware Pareto engine with primitive feasibility pruning. |
| Profile search plans | Add profile-specific lanes for `SC`, `BQ32-96`, `WF-128`, 160-bit, 192-bit, and 256-bit families. |
| Validation | Add algebraic, negative/tamper, security-calculator, serializer, benchmark, and fuzz tests. |
| Paper/docs wording | Update docs to state CROM-only proof status, profile semantics, and full component ledgers. |

## 3. Security-Profile Registry

Add a registry that records what each profile means before changing transcript
parameters.

Create `credential/security_profiles.go` with:

```go
type SecurityMode string

const (
    SecurityModeSingleCandidate   SecurityMode = "single_candidate"
    SecurityModeQueryWorkFactor   SecurityMode = "query_work_factor"
    SecurityModeResidualAtBudget  SecurityMode = "residual_at_budget"
)

type ROMModel string

const (
    ROMModelCROM ROMModel = "crom"
)

type SecurityProfileStatus string

const (
    SecurityProfileCompleteLive            SecurityProfileStatus = "complete_live"
    SecurityProfileProofOnly               SecurityProfileStatus = "proof_only"
    SecurityProfileCandidate               SecurityProfileStatus = "candidate"
    SecurityProfileRequiresNewPrimitives   SecurityProfileStatus = "requires_new_primitives"
    SecurityProfileRequiresTheory          SecurityProfileStatus = "requires_theorem_accounting"
)

type IntGenISISSecurityProfileSpec struct {
    Label string
    Mode SecurityMode
    ROM ROMModel
    TargetBits float64
    CoreBitsRequired float64
    ROQueryCaps []uint64
    DECSHashBits int
    DECSTapeBits int
    FSCollisionBits int
    SaltBits int
    PRFTagElements int
    SeedSlots int
    PackedKeyCoords int
    Status SecurityProfileStatus
    Notes string
}
```

Modify `credential.IntGenISISPreset` in `credential/intgenisis_presets.go`:

```go
SecurityProfile string
SecurityMode string
CoreBitsRequired float64
CompleteSystemClaim bool
```

Rules:

- `ROMModelCROM` is the only live model. Reject `qrom` labels until a theorem
  and ledger path exist.
- Existing presets keep their names and byte gates.
- Advanced profiles are registered but cannot be selected as maintained
  presets until their primitive files and ledger entries exist.
- `CompleteSystemClaim` is true only when the full ledger status is
  `complete_live`.

Tests:

- `credential` registry test covers all labels exactly once.
- Current compact presets map to `SC-*`.
- Current q-budget 128 presets are not complete system claims.
- Advanced profiles remain `requires_new_primitives`.

## 4. Width Accounting Split

The report requires separating Merkle hash width, DECS tape/nonce width,
Fiat-Shamir collision width, salt width, and PRF tag length. The current code
couples hash and tape through `DECSCollisionBits`.

### 4.1 Struct changes

Extend `credential.IntGenISISTuningPreset`, `PIOP.SimOpts`,
`cmd/issuance.intGenISISTuning`, and the persisted `smallWoodTuningSpec` with:

```go
DECSHashBits int
DECSTapeBits int
FSCollisionBits int
SaltBits int
```

Keep `DECSCollisionBits` as a compatibility shorthand:

- If `DECSHashBits == 0` and `DECSTapeBits == 0`, copy
  `DECSCollisionBits` into both fields.
- If all width fields are zero, use the current 144-bit default.
- New profile presets should set the split fields directly.

### 4.2 PIOP parameter application

Replace `PIOP.applyDECSCollisionWidth` with `applyDECSWidths` in
`PIOP/soundness_accounting.go`.

Expected behavior:

- Resolve hash bytes from `DECSHashBits`.
- Resolve tape bytes from `DECSTapeBits`.
- Set `params.HashBytes` and `params.NonceBytes` independently.
- Record both effective widths in proof reports and benchmark JSON.

Update `DECS.IsSupportedHashBytes` in `DECS/decs_types.go` from `16..32` to at
least `16..64`. Tape/nonce bytes should allow `12..64` where DECS params are
validated.

### 4.3 Soundness formula boundary

Update `PIOP.computeSoundnessBudget` so collision accounting uses the width
that the theorem actually consumes:

- FS/Merkle collision term uses `FSCollisionBits` or `DECSHashBits`.
- Tape width is reported and checked separately.
- Do not silently clamp collision bits by tape width unless the derivation note
  explicitly requires that minimum.
- If a theorem path still requires `min(hash,tape,lambda)`, expose that clamp
  in JSON as a visible `clamped_terms` entry.

Tests:

- Same old `DECSCollisionBits` value reproduces old effective params.
- Hash/tape split appears in proof report and benchmark JSON.
- Mismatched verifier hash width rejects.
- Mismatched verifier tape width rejects.
- Collision formula changes when hash width changes, not when only tape width
  changes, unless a clamp path is intentionally selected.

## 5. Complete Security Ledger

Add a ledger that composes proof-level soundness with system-level failure
events. This is the main difference between current q-budget proof presets and
report-complete profiles.

Create `credential/security_ledger.go` or `PIOP/system_security.go`. Keep the
low-level proof accounting in `PIOP`, but expose a credential-level verdict for
profiles and benchmarks.

Ledger inputs:

- Profile target bits and query caps.
- Issuance and showing SmallWood theorem reports.
- Algebraic round bits after query-cap losses and kappa grinding.
- Collision bits for each RO/Merkle/FS domain.
- Tag collision bits from `LenTag`.
- Salt collision bits from `SaltBits`.
- PRF computational estimate from the selected PRF params.
- MLWE/MSIS/commitment estimates from `credential/intgenisis_security.go`.
- Replay rejection result.

The ledger must keep the report's component terms separate. Do not collapse
them into the minimum exponent.

Soundness or one-more-unforgeability terms:

- `signature_assumption` or `intgenisis_advantage`
- `issuance_smallwood_extraction`
- `showing_smallwood_extraction`
- `commitment_binding`
- `sampler_failure`
- `admissibility_failure`
- `challenge_bias`
- `encoding_failure`
- `multi_user_loss`

Unlinkability terms:

- `issuance_smallwood_simulation`
- `showing_smallwood_simulation`
- `commitment_hiding`
- `prf_advantage`
- `tag_collision`
- `salt_collision`
- `context_hash`
- `multi_user_loss`
- `multi_context_loss`
- `encoding_failure`

Correctness terms:

- `honest_sampler_failure`
- `honest_proof_failure`
- `honest_encoding_failure`
- `tag_collision_by_context`
- `salt_collision_if_required`

Ledger outputs:

```go
type SystemSecurityLedger struct {
    SecurityProfile string
    SecurityMode string
    CompleteSystemClaim bool
    TargetBits float64
    CoreBitsRequired float64
    CoreAvailableBits float64
    ProofBits float64
    FullGameBits float64
    CollisionBits float64
    TagCollisionBits float64
    SaltCollisionBits float64
    PRFBits float64
    MLWEBits float64
    LedgerStatus string
    RejectionReasons []string
}
```

Use base-2 log-domain arithmetic only. Avoid direct tiny-probability summing.
For tag collisions, use the report formula in log form:

```text
tag_collision_bits = LenTag * log2(q) - log2_binom(number_of_tags, 2)
```

For equal RO caps, collision intuition is:

```text
collision_bits = hash_bits - 2 * log2(Q) - log2(number_of_oracle_domains)
```

The exact implementation should call a shared helper, not duplicate formulas
across benchmark code and tests.

Composition rules:

- multiply one-proof SmallWood terms by explicit extraction or simulation call
  counts unless a simultaneous-extraction theorem is added
- subtract `log2(Users)` for conservative multi-user lifting
- scope tag collisions by context instead of one global database when context
  separation is part of the tag input
- include challenge-sampling statistical distance as `Q_i * delta_i`
- include tape guessing as `Q_guess * 2^-DECSTapeBits`
- include programming conflicts separately from collision terms
- keep classical and quantum lattice estimates as separate reported fields

Benchmark JSON additions in `cmd/issuance/benchmark_intgenisis_e2e.go` and
`cmd/issuance/benchmark_metrics.go`:

- `security_profile`
- `security_mode`
- `complete_system_claim`
- `core_required_bits`
- `core_available_bits`
- `tag_collision_bits`
- `salt_collision_bits`
- `full_game_bits`
- `ledger_status`
- `ledger_rejection_reasons`

Acceptance rules:

- Complete profiles require `ledger_status == "complete_live"`.
- Proof-only presets may pass existing proof gates without claiming complete
  system security.
- Advanced candidate profiles must fail closed if primitive core bits are below
  the profile floor.

## 6. PRF Profile Support

Current code has a single default PRF parameter file,
`prf/prf_params.json`, with `LenTag=7`. The report requires `LenTag=9` for
`BQ32-96`, and larger tags for stronger bounded-budget profiles.

### 6.1 Parameter plumbing

Add `PRFProfile` and `PRFParamsPath` to preset/tuning structs:

- `credential.IntGenISISTuningPreset`
- `cmd/issuance.intGenISISTuning`
- `cmd/issuance.smallWoodTuningSpec`
- any showing option struct that mirrors preset tuning

Thread the selected params through:

- issuance runtime loading in `cmd/issuance/flow_helpers.go`
- holder secret state, which already stores `PRFParamsPath`
- showing verifier loading in `cmd/showing/main.go`
- PIOP builder/verifier paths that currently fall back to
  `prf/prf_params.json`

Known hardcoded fallback areas to audit:

- `PIOP/masking_fs_helper.go`
- `PIOP/intgenisis_showing.go`
- `PIOP/generic_builder.go`
- `cmd/showing/main.go`

The fallback default may remain for old presets, but maintained complete
profiles must pin their PRF profile explicitly.

### 6.2 Tag-9 profile

Add `prf/prf_params_tag9.json` for `BQ32-96`:

- same field and permutation family as current params
- `LenKey=8`
- `LenNonce=12`
- `LenTag=9`
- `t=20`
- same constants only if state width and permutation constraints remain valid

Do not register 160/192/256-bit PRF profiles as live without Sage-generated
params, security notes, and test vectors.

Tests:

- `BQ32-96` profile requires `LenTag=9`.
- Current `LenTag=7` fails the complete `BQ32-96` ledger.
- Tag tampering is rejected.
- Nonce/context tampering is rejected.
- JSON reports the selected PRF profile and tag collision bits.

## 7. Preset Milestones

Implement and promote profiles in this order.

### 7.1 Milestone A: Registry-only cleanup

Map existing presets without changing transcript bytes:

| Preset | Profile | Claim |
| --- | --- | --- |
| `n512-compact96` | `SC-96` | Complete only if ledger confirms Profile B floor. |
| `n1024-compact96` | `SC-96` | Complete only if ledger confirms Profile C floor. |
| `n1024-compact125` | `SC-125` | Single-candidate `125+`, not full 128. |
| `n1024-q*-96` | proof/q-budget research | Not complete until ledger says so. |
| `n1024-q*-128` | proof/q-budget research | Not complete system claims under current ledger. |

No transcript or parameter changes should be made in this milestone.

Current status:

- Done in `929efd9`.
- Current compact presets map to `SC-96`/`SC-125`.
- Current q-budget presets remain proof/q-budget research presets and do not
  claim complete system security.
- Advanced profiles are registered as candidate/blocked and fail closed.

### 7.2 Milestone B: `BQ32-96`

Add a new explicit bounded-budget preset, preferably `n1024-bq32-96`, rather
than silently changing existing `n1024-q32-96`.

Target settings:

- Profile C core.
- Equal RO caps `[2^32, 2^32, 2^32, 2^32, 2^32]`.
- `DECSHashBits=168` (`21B`).
- `DECSTapeBits=128` (`16B`) after width split, or `168` until decoupling is
  live.
- `LenTag=9` via `prf/prf_params_tag9.json`.
- Current seed packing may remain: 48 slots and 8 packed key coordinates exceed
  the report floor for this profile.
- Keep relation-level PRF, ring degree, modulus, and Profile C dimensions fixed.

Promotion gate:

- issuance and showing theorem bits are at least 96 after caps
- full ledger residual bits are at least 96
- collision, tag, salt, PRF, MLWE/MSIS floors all pass
- replay rejection passes
- transcript status remains live

Current status:

- Candidate preset `n1024-bq32-96` exists.
- Target widths and tag-9 PRF plumbing are implemented.
- Replay rejection passes in the latest live benchmark.
- Issuance and showing theorem bits reach `97.46` after the row-block tuning.
- Tag collision reaches `116.61` bits with tag-9.
- Full-game composition reaches `96.38` bits in the latest live benchmark.
- The candidate still must not be promoted because the registry status is
  `candidate`, no complete-profile gate exists, and the ledger has not been
  reviewed as a paper-grade master advantage bound.
- Next work must focus on promotion-grade ledger validation, serializer
  regression, and complete-profile gate design before any maintained gate or
  public complete-system claim is added.

### 7.3 Milestone C: `WF-128`

Add a candidate `n1024-wf128` only after split width support exists.

Target settings:

- Query work factor semantics, not residual-at-budget semantics.
- Current Profile C allowed only if ledger core floor is at least 128.
- `DECSHashBits=264` (`33B`).
- `DECSTapeBits=128` (`16B`) after decoupling.
- CROM only.

If 33-byte DECS hash support or ledger proof is missing, leave the profile
registered as candidate and do not add it to maintained gates.

Current status:

- Profile is registered as candidate.
- No preset, gate, or promotion work should start until BQ32-96 has either
  been promoted or explicitly recorded as blocked with a final reason.

### 7.4 Milestone D: stronger bounded-budget profiles

Register but do not promote these until new primitives exist:

| Profile | Required primitive family | Report widths and tags |
| --- | --- | --- |
| `BQ32-128` | about 160-bit lattice/PRF | `25B` hash, `20B` tape, `LenTag=10`. |
| `BQ64-96` | about 160-bit lattice/PRF | `29B` hash, `20B` tape, `LenTag=12`. |
| `BQ64-128` | about 192-bit lattice/PRF | `33B` bare hash or `40B` engineering hash, `24B` tape, `LenTag=13`. |
| `BQ128-128` | about 256-bit redesign | `49B` bare hash or `64B` engineering hash, `32B+` tape, `LenTag=20`. |

Each promotion requires estimator notes, PRF parameter generation notes, test
vectors, and updated docs before any public preset gate accepts it.

Current status:

- Profiles are registered as `requires_new_primitives`.
- No 160/192/256-bit primitive families, PRF params, gates, or public claims
  have been added.

## 8. Optimizer and Sweep Harness

Generalize `cmd/issuance/qbudget128_sweep_internal_test.go` into an internal
security-profile sweep. Keep it env-gated and out of public CLI UX.

Suggested path:

- Keep current q-budget 128 sweep as the first backend.
- Add profile-aware candidate structs instead of replacing the old harness in
  one large edit.
- Later rename the file to `security_profile_sweep_internal_test.go` only when
  the old q-budget path is preserved.

Candidate fields:

- profile label and target phase
- relation encoding family
- `LVCSNCols`
- `NLeaves`
- `eta`
- `theta`
- `ell`
- `kappa`
- hash/tape/FS/salt widths
- PRF profile/path
- shortness radix and digit count
- compression level
- replay projection

Evaluation order:

1. Reject primitive-infeasible profiles before compiling relations.
2. Compile relation and record `n`, `d`, `d_prime`, `dQ`, and dominant degree
   source.
3. Derive minimal `eta` and targeted `kappa`.
4. Compute SmallWood proof bits.
5. Compute complete system ledger bits.
6. Serialize exact transcript and bucket bytes.
7. Benchmark only Pareto finalists.

Frontier categories:

- `complete_safe_preset`
- `proof_only_preset`
- `high_k_research`
- `requires_new_primitives`
- `requires_theorem_accounting`
- `rejected`

For heavy query budgets, keep the current parameter strategy:

- Tune relation representation before adding kappa.
- Sweep `LVCSNCols` near row-block breakpoints.
- Use the smallest `ell` that keeps the last algebraic round above target.
- Lower `theta` only when compensating kappa is small and transcript savings are
  material.
- Tune `NLeaves` as the round-1 versus round-4 tradeoff knob.
- Treat `eta` as expensive because it increases `R` and `Pdecs`.
- Compare R7/L5 and R11/L4 shortness shapes empirically.

## 9. Parameter Computation Engine

The report's central optimization rule is dependency order. Do not optimize
SmallWood first. The selected relation encoding determines `n`, `d`,
`d_prime`, and `dQ`; those values determine the SmallWood transcript and
soundness tradeoffs.

### 9.1 New internal data model

Add internal search records under `credential` or `cmd/issuance/internal`
before wiring them into any public preset registry.

Suggested structs:

```go
type ROBudgetVector struct {
    Merkle uint64
    FS [4]uint64
    ChallengeExpansion [4]uint64
    GuessTape uint64
    Programming [4]uint64
    ValidPrefixes [4]uint64
}

type AdversaryScope struct {
    IssuanceQueries uint64
    Presentations uint64
    Verifications uint64
    PRFAttempts uint64
    Users uint64
    Contexts uint64
    TagsPerContext uint64
    Proofs uint64
}

type RelationCandidateReport struct {
    ID string
    Phase string
    PackingWidth int
    LogicalRows int
    ParallelDegree int
    AggregateDegree int
    MaskLength int
    DQParallel int
    DQAggregate int
    DQ int
    ConstraintCounts map[string]int
    RowBreakdown map[string]int
    DominantDegreeSource string
    DominantDQBranch string
}

type SmallWoodCandidateReport struct {
    Theta int
    Rho int
    EllPIOP int
    LVCSNCols int
    NRows int
    LVCSQueries int
    EllDECS int
    DDECS int
    NDECS int
    Eta int
    Kappa [4]int
    HashBits [5]int
    TapeBits int
    SaltBits int
    CounterBits [4]int
}

type ProfileSearchCandidate struct {
    Profile IntGenISISSecurityProfileSpec
    Scope AdversaryScope
    IssueRO ROBudgetVector
    ShowRO ROBudgetVector
    Relation RelationCandidateReport
    SmallWood SmallWoodCandidateReport
    Ledger SystemSecurityLedger
    BytesByComponent map[string]int
    TotalBytes int
    ProveTimeMS float64
    VerifyTimeMS float64
    PeakMemoryBytes uint64
    FrontierClass string
}
```

Keep these records internal until the fields stabilize. Benchmark JSON can
export a flattened subset.

### 9.2 Exact arithmetic helpers

Add one shared helper file, for example `credential/log_math.go`, and use it
from ledger tests and sweep code.

Required helpers:

- `Log2Binom(n, k)` implemented with `math.Lgamma`.
- `Log2AddExp(a, b)` for adding two probabilities represented as log2 values.
- `Log2SumExp(xs)` for component ledgers.
- `BitsFromLog2Prob(logP)` returning `-logP`.
- deterministic formatting with enough precision for JSON diffs.

Do not duplicate binomial or log-sum code inside benchmarks. Existing proof
accounting and new system-ledger accounting must call the same helpers.

### 9.3 Adversary resources and valid prefixes

The resource vector must distinguish raw oracle calls from valid transcript
prefixes. A later Fiat-Shamir-stage candidate is harder to reach because it
must already contain a valid earlier prefix.

Implementation path:

- Extend `PIOP.SoundnessBudget` or add a sibling report with raw caps and
  optional valid-prefix caps.
- Keep current `ROQueryCaps` as raw caps for compatibility.
- Add optional `ROValidPrefixCaps` for future tighter accounting.
- If `ROValidPrefixCaps` is unset, use raw caps and mark the ledger as
  conservative.
- Report both in JSON.

Do not use issuance-query caps, PRF attempts, or presentation counts as
SmallWood RO caps. They are separate system-game resources.

### 9.4 Relation compilation order

Every relation backend must return:

- logical rows `n`
- maximum parallel local degree `d`
- maximum aggregated degree `d_prime`
- mask length `r_mask`
- `dQ` and the branch that attained it
- row layout and constraint family counts
- public data bytes and private witness rows
- proof-enforced bound and sampler acceptance bound

`dQ` must be computed as:

```text
DW = s_SW + r_mask - 1
dQ_parallel = d * DW + s_SW - 1
dQ_aggregate = d_prime * DW
dQ = max(dQ_parallel, dQ_aggregate)
```

Current code already exposes many of these values through `PIOP.ProofReport`,
`PIOP.TranscriptOptimizationReport`, signature-shortness reports, and benchmark
metrics. The plan is to make them mandatory candidate outputs instead of
best-effort diagnostics.

### 9.5 SmallWood derived quantities

For each compiled relation, derive or record:

```text
dDECS = LVCSNCols + ell_DECS - 1
nRows = ceil(n / LVCSNCols) * (s_SW + theta)
      + ceil(dQ / LVCSNCols + 1) * theta
mLVCS = ceil(1 + n / LVCSNCols) * theta
```

Use this continuous seed for `LVCSNCols` before dense breakpoint sweeps:

```text
nCols_seed = sqrt(
    ell_DECS * (n * (s_SW + theta) + dQ * theta)
    / (eta + theta)
)
```

Then evaluate:

- all nearby integers
- every value where `ceil(n / LVCSNCols)` changes
- every value where `ceil(dQ / LVCSNCols + 1)` changes
- current maintained values so regressions are visible

This is more efficient and safer than sweeping a wide interval blindly.

### 9.6 Deriving `eta` and `kappa`

Do not brute-force `eta` over wide ranges. For the degree-enforcement term,
derive the minimal integer that reaches the target after query-cap loss and
planned grinding.

Candidate procedure:

1. Compute raw algebraic round bits with `kappa=0`.
2. Allocate a target bit budget per round.
3. Derive the smallest `eta` satisfying round 1.
4. Derive the smallest nonnegative `kappa[i]` for residual gaps.
5. Reject if any `kappa[i]` exceeds the configured grinding budget.
6. Recompute final theorem bits and transcript bytes exactly.

Policy:

- one extra `eta` buys about `log2(q) ~= 19.96` bits but transmits another
  degree-`dDECS` response polynomial
- one extra `theta` helps rounds 2 and 3 but multiplies extension-field payload
- `kappa` is byte-cheap but prover-expensive, so it must be budgeted by stage
- counter width is selected from expected grinding, not from adversarial `Q`

Use 32-bit serialized counters for modest grinding. Allow 64-bit counters only
for high-k research candidates and report the no-solution probability.

### 9.7 Error allocation search

The report explicitly rejects one blanket margin. Add an error allocation
object:

```go
type ErrorAllocation struct {
    ProofCollision float64
    DegreeEnforcement float64
    ConstraintBatching float64
    RandomEvaluation float64
    LVCSOpening float64
    TapeGuessing float64
    Programming float64
    ChallengeBias float64
    SaltCollision float64
    TagCollision float64
    PrimitiveCore float64
    MultiUser float64
    Encoding float64
}
```

Interpret fields as target bits or log2 probability budgets, but use one
convention consistently.

Search method:

- start from equal allocation
- estimate marginal byte cost for one extra bit in each term
- strengthen cheap terms first
- relax expensive terms only if the full log-sum-exp ledger still passes
- keep the raw component ledger in JSON so the result is auditable

### 9.8 Transcript model and serializer contract

The report's formula is a check on the implementation, not a replacement for
the serializer. The exact serializer remains authoritative.

For every candidate, record the current paper buckets:

- `Pdecs`
- `VTargets`
- `Q`
- `Auth`
- `R`
- `BarSets`
- all remaining buckets in `PIOP.PaperTranscriptReport`

Heavy-budget q32/q16 optimization should start from bucket attribution. Current
q32-128 pressure is dominated by:

| Bucket | Main levers |
| --- | --- |
| `Pdecs` | `eta`, `dDECS`, `LVCSNCols`, `ell_DECS`, dense field packing. |
| `VTargets` | `theta`, row blocks, `LVCSNCols`, relation row count. |
| `Q` | `dQ`, `theta`, relation degree, shortness representation. |
| `Auth` | `NLeaves`, `ell_DECS`, hash width, multiproof shape. |
| `R` | response-polynomial degree, `eta`, `dDECS`, `LVCSNCols`. |
| `BarSets` | row count, `ell`, LVCS query count, explicit matrix payload size. |

`VTargets` and `BarSets` are public proof messages, but the current
SmallWood 2025 transcript does not make them safely omittable. They may be
made smaller by changing the relation, row-block geometry, `theta`, `ell`, or
LVCS layout. They must not be omitted from paper-transcript accounting unless
a verifier reconstruction theorem and byte-for-byte canonical binding path are
added first.

Required serializer work:

- report exact bytes for every generated proof
- report mean, median, p95, max, and theoretical worst case for Merkle
  multiproofs
- reject noncanonical field encodings, overlarge field values, wrong padding,
  wrong coordinate order, and alternate encodings
- keep dense 20-bit field serialization as a first-class candidate if the
  current serializer uses wider field slots in any bucket

### 9.9 Runtime and memory model

Transcript bytes are the primary objective, but not the only constraint. The
sweep should fit a simple runtime model for issuance and showing separately:

```text
T_prove ~= a * NDECS * nRows
        + b * NDECS * eta
        + sum_i h_i * 2^kappa[i]
        + c
```

Measure:

- row interpolation
- extension-field arithmetic
- DECS leaf evaluation
- Merkle hashing
- each Fiat-Shamir stage
- each grinding loop
- serialization and parsing
- verification
- peak memory

This prevents the optimizer from choosing transcript-small candidates with
unacceptable `NLeaves`, `eta`, or grinding.

## 10. Scheme and Relation Optimization Catalogue

This section translates the report's optimization strategies into implementable
scheme work. Each item must either become a supported backend, a candidate-only
research backend, or an explicit non-goal with a rejection reason.

Implementation hook map:

| Strategy family | Primary code hooks |
| --- | --- |
| Shortness radix/digits | `credential/intgenisis_presets.go`, `PIOP/showing_coeff_native_literal_packed_runtime.go`, `PIOP` signature-shortness helpers, `cmd/showing/main_test.go`. |
| Compression level | preset tuning, `PIOP` relation builders, transcript reports, benchmark JSON. |
| Replay projection | `PIOP/row_layout_indices.go`, replay-family audit reports, showing CLI summaries, tamper tests. |
| LVCS/DECS geometry | `PIOP/run.go`, `PIOP/soundness_accounting.go`, `DECS/decs_types.go`, issuance benchmark metrics. |
| PRF trace/tag | `prf/prf.go`, `prf/prf_params*.json`, PIOP PRF relation builders, credential state files. |
| Seed packing | `credential/intgenisis_message.go`, PRF params, relation row layout, ledger key-entropy checks. |
| Context/index binding | credential message/state structs, issuance holder secret files, showing verifier input, PRF relation constraints. |
| Domain separation | Fiat-Shamir helper code in `PIOP`, transcript serialization, verifier reconstruction paths. |
| Serializer savings | `PIOP` proof serialization/reporting, `DECS` opening packing, `cmd/issuance/benchmark_metrics.go`. |
| Security ledger | `credential/security_ledger.go`, `PIOP/soundness_accounting.go`, issuance benchmark JSON, profile gates. |

### 10.1 Coefficient block packing

Current presets expose `NCols`/packing-related geometry through tuning and
reports. The optimizer must treat the witness packing width `s_SW` as a
relation variable, not only as a display value.

Search:

- values dividing `N=512` or `N=1024`
- nearby values that preserve interpolation-domain assumptions
- phase-specific values for issuance and showing

Reject if a new packing width breaks row layout, canonical decoding, or the
degree formula used by the theorem.

### 10.2 Direct small-set membership

Use direct membership polynomials for small alphabets:

- binary: degree 2
- ternary: degree 3
- seed coefficients in `[-4,4]`: degree 9
- direct interval `[-beta,beta]`: degree `2*beta+1`

Implementation hooks:

- seed checks in the credential/PRF relation
- signature-shortness membership checks in `PIOP` showing relation files
- packed small-witness checks controlled by `CompressionLevel`

Do not use direct interval membership for large signature bounds. It explodes
degree and therefore `dQ`.

### 10.3 Small-alphabet compression

Compression packs `p` values from an alphabet of size `alpha` into one field
element. Feasibility requires `alpha^p <= q`.

For every compression candidate, compute:

- row saving
- membership degree `alpha^p`
- actual interpolation degree of decompression polynomials
- new global `d`
- new `dQ`
- serializer savings

Degree-headroom rule: prioritize compression only when its degree is at most
the existing dominant degree. Example: packing two ternary values gives degree
9, which can be free when seed membership already forces degree 9.

Packing three ternary values gives degree 27 and is likely bad for current
Profile C unless split proofs or a different backend isolate the degree.

### 10.4 Signature shortness encodings

Current code already has the main safe comparison knobs:

- `SigShortnessRadix`
- `SigShortnessDigits`
- `CompressionLevel`
- replay projection modes

Extend the search from fixed R7/L5 and R11/L4 choices into a structured
shortness spec:

```go
type ShortnessEncodingSpec struct {
    Kind string
    Radices []int
    DigitSets [][]int
    TopDigitCap int
    PackedGroupSize int
    SignMagnitude bool
    ProofBound int
    SamplerBound int
}
```

Supported safe track:

- R7/L5
- R11/L4
- mixed-radix variants with explicit canonical recomposition
- capped top digit variants

Research track:

- sign-magnitude
- packed digit groups
- hybrid coarse-range plus norm proof
- blockwise norm proof

Acceptance conditions:

- proof-enforced bound covers the sampler bound
- integer recomposition cannot wrap modulo `q`
- encoding is canonical
- tampering one digit or carry rejects
- new `dQ` and transcript buckets are recomputed, not inferred

### 10.5 Mixed radix and top-digit caps

Mixed radix can reduce the largest digit set while keeping total range. Top
digit capping should be derived automatically:

1. choose lower radices and lower digit sets
2. compute remaining range needed to cover the sampler threshold
3. choose the smallest top digit set covering that range
4. prove uniqueness and no wraparound
5. recompute `d`, `d_prime`, and `dQ`

This is a high-priority transcript strategy for heavy q-budget presets because
it targets the `Q` bucket through degree reduction and the committed-row buckets
through row reduction.

### 10.6 Norm-proof and hybrid strategies

Global or blockwise norm proofs may reduce per-coefficient digit rows, but they
change the accepted language. Treat them as candidate-only until the signature
sampler and forgery analysis are updated.

Required research outputs:

- exact integer limb/carry design when sums exceed `q`
- acceptance-rate analysis against the sampler
- proof that the new bound implies the required signature shortness condition
- lattice/security re-estimation if the accepted signature distribution changes
- tamper tests for one square, carry, slack digit, and block aggregate

Do not promote norm-proof variants under current preset names.

### 10.7 Coefficient, limb, and CRT layout

Enumerate:

- coefficient-major digit layout
- limb-major digit layout
- current coefficient plus CRT helper layout
- coefficient-only with CRT values derived through LVCS linear maps
- CRT-only for unbounded inverse variables, if all equations move consistently
- split bounded variables in coefficient form and inverse variables in CRT form

Any helper-row removal must preserve extractability and canonical linkage. It
is a relation rewrite, not a serializer-only optimization.

### 10.8 Public and derived-value elimination

Classify every row as:

- secret independently sampled
- secret deterministically derived
- public
- verifier-reconstructible from openings

Candidate eliminations:

- packed key coordinates derived from seed slots
- CRT coordinates derived by public transforms
- public nonce/context coordinates
- final PRF linear layers
- linear residual intermediates
- LVCS-recoverable DECS values

Only remove a row when the replacement constraints do not increase `dQ` enough
to erase the row saving.

### 10.9 PRF trace packing and tag growth

The current PRF has `LenKey=8`, `LenNonce=12`, `LenTag=7`, width `t=20`, and
about 133 bits of estimated permutation security. The report notes that the
current trace has row slack: increasing tag output can add public tag values
and output constraints without necessarily adding a full PRF trace row at
`s_SW=32`.

Implementation path:

- add a PRF trace compiler report with trace values, rows, slack slots, degree,
  and dominant constraints
- distinguish tag collision security from PRF computational security
- use slack for `LenTag=9` before changing permutation width
- for 160-bit and higher profiles, require new Poseidon2 parameters,
  constants, round counts, trace dimensions, security analysis, and vectors

Tag growth alone never raises PRF computational security.

### 10.10 Seed entropy and packing

The current seed is 48 coefficients in `[-4,4]`, packed six per field element
because `9^6 < q`, giving eight key coordinates.

Generalize seed selection:

```text
alphabet = 2*beta_seed + 1
seed_entropy = seed_slots * log2(alphabet)
pack_factor = floor(log_q(alphabet))
key_coords = ceil(seed_slots / pack_factor)
seed_degree = alphabet
```

Search:

- smaller `beta_seed` with more seed slots
- larger `beta_seed` with fewer seed slots
- direct key-coordinate sampling
- binary/ternary decompositions of seed slots

Reject if key entropy, PRF input width, commitment binding, or `dQ` becomes
worse than the baseline without compensating transcript savings.

### 10.11 Context, index, tag, and replay binding

The report requires a finite presentation-index domain and context-bound tags.
Implement this before treating tag collision accounting as complete.

Preferred scheme:

- public presentation limit `L`
- public index `j in [0,L)`
- context digest includes protocol version, profile id, issuer key digest,
  credential context, epoch, redemption context, and presentation limit
- tag input is `F(k, H_ctx(context, j))`

If the index remains hidden, add a canonical range proof for `j`. Do not treat
unconstrained hidden nonce field elements as a finite rate-limit domain.

Replay projection optimizations remain allowed only when the verifier binds:

- key rows
- nonce or context digest rows
- public tag rows
- transcript coordinate digest
- selected replay family metadata

Keep and extend the replay-family audit already visible in showing reports.

### 10.12 Domain separation and challenge expansion

Every random-oracle input must bind:

- protocol name and version
- profile identifier
- issuance/showing phase
- oracle and round id
- public-key digest
- statement and context digest
- salt
- canonical message lengths
- grinding counter

Use deterministic, domain-separated expansion from each Fiat-Shamir challenge
unless a separate challenge-expansion oracle is added to the resource vector and
ledger. The deterministic-expansion path is the recommended safe track.

### 10.13 Salt role

Decide and encode whether salt uniqueness is required.

If required, ledger term:

```text
salt_collision ~= binom(number_of_proofs, 2) / 2^SaltBits
```

If not required, document the intended role: domain separation, preprocessing
resistance, or transcript uniqueness. Do not include a salt-security claim in
complete profiles without a theorem role.

### 10.14 Split proofs and degree classes

A monolithic PACS proof pays for the maximum local degree everywhere. Splitting
can isolate high-degree shortness or compression checks.

Safe track:

- benchmark monolithic proof only
- model split proof bytes in the optimizer but classify as
  `requires_theorem_accounting`

Research track:

- low-degree core proof plus high-degree shortness proof
- issuance/showing subproofs split by relation family
- heterogeneous-degree PACS batching

Promotion requires a derivation note because salts, roots, FS chains, openings,
and composition all change.

### 10.15 Backend comparison

Current implementation uses the SmallWood small-field backend. Keep it as the
only live backend initially, but make the optimizer record the backend id.

Candidate-only comparators:

- general PCS/LVCS backend with explicit `mu` and stack factor
- direct-DECS backend for very small relations
- split backend for degree classes

No backend comparator may replace a preset without matching theorem accounting
and tamper tests.

## 11. Profile-Specific Optimization Plans

### 11.1 Heavy q-budget proof presets

Current `n1024-q16-128` and `n1024-q32-128` are proof-level research presets.
Keep optimizing them because they reveal the transcript frontier for future
complete profiles.

Priority order for q32:

1. Reduce `Q` by lowering relation degree and `dQ`.
2. Reduce `Pdecs` by deriving minimal `eta` and tuning `LVCSNCols`.
3. Reduce `VTargets` and `BarSets` through row-block breakpoints and relation
   dimensions, not by omitting those matrices.
4. Reduce `Auth` by tuning `NLeaves`, `ell_DECS`, and hash width only inside
   the proof security budget.
5. Use targeted `kappa` before raising `theta`.
6. Test split or mixed-radix shortness only after exact row and degree reports
   exist.

Safe q32 sweep windows:

- `LVCSNCols`: dense around current row-block breakpoints, not just `36..48`
- `NLeaves`: dense around `2^19`, current `655360`, and nearby powers/tables
- `eta`: derive first, then test current value and one below/above
- `theta`: test `8..10` with explicit round-2 and round-3 slack
- `ell_DECS`: smallest value keeping round 4 above target
- `kappa`: prefer no more than a few extra bits unless transcript savings are
  large and measured proving time remains acceptable

Run q16 after q32 trends are known. q16 often shares the same relation and
width lessons, but has more collision/security slack and may choose a smaller
hash or lower kappa.

### 11.2 SC regression profiles

Purpose:

- prove the generalized framework reproduces current compact presets
- keep old byte gates stable
- separate pure serializer savings from cryptographic parameter changes

Required checks:

- current `n`, `d`, `d_prime`, `dQ`, `dDECS`, row blocks, and byte buckets
- one-candidate theorem bits
- tag/salt/ledger fields present but not falsely claimed as bounded-budget
  deployment security

### 11.3 `BQ32-96`

This is the first complete bounded-budget target.

Start from current Profile C and the compact q32/q16 relation frontier, but
complete the missing system pieces:

- 128-bit primitive floor from current lattice/PRF estimates
- equal raw RO caps of `2^32`
- tag length 9
- finite context-bound presentation index
- split hash/tape widths
- salt role decided and accounted
- full ledger residual bits at least 96

Width strategy:

- safe engineering start: 24-byte hash, 18- or 20-byte tape
- minimized target after proof/accounting is clean: 21-byte hash, 16-byte tape
- keep both points in the Pareto frontier

Relation strategy:

- use compression only inside degree headroom
- test R7/L5, R11/L4, mixed radix, and top-digit caps
- use PRF row slack for `LenTag=9`
- avoid norm-proof promotion unless sampler/security analysis is redone

### 11.4 `WF-128`

This profile is a work-factor claim, not 128 residual bits after `2^128`
queries.

Search strategy:

- reuse the best `BQ32-96` algebraic relation when possible
- widen hash/FS collision outputs to the report target of 33 bytes
- keep tape around 16 to 20 bytes depending on zero-knowledge accounting
- require current Profile C core to pass the 128-bit floor in the ledger
- keep CROM wording explicit

This can become the main cryptographic profile only if the full ledger passes,
not merely because the one-proof theorem bits exceed 128.

### 11.5 160-bit profiles: `BQ32-128` and `BQ64-96`

These require new primitive work before transcript tuning is meaningful.

Required before any live preset:

- new lattice/signature/commitment parameters with classical and quantum
  estimates
- new PRF parameters around 160-bit computational security
- at least 160-bit key entropy
- tag lengths 10 and 12 respectively
- tapes around 20 to 24 bytes
- salts around 24 to 32 bytes depending on proof count
- hash outputs from the report table
- SmallWood algebraic target around 162 to 164 bits before composition

Do not retune only `theta`, `eta`, or `kappa` under current Profile C and label
the result `BQ32-128`.

### 11.6 192-bit profile: `BQ64-128`

Initial research design:

- new 192-bit lattice and PRF families
- ring candidates likely starting at degree 2048, but only after estimator runs
- seed around 66 coefficients in `[-4,4]`, packed into about 11 coordinates
- tag length 13 or 14
- hash 40 bytes for first engineering implementation, then test the 33-byte
  bare minimum
- tape 24, 28, and 32 bytes
- salt 32 or 40 bytes
- extension degrees sufficient for roughly 200-bit algebraic terms
- aggressive shortness search because larger rings make digit rows dominant

High-priority strategies:

- mixed radix
- capped top digits
- blockwise norm proofs as candidate-only
- split high-degree shortness proof as candidate-only

### 11.7 256-bit profile: `BQ128-128`

Treat this as a system redesign.

Initial conservative design:

- new 256-bit lattice and PRF families
- likely larger ring and module dimensions after estimator work
- seed around 84 bounded coefficients and 14 packed key coordinates
- tag length 20 or 21
- hash 64 bytes for first implementation, then compare the 49-byte bare minimum
- tape 32 or 40 bytes
- salt 48 or 64 bytes
- high-security SmallWood target around 260 to 264 aggregate bits
- possible phase-specific proof systems and split relations

Transcript minimization is secondary until the complete primitive and theorem
chain is defensible.

## 12. Documentation and Gates

Update docs only after the matching code exists:

- `docs/PROTOCOL.md`: distinguish proof presets from complete system profiles.
- `docs/SECURITY.md`: define `SC`, `WF`, and `BQ` semantics in CROM.
- `ARTIFACT.md`: keep existing maintained preset bytes stable until promoted
  replacements exist.
- `cmd/issuance/gate_degree1024_presets.go`: keep current gates unchanged
  during registry and ledger work.
- Add `cmd/issuance/gate_security_profiles.go` only after complete ledger
  outputs exist.

Gate behavior:

- Existing byte gates continue to protect maintained transcript sizes.
- New complete-profile gates check `ledger_status == "complete_live"`.
- Candidate profiles must be visible in JSON but fail closed for complete
  claims.

## 13. Test Plan

Baseline tests after each phase:

```bash
go test ./credential
go test ./PIOP
go test ./DECS
go test ./cmd/issuance
go test ./cmd/showing
```

Required new tests:

- security profile registry labels, statuses, and CROM-only model
- old `DECSCollisionBits` compatibility path
- split hash/tape width reporting
- hash width mismatch rejection
- tape width mismatch rejection
- per-oracle collision formula against report examples
- tag collision formula against report examples
- salt collision formula
- `BQ32-96` rejects `LenTag=7` and accepts `LenTag=9`
- complete profile fails when core bits are below the required floor
- advanced profiles remain candidate-only without new primitive files
- replay rejection remains passing for promoted profiles
- relation candidate reports contain `n`, `d`, `d_prime`, both `dQ` branches,
  and the dominant constraint source
- shortness encodings reject noncanonical recompositions and modulo wraparound
- mixed-radix and top-digit cap generators prove coverage of the sampler bound
- compression candidates compute actual decompression degrees
- public/context-bound presentation index tampering rejects
- random-oracle domain separation changes verification challenges
- challenge samplers pass uniformity or rejection-sampling tests
- dense field parser rejects overlarge values and nonzero padding bits

Live benchmark validation for promoted candidates:

```bash
SPRUCE_BENCH_JSON=/tmp/<preset>.json go test ./cmd/issuance -run '<gate-or-bench-name>'
```

Each JSON artifact must include exact transcript bytes, bucket bytes, theorem
bits, algebraic round bits, collision bits, full-game bits, ledger status, PRF
profile, and replay result.

## 14. Non-Goals and Safety Rules

- Do not make QROM claims.
- Do not mark `BQ32-128+` profiles live under current Profile C.
- Do not hide tape/hash clamps; report them.
- Do not expose all sweep knobs as public CLI options.
- Do not promote a profile based only on proof theorem bits.
- Do not change old preset names or byte gates during the registry/ledger
  transition.
- Do not add 160/192/256-bit PRF or lattice profiles without parameter
  generation notes, estimator notes, and test vectors.

The first complete new target is `BQ32-96`. The current q-budget 128 presets
remain valuable transcript-reduction research artifacts, but the report-aligned
system-security path is: registry, split widths, full ledger, tag-9 PRF support,
then bounded-budget preset promotion.

## 15. Next Implementation Plan

The next phase is not WF-128. The next phase is to finish the BQ32-96
promotion evidence loop. The candidate no longer misses the numeric default
scope target: the live-tuned preset reaches `96.38` full-game bits and reduces
showing paper transcript bytes to `36764`. It remains candidate-only until the
ledger is reviewed as a complete master advantage bound and a fail-closed
complete-profile gate exists.

### 15.1 Immediate invariant

Until all items below pass:

- keep `BQ32-96` status as `candidate`
- keep `n1024-bq32-96` out of maintained complete-profile gates
- keep `CompleteSystemClaim=false`
- do not change existing compact/q-budget preset byte gates
- do not start WF-128 or stronger BQ profiles

### 15.2 Ledger hardening

Goal: replace conservative placeholder terms with report-grade terms, while
preserving fail-closed behavior.

Implementation steps:

1. Audit every `SystemSecurityLedgerTerm` currently emitted by
   `benchmarkIntGenISISE2ESecurityLedger`.
2. For each term, record whether it is:
   - exact from theorem/report data
   - conservative from available benchmark data
   - missing and therefore rejecting
3. Split the current broad `full_game` and `programming_conflict` terms into
   named components:
   - issuance SmallWood extraction
   - showing SmallWood extraction
   - global RO/Merkle collision
   - programming conflict
   - challenge bias
   - tape guessing
   - multi-proof composition
4. Add JSON fields that explicitly identify conservative fallbacks, not only
   final bits.
5. Add tests proving:
   - missing required terms reject
   - candidate profiles remain candidate even if all terms numerically pass
   - term category bit composition uses `Log2SumExp`
   - lowering one required term below target creates one clear rejection reason

Exit criteria:

- Ledger output explains both the previous `94.97`-bit BQ32-96 result and the
  current `96.38`-bit tuned result by component.
- No term can silently default to a passing value.
- `go test ./credential ./cmd/issuance` passes.

Current status:

- Initial ledger hardening is implemented.
- Ledger terms now carry source/provenance:
  - `exact`
  - `conservative`
  - `missing`
- Diagnostic aggregate terms can be marked `report_only` so they remain visible
  without being double-counted in category totals.
- BQ32-96 benchmark JSON now reports component terms:
  - `issuance_smallwood_extraction`: exact, passes at about `97.54` bits
  - `showing_smallwood_extraction`: exact, passes at about `97.54` bits
  - `ro_collision`: exact, passes in the current run
  - `full_game`: exact report-only diagnostic, passes at `96.38` bits
  - `multi_proof_composition`: exact report-only diagnostic, passes at
    `96.38` bits
  - `tape_guessing`: exact `zero_knowledge` term, passes at `96.00` bits
  - `programming_conflict`: conservative `zero_knowledge` term, passes at
    about `134.00` bits but remains marked `requires_theorem_accounting`
  - `multi_user` and `multi_context`: conservative scope-lift terms,
    informational for the default one-user, one-context benchmark scope
- The PDF-backed decision is now encoded:
  - full-game/multi-proof composition is a real current-theorem loss that must
    be paid by theorem support or parameter margin
  - tape/programming are zero-knowledge/proof-simulation terms, not soundness
    terms
  - default one-user/one-context scope lifts do not depress `composition_bits`
- Current `soundness_bits` is about `96.38`; current `zero_knowledge_bits` is
  approximately `96.00`.
- Next work is promotion-grade validation and further byte reduction, not
  assuming away the full-game loss.

### 15.3 Full-game accounting decision point

Goal: decide whether the previous `94.97`-bit result was a real security
deficit or a conservative double-counting artifact.

Implementation steps:

1. Compare these current benchmark values:
   - one-proof issuance theorem bits
   - one-proof showing theorem bits
   - global collision bits
   - conservative full-game bits
   - global-collision full-game bits
2. Verify whether issuance and showing extraction terms must be union-bounded
   as two independent accepted proofs, or whether the report permits a tighter
   simultaneous/composed argument.
3. If the report supports tighter accounting, encode it as a separate ledger
   theorem mode and keep the current conservative mode visible.
4. If the report does not support tighter accounting, treat the loss as real
   and move to parameter search.

Exit criteria:

- The ledger says why the full-game term was previously below 96.
- Any improved accounting path has a named theorem basis and a regression test.
- If no theorem basis exists, optimizer work must pay the loss with parameter
  margin.

Current status:

- Decision taken: the PDF does not justify a simultaneous-extraction shortcut
  in this implementation pass.
- The tuned preset pays the implemented full-game/multi-proof loss with
  parameter margin.
- Keep the current conservative composition visible in benchmark JSON even if a
  future theorem mode is added.

### 15.4 BQ32-96 targeted parameter search

Goal: keep the current numeric clearance while reducing transcript bytes
further, without changing public CLI behavior or existing gates.

Search constraints:

- Profile C core remains fixed.
- Ring degree, modulus, relation-level PRF family, seed packing, and Profile C
  dimensions remain fixed.
- `LenTag=9` remains fixed unless ledger work proves it must grow.
- Existing compact and q-budget presets remain unchanged.
- Candidate search remains internal/env-gated.

Search order:

Completed first pass:

- Added benchmark diagnostics:
  - `required_phase_algebraic_bits`
  - `phase_algebraic_slack_bits`
  - `dominant_soundness_limiter`
- Added focused BQ32 sweep candidates:
  - `bq32-current-control`
  - `bq32-safe-n524288-lvcs37-eta44-ell9`
  - `bq32-rowblock-n557056-lvcs40-eta44-ell9`
  - `bq32-rowblock-n589824-lvcs44-eta47-ell9`
  - `bq32-fallback-ell10-lvcs37-n458752-eta44`
- Accepted `bq32-rowblock-n557056-lvcs40-eta44-ell9`:
  - `full_game_bits=96.38`
  - `soundness_bits=96.38`
  - `zero_knowledge_bits=96.00`
  - `phase_algebraic_slack_bits=0.42`
  - showing paper transcript bytes `36764`, down `480` from the prior
    `37244`
- Rejected `bq32-rowblock-n589824-lvcs44-eta47-ell9` for now despite better
  bytes because its live `96.06` full-game bits are below the `96.25`
  candidate acceptance threshold.
- Updated only the `n1024-bq32-96` candidate tuning; compact/q-budget gates and
  public CLI behavior remain unchanged.

Next search order:

1. Add serializer-level byte reductions before further cryptographic tuning:
   - `pdecs` bucket compression or deduplication
   - `vtargets` compression or shared target encoding
   - `barsets` compact encoding
   - Merkle auth path/multiproof accounting checks
2. Then sweep transcript geometry near the new tuned point:
   - `LVCSNCols` around `40`
   - `NLeaves` around `557056`
   - `theta`
   - `ell`
3. Then evaluate relation-level transcript changes:
   - shortness radix/digit shape
   - compression level
   - replay projection
4. Only after those fail, consider larger width/tag changes:
   - `FSCollisionBits`
   - `DECSHashBits`
   - `SaltBits`
   - `LenTag`

Internal harness requirements:

- Extend `SPRUCE_SECURITY_PROFILE_SWEEP=1` to emit:
  - candidate parameters
  - exact transcript bytes
  - relation candidate report
  - ledger terms
  - frontier class
  - rejection reasons
- Keep the q-budget sweep behavior unchanged.
- Add filters/max-runs so a focused BQ32-96 lane can run quickly.

Exit criteria:

- At least one Pareto candidate has `ledger_status` still candidate-only,
  every numeric term at or above 96, and showing paper transcript bytes below
  `36764`.
- If no candidate clears 96, the summary records the narrowest blocker:
  theorem margin, full-game composition, transcript status, primitive floor, or
  replay/tamper failure.

### 15.5 Relation report completion

Goal: make candidate reports decision-useful for optimizer work.

Add or tighten reports for:

- logical rows `n`
- parallel degree `d`
- aggregate degree `d_prime`
- `dQ_parallel`
- `dQ_aggregate`
- final `dQ`
- dominant `dQ` branch
- dominant constraint source
- row counts by family
- constraint counts by family
- row-degree exchange score for each candidate

Exit criteria:

- Every benchmark JSON and sweep summary can explain why a candidate has its
  current `dQ`, row count, and byte shape.
- Tests assert both `dQ` branches for at least one issuance and one showing
  relation.

### 15.6 Negative and tamper test completion

Goal: finish the validation items needed before promotion.

Already covered:

- profile registry labels/statuses/CROM-only
- split hash/tape width compatibility
- DECS hash/tape mismatch rejection
- tag-7 fails and tag-9 passes the BQ32 tag term
- required ledger terms reject
- candidate profiles remain non-live
- public tag/nonce/context tampering rejects
- Fiat-Shamir domain separation changes challenges

Still needed before promotion:

- per-oracle collision formulas against report examples
- challenge sampler uniformity or rejection-sampling tests
- dense field parser overlarge/nonzero-padding rejection
- serializer bucket regression for candidate benchmark JSON
- replay rejection recorded as a promotion gate input, not just a benchmark note
- noncanonical shortness recomposition tests for any new radix/mixed-radix
  candidate

### 15.7 Promotion gate design

Goal: define the gate before promoting anything.

Add the gate only after a BQ32-96 candidate numerically clears the ledger:

- new gate file: `cmd/issuance/gate_security_profiles.go`
- gate condition:
  - selected profile status is intended to be `complete_live`
  - benchmark runs exact issuance/showing flow
  - `ledger_status == "complete_live"`
  - all required ledger terms pass
  - replay rejection passes
  - transcript status is live
  - exact byte ceilings match checked-in expected values
- candidate profiles remain visible in JSON but are not accepted by this gate.

Exit criteria:

- Gate fails on current `n1024-bq32-96` while it is candidate.
- Gate would pass only after an explicit status change and reviewed expected
  bytes.

### 15.8 Documentation sequence

Update public docs only after code evidence exists:

1. Internal plan document records candidate evidence and blockers.
2. `docs/SECURITY.md` defines SC/WF/BQ semantics and CROM-only scope.
3. `docs/PROTOCOL.md` states which presets are proof-only and which, if any,
   are complete system-security claims.
4. `ARTIFACT.md` updates benchmark evidence only after maintained gates are
   intentionally changed.

Do not describe `n1024-bq32-96` as a complete system-security preset until the
security-profile gate exists and passes.

### 15.9 Advanced BQ NIZK-only research lane

Goal: parameterize `BQ32-128`, `BQ64-96`, `BQ64-128`, and `BQ128-128` at the
NIZK layer without changing lattice parameters, PRF parameters, public CLI
behavior, or maintained gates.

Current status:

- Internal env-gated projection sweep added:
  `SPRUCE_NIZK_PROFILE_SWEEP=1 go test ./cmd/issuance -run TestInternalNIZKProfileSweep -count=1 -v`.
- Targets are generated in report order:
  - `BQ32-128`: NIZK target `164`, 160-bit primitive blocker.
  - `BQ64-96`: NIZK target `164`, 160-bit primitive blocker.
  - `BQ64-128`: NIZK target `200`, 192-bit primitive blocker.
  - `BQ128-128`: NIZK target `264`, 256-bit primitive/redesign blocker.
- `BQ64-96` registry salt metadata now follows the PDF bare target:
  `SaltBits=224`; the NIZK research lane records the practical `256`-bit
  engineering salt point.
- The sweep reports relation data, SmallWood knobs, required grinding,
  projected transcript buckets, ledger status, forced-by-security widths, and
  primitive blockers.
- The sweep now has an opt-in measured overlay:
  `SPRUCE_NIZK_PROFILE_SWEEP_MEASURED=1` reruns selected finalists through
  `benchmark-intgenisis-e2e` and replaces relation/bucket fields with compiled
  proof metadata and measured paper transcript buckets.
- Feasibility decision after degree/row audit:
  - raw mixed-radix/top-cap encodings are not active optimization tracks because
    the current polynomial membership backend cannot reduce rows without
    increasing `dQ`
  - full R2 decomposition spends more rows than its degree reduction buys back
  - R121/L2 and split-shortness remain theorem/accounting ideas only, not
    candidate relation encodings
  - the active sweep therefore focuses on the current safe R7/L5-style relation
    plus a q32 control alias.
- Latest full projection result:
  - all four lanes remain system-level `requires_new_primitives`
  - the NIZK-only frontier now contains concrete algebraic candidates for all
    four advanced labels
  - no advanced profile is live or promotable without new primitive families
- `BQ32-96` tuning remains unchanged.

Concrete NIZK-only frontier from
`SPRUCE_NIZK_PROFILE_SWEEP=1 SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE=0`:

| Profile | Selected NIZK-only candidate | Projected algebraic bits | Projected paper bytes | SmallWood knobs | Required grinding | Still blocked by |
| --- | --- | ---: | ---: | --- | --- | --- |
| `BQ32-128` | `r7l5-current-theta10-ell15-n917504-lvcs43` | `166.12` | `78465` | `eta=56`, `theta=10`, `ell=15`, `LVCSNCols=43`, `NLeaves=917504`, `dQ=445` | `[0,0,8,0]` | 160-bit lattice/PRF/key family |
| `BQ64-96` | `r7l5-current-theta12-ell16-n983040-lvcs43` | `165.31` | `91660` | `eta=58`, `theta=12`, `ell=16`, `LVCSNCols=43`, `NLeaves=983040`, `dQ=454` | `[0,0,0,2]` | 160-bit lattice/PRF/key family |
| `BQ64-128` | `r7l5-current-theta14-ell18-n983040-lvcs43` | `201.49` | `108868` | `eta=61`, `theta=14`, `ell=18`, `LVCSNCols=43`, `NLeaves=983040`, `dQ=472` | `[0,0,0,10]` | 192-bit lattice/PRF/key family |
| `BQ128-128` | `r7l5-current-theta20-ell28-n983040-lvcs59` | `265.25` | `193896` | `eta=86`, `theta=20`, `ell=28`, `LVCSNCols=59`, `NLeaves=983040`, `dQ=562` | `[0,0,4,10]` | 256-bit primitive redesign |

The `1048576+`-leaf projections remain allowed in the research search space,
but they are not measurable as current Profile C proofs. The explicit DECS
domain needs distinct base-field points and Profile C has only `q=1017857`
points. Accepting duplicate evaluation points would break the opening and
interpolation argument. Measured overlays therefore use the closest executable
`983040`-leaf neighbors unless a larger-field or extension-domain primitive
lane is introduced.

Compiler-backed measured finalists:

Command:

```bash
SPRUCE_NIZK_PROFILE_SWEEP=1 \
SPRUCE_NIZK_PROFILE_SWEEP_MEASURED=1 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_E2E=1 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE=1 \
SPRUCE_NIZK_PROFILE_SWEEP_FILTER=BQ32-128 \
SPRUCE_NIZK_PROFILE_SWEEP_ARTIFACT_ROOT=/tmp/spruce-nizk-measured-safe \
go test ./cmd/issuance -run TestInternalNIZKProfileSweep -count=1 -v
```

Measured results:

| Profile | Candidate | Status | Measured paper bytes | Measured relation | Measured bucket order |
| --- | --- | --- | ---: | --- | --- |
| `BQ32-128` | `r7l5-current-theta10-ell15-n917504-lvcs43` | primitive-blocked NIZK research | `59522` | `rows=472`, `d=9`, `d'=8`, `dQ=445`, dominant source `compression` | `pdecs=16954`, `vtargets=12910`, `q=11052`, `auth=7541`, `r=6008`, `barsets=4510` |
| `BQ64-96` | `r7l5-current-theta12-ell16-n983040-lvcs43` | primitive-blocked NIZK research | `69768` | `rows=472`, `d=9`, `d'=8`, `dQ=454`, dominant source `compression` | `pdecs=18884`, `vtargets=15490`, `q=13531`, `auth=9323`, `r=6222`, `barsets=5770` |
| `BQ64-128` | `r7l5-current-theta14-ell18-n983040-lvcs43` | primitive-blocked NIZK research | `83223` | `rows=472`, `d=9`, `d'=8`, `dQ=472`, dominant source `compression` | `pdecs=22144`, `vtargets=18070`, `q=16415`, `auth=11928`, `barsets=7570`, `r=6544` |
| `BQ128-128` | `r7l5-current-theta20-ell28-n983040-lvcs59` | primitive-redesign NIZK research | `146765` | `rows=472`, `d=9`, `d'=8`, `dQ=562`, dominant source `compression` | `auth=35913`, `pdecs=30524`, `q=27940`, `vtargets=26560`, `r=12658`, `barsets=12610` |

Interpretation:

- The compiler-backed relation agrees with the safe relation model:
  `rows=472`, `d=9`, `d'=8`, and formula-correct `dQ=445`.
- Measured serialization is substantially smaller than the conservative
  projections for all compiler-backed finalists. The current measured bytes
  are `59522`, `69768`, `83223`, and `146765` for `BQ32-128`, `BQ64-96`,
  `BQ64-128`, and `BQ128-128` respectively.
- The measured bucket order changes the immediate serializer audit:
  `pdecs` is largest for `BQ32-128`, `BQ64-96`, and `BQ64-128`; `auth`
  becomes largest for `BQ128-128` because `ell=28` and 512-bit hashes make
  each Merkle level expensive. The next byte-reduction pass should still track
  `vtargets`, `barsets`, LVCS row-block breakpoints, auth/multiproof paths,
  and duplicated serializer payloads, but the first measured audit must include
  `pdecs` duplication/opening accounting as well.

Current projected class counts:

| Profile | `nizk_candidate` | `high_k_research` | Interpretation |
| --- | ---: | ---: | --- |
| `BQ32-128` | `1782` | `178` | 164-bit NIZK is feasible in projection on the current safe relation, but system security is primitive-blocked. |
| `BQ64-96` | `1446` | `514` | 164-bit NIZK is feasible with modest grinding after eta/LVCS are derived conservatively. |
| `BQ64-128` | `958` | `1002` | 200-bit NIZK is feasible but tight and grinder-sensitive. |
| `BQ128-128` | `378` | `1582` | 264-bit NIZK is projection-feasible only with very large widths and a full 256-bit redesign. |

Measured transcript-bucket notes for the selected frontiers:

| Profile | `pdecs` | `vtargets` | `q` | `auth` | `barsets` | `r` | Main byte pressure |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `BQ32-128` | `16954` | `12910` | `11052` | `7541` | `4510` | `6008` | `pdecs` and `vtargets` dominate; duplicate DECS-opening payloads and target encodings are now the first serializer targets. |
| `BQ64-96` | `18884` | `15490` | `13531` | `9323` | `5770` | `6222` | `pdecs`, `vtargets`, and `q` dominate; LVCS row-block changes should be judged only after exact bucket measurement. |
| `BQ64-128` | `22144` | `18070` | `16415` | `11928` | `7570` | `6544` | same safe relation shape as `BQ64-96`, but wider hash/tape and `theta=14` push every target/opening bucket upward. |
| `BQ128-128` | `30524` | `26560` | `27940` | `35913` | `12610` | `12658` | authentication is largest because 512-bit hashes and `ell=28` make every Merkle level expensive; `pdecs`, `q`, and `vtargets` remain close behind. |

#### 15.9.1 BQ64-96 measured reduction pass

Goal: reduce the `BQ64-96` research-lane transcript below the measured
`69768`-byte target while preserving the current theorem model. This lane
still remains `requires_new_primitives` because the required 160-bit primitive
family is not implemented.

Implemented BQ64-96 reduction lane:

- Width discipline is explicit:
  `hash/FS >= 232`, `tape >= 160`, `salt >= 224`, `LenTag >= 12`.
- Salt `224` is the bare lane and salt `256` is the engineering lane.
- The active theorem-valid relation remains the current safe `R7/L5`
  relation.
- R11/L4, mixed radix, full R2, and split-shortness are reported only as
  theorem-accounting or split-theorem audit candidates.
- `VTargets` and `BarSets` remain explicit in every measured candidate.

Measured command:

```bash
SPRUCE_NIZK_PROFILE_SWEEP=1 \
SPRUCE_NIZK_PROFILE_SWEEP_MEASURED=1 \
SPRUCE_NIZK_PROFILE_SWEEP_FILTER=BQ64-96 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_E2E=12 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE=0 \
SPRUCE_NIZK_PROFILE_SWEEP_ARTIFACT_ROOT=/tmp/spruce-nizk-bq64-96-measured \
go test ./cmd/issuance -run TestInternalNIZKProfileSweep -count=1 -v
```

Measured reduction results:

| Candidate | Frontier | Algebraic bits | Bytes | Required kappa | Key result |
| --- | --- | ---: | ---: | --- | --- |
| `baseline-h232-s224` | `nizk_candidate` | `165.31` | `69776` | `[0,0,0,2]` | measured control; live run is 8 bytes above the older stored target |
| `engineering-salt256` | `nizk_candidate` | `165.31` | `69776` | `[0,0,0,2]` | practical salt width does not change paper transcript bytes in the current encoding |
| `lvcs44-h232` | `nizk_candidate` | `165.64` | `70390` | `[0,0,0,3]` | larger than baseline |
| `lvcs45-h232` | `nizk_candidate` | `165.39` | `71010` | `[0,0,0,3]` | larger than baseline |
| `lvcs46-h232` | `nizk_candidate` | `165.58` | `71040` | `[0,0,0,4]` | larger than baseline |
| `lvcs47-h232` | `nizk_candidate` | `165.47` | `71667` | `[0,0,0,4]` | larger than baseline |
| `lvcs48-h232` | `nizk_candidate` | `165.76` | `69098` | `[0,0,0,5]` | best current-theorem BQ64-96 byte reduction in this pass |
| `lvcs49-h232` | `nizk_candidate` | `165.23` | `69583` | `[0,0,0,5]` | still below baseline, but worse than LVCS48 |
| `lvcs50-h232` | `nizk_candidate` | `165.32` | `70193` | `[0,0,0,5]` | larger than baseline |
| `lvcs51-h232` | `nizk_candidate` | `165.66` | `70327` | `[0,0,0,6]` | larger than baseline |
| `lvcs52-h232` | `nizk_candidate` | `164.70` | `70817` | `[0,0,0,6]` | larger than baseline |
| `theta11-lvcs43-h232` | `high_k_research` | `159.67` | `66478` | `[0,11,20,2]` | large byte win, but below target and over the grinding cap |

Interpretation:

- The safe measured optimum is `LVCSNCols=48`, not the original `43`, for this
  BQ64-96 research lane.
- The byte win is real but modest: about `678` bytes relative to the live
  `69776`-byte baseline.
- `theta=11` proves the main byte lever is still theta, but it is not valid
  under the current theorem/accounting because round 3 needs `kappa=20`.
- Salt width is not currently a size lever.
- Full R2, R11/L4, mixed radix, and split-shortness remain outside the active
  theorem-valid path.

#### 15.9.2 BQ64-128 measured reduction pass

Goal: reduce the `BQ64-128` research-lane transcript from the measured
`83223`-byte baseline without changing lattice or PRF primitive parameters and
without promoting the profile. This lane remains `requires_new_primitives`.

Implemented diagnostics:

- `PIOP.PaperTranscriptReport` now carries a serializer audit for:
  - `pdecs` metadata bytes, residue stream bytes, encoded columns, omitted
    columns, and packed bit width
  - `vtargets` rows, columns, packed bytes, and bit width
  - `barsets` rows, columns, packed bytes, and bit width
  - auth node count, node bytes, path depth, path bits, index bytes, and total
    auth bytes
  - tape seed/nonce metadata bytes
- Benchmark JSON carries this audit as `transcript_audit`.
- The NIZK research summary carries `bq64_128_reduction` reports with:
  - width model
  - serializer model
  - measured audit, when the candidate is measured
  - baseline bytes and transcript delta
  - acceptance reasons
- Serializer omissions are fail-closed:
  - current P/M opening omitted-column compression is reported as an existing
    safe reconstruction path because `smallfield2025` binds omission metadata
    and payload digests
  - `VTargets` and `BarSets` omission candidates are blocked until the verifier
    reconstructs the exact old bytes before DECS verification and the omission
    map is Fiat-Shamir-bound
- Split-shortness is classified as `requires_split_theorem`, not a live
  optimization.

Measured command:

```bash
SPRUCE_NIZK_PROFILE_SWEEP=1 \
SPRUCE_NIZK_PROFILE_SWEEP_MEASURED=1 \
SPRUCE_NIZK_PROFILE_SWEEP_FILTER=BQ64-128 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_E2E=16 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE=0 \
SPRUCE_NIZK_PROFILE_SWEEP_ARTIFACT_ROOT=/tmp/spruce-nizk-bq64-128-measured \
go test ./cmd/issuance -run TestInternalNIZKProfileSweep -count=1 -v
```

Measured reduction results:

| Candidate | Frontier | Algebraic bits | Bytes | Delta | Key result |
| --- | --- | ---: | ---: | ---: | --- |
| `baseline` | `nizk_candidate` | `201.49` | `83231` | `+8` | measured control: `theta=14`, `ell=18`, `LVCSNCols=43`, `NLeaves=983040`, `dQ=472` |
| `bare-hash256` | `nizk_candidate` | `201.49` | `82871` | `-352` | saves one byte per auth node; tape stays `192`, salt `256`, tag lane `13` |
| `bare-hash264` | `nizk_candidate` | `201.49` | `83231` | `+8` | same measured bytes as baseline, as expected for the current 33-byte hash lane |
| `engineering-hash320` | `nizk_candidate` | `201.49` | `85751` | `+2528` | conservative 40-byte hash lane is expensive and should not be used for byte-minimized research unless required by ledger review |
| `pdecs-dedup` | `nizk_candidate` | `201.49` | `83231` | `+8` | no extra win: current safe serializer already uses omitted P/M opening columns |
| `vtargets-dedup` | `serializer_model_blocked` | `201.49` projected | projected only | n/a | blocked until exact verifier reconstruction exists |
| `auth-multiproof-audit` | `nizk_candidate` | `201.49` | `83231` | `+8` | report-only; no serializer change |
| `theta13` | `high_k_research` | `199.09` | `79778` | `-3445` | byte win, but below `200.25` and needs `kappa3=16` > supported cap `13` |
| `ell17` | `high_k_research` | `191.10` | `80604` | `-2619` | byte win, but eps4 collapses and needs `kappa4=24` |
| `lvcs-breakpoint` | `nizk_candidate` | `202.57` | `82190` | `-1033` | best theorem-valid measured reduction in this pass; `LVCSNCols=48`, `kappa4=13` |
| `lvcs49-h256` | `nizk_candidate` | `202.14` | `82500` | `-723` | narrower hash does not compensate for larger LVCS payloads |
| `lvcs50-h256` | `high_k_research` | `201.63` | `83050` | `-173` | crosses the grinding cap with `kappa4=14` |
| `lvcs51-h256` | `high_k_research` | `201.28` | `83726` | `+503` | larger and high-k |
| `lvcs52-h256` | `high_k_research` | `200.85` | `84408` | `+1185` | larger and high-k |
| `theta13-lvcs49-h256` | `high_k_research` | `199.19` | `79080` | `-4143` | byte-attractive but below target and over the round-3 grinding cap |
| `split-shortness-research` | `requires_split_theorem` | projected only | projected only | n/a | theorem/accounting track only |

Measured baseline audit:

```text
pdecs:    total=22144, stream=22141, encoded_cols=492, bit_width=20
vtargets: total=18070, rows=168, cols=43, bit_width=20
q:        total=16415
auth:     total=11928, nodes=360, node_bytes=11880, path_depth=20
barsets:  total=7570, rows=168, cols=18, bit_width=20
r:        total=6544
tapes:    total=25, nonce_seed_bytes=24
```

Measured `lvcs-breakpoint` audit:

```text
pdecs:    total=20074, stream=20071, encoded_cols=446, bit_width=20
vtargets: total=18490, rows=154, cols=48, bit_width=20
q:        total=16415
auth:     total=11928, nodes=360, node_bytes=11880, path_depth=20
barsets:  total=6940, rows=154, cols=18, bit_width=20
r:        total=7784
```

Interpretation:

- The current largest BQ64-128 buckets are real measured serializer payloads,
  not projection artifacts.
- `pdecs` is dominated by the encoded residue stream. Metadata is only `3`
  bytes, so the next reduction cannot come from metadata cleanup.
- `auth` is almost entirely Merkle node bytes: `360` nodes at the active hash
  width. Index/path metadata is negligible.
- The LVCS breakpoint works because it reduces encoded opening columns and
  row-block payloads enough to outweigh larger `R` and `VTargets`.
- `theta13` is attractive for bytes but is not theorem-valid under the current
  supported grinding cap; it should not be used without a new security margin
  source.
- `ell17` is worse: its eps4 loss is too large.
- `bare-hash256` is a clean 360-byte width-model win if the PDF/security review
  accepts 256-bit hash/FS for the BQ64-128 lane. It does not touch tape width.

Corrected BQ64-128 matrix-accounting follow-up:

| Candidate | Frontier | Algebraic bits | Bytes | Required kappa | Interpretation |
| --- | --- | ---: | ---: | --- | --- |
| `bq64-128-vp-lvcs48-h256` | `valid_prefix_research` | `202.57` | `81830` | `[0,0,0,13]` | best measured lane that keeps explicit matrices and stays inside the supported grinding cap |
| `bq64-128-vp-theta13-h256` | `valid_prefix_research` | `200.97` | `78438` | `[0,7,13,13]` | best measured byte lane under the explicit round-3 valid-prefix cap; still theorem-research, not live |
| `bq64-128-vp-theta13-lvcs49-h256` | `valid_prefix_research` | `200.81` | `79080` | `[0,7,13,13]` | dense LVCS49 does not improve over LVCS48/theta13 despite staying within the cap |
| `bq64-128-vp-lvcs49-h256` | `valid_prefix_research` | `202.14` | `82500` | `[0,0,0,13]` | current-theorem-style LVCS49 is larger than LVCS48 |
| `bq64-128-vp-theta13-h256-vtargets-included-pdecs` | `valid_prefix_research` | `200.52` | `79535` | `[0,7,13,10]` | explicit VTargets/BarSets plus digest-bound Pdecs path is safe but not smaller than theta13 LVCS48 |
| `bq64-128-vp-lvcs53-h256` | `high_k_research` | `200.35` | `80408` | `[0,0,0,15]` | row-block win is real, but eps4 needs too much grinding |
| `bq64-128-vp-lvcs59-h256` | `high_k_research` | `197.95` | `79979` | `[0,0,0,17]` | smaller again, but beyond grinding cap and below target |
| `bq64-128-vp-theta13-lvcs53-h256` | `high_k_research` | `199.83` | `77100` | `[0,7,13,15]` | byte-attractive but not acceptable under the current cap |
| `bq64-128-vp-theta13-lvcs59-h256` | `high_k_research` | `197.83` | `76715` | `[0,7,13,17]` | strongest byte result in this family, but security margin is not there |

Interpretation:

- The safe LVCS optimum for the current supported-grinding model is still
  `LVCSNCols=48`.
- `LVCSNCols=53` and `59` prove that row-block savings can reduce bytes, but
  they consume eps4 slack and push round-4 grinding beyond `13`.
- The concrete next optimization target is therefore not serializer omission;
  it is recovering eps4 margin for the byte-attractive LVCS53/LVCS59 lanes
  without lowering tape below `192`, without exceeding `kappa=13`, and without
  changing primitive families.
- `VTargets` and `BarSets` remain explicit in every corrected measurement.

Corrected BQ128 measured trail status:

| Trail | Candidate | Frontier | Algebraic bits | Bytes | Required kappa | Interpretation |
| --- | --- | --- | ---: | ---: | --- | --- |
| `vp64` | `bq128-128-vp64-lvcs48-h512` | `valid_prefix_research` | `202.57` | `93358` | `[0,0,0,13]` | best corrected measured vp64 lane under the supported cap |
| `vp64` | `bq128-128-vp64-lvcs53-h512` | `high_k_research` | `200.35` | `91936` | `[0,0,0,15]` | saves bytes but fails the grinding cap |
| `vp64` | `bq128-128-vp64-lvcs59-h512` | `high_k_research` | `197.95` | `91507` | `[0,0,0,17]` | more byte savings, but no acceptable algebraic margin |
| `vp64` | `bq128-128-vp64-theta14-ell17-lvcs48-h512` | `high_k_research` | `188.79` | `90142` | `[0,0,0,27]` | ell reduction is too expensive in eps4 |
| `vp80` | `bq128-128-vp80-search` | `valid_prefix_research` projected | `230.29` | `149112` projected | `[0,0,0,0]` | corrected explicit matrices make this worse than the old optimistic projection; it needs a better search shape and larger-domain measurement support |
| `raw128` | `bq128-128-raw128-control` | `nizk_candidate` | `265.25` | `146773` | `[0,0,4,10]` | current theorem/raw-cap control |
| `raw128` | `bq128-128-raw128-lvcs64-h512` | `nizk_candidate` | `265.35` | `149175` | `[0,0,4,13]` | theorem-valid but larger; LVCS64 is rejected for raw128 |
| `raw128` | `bq128-128-raw128-theta20-ell27-lvcs59-h512` | `high_k_research` | `256.13` | `143355` | `[0,0,4,23]` | ell reduction saves bytes but breaks round-4 margin |

Corrected BQ128 interpretation:

- The earlier `60k-90k` targets depended on unsafe matrix omission or
  optimistic projection. With `VTargets` and `BarSets` explicit, the measured
  safe vp64 target is about `93k`, and raw128 remains about `147k`.
- For vp64, the same pattern as BQ64 holds: LVCS53/LVCS59 would save bytes but
  require `kappa4=15/17`.
- For raw128, larger LVCS columns increase `R` and `VTargets` enough that
  LVCS64 is worse than the raw control.
- The practical path to a large reduction is now precise: either recover
  eps4 margin for LVCS53/LVCS59, or introduce a new theorem-backed split proof
  that stops the high-degree shortness component from charging the whole
  SmallWood transcript. Plain serializer omission is not available.

What is bloating the proofs:

- Live `BQ32-96` showing is still the immediate measured baseline:
  `36764` paper bytes with `LVCSNCols=40`, `NLeaves=557056`,
  `eta=44`, `ell=9`, `theta=7`, `dQ=391`.
- Its exact showing buckets are:
  `pdecs=10062`, `vtargets=9110`, `q=6793`, `r=4391`,
  `auth=3806`, `barsets=2058`.
- For advanced BQ profiles, the measured bloat concentrates in transmitted
  DECS/opening payloads and target values, not only in projected row-block
  terms. `pdecs` is largest for the BQ32/BQ64 measured lanes; `auth` is largest
  only in the `BQ128-128` 512-bit-hash lane.
- The measured evidence refines the earlier projection: duplicate-opening and
  DECS payload accounting must be audited before changing proof parameters.
- The active projection now recomputes `dQ` from each candidate's `ell`.
  This is more conservative than reusing the `BQ32-96` baseline `dQ=391`.
- The implementation already uses compact field packing (`20`-bit payloads for
  the current field-valued objects). The remaining large wins must remove
  transmitted values, reduce relation rows/`dQ`, reduce row blocks, or change
  the proof theorem. They cannot come from replacing `uint64` storage alone.

PDF-aligned optimization implications:

1. First-order byte savings must come from compiler-backed relation search:
   each removed logical row or `dQ` unit saves across `Q` and `VTargets`.
   At the selected frontiers, a 64-unit row/degree improvement is worth about
   `1600` bytes for `BQ32-128`, `1920` bytes for `BQ64-96`, `2240` bytes for
   `BQ64-128`, and `3200` bytes for `BQ128-128`.
2. `LVCSNCols` must be swept at row-block and `dQ/LVCSNCols` breakpoints:
   one committed row block is worth about `1575` bytes for `BQ32-128`,
   `1760` bytes for `BQ64-96`, `2070` bytes for `BQ64-128`, and `3640` bytes
   for `BQ128-128`, but changing it also changes `dDECS`, `eta`, and `eps4`.
3. Merkle depth is not the largest bucket, but it is no longer negligible:
   one Merkle level costs about `375` bytes for `BQ32-128`, `464` bytes for
   `BQ64-96`, `594` bytes for `BQ64-128`, and `1792` bytes for `BQ128-128`.
4. Lowering `eta` or `theta` would help bytes, but the PDF says these are
   security terms, not free serializer knobs. One `eta` repetition costs about
   `440-510` bytes across `R/Pdecs`, while removing it loses about one
   `log2(q)` unit of the first SmallWood term.
5. The only plausible drastic reduction beyond relation/layout tuning is a
   split or heterogeneous-degree proof path. That could avoid charging the
   full high-degree shortness relation to the whole proof, but it requires new
   theorem/accounting and must not be claimed under the current SmallWood
   theorem.

Completed research work in this lane:

1. Audited the tempting relation candidates and removed them from the active
   optimization track:
   R11/L4 and mixed radix raise `dQ`; top-capping misses the current
   coefficient bound unless a new membership/lookup theorem is added; full R2
   spends too many rows; R121/L2 and split-shortness remain theorem ideas only.
2. Kept the active NIZK research lane on the current safe BQ32/R7-L5 relation
   plus q32 control aliases.
3. Replaced the hand-written shape probes with a generated relation-first
   sweep over theta/ell/NLeaves shapes and LVCS row/`dQ` breakpoints.
4. Made generated candidates derive `eta` from the target floor instead of
   using eta as a generic safety buffer.
5. Added `BQ128-128` as a 264-bit NIZK-only feasibility lane while keeping it
   blocked by the 256-bit primitive redesign.
6. Made active projection `dQ` formula-correct for each candidate `ell`.
7. Added the measured overlay that replaces projected relation/bucket fields
   with `benchmark-intgenisis-e2e` outputs for selected finalists.
8. Measured the first BQ32-128 finalist and confirmed the compiled safe
   relation has `rows=472`, `d=9`, `d'=8`, and `dQ=445`.
9. Kept frontier classes separate:
   `nizk_candidate`, `high_k_research`,
   `requires_theorem_accounting_work`, `requires_new_primitives`, and
   `rejected`.
10. Confirmed the ranking prefers NIZK-candidate, lower-byte frontiers while
   preserving the primitive-blocker status and demoting control aliases on
   exact ties.
11. Added internal transcript-driver, forced-width, compiler-backed status, and
   optimization-lever diagnostics to the NIZK sweep summaries.
12. Added flattened `lvcs_ncols`, `nleaves`, `eta`, and `ell` geometry to
   benchmark JSON reports for repeatable size audits.
13. Added measured serializer sub-bucket audits to paper transcript reports and
   benchmark JSON.
14. Added the BQ64-96 and BQ64-128 reduction lanes with ordered candidates,
   fail-closed width/serializer models, split-theorem classification, measured
   audit overlay, and focused tests.
15. Measured the BQ64-96 reduction lane; the best current-theorem reduction is
   `lvcs48-h232` at `69098` bytes with `165.76` algebraic bits and
   `kappa=[0,0,0,5]`.
16. Measured the dense BQ64-128 reduction pass; the best current-theorem
   reduction remains `lvcs-breakpoint` at `82190` bytes, and dense
   `lvcs49..52` probes either grow bytes or exceed the supported grinding cap.
17. Measured the BQ64-128 valid-prefix trail; the best theorem-research lane
   inside the supported grinding cap remains `bq64-128-vp-theta13-h256` at
   `78438` bytes, while `theta13-lvcs49-h256` is larger at `79080` bytes.
18. Corrected the serializer research lane so `VTargets` and `BarSets` remain
   explicit proof payloads. Only the existing digest-bound Pdecs omitted-column
   path is treated as safe.
19. Added and measured LVCS breakpoint probes for BQ64-128 and BQ128 trails:
   LVCS53/LVCS59 save bytes in vp64/BQ64, but require `kappa4=15/17`; raw128
   LVCS64 is theorem-valid but larger.

Next research work:

1. Recover eps4 margin for the byte-attractive LVCS53/LVCS59 lanes without
   exceeding `kappa=13`. Candidate methods are unequal error allocation,
   minimal `NLeaves` changes that still fit the current field/domain, or a
   theorem-backed valid-prefix accounting refinement. Do not lower tape width.
2. Re-search vp80 with explicit matrices. The current projected `149112` bytes
   is not competitive; it needs a better theta/ell/LVCS shape before measured
   runs are useful.
3. Continue replacing projected buckets with measured benchmark buckets in the
   research summary whenever `SPRUCE_NIZK_PROFILE_SWEEP_MEASURED=1` is enabled.
4. Attack measured serializer pressure through safe layout work:
   `pdecs`, explicit `vtargets`, explicit `barsets`, LVCS row-block
   breakpoints, exact multiproof/auth path counts, and removal of duplicated
   openings that the verifier already reconstructs. Do not rely on matrix
   omission, high-radix, or decomposition shortcuts.
5. Keep split-proof, lookup, high-radix top-cap, full R2, and R121/L2 outside
   the active preset path until a new theorem/accounting path exists.
6. Do not promote or rename any advanced profile in this lane.

### 15.10 Validation commands for next phase

Run after each ledger/search implementation chunk:

```bash
go test ./credential
go test ./PIOP
go test ./DECS
go test ./prf
go test ./cmd/issuance
go test ./cmd/showing
go test ./...
git diff --check
```

Run focused BQ32-96 evidence collection:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n1024-bq32-96 \
  -artifact-dir /tmp/spruce-bq32-96 \
  -json-out /tmp/spruce-bq32-96.json \
  -force \
  -verbose
```

Run internal profile sweep only with explicit bounds:

```bash
SPRUCE_SECURITY_PROFILE_SWEEP=1 \
SPRUCE_SECURITY_PROFILE_SWEEP_FILTER=BQ32-96 \
SPRUCE_SECURITY_PROFILE_SWEEP_MAX_E2E=1 \
go test ./cmd/issuance -run TestInternalSecurityProfileSweep -count=1 -v
```

Run the advanced NIZK-only projection sweep:

```bash
SPRUCE_NIZK_PROFILE_SWEEP=1 \
SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE=1 \
go test ./cmd/issuance -run TestInternalNIZKProfileSweep -count=1 -v
```

### 15.11 Next stopping points

Stop and reassess at the first true condition:

- A serializer-reduced BQ32-96 candidate beats `36764` showing bytes while
  preserving every numeric ledger term.
- Serializer work cannot reduce bytes without losing the current 96-bit
  full-game margin.
- Ledger audit finds the current full-game accounting is invalid or missing a
  required theorem.
- Any proposed change requires modifying maintained gates or public CLI
  behavior.
- Any proposed change requires a new primitive family.

### 15.12 BQ64 valid-prefix theorem/accounting pass

Implemented after the measured BQ64 reduction pass:

1. Added an explicit valid-prefix algebraic accounting decision object. It
   separates raw Fiat-Shamir caps from optional valid-prefix algebraic caps and
   records that collision, programming, and challenge-bias accounting remain on
   raw caps.
2. Kept current-theorem accounting as the default. Valid-prefix caps do not
   change algebraic caps unless an internal theorem-candidate mode is explicit.
3. Made theorem-candidate valid-prefix accounting fail closed with
   `valid-prefix algebraic accounting requires a new theorem`.
4. Added the accounting report to internal NIZK profile summaries:
   `theorem_mode`, raw FS caps, effective algebraic caps, valid-prefix
   discounts, raw collision cap, programming caps, challenge-bias caps, and
   raw-cap invariants.
5. Added relation-safety certificates to internal NIZK reports. A candidate is
   current-theorem-safe only if it is compiler-backed, does not need relation
   theorem work, does not need split-proof composition, and does not increase
   `dQ` over the current safe relation at the same `ell`.
6. Locked the key BQ64 decisions in tests:
   - `BQ64-128 theta13` remains high-k/under-target under raw caps.
   - `bq64-128-vp-theta13-h256` is eligible only with the explicit round-3
     valid-prefix cap and remains `valid_prefix_research`.
   - `BQ64-96 theta11` remains rejected under raw current-theorem accounting.
   - Split/relation-theorem candidates remain theorem-blocked.

Current path forward:

1. The first theorem target is still `BQ64-128 theta13+h256`. To move it out of
   research, prove a SmallWood-compatible bound that charges algebraic
   extraction terms to valid round-prefix queries while keeping raw caps for
   collision, programming conflict, challenge bias, and ZK programming.
2. The relation/compiler path must be certificate-backed. Search only for row
   or `dQ` reductions that preserve the current witness language and do not add
   lookup, split-proof, or heterogeneous-degree theorem burden.
3. `BQ64-96 theta11` is a lower-priority theorem target because its deficit is
   materially larger than the `BQ64-128 theta13` gap.
