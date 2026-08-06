# SPRUCE Security And Provenance

This note defines the security boundary of the mixed-epoch SPRUCE artifact.
Seven maintained presets retain their historical hard-v2 path. Exactly two
targets use the strict-v3 proof path: `poc-n1024-bq128-r128-v3` (BQ128-128) and
`system-n1024-wf128-crom-v2` (WF128; the `-v2` suffix is a stable selector, not
the target manifest version). Every maintained preset has
`claim_scope=proof_only`. A benchmark can show that an implemented issuance or
showing statement executes, verifies, binds its manifest, and passes the
selected per-proof accounting gates. It does not by itself establish security
of a deployed credential service.

The mathematical construction and reductions live in
`../Better-Lattice-based-Blind-Signatures`. The Go repository supplies
executable evidence for a concrete encoding. Neither repository silently
upgrades artifacts or evidence from another protocol epoch.

For the strict-v3 targets, the deliberately narrow conclusion is that, after
the implemented gates pass, there is no known deviation in the applicable
**per-proof SmallWood flow** from the paper. This is not certainty about the
full credential construction. It is not a claim of full-game or multi-user
security, QROM security, unconditional security, accepted estimates for every
surrounding lattice primitive, or externally reviewed theorems for the local
input-trace and public-linear hat-fusion reformulations. The implementation,
measurements, local equivalence lemmas, and residual assumptions are recorded in
[`CREDENTIAL_SIZE_OPTIMIZATION.md`](CREDENTIAL_SIZE_OPTIMIZATION.md).

## Canonical Claim Surface

These are the only maintained protocol identities:

| Canonical ID | Security metadata | Lifecycle | Proof epoch | Claim scope |
| --- | --- | --- | --- | --- |
| `poc-n512-sc96-v2` | `SC-96` | `poc` | historical v2 | `proof_only` |
| `artifact-n1024-sc125-v2` | `SC-125` | `artifact` | historical v2 | `proof_only` |
| `artifact-n1024-bq10-r96-v2` | `BQ10-96` | `artifact` | historical v2 | `proof_only` |
| `artifact-n1024-bq16-r96-v2` | `BQ16-96` | `artifact` | historical v2 | `proof_only` |
| `pilot-n1024-bq32-r96-v2` | `BQ32-96` | `candidate` | historical v2 | `proof_only` |
| `poc-n1024-bq64-r128-v2` | `BQ64-128` | `poc` | historical v2 | `proof_only` |
| `poc-n1024-bq96-r128-v2` | `BQ96-128` | `poc` | historical v2 | `proof_only` |
| `poc-n1024-bq128-r128-v3` | `BQ128-128` | `poc` | strict v3 | `proof_only` |
| `system-n1024-wf128-crom-v2` | `WF-128` | `candidate` | strict v3 | `proof_only` |

The security metadata selects a proof-accounting threat model: ROM mode,
oracle-query scope, honest-proof volume, tag volume, collision widths,
grinding, and theorem target. Lifecycle describes why a configuration is kept.
Neither changes the proof-only boundary.

The reporting invariant is:

> A report records what the proof actually executed. A profile records the
> requirements against which those executed values are checked. Desired
> metadata is never substituted for a missing or different runtime value.

Consequently, a profile name alone is not evidence. Review the canonical
manifest digest, executed-parameter audit, transcript tuple, PRF digest,
rate-limit policy, and theorem/accounting fields in the generated report.

## Mixed-Epoch Binding And Fail-Closed Parsing

Security-relevant objects bind the canonical preset, manifest digest, public
parameters, primitive profile, PRF parameters, transcript, and rate policy.
The epoch identities are:

| Identity | Seven historical presets | BQ128/WF128 strict targets |
| --- | --- | --- |
| preset manifest | `2` | `3` |
| proof schema | `2` | `3` |
| canonical proof codec | schema-2/v2 proof object | codec `6`, magic `SPRUCEP6`, grouped radix-`q`, constant-only `Q` kernel, exact unpadded tail-derived frontier |
| transcript protocol | `smallfield_2025_1085_salted_tapes_v2` | `smallfield_2025_1085_salted_tapes_v3` |
| transcript version | `smallwood_2025_1085_salted_decs_v2` | `smallwood_2025_1085_salted_decs_v3` |
| relation/layout | historical v2 values | `3 / 3` |
| credential state | JSON `7` | canonical binary `8` |
| presentation | JSON `2` | canonical binary `3` |
| issuance artifact | JSON `3` | canonical-proof format `4` |
| holder usage | `2` | `3` |
| claim scope | `proof_only` | `proof_only` |
| NTRU containers | v2 | unchanged v2 containers, target-manifest bound |

Artifact decoders require the exact storage schema selected by the validated
manifest, reject unknown fields and non-canonical values, and check content
digests. A mismatched epoch, manifest, role, salt, public parameter, verifier
key, PRF file, or NTRU object is rejected. Target legacy state, presentation,
issuance, and holder-usage artifacts are rejected: there is no conversion path,
v2/debug fallback, or mixed-epoch verification.

For target v3, strict decoders do not probe legacy JSON, and the proof verifier
has no fallback to debug coefficient payloads, materialized mask/Q data, or a
schema-2 verifier. This strict boundary prevents an apparently familiar
filename or selector from changing the statement that a verifier accepts.

## Independent Salted-Tape Transcript

DECS/LVCS v2 uses a proof-global fresh salt and independently sampled tapes,
one tape for every logical committed leaf. There is no accepted compact seed
from which all leaf randomness is regenerated.

Each DECS commitment is given an explicit context containing:

- commitment version `2`;
- a role distinguishing main rows, Q payload, companion rows, replay rows, or
  signature-shortness rows; and
- the proof-global salt.

The v2 leaf hash frames and binds that context, leaf index, evaluation point,
field modulus, canonical P/M residues, and the leaf's independent tape.
Internal nodes and padding have separate domains and bind their structural
indices. Fiat-Shamir also receives the same salt. These bindings prevent a
root or opening from being reinterpreted under a different proof role or salt.

An opening carries exactly one tape for each distinct opened leaf.
Verification rejects duplicate indices, non-canonical field elements,
incorrect tape widths or counts, malformed paths, role/salt mismatches, and
earlier-format opening fields. Merged openings deduplicate an identical leaf
and reject conflicting tape, value, or authentication data.

Security consequences and limits:

- Compromise or disclosure of one opened tape does not determine unopened
  tapes by construction.
- Fresh salt domain-separates proofs and is included in collision and
  Fiat-Shamir accounting.
- Salt freshness does not repair weak hash, tape, PRF, or algebraic
  parameters. The manifest and generated report must be audited together.
- Independence depends on successful entropy reads. Entropy errors abort;
  there is no deterministic fallback.
- Proof size and time changed with this format. Earlier measurements cannot be
  used as current-epoch evidence.

Strict v3 retains the same independently sampled tape policy but replaces
per-leaf authentication paths with one canonical positional frontier
multiproof. Positions and the exact node count are derived from the
Fiat--Shamir tail. No padding is transmitted. Duplicate or missing siblings,
retired codec-5 padding, truncation, trailing bytes, and alternate encodings
reject.

The target transcript absorbs the injectively framed complete public statement
directly into SHAKE-256 and expands each challenge from a 64-byte chained round
digest. That statement includes the full preset manifest, public matrices,
context/tag inputs, fixed field-profile bytes, the bound PRF profile identity,
digest, canonical constants, relation parameters, and the verifier-reconstructed
complete `RowLayout`. Layout encoding is injective over field names, zero values,
nil/present markers, slice lengths, row locations, and the hat-source mode. A
stale materialized-hat layout is therefore a different statement and rejects.
No SHA-256 digest or `LabelsDigest` is the sole binding for a v3 statement.
Every target challenge and randomizer uses exact domain-separated SHAKE-256
rejection sampling for its stated set; modulo reduction is not an accepted
v3 sampling rule.

More precisely, the target path has exact samplers for `Fq`, extension-field
`K` (limb by limb), bounded integers, distinct tail indices, and `K \ Omega`.
Witness and mask randomizers use the same exact-uniform rule. Prover and
verifier deterministically replay each domain-separated SHAKE stream from the
same transcript state. The seven historical v2 call sites remain isolated;
their historical sampler behavior is not reinterpreted as v3 evidence.

Each v3 Fiat--Shamir round injectively frames the round number, previous full
digest, material count, every message, and the unchanged `uint64` grinding
counter. Counters are carried canonically as minimal unsigned LEB128 and
zero-extended before transcript use. The first round binds the complete
canonical public statement; later rounds bind the complete executed `R`, full
reconstructed `QPayload`, dense reconstructed `VTargets`, and `BarSets`
material before deriving the distinct tail. The physical wire omits only values
uniquely fixed by trusted geometry and enforced identities, as specified below;
it does not shorten `R` or remove an independently variable challenge message.

### Strict-v3 field, witness, mask, and Q invariants

The target manifests select fixed public extension-field profiles for
`q=1017857`: `spruce-smallwood-kfield-q1017857-theta13-v3` for BQ128 and
`spruce-smallwood-kfield-q1017857-theta7-v3` for WF128. Each profile fixes a
vetted monic irreducible `Chi` and `omegaExtra = X mod Chi`; construction
validates irreducibility, separation from `Omega`, and interpolation inverses.
The profile identifier, digest, and canonical bytes are manifest- and
transcript-bound. Neither `Chi` nor `omegaExtra` is transmitted or accepted
from the proof.

Every committed logical witness polynomial receives fresh independent
`rho_i in K`. Its interpolant preserves all values on `Omega` and satisfies
`P_i(omegaExtra)=rho_i`; the split base-field coordinates occupy the existing
tail rows. Thus a repeated logical witness does not reuse its extra-support
randomizer.

For mask degree `dQ` and LVCS width `L`, target v3 implements the paper's
Equation (2) shape exactly:

```text
mu = ceil(dQ / L)
mask rows = (mu + 1) * theta.
```

The mask includes the shifted final column and independent Equation (2)
randomizers. Semantic multiplication queries reconstruct and authenticate
`M(e)` through `VTargets`; historical identity/rank-padding queries are not a
v3 substitute. The verifier derives the DECS row-degree bound from trusted
preset data as `LVCSNCols + ell - 1` (60 for BQ128, 50 for WF128 issuance,
and 49 for the adopted WF128 showing width). A proof cannot transmit or raise
`RowDegreeBound`.

Target v3 also retires the formal `BuildQK` verifier path. One semantic
relation IR supplies both prover construction and verifier evaluation of the
paper's Equation (4). The prover evaluates it at `dQ+1` fixed distinct
base-field points and interpolates each extension-field limb; the verifier
evaluates the same relation at its challenge. `Q` is accepted only from
`QPayload`, and `M(e)` only through authenticated mask queries. There is no v3
wire field or verification fallback for `MaskCoeffDebug`, `FparCoeffDebug`,
`FaggCoeffDebug`, `QCoeffDebug`, `MKData`, or `QKData`.

For each limb `Q(X)=sum_{i=0}^{dQ} q_i X^i`, the enforced
`sum_{omega in Omega} Q(omega)=0` identity uniquely fixes

```text
q_0 = -|Omega|^(-1) * sum_{i=1}^{dQ} q_i *
                         sum_{omega in Omega} omega^i.
```

The canonical encoder checks this equality, omits `q_0`, and the decoder
restores it before deriving the third Fiat--Shamir round. This is exact
deterministic reconstruction—one base-field constant per limb, collectively
one `K` coefficient—not a second challenge or a relaxed Q check.

`VTargets` has a similarly trusted ragged wire shape. Final issuance witness
layers have 36 meaningful columns for BQ128 and 39 for WF128; final showing
layers have 14 and 13. WF128 mask queries have width 40 under phase widths
42/41, while BQ128's mask-query width remains 43. Every omitted suffix is
required to be zero. Dimensions are
derived from the manifest-bound compiler, and dense rows are restored before
transcript and Equation (2) checks. The shape is fixed before challenges, so
this does not introduce challenge-dependent transcript lengths.

For paper accounting, the implementation sends full `R` and omits standalone
`M(e)`. The paper's alternative of shortening `R` by `ell` columns is sound only
when `M(e)` is retained; both choices account for
`eta*(dDECS+1)` base-field elements. The earlier accounting that combined
shortened `R` with omitted `M` was an undercount, not a security-preserving
optimization. Current paper metrics use full `R`, omitted `M`, and a full `Q`
degree range but omit the same pre-challenge-determined constant: the safe
paper `Q` bucket is exactly `rho*dQ*theta` base-field elements. The physical
canonical wire applies that omission too, then uses the separately audited
grouped radix-`q` byte encoding.

## Exact Public-Context/Hidden-Slot Policy

The rate-limit statement has 11 public context lanes and one hidden slot lane.
The holder and verifier start from opaque service-controlled bytes. Separate
SHAKE256 domains derive the context digest and the lanes, while binding:

- the raw service context;
- field modulus and quota size;
- preset-manifest digest;
- public-parameter digest; and
- verifier-key digest.

The 11 lanes use unbiased rejection sampling. The verifier supplies the raw
context independently and rederives the expected public statement; the
presentation cannot choose that expectation. Raw bytes are not carried in the
presentation.

The holder reserves a hidden slot

```text
s in {0,...,15}
```

and proves

```text
tag = PRF(k, context || s).
```

Four Boolean witness bits reconstruct `s`, giving an exact quota `L=16`.
Neither `s` nor its bits appear in the public presentation.

### Holder invariant

The holder usage state is bound to the public parameters, preset manifest, and
credential fingerprint. Under an exclusive file lock, it reads the next slot
for the context digest, rejects exhaustion, increments the counter, and
atomically persists the new state before proving. This is a monotonic burn:
process failure or proof failure after reservation consumes the slot.

Historical presets use holder-usage format 2. The strict targets use format 3,
with a credential fingerprint derived from canonical state-v8 bytes and
configured-width public/key bindings. A format-2 ledger at a target path is
rejected rather than migrated.

The burn-before-prove order prevents local crashes from accidentally reusing a
slot. It also means state backup/restore, cloning, rollback, loss, or concurrent
use outside the shared lock boundary is an operational security concern. A
holder must protect this state as carefully as the credential state.

### Verifier invariant

After strict artifact validation, independent context derivation, and
cryptographic proof verification, stateful verification locks its replay file.
The state is bound to the public-parameter and verifier-key digests and stores
accepted tag digests under a context namespace. An existing `(context, tag)`
is rejected; otherwise the new acceptance is atomically persisted.

Historical replay state remains format 2. The strict targets use format 3 and
configured-width bindings; cross-format state is rejected.

The rate policy is only as global as the verifier state. Forked, rolled-back,
or per-node files create separate acceptance histories. A service that expects
one quota domain must provide a linearizable shared state or an equivalent
transactional backend around the same check-and-mark operation.

`-proof-only` verifies the algebraic statement but deliberately skips the
check-and-mark transition. It cannot be combined with `-verifier-state` and
must never be interpreted as operational rate-limit acceptance.

### What `L=16` does and does not say

The proof constrains every accepted presentation to one of 16 slot values for
the credential key and exact derived context. Stateful duplicate-tag rejection
then permits at most one acceptance per slot, subject to PRF correctness and
one consistent verifier state.

This does not protect against service-state forks, context-definition mistakes,
credential theft, verifier-key substitution outside the bound setup, or a
failure of the PRF or proof assumptions. Context construction must encode the
service's intended policy epoch and scope unambiguously before its bytes reach
the SPRUCE CLI.

## Bounded BB-Tran Relation

The current public BB-tran matrix samples `B0` independently and uniformly.
The issuer samples `mu_sig`, each `x0` row, and `x1` coefficient-wise from
`{-1,0,1}` and resamples `x1` until the denominator is invertible. The signed
target is

```text
Z = (B3 - x1)^(-1)
T = c + B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z.
```

Historical v2 retains each bounded source explicitly. The N=512 preset keeps
its bounded-source `project_u_digits_and_y_view_v3` projection, and the six
historical N=1024 presets keep
`project_u_digits_y_bounded_sources_v6`; their historical rows, bridges, and
measurements are unchanged. Strict v3 retains the same extractable sources
through the injective carrier `Enc(a,b)=(a+1)+3*(b+1)` in `{0,...,8}`. A
degree-nine membership equation and fixed degree-at-most-eight lane decoders
feed every coefficient, CRT, NTT, and signature semantic check; no
unconstrained decoded advice or duplicate raw row is accepted. No supported
relation collapses the BB-tran sources into an unconstrained full-image
residual.

Packing converts the target presets' 96 logical ternary-source rows into 48
carrier rows. It changes representation, not the source domains or the
source-to-coefficient, CRT, NTT, and signature equations.

The current strict-v3 relation additionally removes 32 separately committed
`mu_sig` hats and 32 `x0` hats. Those hats are public-linear expressions, not
independent witness values required by the paper. For decoded carrier rows
`C_r`, fixed transform weights `H_t,alpha[t,r]`, and target `t`, the unique
eliminated value is

```text
hat(a)[t] = sum_{x in Omega} H_t(x) *
            sum_r alpha[t,r] * Decode(C_r(x)).
```

The old projected-signature aggregate consumed it only as the public-linear
term `B[t]*hat(a)[t]`. The fused relation substitutes the right-hand side. An
old satisfying witness therefore maps to a fused one by deletion, while any
fused satisfying bounded sources uniquely reconstruct the deleted hats and
extend back to the old relation. This two-way map preserves the statement
language and extractor outputs; it is not an unconstrained virtual-hat advice
mechanism.

The 32 `x1` hats and 32 `Z` hats remain committed and source-bound because
`(B3[t]-hat(x1)[t])*hat(Z)[t]=1` is nonlinear in two witness images. Fusing
either operand would require new degree and soundness reasoning. The current
relation deliberately keeps that inverse chain unchanged.

The eliminated expressions are not published. Their commitments are removed,
while every surviving carrier and witness row retains its independent
`omegaExtra` randomizer and every DECS opening retains independent tapes. No
new deterministic source evaluation appears on the wire. The proof compiler
recomputes layers, masks, queries, and all four SmallWood terms for the reduced
row set, so the zero-knowledge and soundness gates apply to the executed
geometry rather than being copied from the materialized-hat layout.

These changes give the extractor the individual bounded witnesses that the
stated relation requires and make `hash_input_bound=1` a public, transcript-
bound fact. It does not on its own prove the IntGenISIS assumption or the
security of the NTRU sampler. The inverse witness `Z` remains algebraic rather
than short, and the manuscript reduction must match that exact relation. The
public-linear hat equivalence is a local implementation lemma that still
requires external review.

## Commitment, NTRU, And PRF Boundaries

The Ajtai commitment relation is

```text
c = C_M*M + A_s*s_com + e.
```

The implementation proves the configured coefficient domains and binding
between the committed seed and showing key. Lattice-estimator results are
model-based provenance for the selected MLWE/MSIS instances, not reductions
performed by the Go verifier.

The NTRU/vSIS layer proves a short `u` satisfying `A*u=T`. Parameters, keys,
and signature bundles have content-derived v2 identities. Public/private key
loading validates parameter digests, public-key identity, canonical centered
coefficients, and cross-object bindings. Key generation and preimage sampling
use `crypto/rand` or an explicitly injected `io.Reader`; entropy failure is
returned. Numerical sampler correctness, side channels, trapdoor leakage, and
the exact lattice-signature reduction still require analysis beyond a
successful proof run.

The Poseidon2 relation proves the full configured trace from the packed secret
seed and `(context, hidden_slot)` input to every published tag element. The
canonical manifest binds the exact PRF profile, parameter-file digest, and tag
width. Strict v3 additionally absorbs the full canonical parameter bytes into
the public statement and validates the direct API's loaded profile before
either side uses it, so the SHA-256 file digest is not a Fiat--Shamir
bottleneck. The filesystem path is operational: relocation is accepted only
when the decoded canonical constants are byte-for-byte identical; altered or
unsupported profiles and widths are rejected. PRF parameter generation and
cryptanalysis remain external provenance, not something the Go runtime
re-establishes.

The target relation commits all 179 Poseidon S-box inputs and derives their
cubes inside the relation. Selector-weighted recurrence terms are `L*P^3`, not
`(L*P)^3`; the latter would change the off-support polynomial. The relation
reuses the already authenticated seed, context, hidden-slot, and slot-bit
sources and derives the tag from the terminal MDS/feed-forward equations.
Consequently BQ retains 189 PRF scalars and WF 192, each in six 32-column rows.
The six historical PRF bridge matrices and their metadata have no target-v3
representation.

Induction over the fixed round schedule gives the local
input-trace/output-trace equivalence lemma: equal initial state and sources
produce equal S-box outputs, linear-layer states, and final feed-forward tag at
each step; conversely the honest output trace uniquely supplies the committed
inputs. This local lemma is tested and keeps compiler showing degrees BQ
`(d,d')=(9,8)` and WF `(11,8)`; it is still an implementation-side lemma
requiring review, not a claim that the manuscript already states this encoding.

Together, the input trace and carrier packing first reduced the target showing
relations by 49 logical rows: BQ from 600 to 551 and WF from 536 to 487. The
public-linear hat lemma removes another 64 rows, giving BQ 487 rows and WF 423.
BQ keeps `LVCSNCols=43`, 12 witness layers, 540 replay rows, 156 mask rows, 696
physical rows, 169 queries, and 527 opening rows. WF keeps its adopted
`LVCSNCols=41`, with 11 witness layers, 429 replay rows, 91 mask rows, 520
physical rows, 84 queries, and 436 opening rows. Compiler showing degrees are
BQ `(d,d',dQ)=(11,8,570)` and WF `(11,8,471)`.

Issuance now uses 49 source rows in both targets. Paired base-9 carriers plus
degree-9 membership and degree-at-most-8 decoders uniquely recover ordinary
`M`, `S`, and `E`; two raw rows retain the reserved/seed tail. The relation
reconstructs and checks all 1,024 commitment coordinates. Its direct
challenge-weighted aggregate evaluator is a distributive reassociation of all
1,024 formal residuals in canonical challenge order, not a sampled subset.
Independent complete-`Q` tests cover both BQ `theta=13,dQ=472` and WF
`theta=7,dQ=391`.

The public `m_eq` policy boundary is canonical signed ternary. Attribute slots
outside `{-1,0,1}`, nonzero reserved/key slots, unknown/trailing JSON, and
modular aliases such as `q-1` or `q+1` reject before relation compilation.

## Strict-v3 Canonical Codec Boundary

The only accepted target proof grammar is codec 6 with `SPRUCEP6` magic and
the manifest-bound `ker-sum-omega-constant-v1` profile; codecs 3, 4, and 5
reject.
The target proof wire carries only independently necessary material: magic,
version, proof kind, configured-width root, exact salt, four canonical
counters, packed full `R`, packed nonconstant `QPayload` coefficients,
trusted-ragged `VTargets`, packed `BarSets`, and one authoritative DECS opening.
Dimensions, layouts, field profiles, challenges, query indices, coefficient
plans, and omission metadata are reconstructed from the trusted
`CanonicalProofContext`. Full Q and dense V matrices are restored before
Fiat--Shamir replay and semantic verification.

Every bounded group of at most 1,024 `Fq` elements has one fixed-width
radix-`q` encoding. Group values outside `[0,q^r)`, nonzero spare bits,
alternate encodings, nonminimal counters, retired padding, excessive
allocation claims, truncation, and trailing data
reject. The proof kind and all public context are supplied independently and
bound into Fiat--Shamir; a pre-sign proof cannot be replayed as a showing proof.
Independent DECS tapes are retained. The positional Merkle multiproof omits
tail-derived positions and transmits exactly the derived frontier, without a
count or zero-only worst-case suffix.
The public statement binds the complete injectively framed reconstructed
`RowLayout`, including fusion mode and absent-row markers; the wire cannot
select a cheaper relation layout.

State format 8 is a canonical secret-only binary encoding. It packs ternary
message and witness values five base-3 digits per byte, packs the 48 base-9
seed symbols in canonical five-symbol groups, omits the reserved zero tail,
and packs bound-shifted signature coefficients four per fixed-width group.
Public matrices, `MAttr`, packed key `K`, preset/layout metadata, paths, NTRU
public material, and signature bounds are reconstructed from the supplied
public-parameter/verifier-key context. Saves are atomic with mode `0600`.

Presentation format 3 contains only its magic/version, packed tag, and
canonical showing proof. The preset, public parameters, verifier key, and raw
service context come from the verifier. Any JSON companion is diagnostic only:
its binary digest, length, and report are not a lossless verifying format.
Target state-v8, proof-schema-3, presentation-v3, issuance-format-4, and
holder-usage-v3 readers never probe a legacy format.

## Proof Accounting

Each manifest records the proof-system threat model and accepted accounting
mode. Benchmark output separates, where available:

- executed SmallWood geometry and algebraic theorem terms;
- random-oracle query caps and their scope;
- collision, salt, tape, and Fiat-Shamir widths;
- honest issuance/showing volume and tag volume;
- grinding and phase composition;
- primitive estimates or assumptions; and
- missing, informational, or theory-pending evidence.

Do not combine these by taking an informal minimum from log output. Use the
structured report and the accounting code, and preserve whether a term is
measured, theorem-derived, estimated, conservatively bounded, or missing.
Bounded-query caps for the NIZK do not automatically become PRF, multi-user,
or tag-volume bounds.

The target search froze BQ `kappa=[5,6,12,13]` and WF
`kappa=[1,0,2,13]`, as well as query caps, salt/hash/tape/tag widths, nonce and
seed sizes, `NCols=32`, `rho=1`, `ellPrime=1`, and all primitive parameters.
No accepted candidate increased grinding, `NLeaves`, corrected projected work,
or `NDECS*eta`. BQ had no eligible size-improving retune and keeps `L=43`.
WF showing alone adopts `L=41`; its issuance width remains 42. The rejected
historical broad-retune tuples changed kappa, increased `NLeaves`, and failed
the frozen-kappa security gates.

For each target phase, the report separately recomputes the four SmallWood
soundness terms, collision accounting, primitive-profile and zero-knowledge
gates, compiler degrees, corrected mask geometry, query/opening counts, and
canonical/paper bytes. The measured per-proof theorem totals are 131.251 bits
for BQ issuance and showing, 128.060 bits for WF issuance, and 128.421 bits for
WF showing. These are per-proof results only; they are not a composed
credential-game ledger.

All nine manifests remain proof-only even when their executed-parameter audit
passes. Security against malicious implementations, multi-user and
multi-context composition, side channels, state rollback, key compromise, and
service-level failures is outside the generated proof report.

## Evidence Status

The seven non-target presets retain their three-run historical-v2 reports and
deterministic v2 lock. Their rows, formats, byte counts, and timings were not
regenerated or reinterpreted by the target work. A historical-v2 report cannot
satisfy either target manifest.

The preceding strict-v3 records remain historical. The current checked record
is [`../evidence/focused-v3-final-size-optimization.json`](../evidence/focused-v3-final-size-optimization.json),
and its raw runs are under
`../artifacts/smallwood-v3/final-size-optimization-v2/{bq128,wf128}/run-{1,2,3}`.
All six codec-6 runs verified issuance and showing, completed canonical codec
round trips, and recorded replay rejection. Every individual proving-time and
peak-memory measurement stayed below twice the preceding accepted median.
Each run's evidence fixes the complete 15-artifact production bundle in
canonical role/path order and verifies every regular file's byte length and
SHA-256 digest, as well as the report/resource and nested issuance/showing
proof digests. A substituted matrix, key, response, NTRU object, state, or
presentation therefore invalidates the local evidence gate.
The reports also bind the Go build-input snapshot (including embedded PRF
parameters), digest
`07035083fc3a35ae3226a2598b1f879bc12b36e06b1ada863b92d4f228df23ff`.
This closes the ambiguity left by recording only a base HEAD plus a dirty bit.

The target reports keep four unlike metrics separate:

| Target | Canonical state | Canonical issuance proof | Canonical showing proof | Canonical presentation | Paper issuance/showing |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128 | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B |
| WF128 | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B |

Exact frontier sizes and minimal-LEB128 counter widths vary with the
Fiat–Shamir tail. The immediately preceding codec-5 medians remain
52,385 / 86,801 / 86,834 B for BQ and
22,050 / 38,068 / 38,109 B for WF; their immutable paper values remain
57,271 / 91,756 B and 23,790 / 39,837 B.

One provisional codec-4 implementation tried to recover another `Q`
coefficient from the challenged evaluation equation. That would let the
challenged equality be repaired after the evaluation point was known. Those
runs are withdrawn; codec 6 omits only the pre-challenge support-sum constant,
and P3/P4/P5 byte grammars reject.

The transcript-preserving time pass retains exact Fiat--Shamir prefix cloning,
one immutable relation-bound prepared domain with authenticated row-head
provenance and lazy NTT materialization, a shared formal-degree validator,
semantic-Q `Into` arithmetic with worker-local arenas, cached replay plans and
structural semantic metadata, and fused implicit-preorder exact-`N` Merkle
storage. Production DECS uses the established combined evaluator. The portable
row-major candidate is provisional, available only through an explicit
internal test constructor, and is not adopted without the fixed-entropy paired
gate. None of the retained work changes a relation, theorem input, challenge-
selection rule, committed value, transcript frame, or canonical format. The
slower tiled DECS kernels and per-DECS-frame SHAKE-prefix cloning are not
production paths. Fixed DECS frame templates are also excluded: although their
exact frame/hash equivalence passed, pure framing was 59--107% slower, whole-
hash templating had no stable cross-target 3% win, and prefix cloning added
448 B plus one allocation per hash. The diagnostic record is
`../tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/RESULTS.md`.

Three fresh candidate-build runs per target record these median resources:

| Target | Issuance prove | Showing prove | Issuance/showing verify | Max RSS |
| --- | ---: | ---: | ---: | ---: |
| BQ128 | 1,349.588 ms | 2,902.833 ms | 499.882 / 273.419 ms | 369,393,664 B |
| WF128 | 521.758 ms | 1,256.464 ms | 241.098 / 148.445 ms | 194,871,296 B |

The proving MADs are 36.483/97.182 ms for BQ and 4.210/8.127 ms for WF.
Relative to the immutable accepted predecessor, the four nominal unpaired
timing differences are 20.93%/21.39% for BQ and 28.44%/11.59% for WF; peak-RSS
medians differ by 38.62%/40.29%. This does not pass the formal performance/
adoption gate. Independent entropy changes accepted Fiat--Shamir counters, and
counter variability can materially affect top-level proving time. Runtime
direction remains unestablished until seven fixed-entropy alternating pairs
are measured. These raw runs are under
`../artifacts/smallwood-v3/time-optimization-v1/{bq128,wf128}/run-{1,2,3}`.
They bind source-input digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.

This measurement does not relax the fixed-entropy equality gate. Across fresh
entropy, canonical proof and presentation lengths vary because both the exact
Merkle-frontier node count and minimal-LEB128 Fiat--Shamir counter widths are
challenge-dependent. With identical entropy, domains, rows, leaf frames and
hashes, roots/openings, all four challenges and counters, `R`, `QPayload`, and
complete proof/presentation bytes must remain equal.

The focused machine-readable time-optimization successor has two blockers.
First, its seven alternating fixed-entropy end-to-end/allocation pairs have not
been generated, so formal runtime direction is unestablished. Second, the
all-nine functional gate currently fails its
manifest-bound engineering high-watermark for BQ showing: issuance/showing
`algebraic_total_bits` are 131.548362/131.511683, versus the 131.540568-bit
engineering target. Showing is short by 0.028885 bits.

This is not a failure of the actual required 128-bit per-phase security audit.
BQ showing remains 3.511683 bits above that requirement, while its proof,
parameter audit, and replay checks pass. Nevertheless, the complete
`gate-functional-presets` result is not green, and neither the target nor its
manifest, geometry, or accounting may be changed under this optimization to
mask the mismatch. Until both blockers are resolved, the final-size record
above remains the latest promoted machine-readable evidence. Neither the
nominal timing comparison nor a future promotion broadens
`claim_scope=proof_only`; full-game credential accounting and QROM security
remain out of scope.

The historical `proof_size_bytes` quantity is a modeled verifier-message
estimate, not serialized output. It is not compared as though it were an
actual canonical proof or presentation wire. Full component tables, runtime
and memory values, rejected candidates, paper-to-code mappings, and exact
claim qualifications are in
[`CREDENTIAL_SIZE_OPTIMIZATION.md`](CREDENTIAL_SIZE_OPTIMIZATION.md),
[`PROOF_TIME_OPTIMIZATION.md`](PROOF_TIME_OPTIMIZATION.md), and
[`PROOF_TIME_PROFILE.md`](PROOF_TIME_PROFILE.md); the summary tables are in
[`../results.md`](../results.md).

Reproduce the current evidence with the exact six-run BQ128/WF128 loop in
[`../ARTIFACT.md`](../ARTIFACT.md), then build and check its projection with:

```bash
go run ./cmd/spruce-evidence focused-v3-nonresearch \
  --spruce-dir . \
  --paper-dir ../Better-Lattice-based-Blind-Signatures \
  --measured-on 2026-08-04
go test ./evidence -run '^TestFocusedV3NonResearch' -count=1
```

The historical `baseline` command applies only to the seven unaffected v2
presets. Preserve every report and manifest binding; do not copy a result
between manifests or epochs.

## Provenance Tools

The Go/Docker validation path does not rerun Sage or the external lattice
estimator. Relevant sources are:

```text
tools/intgenisis_commitment_estimator.py
tools/intgenisis_lattice_security_estimator.py
prf/generate_params.sage
prf/sweep_rounds.sage
../Better-Lattice-based-Blind-Signatures/sections/03_blind_signature.tex
../Better-Lattice-based-Blind-Signatures/sections/04_arc_construction.tex
../Better-Lattice-based-Blind-Signatures/sections/05_smallwood_model.tex
../Better-Lattice-based-Blind-Signatures/sections/06_parameters.tex
../Better-Lattice-based-Blind-Signatures/appendix/B_gaussian_sampler.tex
../Better-Lattice-based-Blind-Signatures/appendix/C_smallwood_details.tex
../Better-Lattice-based-Blind-Signatures/appendix/D_extended_parameters.tex
../Better-Lattice-based-Blind-Signatures/appendix/E_prf_and_misc.tex
```

To reproduce the lattice-model outputs, use a checkout outside this repository
at the commit pinned by the manuscript/artifact record, then run:

```bash
export SPRUCE_LATTICE_ESTIMATOR="$PWD/external/lattice-estimator"
python3 tools/intgenisis_commitment_estimator.py --pretty
python3 tools/intgenisis_lattice_security_estimator.py --pretty
```

PRF parameter regeneration uses the Sage scripts above. Generated JSON must be
reviewed and its digest deliberately updated in the preset manifest; replacing
a file without changing the bound identity is rejected.

## Remaining Claim Boundary

Passing every target gate supports only this narrow conclusion: no known
deviation remains in the implemented BQ128/WF128 per-proof SmallWood flow. It
does not establish adaptive multi-proof extraction, blindness/unlinkability of
the complete credential protocol, a global adversarial-query theorem,
MSIS/IntGenISIS or lattice-signature reduction losses, QROM security, service
state consistency, implementation side-channel resistance, or unconditional
security. The presets are custom theorem instantiations; the input-trace and
public-linear hat-fusion equivalence lemmas remain local assumptions requiring
external review.

## Reviewer Checklist

For a historical-v2 result, verify:

1. The command uses one of the seven historical canonical IDs and the report
   repeats that ID with preset schema `2`.
2. Public parameters, verifier key, credential state, PRF parameters, NTRU
   material, and presentation all pass their digest and schema checks.
3. The report uses `smallfield_2025_1085_salted_tapes_v2` with proof and DECS
   schema `2`.
4. Every opening uses independently sampled tapes under the proof salt and
   exact commitment role.
5. `hash_input_bound=1`, `B0` is part of the uniform public matrix, and the
   showing layout retains bounded `mu_sig`, `x0`, and `x1` sources with their
   bridges.
6. The public context has exactly 11 lanes, the proof contains one hidden
   four-bit slot, and the verifier derives context from an independent service
   input.
7. Holder quota state is durable and monotonic; rate-limited verification uses
   one atomic verifier state. A `-proof-only` result is labeled accordingly.
8. Size and timing statements cite a generated v2 report from the same code
   revision rather than an earlier table.
9. Any manuscript statement uses the same relation, transcript, rate policy,
   preset identity, and evidence status as the executable artifact.

For BQ128/WF128 strict v3, additionally verify manifest 3 and proof schema 3;
the frozen kappa arrays; exact samplers and full statement/profile binding;
the fixed field profile, randomized witness extension, corrected Eq. (2)
masks, and semantic Eq. (4); input-trace/carrier/public-linear-hat degree and
two-way equivalence contracts; retained `x1`/`Z` nonlinear hats; complete
`RowLayout` binding; Q-constant and ragged-V reconstruction; full-R/omitted-M
paper accounting; canonical state/proof/presentation rejection tests; the
three-run focused evidence and 2x resource gates; and
`claim_scope=proof_only`. Never substitute a modeled verifier-message estimate
for an actual canonical wire length.
