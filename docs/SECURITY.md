# SPRUCE Security And Provenance

This note defines the security boundary of the hard v2 SPRUCE artifact. Every
maintained preset has `claim_scope=proof_only`. A benchmark can show that the
implemented issuance and showing statements execute, verify, bind their
manifest, and report the selected proof-accounting model. It does not by
itself establish security of a deployed credential service.

The mathematical construction and reductions live in
`/home/jonas/Bureau/GIT_Paper`. The Go repository supplies executable evidence
for a concrete encoding. Neither repository silently upgrades artifacts or
evidence from another protocol epoch.

## Canonical Claim Surface

These are the only maintained protocol identities:

| Canonical ID | Security metadata | Lifecycle | Claim scope |
| --- | --- | --- | --- |
| `poc-n512-sc96-v2` | `SC-96` | `poc` | `proof_only` |
| `artifact-n1024-sc125-v2` | `SC-125` | `artifact` | `proof_only` |
| `artifact-n1024-bq10-r96-v2` | `BQ10-96` | `artifact` | `proof_only` |
| `artifact-n1024-bq16-r96-v2` | `BQ16-96` | `artifact` | `proof_only` |
| `pilot-n1024-bq32-r96-v2` | `BQ32-96` | `candidate` | `proof_only` |
| `poc-n1024-bq64-r128-v2` | `BQ64-128` | `poc` | `proof_only` |
| `poc-n1024-bq96-r128-v2` | `BQ96-128` | `poc` | `proof_only` |
| `poc-n1024-bq128-r128-v3` | `BQ128-128` | `poc` | `proof_only` |
| `system-n1024-wf128-crom-v2` | `WF-128` | `candidate` | `proof_only` |

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

## Hard-Epoch Binding And Fail-Closed Parsing

Security-relevant objects bind the canonical preset, manifest digest, public
parameters, primitive profile, PRF parameters, transcript, and rate policy.
The current identities are:

```text
preset schema                 2
proof schema                  2
DECS commitment/opening       2
presentation schema           intgenisis_presentation_v2
public-context policy         public_context_hidden_slot_v2
transcript protocol           smallfield_2025_1085_salted_tapes_v2
transcript version            smallwood_2025_1085_salted_decs_v2
NTRU parameters               ntru-params-v2
NTRU keys                     ntru-key-v2
NTRU signatures               ntru-signature-v2
```

Artifact decoders require the exact current storage schema, reject unknown
fields and non-canonical values, and check content digests. A mismatched epoch,
manifest, role, salt, public parameter, verifier key, PRF file, or NTRU object
is rejected. There is no conversion path and no mixed-epoch verification.

This strict boundary prevents an apparently familiar filename or selector
from changing the statement that a verifier accepts.

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
  used as v2 evidence.

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

The showing proof retains each bounded source explicitly. It proves ternary
membership in the coefficient domain, creates the transformed source used by
the ring/NTT signature check, and proves a source-to-transform bridge. The
canonical degree-1024 replay projection is
`project_u_digits_y_bounded_sources_v6`; the compact degree-512 path uses its
bounded-source `y_view` encoding. No supported relation collapses the BB-tran
sources into an unconstrained full-image residual.

This change gives the extractor the individual bounded witnesses that the
stated relation requires and makes `hash_input_bound=1` a public, transcript-
bound fact. It does not on its own prove the IntGenISIS assumption or the
security of the NTRU sampler. The inverse witness `Z` remains algebraic rather
than short, and the manuscript reduction must match that exact relation.

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
canonical manifest binds the exact PRF profile, parameter path, parameter-file
digest, and tag width. A different file or width is rejected. PRF parameter
generation and cryptanalysis remain external provenance, not something the Go
runtime re-establishes.

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

All nine manifests remain proof-only even when their executed-parameter audit
passes. Security against malicious implementations, multi-user and
multi-context composition, side channels, state rollback, key compromise, and
service-level failures is outside the generated proof report.

## Evidence Status

The hard v2 transition changed the witness rows, transcript openings,
presentation envelope, and stateful context path. Therefore:

- earlier paper-transcript byte counts are not v2 results;
- earlier phase timings are not v2 results;
- tables derived from the earlier row layout or opening format must be
  regenerated; and
- a stable exact-byte gate should be enabled only after reviewed v2 reports
  have been generated on the intended code revision.

Fresh size and timing evidence is currently pending generated v2 benchmark
reports. This document intentionally states no replacement byte or timing
figures.

Generate evidence with:

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset artifact-n1024-sc125-v2 \
  -artifact-dir artifacts/sc125-v2 \
  -json-out artifacts/sc125-v2/benchmark-intgenisis-e2e.json \
  -force
```

Repeat for the exact canonical IDs whose results will be cited. Preserve the
commit/build metadata and report file; do not copy a result between manifests.

## Provenance Tools

The Go/Docker validation path does not rerun Sage or the external lattice
estimator. Relevant sources are:

```text
tools/intgenisis_commitment_estimator.py
tools/intgenisis_lattice_security_estimator.py
prf/generate_params.sage
prf/sweep_rounds.sage
/home/jonas/Bureau/GIT_Paper/sections/03_blind_signature.tex
/home/jonas/Bureau/GIT_Paper/sections/04_arc_construction.tex
/home/jonas/Bureau/GIT_Paper/sections/05_smallwood_model.tex
/home/jonas/Bureau/GIT_Paper/sections/06_parameters.tex
/home/jonas/Bureau/GIT_Paper/appendix/B_gaussian_sampler.tex
/home/jonas/Bureau/GIT_Paper/appendix/C_smallwood_details.tex
/home/jonas/Bureau/GIT_Paper/appendix/D_extended_parameters.tex
/home/jonas/Bureau/GIT_Paper/appendix/E_prf_and_misc.tex
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

## Reviewer Checklist

For any claimed v2 result, verify:

1. The command uses one of the nine canonical IDs and the report repeats that
   ID with preset schema `2`.
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
