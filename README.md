# SPRUCE

SPRUCE is the executable Go artifact for the ARC-SPRUCE construction in the
sibling manuscript repository `../Better-Lattice-based-Blind-Signatures`. It
implements committed-message IntGenISIS issuance, the SmallWood issuance and
showing proofs, NTRU/vSIS signing, the Poseidon2 tag relation, and stateful
rate-limit verification.

This tree preserves seven presets in the historical hard-v2 epoch and selects
a strict v3 proof path for BQ128 and WF128. Preset identifiers, manifest
digests, transcript versions, and persisted formats are protocol identity, not
compatibility labels. Target legacy artifacts are rejected; there is no
selector aliasing, in-place upgrade, or mixed-version verification.

Every maintained preset has `claim_scope=proof_only`. Security-profile names
and benchmark accounting describe the executed proof configuration; they are
not deployment claims.

## Reviewer Path

Read these files in order:

1. [ARTIFACT.md](ARTIFACT.md) for build, validation, manual CLI use, generated
   state, and evidence status.
2. [docs/PROTOCOL.md](docs/PROTOCOL.md) for the implemented equations,
   public-context/hidden-slot policy, transcript, and paper-to-code map.
3. [docs/SECURITY.md](docs/SECURITY.md) for the proof-only security boundary,
   operational invariants, provenance, and unresolved evidence.

The manuscript gives the mathematical construction and security arguments.
This repository fixes their executable encoding, artifact schemas, transcript
domains, preset manifests, and operator state transitions.

## Supported Presets

`go run ./cmd/issuance list-presets` prints these nine canonical IDs:

| Canonical ID | Lifecycle | Security profile |
| --- | --- | --- |
| `poc-n512-sc96-v2` | `poc` | `SC-96` |
| `artifact-n1024-sc125-v2` | `artifact` | `SC-125` |
| `artifact-n1024-bq10-r96-v2` | `artifact` | `BQ10-96` |
| `artifact-n1024-bq16-r96-v2` | `artifact` | `BQ16-96` |
| `pilot-n1024-bq32-r96-v2` | `candidate` | `BQ32-96` |
| `poc-n1024-bq64-r128-v2` | `poc` | `BQ64-128` |
| `poc-n1024-bq96-r128-v2` | `poc` | `BQ96-128` |
| `poc-n1024-bq128-r128-v3` | `poc` | `BQ128-128` |
| `system-n1024-wf128-crom-v2` | `candidate` | `WF-128` |

The first seven entries retain their historical v2 results. BQ128 and WF128
use preset manifest 3, proof/transcript/relation/layout 3, state 8,
presentation 3, issuance artifact 4, and holder usage 3. The lifecycle is an
artifact-maintenance label. It does not widen the proof-only claim scope.
The `-v2` suffix in WF128's canonical ID is therefore a historical identifier,
not the active proof epoch; the manifest and transcript tuple are authoritative.

## Transcript And Size Epochs

- A showing uses an opaque service context supplied independently by the
  holder and verifier. SHAKE256 rejection sampling derives exactly 11 public
  field lanes. One additional PRF input lane is a hidden slot
  `s in {0,...,15}`. The proof enforces its four-bit decomposition, so the
  per-credential, per-context quota is exactly `L=16`.
- The holder durably burns the next slot before proving. The verifier
  cryptographically verifies the presentation and then atomically records the
  `(context, tag)` acceptance. Proof-only verification deliberately skips that
  operational state transition.
- The seven historical presets retain DECS/LVCS v2. Both epochs commit
  independently sampled per-leaf tapes and reject seed-derived opening
  material. The strict-v3 targets additionally use v3 commitment domains and
  positional Merkle authentication reconstructed from the Fiat–Shamir tail.
- BB-tran inputs `mu_sig`, every `x0` row, and `x1` are independently sampled
  coefficient-wise from `{-1,0,1}`. `B0` is an independently uniform public
  polynomial. The showing proof retains every bounded source and its ternary
  membership. Public-linear `mu_sig`/`x0` transforms are now substituted
  directly into the signature aggregate; the `x1` transform and `Z` rows stay
  materialized because they feed the nonlinear inverse check.
- Public parameters, credential state, verifier keys, presentations, holder
  usage state, verifier replay state, NTRU material, and proof transcripts have
  strict identities. Cross-manifest and cross-epoch combinations fail closed.

For BQ128 and WF128, strict v3 additionally uses exact SHAKE256 rejection
sampling, full public-statement Fiat–Shamir binding, fixed extension-field
profiles, paper-shaped mask rows, randomized witness extensions, semantic-Q
reconstruction, input-trace Poseidon constraints, paired ternary carriers,
and positional Merkle multiproofs. The current final-size pass additionally:

- replaces the 165-row issuance core/view witness by 49 committed source rows
  while retaining all 1,024 ring-coordinate commitment residuals;
- computes the Fiat–Shamir-weighted aggregate residual directly, bit-exactly
  with the independent 1,024-residual formal evaluator, without materializing
  that audit-only family during production proving;
- keeps proof schema 3 but requires canonical codec 6 (`SPRUCEP6`), grouped
  radix-`q` field encoding, and omission of only the constant coefficient of
  each `Q` limb, reconstructed before the evaluation challenge solely from
  `sum_{omega in Omega} Q(omega)=0`;
- transmits exactly the positional Merkle frontier derived from the
  Fiat–Shamir tail, with no node count, positions, or worst-case zero padding;
- changes only BQ128 showing shortness from R7/L5 to R11/L4, reducing its
  witness from 487 to 423 rows while the compiler raises `(d,dQ)` from
  `(9,472)` to `(11,570)` and recomputes every dependent mask/query/opening
  dimension; and
- rejects retired PRF-companion metadata and target codec-3/codec-4/codec-5 artifacts
  instead of normalizing or migrating them.

None of these changes increases κ, leaf counts, cryptographic widths, query
caps, salt/tape widths, or seed/nonce sizes. The earlier input-trace,
public-linear showing-row reduction, trusted-ragged `VTargets`, and complete
row-layout binding remain in force.

The table reports independent scalar medians from three fresh codec-6 runs.
Canonical wire sizes vary slightly because the exact Fiat–Shamir-derived
frontier has a challenge-dependent node count and counters use minimal LEB128
widths; state and paper totals are fixed.

| Target | Persistent canonical state | Issuance canonical proof wire | Showing canonical proof wire | Canonical presentation wire | Paper transcript, issuance / showing |
| --- | ---: | ---: | ---: | ---: | ---: |
| BQ128 (showing R11/L4) | 4,926 B | 51,895 B | 84,717 B | 84,750 B | 57,271 / 90,494 B |
| WF128 (`LVCSNCols=41` showing) | 4,894 B | 21,720 B | 37,936 B | 37,977 B | 23,790 / 39,837 B |

These are four separate metric families: persistent credential-state bytes;
actual presentation-wire bytes; actual proof-wire bytes, reported separately
for issuance and showing; and paper-accounted transcript bytes, also reported
per phase. None is inferred from a JSON envelope or from the separately
labeled modeled verifier-message estimate. The three-run verification,
replay-rejection, theorem, zero-knowledge eligibility, and per-run 2× proving-
time and peak-memory gates pass. Relative to the accepted codec-5 medians,
canonical issuance proofs shrink by 490 B for BQ128 and 330 B for WF128;
showing proofs and presentations shrink by 2,084 B and 132 B respectively.
BQ paper-accounted showing falls by 1,262 B; all other paper totals and both
persistent states are unchanged. The claim
remains `proof_only`; full-game accounting is deferred.

The six raw reports and checked summary additionally bind the same exact
`go list` build-input snapshot, including the embedded PRF parameters:
`07035083fc3a35ae3226a2598b1f879bc12b36e06b1ada863b92d4f228df23ff`.
This identifies the dirty implementation tree that produced the measurements,
instead of relying on the base Git HEAD and `modified=true` alone.

The two preceding strict-v3 epochs remain frozen for comparison. Their most
recent accepted medians were 60,426 / 87,091 / 87,124 B for BQ issuance proof,
showing proof, and presentation, and 25,935 / 38,199 / 38,240 B for WF. Their
paper totals are corrected, without rewriting historical evidence, to
65,091 / 91,756 B and 27,575 / 39,837 B. Those figures are retained only as an
older structural epoch. The current codec-6 deltas above use the immediately
preceding accepted codec-5 medians (52,385 / 86,801 / 86,834 B for BQ and
22,050 / 38,068 / 38,109 B for WF), never JSON or a modeled
verifier-message estimate.

Strict-target benchmark runs write
`credential_state.intgenisis.v8`, a version-4 `presign_submission.json`
whose sole proof representation is the canonical issuance proof,
`presentation.intgenisis.v3`, and version-3 `holder_usage_state.json`. Their
target loaders reject legacy, wrong-version, noncanonical, cross-manifest, and
cross-binding inputs instead of migrating them or falling back to v2/debug
verification. See
[docs/CREDENTIAL_SIZE_OPTIMIZATION.md](docs/CREDENTIAL_SIZE_OPTIMIZATION.md)
for the implementation report,
[the current focused evidence record](evidence/focused-v3-final-size-optimization.json)
for the frozen measurements, and [ARTIFACT.md](ARTIFACT.md) for exact
reproduction paths. The two preceding strict-v3 records remain at
[evidence/focused-v3-transcript-reduction.json](evidence/focused-v3-transcript-reduction.json)
and [evidence/focused-v3-size-optimization.json](evidence/focused-v3-size-optimization.json)
as historical comparison data.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full relation and exact
protocol identifiers.

## Strict-v3 Proof-Time Optimization

The BQ128/WF128 proving paths now retain a transcript-preserving time pass:
exact Fiat--Shamir prefix cloning, one bound prepared domain with authenticated
row provenance and lazy NTT materialization, allocation-free semantic-Q
`Into` arithmetic with worker-local arenas, cached replay plans and structural
semantic metadata, a shared formal-degree check, and portable DECS/Merkle
layout improvements. Production DECS retains the established combined
evaluator. The structurally selected row-major candidate remains provisional
R&D, callable only through an explicit internal test constructor, and is not
adopted without the missing fixed-entropy paired gate. The slower tiled,
fixed-frame-template, and per-DECS-hash SHAKE-prefix prototypes remain
rejected. The template prototypes preserved exact bytes and hashes, but pure
framing was 59--107% slower, whole-hash templating had no stable cross-target
3% win, and SHAKE cloning added 448 B plus one allocation per hash. Details are
in
`tmp/profiling-v3/time-optimization/_decs-frame-template-prototype/RESULTS.md`.

Three fresh runs per target on Go 1.23.12, Darwin/arm64, with
`GOMAXPROCS=15` measured:

| Target | Issuance prove | Showing prove | Issuance/showing verify | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| BQ128 | 1,349.588 ms (-20.93%) | 2,902.833 ms (-21.39%) | 499.882 / 273.419 ms | 369,393,664 B (-38.62%) |
| WF128 | 521.758 ms (-28.44%) | 1,256.464 ms (-11.59%) | 241.098 / 148.445 ms | 194,871,296 B (-40.29%) |

The proving MADs are 36.483/97.182 ms for BQ and 4.210/8.127 ms for WF.
The unpaired comparison against the predecessor medians is nominally
20.93%/21.39% faster for BQ issuance/showing and 28.44%/11.59% faster for WF,
so each number is greater than 3%. It is not a passed performance/adoption
gate: these runs use independent entropy and counters, and Fiat--Shamir counter
variability can materially affect top-level proving time. Runtime direction
remains unestablished until seven fixed-entropy alternating predecessor/
candidate pairs are measured. Geometry, kappa, state sizes, and paper
issuance/showing totals remain unchanged at
4,926 B and 57,271/90,494 B for BQ, and 4,894 B and 23,790/39,837 B for WF.
Fresh proof/presentation wire lengths can vary with both the exact-frontier
node count and minimal-LEB128 counter widths; fixed-entropy byte equality, not
equality across fresh entropy, is the preservation criterion.

The raw runs are under
`artifacts/smallwood-v3/time-optimization-v1/{bq128,wf128}/run-{1,2,3}`.
All six bind source-input digest
`c9cf9e245014143c2716aac276498de774ccd0d4af57f4a410f02ac87fb06d56`.
Machine-readable promotion has two blockers: the seven fixed-entropy paired
end-to-end/allocation records have not yet been generated, and the all-nine
`gate-functional-presets` run is not green. BQ issuance/showing algebraic
totals are 131.548362/131.511683 bits; showing is 0.028885 bits below the
manifest-bound 131.540568-bit engineering high-watermark. The actual required
128-bit per-phase gate still passes, with BQ showing 3.511683 bits above it;
the BQ proof, parameter audit, and replay checks also pass. No target,
manifest, geometry, or accounting value is changed to hide this mismatch.
See [the optimization report](docs/PROOF_TIME_OPTIMIZATION.md) and
[the baseline profile](docs/PROOF_TIME_PROFILE.md). The claim remains
`proof_only`; this is not full-game or QROM evidence.

## Fast Native Run

```bash
go test ./...
go build ./cmd/issuance ./cmd/showing
go run ./cmd/issuance list-presets
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset artifact-n1024-sc125-v2
go run ./cmd/issuance gate-functional-presets
```

The benchmark report is the source of truth for executed dimensions,
transcript accounting, theorem/accounting fields, phase timings, and artifact
paths. Historical three-run v2 evidence for the seven non-target presets is
summarized in [results.md](results.md). Focused BQ128/WF128 v3 evidence lives
under the ignored `artifacts/smallwood-v3/` measurement tree and is frozen in
[evidence/focused-v3-nonresearch-optimization.json](evidence/focused-v3-nonresearch-optimization.json).

Run the repository validation path with:

```bash
./scripts/validate-artifact.sh
```

To preserve its outputs:

```bash
ARTIFACT_ROOT="$(pwd)/artifacts" ./scripts/validate-artifact.sh
```

## Fast Docker Run

```bash
docker build -t spruce-artifact .
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact list
docker run --rm --user "$(id -u):$(id -g)" \
  spruce-artifact bench artifact-n1024-sc125-v2
docker run --rm --user "$(id -u):$(id -g)" spruce-artifact gate
```

To retain generated reports:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/artifacts:/artifacts" \
  spruce-artifact validate
```

The Docker runtime is Go-only. Sage/Python and the external pinned lattice
estimator are provenance tools documented in
[docs/SECURITY.md](docs/SECURITY.md).

## Showing CLI State Boundary

Presentation creation requires all of:

```text
-preset
-state-path
-verifier-key
-context-file
-holder-usage-state
-presentation-out
```

Rate-limited verification requires all of:

```text
-preset
-public-params
-verifier-key
-verify-presentation
-expected-context-file
-verifier-state
```

`-proof-only` is valid only with `-verify-presentation`. It omits
`-verifier-state`, verifies the cryptographic statement, and intentionally does
not enforce or persist rate-limit acceptance. It cannot be combined with
`-verifier-state`.

The full manual command sequence is in [ARTIFACT.md](ARTIFACT.md).
