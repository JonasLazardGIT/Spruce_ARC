# SmallWood DECS Transcript Alignment

## Status

Priority: high before making a complete NIZK or complete anonymous-credential
security claim.

The current implementation supports the SmallWood soundness calculations, but
two zero-knowledge details do not directly instantiate the construction in
[SmallWood, ePrint 2025/1085](https://eprint.iacr.org/2025/1085):

1. The paper samples an independent tape `rho_j` for every DECS leaf and reveals
   only the tapes belonging to opened leaves. The implementation derives every
   leaf nonce from one seed and includes that seed in the opening, allowing all
   leaf nonces to be reconstructed.
2. The paper uses the proof's global salt as auxiliary input to DECS leaf
   hashing and to the first Fiat-Shamir hash. The implementation currently
   samples the salt after the main DECS commitment, so the salt is used by
   Fiat-Shamir but is absent from those leaf hashes.

These are theorem-applicability gaps. They should not be described as a known
forgery, and they do not invalidate the reported algebraic soundness work
factors by themselves. They do prevent us from citing the paper's complete
zero-knowledge argument without either correcting the transcript or proving a
separate seed-compressed variant.

## Expected Size Of The Change

This is a moderate, cross-package protocol change, not a lattice-backend or
SmallWood polynomial rewrite.

- The core correction is local: sample and retain independent tapes, disclose
  selected tapes, sample the salt earlier, and include it in leaf hashes.
- The propagation is broad: DECS, LVCS, PIOP proving, PIOP verification,
  opening packing, transcript accounting, serialization tests, benchmarks, and
  manifests all depend on the current representation.
- Expect changes in roughly 8-12 production files and a similar number of test
  files. A careful implementation will likely be a few hundred lines plus
  fixture updates.
- No lattice parameters, witness relations, formal-polynomial backend, or
  SmallWood tuning parameters need to change.
- The salt is already transmitted, so binding it to leaves adds no salt bytes.
  Replacing one disclosed seed with one tape per opened leaf adds hundreds of
  bytes, not tens of kilobytes, to a typical proof.

For an opening of `m` distinct leaves with `t`-byte tapes, the direct tape
payload changes approximately from `t` bytes to `m*t` bytes, a delta of
`(m-1)*t` bytes per DECS opening. Indicative single-opening deltas for current
geometries are:

| Geometry | Opened leaves | Tape bytes | Approximate delta |
|---|---:|---:|---:|
| WF-128 | 9 | 16 | +128 bytes |
| Q64-R128 | 13 | 25 | +300 bytes |
| Q96-R128 | 16 | 29 | +435 bytes |
| Q128-R128 | 18 | 33 | +561 bytes |

These are planning estimates only. A proof may combine or carry more than one
DECS opening, so issuance and showing totals must be measured from the final
wire encoding rather than updated from this table.

The prover must retain all independent tapes until opening. A flat tape buffer
would cost approximately 8 MiB for `524288 * 16`, 21.88 MiB for
`917504 * 25`, 21.75 MiB for `786432 * 29`, and 24.75 MiB for
`786432 * 33`. This is material but bounded and avoids the allocation overhead
of one Go slice per leaf.

## Required Security Invariants

The corrected transcript must enforce all of the following:

- Each DECS leaf receives an independently sampled, uniformly random tape of
  the configured tape width.
- A proof opening contains exactly one tape for each distinct opened leaf and
  reveals no seed or state from which unopened tapes can be reconstructed.
- One global salt is sampled before any transcript-bound DECS commitment.
- The same global salt is bound to every relevant DECS leaf and to the first
  Fiat-Shamir invocation for that proof.
- Issuance and showing verifiers reconstruct exactly the same salted leaf
  preimage as their corresponding provers.
- Leaf encodings are canonical and domain separated by protocol version and
  commitment role.
- The verifier rejects malformed tape counts, tape widths, duplicate or invalid
  indices, mixed seed/tape encodings, non-canonical field values, and a salt of
  the wrong width.
- Security accounting obtains actual tape entropy from the disclosed tape
  format. It must never infer paper-aligned tape hiding from the length of a
  disclosed master seed.
- Old and corrected transcript formats cannot be confused or verified under
  the same canonical manifest.

## 1. Choose The Construction

Implement the paper-aligned construction by default:

- Sample `N` independent tapes with `crypto/rand`.
- Keep them private in the prover.
- Copy only the challenged tapes into the DECS opening.

A random-access PRF keyed by a private seed could avoid storing all tapes while
still revealing only selected outputs. That is not the construction proved in
the paper: it replaces information-theoretically independent tapes with
pseudorandom tapes and introduces another computational assumption and proof
obligation. Do not use that optimization for a paper-aligned claim unless a
separate reduction is written and reviewed.

## 2. Version The Transcript

Do not silently change the existing transcript under its current identifier.

- Add a new transcript/manifest version for salted leaves and selective tape
  disclosure.
- Bind the version into the canonical preset manifest and Fiat-Shamir domain.
- In the new version, reject `NonceSeed` unconditionally and require explicit
  per-opening tapes.
- Decide explicitly whether the old verifier remains available only for
  historical artifact reproduction or is removed. If retained, label it as a
  legacy format with no complete NIZK claim.
- Prevent credentials or proofs produced under the legacy format from being
  accepted under the corrected preset identity.

Affected areas include the proof transcript constants, preset manifest
construction, issuance/showing serialization, and replay verification.

## 3. Replace Seed-Derived Nonces With Independent Tapes

The current implementation is centered on `deriveNonce` and `NonceSeed` in
[`DECS/decs_prover.go`](DECS/decs_prover.go) and
[`DECS/decs_types.go`](DECS/decs_types.go).

Required changes:

1. Add prover-private storage for a flat `N * TapeBytes` byte buffer. Keep a
   checked multiplication and a configured allocation limit to avoid integer
   overflow or accidental unbounded allocation.
2. Fill the complete buffer from `crypto/rand.Reader` before leaf construction.
   Propagate entropy-source failures.
3. During scalar, parallel, tiled, and formal leaf construction, select
   `tapes[i*TapeBytes:(i+1)*TapeBytes]` directly. Every implementation path must
   hash byte-identical leaf preimages for fixed inputs.
4. Change `EvalOpen(E)` to copy only the tapes for indices in `E` into the
   opening, in exactly the same logical order as `Pvals`, `Mvals`, and paths.
5. Stop populating `NonceSeed` in the corrected format. Rename internal
   nonce-oriented symbols to tape-oriented names where doing so does not break
   legacy decoding.
6. Make the corrected verifier require `len(open.Nonces) == EntryCount()` (or
   the equivalent renamed tape field) and require every tape to have exactly
   `TapeBytes` bytes. Remove its seed-derivation fallback for the new version.
7. Ensure repeated opening calls either return consistent copies of the same
   retained tapes or are prohibited after finalization with a clear error.
8. Release the full private tape buffer when the prover state is no longer
   needed. Zeroing can be considered for hygiene, although these tapes are not
   long-term keys.

The opening type already has a `Nonces` field, so this does not require an
entirely new proof object. It does change which field is populated and therefore
changes serialized proof bytes.

## 4. Bind The Global Salt To DECS Leaves

The current main root is committed before `runMaskFS` samples the salt in
[`PIOP/masking_fs_helper.go`](PIOP/masking_fs_helper.go). Move salt creation to
the beginning of proof construction.

Required changes:

1. Sample the salt once in the top-level PIOP prover before calling
   `commitRows`.
2. Pass an internal commitment context containing the salt, transcript version,
   and commitment-role label through PIOP -> LVCS -> DECS.
3. Use the same salt for the main row commitment, Q-payload commitment, and any
   transcript-bound companion/replay commitment that belongs to the proof.
4. Pass that already sampled salt into `runMaskFS`; it must not silently sample
   a second value.
5. On verification, obtain the salt from the proof header and pass the same
   context to every DECS opening check.
6. Reject a missing or incorrectly sized salt before performing Merkle-path or
   Fiat-Shamir verification.

There is no circular dependency: the salt is sampled first, the salted DECS
root is computed second, and Fiat-Shamir hashes the salt and root third.

## 5. Define One Canonical Leaf Encoding

Replace ad hoc concatenation with a documented encoder used by both prover and
verifier. At minimum, the encoded/hash input must bind:

```text
DECS leaf domain label
transcript version
commitment role
global salt
evaluation-domain point or full leaf index
canonical P evaluations
canonical M evaluations
the independent tape
```

Use fixed-width or length-prefixed fields so no two tuples have the same byte
encoding. Validate every field element as a canonical residue below `q` before
hashing it on the verifier side.

The current leaf encoder writes `uint16(index)`. Current authentication domains
can contain hundreds of thousands of leaves, so 16 bits do not uniquely encode
the index. While changing the leaf format, encode either the actual field point
or an index wide enough for the complete domain, and test values on both sides
of 65535.

The Merkle implementation exposes a legacy 16-byte `Root()` and a full-width
`RootHash()`. Corrected wide-hash profiles must bind and verify the full root at
their declared width. Keep the 16-byte value only as an explicitly legacy API;
never let it become a fallback for a 264-, 328-, or 392-bit hash profile.

Candidate framing, subject to matching the paper's exact notation during
implementation, is:

```text
SHAKE256(
  "SPRUCE/SmallWood/DECS/leaf/v2" ||
  encode(role) || encode(salt) || encode(point) ||
  encode(P(point)) || encode(M(point)) || encode(tape)
)
```

Merkle internal-node hashing should retain a separate node domain. Whether the
salt is also included in internal nodes must follow the selected formalization;
the paper-alignment requirement here is that the salt is included in every leaf
hash.

## 6. Propagate The Context Through Every Proof Path

Audit and update at least these layers:

- DECS commitment, optimized/formal leaf builders, opening packing, and
  verification in `DECS/`.
- LVCS prover/verifier wrappers and subset-opening helpers in `LVCS/`.
- Main row commitment setup in
  [`PIOP/commit_helpers.go`](PIOP/commit_helpers.go) and
  [`PIOP/generic_builder.go`](PIOP/generic_builder.go).
- Fiat-Shamir initialization and Q commitments in
  [`PIOP/masking_fs_helper.go`](PIOP/masking_fs_helper.go).
- Opening reconstruction and verification in
  [`PIOP/VerifyNIZK.go`](PIOP/VerifyNIZK.go).
- Opening clone, combine, pack, and size helpers in
  [`PIOP/run.go`](PIOP/run.go).
- PRF companion, pre-sign/post-sign replay, subset-row recovery,
  sig-shortness, and other auxiliary proof paths that construct or verify a
  DECS opening.

Opening combination is particularly sensitive. When mask and tail openings are
merged, merge tapes by logical leaf index, preserve the final `EntryCount()`
ordering, deduplicate repeated indices, and reject two different tapes claimed
for the same leaf.

## 7. Correct Reporting And Security Audits

Update [`PIOP/canonical_transcript.go`](PIOP/canonical_transcript.go) and the
security ledger so reports describe the actual corrected proof:

- Count every serialized opened tape in `tapes_bytes`.
- Separate tape payload bytes from tape-count/length metadata.
- Remove `nonce_seed_bytes` from corrected-format reports, or retain it only in
  a clearly labeled legacy audit section.
- Derive actual tape width from every opened tape and reject inconsistent
  widths.
- Mark seed-compressed openings as incompatible with the paper-aligned profile.
- Retain the theorem's hidden-tape term only when unopened tapes are not
  reconstructible from the proof.
- Continue reporting soundness and zero-knowledge terms separately. Passing the
  algebraic/full-game soundness calculation alone must not promote a complete
  NIZK claim.

Do not refresh expected transcript totals until the encoding and verifier have
passed review. Once fixed, remeasure every executable preset rather than adding
the estimated deltas above to existing totals.

## 8. Test Matrix

### DECS unit tests

- Inject deterministic tapes and salt through a test-only/internal entropy
  source and compare scalar, parallel, tiled, ring-backed, and formal roots.
- Assert that an opening contains exactly the selected tapes and no master
  seed.
- Assert that changing the salt changes the root for otherwise identical
  inputs.
- Assert that changing one leaf tape changes the root.
- Reject a changed salt, changed tape, missing tape, extra tape, short/long
  tape, mixed seed/tape representation, malformed index, and non-canonical
  field value.
- Cover indices `65535`, `65536`, and the largest maintained authentication
  domain index.
- Verify that duplicate opening indices are either canonicalized once or
  rejected consistently.

### LVCS/PIOP integration tests

- Prove and verify low-degree and formal high-degree rows with salted DECS
  leaves.
- Exercise main, Q-payload, PRF companion, replay, subset-row, and
  sig-shortness paths.
- Tampering with `Proof.Salt` must fail both the DECS opening and Fiat-Shamir
  checks.
- Combining and packing openings must preserve tape-to-index alignment.
- Serialization round trips must preserve all selected tapes and the full root.
- A corrected verifier must reject a legacy seed-compressed opening.
- Legacy artifact verification, if retained, must dispatch only under the
  explicit legacy transcript identifier.

### Accounting and end-to-end tests

- Assert exact tape bucket accounting from serialized data.
- Assert parameter-audit failure when actual tape/salt/root widths differ from
  the manifest.
- Benchmark issuance and showing for every executable preset.
- Run functional gates, replay rejection, manifest binding, and artifact gates.
- Record memory and prover-time changes caused by random tape generation and
  the larger salted leaf preimage.

## 9. Acceptance Criteria

The correction is complete only when:

- No corrected proof serializes `NonceSeed` or any equivalent master secret.
- Only tapes corresponding to opened leaves are serialized.
- Every corrected DECS root commits to the proof's global salt.
- Prover and verifier share one canonical, versioned leaf encoder.
- Large leaf indices and full-width Merkle roots are handled without
  truncation.
- All proof paths pass end to end and all salt/tape tampering tests reject.
- Transcript reports and security audits use measured wire data.
- Preset manifests bind the corrected transcript version.
- Exact issuance, showing, and combined bytes are remeasured and documented.
- The zero-knowledge argument is checked line by line against the paper before
  changing any preset from `proof_only` or diagnostic status.

Final validation should include:

```bash
gofmt -l <changed Go files>
git diff --check
go test ./DECS ./LVCS ./PIOP -count=1
go test ./credential ./cmd/issuance ./cmd/showing -count=1
go test ./... -count=1
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
go build ./cmd/issuance ./cmd/showing
```

Then run one measured issuance/showing proof for every executable preset and the
functional and historical artifact gates.

## Suggested Commit Sequence

1. `decs: disclose independent opening tapes`
   - Independent tape storage, selective disclosure, strict verifier checks,
     and DECS unit tests.
2. `piop: bind global salt to decs leaves`
   - Early salt sampling, context propagation, canonical leaf encoding, full
     index/root handling, and all proof-path tests.
3. `reporting: account for selective decs tapes`
   - Wire-size accounting, parameter audit, and security-ledger semantics.
4. `validation: refresh corrected transcript fixtures`
   - End-to-end measurements, expected byte fixtures, gates, and documentation.

Keep parameter retuning out of these commits. First establish a correct and
paper-aligned transcript, measure its cost, and only then decide whether the
additional tape bytes justify a new tuning pass.
