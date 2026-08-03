# SPRUCE

SPRUCE is the executable Go artifact for the ARC-SPRUCE construction in the
sibling manuscript repository `/home/jonas/Bureau/GIT_Paper`. It implements
committed-message IntGenISIS issuance, the SmallWood issuance and showing
proofs, NTRU/vSIS signing, the Poseidon2 tag relation, and stateful rate-limit
verification.

This tree is in a hard v2 protocol epoch. Preset identifiers and persisted
artifacts are protocol identity, not compatibility labels. Only the canonical
identifiers below are supported. Material from an earlier epoch is rejected;
there is no selector aliasing, in-place upgrade, or mixed-version verification.

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

## Canonical v2 Presets

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

The lifecycle is an artifact-maintenance label. It does not widen the
proof-only claim scope.

## Hard v2 Changes

- A showing uses an opaque service context supplied independently by the
  holder and verifier. SHAKE256 rejection sampling derives exactly 11 public
  field lanes. One additional PRF input lane is a hidden slot
  `s in {0,...,15}`. The proof enforces its four-bit decomposition, so the
  per-credential, per-context quota is exactly `L=16`.
- The holder durably burns the next slot before proving. The verifier
  cryptographically verifies the presentation and then atomically records the
  `(context, tag)` acceptance. Proof-only verification deliberately skips that
  operational state transition.
- DECS/LVCS v2 commits independently sampled per-leaf tapes. A proof-global
  salt and a commitment role are included in every v2 leaf, node, padding, and
  challenge domain. Seed-derived opening material is not accepted by v2.
- BB-tran inputs `mu_sig`, every `x0` row, and `x1` are independently sampled
  coefficient-wise from `{-1,0,1}`. `B0` is an independently uniform public
  polynomial. The showing proof retains each bounded source and proves its
  ternary membership and source-to-transform bridge.
- Public parameters, credential state, verifier keys, presentations, holder
  usage state, verifier replay state, NTRU material, and proof transcripts have
  strict v2 identities. Cross-manifest and cross-epoch combinations fail
  closed.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full relation and exact
protocol identifiers.

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
paths. Pre-v2 byte and timing baselines do not apply after the bounded-source
and salted-tape changes. Maintained v2 size and timing evidence is pending
fresh generated reports; this documentation intentionally does not substitute
estimated values.

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
