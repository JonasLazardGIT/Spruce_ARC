# Docker Cleanup Endgoal

This document defines the target state for the Docker cleanup branch. The goal
is not to preserve every experiment in the repository. The goal is to produce a
small, readable, reproducible artifact for the maintained IntGenISIS prototype.

The cleanup should make the repository easy to inspect, easy to run, and hard to
misuse. Anything outside the maintained proof path should either be removed,
moved behind an explicit internal label, or excluded from the Docker artifact.

## Primary Goal

The final repository should expose one clear artifact:

```text
Maintained ARC-SPRUCE IntGenISIS issuance and showing prototype
```

The artifact should support:

- maintained public parameter setup;
- maintained NTRU key setup;
- holder commitment;
- pre-sign issuance proof;
- issuer verification and signing;
- holder finalization;
- showing proof generation;
- showing proof verification;
- fixed-size transcript reporting;
- maintained E2E benchmarks for the promoted presets;
- a Docker image that reproduces tests, benchmarks, and byte-size reports.

The artifact should not expose:

- stale N=256 profiles;
- old x0len70 showing profiles;
- broad parameter search;
- paper-development scratch output;
- private credential states;
- local cache directories;
- old challenge-style command surfaces;
- unsafe flags as normal public commands;
- half-supported proof layouts as maintained features.

## End State In One Sentence

A fresh reviewer should be able to clone the repository, run one Docker command,
and reproduce the maintained IntGenISIS proof generation, verification, timing,
and fixed transcript-size tables without needing local paths, private files,
manual setup, Sage, lattice-estimator installs, or historical context.

## Maintained Presets

Only these presets are public artifact presets:

```text
n512-compact96
n1024-compact96
n1024-compact125
```

Interpretation:

- `n512-compact96`: engineering and smoke-test preset;
- `n1024-compact96`: maintained degree-1024 96-bit profile;
- `n1024-compact125`: maintained high-security profile;
- `n1024-compact125` is a 125+ profile, not a 128-bit claim.

All public commands, docs, and Docker flows should default to these names.

Any other preset may exist only when it is:

- required by a unit test;
- kept in a clearly internal package;
- documented as legacy or comparison-only;
- absent from README quickstarts and Docker entrypoints.

## Public Command Surface

The final public command surface should be narrow.

Required public commands:

```bash
go run ./cmd/issuance setup-intgenisis-public
go run ./cmd/issuance setup-ntru-keys
go run ./cmd/issuance holder-commit
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125
go run ./cmd/issuance gate-degree1024-maintained-presets
go run ./cmd/showing -preset n1024-compact125
```

Required Docker commands:

```bash
docker build -t spruce-artifact .
docker run --rm spruce-artifact test
docker run --rm spruce-artifact bench n512-compact96
docker run --rm spruce-artifact bench n1024-compact96
docker run --rm spruce-artifact bench n1024-compact125
docker run --rm spruce-artifact gate
```

Optional Docker commands:

```bash
docker run --rm -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n1024-compact125
docker run --rm -v "$(pwd)/artifacts:/artifacts" spruce-artifact all
```

Commands that should not appear in public quickstarts:

- old challenge-generation flows;
- raw parameter sweeps;
- N=256 profile commands;
- x0len70 command examples;
- one-off beta audit commands;
- manual `go test` invocations that require private generated files;
- commands that rely on absolute paths under `/home/jonas`.

## Proof-Format End State

The maintained artifact should emit current maintained proof format by default:

- SmallWood 2025 transcript path;
- paper-Q issuance where maintained;
- direct-full PRF companion relation;
- fixed-size transcript mode enabled for maintained presets;
- fixed-width DECS openings for maintained proof-size reporting;
- compact frontier DECS openings retained only as explicit legacy mode.

The public README should not present format variants as user choices unless they
are needed to reproduce a table. The artifact can keep legacy verification code,
but public proving should stay on the maintained path.

## Fixed-Size Transcript Requirement

Maintained proof byte counts should be constant across repeated runs for the
same preset and mode.

Required invariant:

```text
same preset + same transcript mode + same fixed-size flag
=> same issuance paper bytes
=> same issuance proof bytes
=> same issuance auth bytes
=> same showing paper bytes
=> same showing proof bytes
=> same showing auth bytes
```

Timing may vary. Byte size must not vary.

If byte size changes across runs, the cleanup is not finished. The cause must be
found before Docker numbers are documented.

## Docker End State

Docker should be a reproducibility wrapper, not a development environment.

The Docker image should:

- build from a clean checkout;
- install Go dependencies during build;
- not require network during runtime commands;
- run `go test ./...`;
- run maintained E2E benchmarks;
- write JSON artifacts to `/artifacts` when mounted;
- run without host absolute paths;
- not copy `.git`, `.gocache`, `.private`, `.vscode`, generated credential
  states, local paper repositories, or scratch artifacts;
- not include lattice-estimator source unless explicitly needed by a documented
  command;
- not require Sage;
- not require external keys or generated files.

The Docker image should not be huge. It should be a Go artifact image, not a
full research workstation.

Recommended structure:

```text
Dockerfile
.dockerignore
scripts/artifact-entrypoint.sh
scripts/artifact-test.sh
scripts/artifact-bench.sh
scripts/artifact-gate.sh
README.md
docs/degree1024_maintained_presets.md
docs/docker_cleanup_endgoal.md
```

Use scripts for Docker entrypoints so the README stays short and commands are
stable.

## README End State

The final README should answer four questions:

1. What is this artifact?
2. Which commands reproduce the maintained results?
3. Which presets are maintained?
4. Where are the proof-size and security claims documented?

The README should not be a historical changelog.

Required README sections:

```text
# SPRUCE
## Artifact Scope
## Maintained Presets
## Docker Quickstart
## Native Quickstart
## Reproducing Results
## Output Artifacts
## Security And Parameter Notes
## Repository Layout
## Non-Goals
```

README must link to:

- `docs/degree1024_maintained_presets.md`;
- `docs/intgenisis_lattice_security.md`;
- `docs/intgenisis_protocol_h_tran.md`;
- `docs/modulus_choice.md`;
- `docs/protocol.md`;
- paper Section 6 location if the paper repository is available.

README must not link to:

- private local paper paths;
- generated credential states as canonical inputs;
- stale parameter search directories;
- local cache directories.

## Documentation End State

Documentation should separate maintained claims from background research.

Canonical docs:

```text
docs/protocol.md
docs/intgenisis_protocol_h_tran.md
docs/intgenisis_lattice_security.md
docs/modulus_choice.md
docs/degree1024_maintained_presets.md
docs/docker_cleanup_endgoal.md
```

Optional docs may remain only if they serve a maintained command or clarify a
maintained proof relation.

Documentation should not duplicate tables unless there is a clear source of
truth. Prefer:

- one maintained preset table;
- one paper Section 6 table;
- generated JSON files for raw E2E output.

If a result is updated, update all three or explicitly state why one is not
updated.

## Package End State

The codebase should be small enough that the maintained proving path is obvious.

Target package roles:

```text
cmd/issuance      public artifact CLI and E2E benchmark/gate command
cmd/showing       public showing CLI
credential        maintained credential parameter and state model
issuance          issuance flow helpers
commitment        Ajtai commitment helpers
ntru              NTRU signing and ring arithmetic used by maintained flow
ntru/io           NTRU serialization helpers
ntru/keys         NTRU key wrappers
ntru/signverify   NTRU sign/verify helpers
prf               PRF and grouped witness trace
PIOP              SmallWood/PACS proof builder and verifier
DECS              DECS commitment, opening, fixed-size packing
LVCS              LVCS wrapper over DECS
internal/domain   Fiat-Shamir/domain helpers
internal/fpoly    formal polynomial helpers
internal/kfield   finite-field helpers
internal/packedwidth fixed-width packing helpers
```

Packages that should be removed from the public artifact unless still imported:

```text
parameter_search
lattice-estimator-main
tools
Parameters
_markdown_test
```

Packages/directories that should be quarantined or deleted if not needed by
maintained commands:

```text
vSIS-HASH
Preimage_Sampler
cmd/ntrucli
prf/*.sage
prf/RUN_SAGE.md
```

Current import graph still references:

```text
ntru -> Preimage_Sampler
credential/cmd -> vSIS-HASH
cmd/ntrucli -> ntru and vSIS-HASH
```

So first pruning pass should not blindly delete `Preimage_Sampler` or
`vSIS-HASH`. Instead:

- inspect whether maintained NTRU and credential paths need them;
- inline or move the small required pieces if simple;
- otherwise keep them but mark as internal implementation packages;
- remove docs and public command examples around them.

## Artifact Tree Target

Target clean tree:

```text
.
|-- Dockerfile
|-- .dockerignore
|-- README.md
|-- go.mod
|-- go.sum
|-- cmd
|   |-- issuance
|   `-- showing
|-- credential
|-- issuance
|-- commitment
|-- ntru
|-- prf
|-- PIOP
|-- DECS
|-- LVCS
|-- internal
|-- docs
`-- scripts
```

Allowed test data:

- small deterministic fixtures required by tests;
- generated-in-test temporary files under `t.TempDir()`;
- no checked-in private holders, requests, responses, or keys unless they are
  intentionally tiny public test vectors.

Disallowed artifact files:

- `.private/**`;
- `.gocache/**`;
- `.vscode/**`;
- `credential/issuance/**/*.json` if generated state;
- `PIOP/ntru_keys/*.json` if generated local key material;
- `ntru/signverify/ntru_keys/*.json` if generated local key material;
- paper build output;
- benchmark scratch output;
- local estimator clone unless isolated outside Docker context.

## Generated Artifact Policy

Generated proof and benchmark files should not be source files.

Allowed generated output location:

```text
artifacts/
```

`artifacts/` should be gitignored.

Docker should write:

```text
artifacts/n512-compact96-e2e.json
artifacts/n1024-compact96-e2e.json
artifacts/n1024-compact125-e2e.json
artifacts/gate-degree1024.json
```

Native commands may write into a user-supplied `-artifact-dir`.

No generated file should be required for a clean checkout to pass tests.

## CLI Simplification Rules

CLI cleanup should make maintained paths boring.

Rules:

- maintained preset required for public showing;
- maintained preset required for public E2E benchmark unless explicitly using
  comparison mode;
- fixed transcript size defaults to on for maintained presets;
- direct-full PRF defaults to on for maintained showing;
- legacy compact transcript mode remains explicit;
- baseline issuance transcript remains explicit;
- dangerous or research flags should be hidden from README and Docker;
- if a flag is only useful for old experiments, remove it or mark it internal.

The CLI should not ask users to understand:

- DECS frontier compression;
- row layout variants;
- residual vs direct layouts if only one is maintained;
- old challenge formats;
- experimental preset sweep knobs.

## Test End State

The final repository should pass:

```bash
go test ./...
```

The Docker artifact should pass:

```bash
docker run --rm spruce-artifact test
docker run --rm spruce-artifact gate
```

Tests should cover:

- maintained issuance proof builds and verifies;
- maintained showing proof builds and verifies;
- direct-full PRF companion relation rejects tampering;
- fixed-size transcript mode keeps sizes constant;
- compact legacy DECS openings still verify if support is retained;
- JSON round-trip verifies without local caches;
- Docker scripts run from clean checkout.

Long E2E tests may be behind explicit benchmark/gate command, but the Docker
artifact must provide one command that runs them.

## Result Reporting End State

Result reporting should be deterministic in structure.

Every E2E JSON should include:

```text
preset
security_bits_binding
security_bits_hiding
issuance_transcript_mode
showing_transcript_mode
fixed_transcript_size
issuance_paper_transcript_bytes
issuance_proof_size_bytes
issuance_auth_bytes
showing_paper_transcript_bytes
showing_proof_size_bytes
showing_auth_bytes
issuance_prove_ms
issuance_verify_ms
showing_prove_ms
showing_verify_ms
phase_timings
go_version
gomaxprocs
git_commit
```

Timing can be reported as fresh measured values. Byte counts should be exact.

Docs should say:

- timings are platform-dependent;
- byte counts are format-dependent and constant under fixed-size mode;
- theorem/security bits come from the maintained estimator review.

## Dockerfile Requirements

Dockerfile should:

- use a pinned Go base image;
- copy only source files needed to build and test;
- use build cache for modules if available;
- run `go mod download` during build;
- build public commands during build;
- default to artifact entrypoint;
- not copy hidden local directories;
- not install Sage or system packages unless proven necessary;
- not fetch lattice estimator at runtime.

Recommended shape:

```dockerfile
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./...
RUN go build -o /out/issuance ./cmd/issuance
RUN go build -o /out/showing ./cmd/showing

FROM golang:1.23-bookworm
WORKDIR /src
COPY --from=build /src /src
COPY --from=build /out /usr/local/bin
ENTRYPOINT ["./scripts/artifact-entrypoint.sh"]
CMD ["help"]
```

Final image can be optimized later. First priority: reproducible and simple.

## .dockerignore Requirements

`.dockerignore` should exclude:

```text
.git
.gocache
.private
.vscode
artifacts
tmp
*.log
credential/issuance
PIOP/ntru_keys
ntru/signverify/ntru_keys
lattice-estimator-main
parameter_search
tools
_markdown_test
```

If a directory is excluded but needed by tests, that is a sign the tests rely on
generated or local state. Fix tests before widening Docker context.

## Cleanup Principles

Use these principles when pruning:

- public artifact beats research archive;
- current maintained proof path beats historical alternatives;
- tests beat comments;
- generated files belong outside git;
- Docker quickstart beats CLI completeness;
- exact byte reproduction beats tiny proof-size compression;
- clear package boundaries beat clever retention of old modes;
- legacy verification can remain, but legacy proving should not be public;
- if a directory has no maintained import edge and no documented artifact role,
  delete it from the artifact branch.

## Non-Goals

The Docker cleanup should not:

- redesign the proof system;
- change security parameters;
- change Section 6 claims without rerunning E2E;
- introduce new transcript versions;
- optimize proof speed;
- add new presets;
- turn the repository into a general lattice playground;
- preserve every historical experiment.

## Stage 0: Baseline Capture

Purpose: capture current known-good state before pruning.

Commands:

```bash
git status --short --branch
go test ./...
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n512-compact96 -artifact-dir /tmp/spruce-baseline -force
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact96 -artifact-dir /tmp/spruce-baseline -force
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125 -artifact-dir /tmp/spruce-baseline -force
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root /tmp/spruce-baseline
```

Record:

- commit hash;
- Go version;
- command output;
- JSON artifacts;
- proof byte counts;
- timing summary.

Exit criteria:

- tests pass;
- maintained E2E runs pass;
- fixed-size byte counts stable if repeated;
- no unknown dirty files except planned doc/cleanup files.

## Stage 1: Docker Boundary Inventory

Purpose: decide what Docker copies and what Docker excludes.

Run:

```bash
find . -maxdepth 2 -type d | sort
rg --files | sort > /tmp/spruce-files-before.txt
go list ./... > /tmp/spruce-packages-before.txt
go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... > /tmp/spruce-imports-before.txt
```

Classify each top-level entry:

```text
keep-public
keep-internal
delete
dockerignore
needs-inspection
```

Expected classification:

```text
DECS                  keep-public/internal core
LVCS                  keep-public/internal core
PIOP                  keep-public/internal core
cmd                   keep-public, prune to issuance/showing
commitment            keep-public/internal core
credential            keep-public/internal core, prune generated states
docs                  keep-public, prune stale docs
internal              keep-public/internal core
issuance              keep-public/internal core
ntru                  keep-public/internal core, prune generated keys
prf                   keep-public/internal core, prune Sage scripts if not needed
Preimage_Sampler      needs-inspection, imported by ntru
vSIS-HASH             needs-inspection, imported by credential/cmd/ntru
cmd/ntrucli           delete or internal-only
Parameters            delete or dockerignore
parameter_search      delete or dockerignore
lattice-estimator-main delete or dockerignore
tools                 delete or dockerignore
_markdown_test        delete or dockerignore
.gocache              delete and dockerignore
.private              dockerignore, never artifact
.vscode               dockerignore
```

Exit criteria:

- classification table committed in this document or cleanup notes;
- `.dockerignore` draft matches classification;
- no unknown directory copied into Docker context by accident.

## Stage 2: Public Interface Freeze

Purpose: freeze exactly what the artifact promises before deleting code.

Tasks:

- define public presets in one credential helper;
- define public transcript defaults in one runtime helper;
- define public CLI commands in README;
- define Docker commands in scripts;
- mark non-public modes as internal or remove flags.

Public proving defaults:

```text
preset: maintained compact preset
issuance transcript: smallfield maintained paper-Q mode
showing transcript: smallfield maintained mode
PRF companion: direct_full
fixed transcript size: true
```

Exit criteria:

- `README.md` quickstart uses only public commands;
- `cmd/README.md` either matches README or is removed;
- no stale N=256/x0len70 command remains in docs except removal notes;
- E2E benchmark still runs for all maintained presets.

## Stage 3: Package Reachability Audit

Purpose: delete only packages that are unreachable from maintained commands, or
turn reachable legacy packages into internal implementation details.

Run:

```bash
go list -deps ./cmd/issuance ./cmd/showing | sort -u > /tmp/spruce-maintained-deps.txt
go list ./... | sort > /tmp/spruce-all-packages.txt
comm -13 /tmp/spruce-maintained-deps.txt /tmp/spruce-all-packages.txt
```

Audit each package not required by `cmd/issuance` or `cmd/showing`.

Likely actions:

- delete `cmd/ntrucli` if not needed by artifact;
- delete or ignore parameter search;
- delete generated docs/tests not connected to maintained flow;
- keep `Preimage_Sampler` only if NTRU still imports it;
- keep `vSIS-HASH` only if credential hash relation still imports it;
- move retained helper packages under `internal/` only if import paths can be
  changed without churn.

Exit criteria:

- `go list ./...` contains no unused command/package meant only for old demos;
- maintained commands still build;
- `go test ./...` still passes.

## Stage 4: Generated And Private Material Pruning

Purpose: remove generated local files from source tree and prevent recurrence.

Delete from artifact branch if tracked or present as repo material:

```text
credential/issuance/**/*.json
PIOP/ntru_keys/*.json
ntru/signverify/ntru_keys/*.json
artifacts/**
*.log
```

Then add or update `.gitignore`:

```text
artifacts/
credential/issuance/
PIOP/ntru_keys/
ntru/signverify/ntru_keys/
.gocache/
.private/
.vscode/
```

Tests must generate temporary keys/states under `t.TempDir()`.

Exit criteria:

- clean checkout does not need generated JSON;
- tests create their own temp states;
- Docker context excludes private/generated material;
- `git status --ignored --short` confirms ignored local output.

## Stage 5: Public CLI Simplification

Purpose: remove old user-facing choices.

Tasks:

- keep `cmd/issuance` as main artifact CLI;
- keep `cmd/showing` as maintained showing CLI;
- remove `cmd/ntrucli` unless explicitly needed for tests;
- hide or delete flags that expose stale profile families;
- keep `-fixed-transcript-size` only if useful for comparison;
- keep `-preset` constrained to maintained names for public flows;
- remove public examples for internal flags.

Exit criteria:

- `go run ./cmd/issuance -h` is not overwhelming;
- `go run ./cmd/showing -h` points to maintained presets;
- README commands match actual CLI behavior;
- old modes require explicit internal flags or are gone.

## Stage 6: Core Package Pruning

Purpose: simplify packages without changing maintained proof behavior.

PIOP:

- keep SmallWood maintained builder/verifier;
- keep direct-full PRF relation;
- keep fixed transcript support;
- keep legacy verification only if tests require it;
- remove dead old proof-layout builders if not imported;
- remove stale benchmark fixtures that do not represent maintained shapes;
- keep maintained DECS fixture benchmark.

DECS/LVCS:

- keep fixed-size opening path;
- keep compact legacy verifier if needed;
- remove obsolete experimental packing modes if not tested;
- keep deterministic opening tests.

credential:

- keep maintained presets and state model;
- remove stale profiles;
- remove generated credential state files;
- keep security parameter helpers.

ntru:

- keep ring/key/sign/verify/preimage pieces used by maintained flow;
- remove demo-only CLI glue;
- remove checked-in generated keys;
- keep small tests.

prf:

- keep PRF params and grouped witness trace;
- remove Sage generation scripts from Docker context;
- keep them only under `research/` if still valuable.

Exit criteria:

- package names map cleanly to maintained proof flow;
- no stale mode appears as a maintained option;
- tests pass after each package prune.

## Stage 7: Optional Dependency Isolation

Purpose: keep research tools out of artifact.

Actions:

- remove `lattice-estimator-main` from Docker context;
- remove `parameter_search` from Docker context;
- move estimator instructions to docs if needed;
- keep security numbers as documented measured results, not Docker runtime
  estimator output;
- do not require Sage for PRF params.

Exit criteria:

- Docker build does not copy estimator/search directories;
- Docker build does not install Sage;
- README says estimator review is documented, not rerun by artifact command.

## Stage 8: Docker Artifact Construction

Purpose: add simple reproducible Docker.

Files:

```text
Dockerfile
.dockerignore
scripts/artifact-entrypoint.sh
scripts/artifact-test.sh
scripts/artifact-bench.sh
scripts/artifact-gate.sh
```

Entrypoint commands:

```text
help
test
bench <preset>
gate
all
shell
```

Script requirements:

- `set -euo pipefail`;
- write artifacts to `/artifacts` if it exists;
- use temp dirs otherwise;
- print command being run;
- fail on unknown preset;
- fail if fixed-size byte counts drift across repeated runs in gate mode.

Exit criteria:

- Docker builds from clean checkout;
- Docker runs tests;
- Docker runs maintained E2E;
- Docker writes JSON to mounted `/artifacts`.

## Stage 9: README Rewrite

Purpose: make first page match artifact.

Rewrite README around:

- maintained artifact scope;
- Docker quickstart;
- native quickstart;
- maintained presets;
- expected outputs;
- result reproduction;
- repository layout;
- non-goals.

Delete or move:

- stale command examples;
- historical profile descriptions;
- hidden flag explanations;
- local path references;
- broad research narrative.

Exit criteria:

- reviewer can run Docker command without reading source;
- README does not mention removed files as active;
- README links to canonical docs only.

## Stage 10: Final Reproducibility Gate

Purpose: verify clean artifact from scratch.

Run from clean clone or clean worktree:

```bash
go test ./...
docker build -t spruce-artifact .
docker run --rm spruce-artifact test
docker run --rm -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n512-compact96
docker run --rm -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n1024-compact96
docker run --rm -v "$(pwd)/artifacts:/artifacts" spruce-artifact bench n1024-compact125
docker run --rm -v "$(pwd)/artifacts:/artifacts" spruce-artifact gate
```

Check output:

```bash
jq '.preset,
    .issuance.paper_transcript_bytes,
    .issuance.proof_size_bytes,
    .issuance.auth_bytes,
    .showing.paper_transcript_bytes,
    .showing.proof_size_bytes,
    .showing.auth_bytes' artifacts/*.json
```

Search stale terms:

```bash
rg -n "n256|x0len70|output_audit|direct_auth|frontier|challenge-style|/home/jonas" README.md docs cmd
```

Remaining hits must be:

- legacy verification notes;
- comparison-only notes;
- deletion notes;
- internal code comments, not public instructions.

Exit criteria:

- native tests pass;
- Docker tests pass;
- Docker E2E verifies;
- fixed-size byte counts match docs;
- docs do not advertise removed modes;
- no private/generated/cache file enters Docker context.

## Commit Strategy

Use small stage-aligned commits.

Recommended commits:

```text
docs: restore Docker cleanup objective
docker: add artifact build boundary
cleanup: ignore generated and private artifacts
cli: narrow maintained command surface
cleanup: remove generated credential material
cleanup: prune stale research directories
pioP: quarantine obsolete proof modes
docs: rewrite artifact README
docker: add artifact entrypoint scripts
test: add Docker reproducibility checks
```

Do not combine:

- Dockerfile with proof-system refactors;
- result-table updates with pruning;
- package deletion with README rewrite;
- compatibility removal with transcript behavior changes.

Every commit should answer:

```text
What surface got smaller?
Which maintained command proves it still works?
```

## Aggressive Pruning Policy

This branch is for artifact cleanup. Prefer deletion over indefinite quarantine
when a file has no maintained role.

Delete quickly when all are true:

- not imported by `cmd/issuance` or `cmd/showing`;
- not required by `go test ./...`;
- not part of canonical docs;
- not required by Docker scripts;
- generated, cached, private, or local scratch output.

Quarantine only when:

- imported by maintained commands but ugly;
- needed by tests but not public;
- useful for legacy verification;
- easy deletion would cause broad refactor.

Keep only when:

- on maintained proof path;
- needed for security/result docs;
- needed for Docker reproducibility;
- small and tested.

## Implementation Agent Prompt: First Pruning Pass

Use this prompt to start an implementation agent on the cleanup branch.

```text
You are working in /home/jonas/Desktop/Spruce Folder/SPRUCE on branch
Docker-Cleanup. Goal: make the repository a small Docker-reproducible artifact
for the maintained IntGenISIS presets only. Be aggressive: prune generated,
stale, and research-only material instead of preserving it by default.

Do first pruning pass only. Do not change proof logic, transcript logic, or
security parameters in this pass.

Maintained public presets:
- n512-compact96
- n1024-compact96
- n1024-compact125

Maintained public commands:
- go run ./cmd/issuance benchmark-intgenisis-e2e -preset <preset>
- go run ./cmd/issuance gate-degree1024-maintained-presets
- go run ./cmd/showing -preset <preset>
- setup/holder/issuer issuance commands already listed in README

Stage A: Baseline
1. Run git status --short --branch.
2. Run go test ./...
3. Run go list ./... and save package list in /tmp.
4. Run go list -deps ./cmd/issuance ./cmd/showing and save maintained deps in
   /tmp.

Stage B: Ignore and remove generated/local material
1. Add or update .gitignore and .dockerignore for:
   - .gocache/
   - .private/
   - .vscode/
   - artifacts/
   - credential/issuance/
   - PIOP/ntru_keys/
   - ntru/signverify/ntru_keys/
   - lattice-estimator-main/
   - parameter_search/
   - tools/
   - _markdown_test/
2. Remove generated JSON/key/state files from the artifact branch when tracked
   or present as repo material.
3. Tests must use t.TempDir(), not checked-in generated states.

Stage C: Delete obvious public-surface clutter
1. Remove or quarantine directories not imported by maintained commands:
   - parameter_search
   - lattice-estimator-main
   - tools
   - Parameters
   - _markdown_test
2. Remove cmd/ntrucli if no maintained test or Docker command needs it.
3. Remove public docs/examples for N=256, x0len70, old challenge-style flows,
   and broad sweeps. If a mention must remain, label it legacy/comparison-only.

Stage D: Inspect reachable old packages
1. Check why ntru imports Preimage_Sampler. If tiny and easy, inline or move
   needed code under ntru/internal; otherwise keep it but hide from README and
   Docker quickstart.
2. Check why credential/cmd imports vSIS-HASH. If tiny and easy, inline or move
   needed code under internal/hash; otherwise keep it but hide from README and
   Docker quickstart.
3. Remove Sage PRF generation scripts from Docker context. Keep source params
   that Go tests need.

Stage E: Validate after each deletion group
1. Run go test ./...
2. Run go run ./cmd/issuance benchmark-intgenisis-e2e -preset n512-compact96
   -artifact-dir "$(mktemp -d)" -force
3. Run git diff --check.

Deliverables:
- .gitignore update
- .dockerignore draft
- deleted generated/stale files
- optional removal of cmd/ntrucli if safe
- short cleanup note in docs/docker_cleanup_endgoal.md or README if needed
- final status and exact validation commands run

Do not:
- edit proof math
- edit parameter values
- update paper tables
- introduce Dockerfile yet unless pruning is complete
- preserve stale files just because they might be interesting
```

## First Pruning Pass Note

This pass removes generated/local state and obvious public-surface clutter while
leaving proof logic, transcript logic, and security parameters unchanged.
`Parameters/` stays for now because maintained commands and tests still load the
checked-in source parameter JSON. `Preimage_Sampler/` and `vSIS-HASH/` stay
reachable because `ntru`, `credential`, `cmd/issuance`, and `cmd/showing` import
them; they should remain absent from README and Docker quickstarts unless later
internalization is done.

## Second Pruning Pass Note

This pass removes remaining research-only and stale public-surface files:
external paper PDFs, Sage PRF parameter-generation scripts, the dead showing
beta-audit helper, and the `demo-local` issuance subcommand. The maintained
role-separated issuance commands and `benchmark-intgenisis-e2e` remain the
artifact reproduction path. The lattice-estimator note is now explicitly
archived/comparison-only because its Python wrapper and estimator checkout are
not part of the artifact branch.

## Deep Code Pruning Pass Note

This pass removes code with no maintained-command reachability and no remaining
source references: root Poseidon text dumps, local desktop metadata, obsolete
NTRU helpers, default-path key/signature wrappers, unused command helpers,
inspection-only IntGenISIS row inventory code, LVCS test wrappers, and isolated
PIOP helper/reference paths. Remaining deadcode candidates are still referenced
by compiled proof chains or package tests, so they should be handled only in a
separate proof-logic-aware pruning pass.

## Final Acceptance Criteria

Cleanup is complete when:

- `go test ./...` passes from clean checkout;
- Docker builds from clean checkout;
- Docker does not copy private, generated, cache, or editor files;
- Docker can reproduce maintained E2E proof generation and verification;
- maintained fixed-size transcript byte counts are constant across repeated runs;
- README is enough for a fresh reviewer to run artifact;
- obsolete presets and research modes are not presented as public features;
- paper Section 6, `docs/degree1024_maintained_presets.md`, and E2E JSON agree
  on maintained sizes and theorem bits;
- comparison-only modes are explicitly labeled;
- repository tree is small enough that maintained proof path is easy to inspect.
