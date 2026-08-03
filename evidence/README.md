# SPRUCE v2 paper evidence

`spruce-evidence` freezes the executable v2 preset registry and the nine final
three-run `benchmark-intgenisis-e2e` baselines into the deterministic
`spruce.paper-artifact-lock.v2` lock. It also renders the paper's tracked
`generated/v2_macros.tex` and `generated/v2_tables.tex` inputs. The lock has no
wall-clock export timestamp and contains no absolute checkout paths.

For every canonical preset, run the benchmark three times and preserve its
reports at exactly:

```text
artifacts/smallwood-salted-v2/<canonical-id>/runs/run-01.json
artifacts/smallwood-salted-v2/<canonical-id>/runs/run-02.json
artifacts/smallwood-salted-v2/<canonical-id>/runs/run-03.json
```

No fourth JSON report is accepted in `runs/`. Aggregate all nine presets with:

```sh
go run ./cmd/spruce-evidence baseline --spruce-dir .
```

During incremental measurement, add
`--preset <exact-canonical-v2-preset-id>` to process one preset. The operation
strictly validates each report against its preset and requires identical byte,
geometry/relation, security, and environment projections. It then writes:

```text
artifacts/smallwood-salted-v2/<canonical-id>/benchmark-intgenisis-e2e.json
artifacts/smallwood-salted-v2/<canonical-id>/benchmark-intgenisis-e2e-baseline.json
```

The canonical report is a byte-for-byte copy of run 02; it is never rewritten
to look like a synthetic benchmark execution. The sidecar binds the SHA-256
digest and timestamp of every run and records independent scalar medians for
all six setup timings plus issuance/showing proving and verification timings.

Generate final evidence only after those canonical reports and sidecars exist:

```sh
go run ./cmd/spruce-evidence export \
  --spruce-dir . \
  --paper-generated-dir ../GIT_Paper/generated
```

Final export revalidates each sidecar from its three run files, requires the
canonical report to still equal run 02, and binds all 27 run SHA-256 digests.
The lock records `run_count=3`, the
`independent_scalar_median_of_three_v2` aggregation identity, the sidecar
digests, and an independently domain-separated digest of the 27-run set.

For initial wiring only, `--allow-pending` emits a lock whose status is
explicitly `pending` and whose missing preset entries carry a reason. Final
validation rejects that lock unless the same bootstrap flag is supplied.

Validate the source tree, reports, lock digest, and tracked TeX with:

```sh
go run ./cmd/spruce-evidence validate \
  --spruce-dir . \
  --paper-generated-dir ../GIT_Paper/generated
```

`--spruce-dir` may be omitted when `SPRUCE_DIR` is set. A non-default report
root can be selected with `--reports-dir`; relative report roots are resolved
below the SPRUCE checkout. No repository location is compiled into the tool.

JSON readers reject unknown fields, trailing values, non-v2 identities,
manifest mismatches, and report/preset transcript mismatches. The source-tree
digest covers protocol source, tests, scripts, parameter JSON, and repository
documentation while deliberately excluding `.git`, ignored `artifacts/`, and
the user-owned `TODO.md` and `results.md` notes.

Final report ingestion also requires exact independent-selective tape
accounting (`tape_bytes`, count and width), leaf-encoding version 2, full root
width, and a live zero-knowledge-eligibility result. Those values are copied
into the lock rather than inferred from a preset.
