# IntGenISIS Cleanup Agent Prompt

Use this prompt for behavior-preserving cleanup passes after profile-B IntGenISIS changes.

```text
You are a Codex cleanup agent working in the ARC-SPRUCE repository.

Goal:
Audit IntGenISIS code, tests, CLI paths, docs, and generated artifacts. Remove dead or remnant code only when it is provably unused or superseded by the current live profile-B path. Preserve explicit legacy behavior under legacy routing.

Start by reading:
- docs/arc_spruce_intgenisis/IMPLEMENTATION_RUNBOOK.md
- docs/arc_spruce_intgenisis/FULL_ALIGNMENT_PLAN.md
- credential/intgenisis_*.go
- PIOP/intgenisis_*.go
- cmd/issuance/*
- cmd/showing/*
- issuance/intgenisis.go
- commitment/target.go

Current live IntGenISIS invariants:
- profile B is the only live profile;
- semantic M is ternary and includes m plus ternary key slots;
- issuer response does not serialize T or a full signature bundle;
- showing uses packed coefficient rows, supported odd signed-radix u shortness, compressed M/s/e carriers, YView/YHat, and no live MHat/SHat/EHat rows;
- presentation contains nonce, tag, proof, profile, and public metadata only;
- verifier replay state rejects repeated nonce/tag;
- R121/L2 and unsafe shadow lookup are rejected for IntGenISIS.

Classification rules:
1. Keep live IntGenISIS code if it is used by issuance, showing, presets, verifier state, benchmark, or tests.
2. Keep legacy code only if reachable through explicitly legacy commands, explicitly legacy tests, or docs/arc_spruce_old references.
3. Remove or quarantine code that is only an obsolete IntGenISIS transition path: old full-u bridge attempts, stale serialized T/signature bundle handling, old bounded [-8,8] live assumptions, old N/2 key packing, or obsolete benchmark artifacts.
4. Do not rename legacy r0/r1/LHL concepts into IntGenISIS objects.
5. Do not delete generated benchmark outputs silently. Add ignore rules and keep only curated compact preset evidence when docs reference it.
6. Do not revert unrelated user changes.

Required workflow:
- Map live IntGenISIS entrypoints and referenced helpers with rg and go test.
- Produce a deletion/quarantine list before editing.
- Make small commits, each passing focused tests before moving on.
- Update docs only after code and tests reflect the final state.
```

Focused verification:

```bash
go test ./credential -run IntGenISIS
go test ./PIOP -run 'IntGenISIS|SmallField|SignatureShortness|TransformBridge'
go test ./cmd/issuance -run 'IntGenISIS|BenchmarkIntGenISIS|Sweep|Preset'
go test ./cmd/showing -run IntGenISIS
```
