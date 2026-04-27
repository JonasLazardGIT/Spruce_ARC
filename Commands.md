# Commands

## Showing

Live commands:

```bash
go run ./cmd/showing
go run ./cmd/showing -showing-profile showing_n512_x0len70_100
go run ./cmd/showing -showing-profile showing_n512_x0len70_128
go run ./cmd/showing -showing-profile showing_n1024_x0len70_100
```

The no-flag command resolves to `showing_n512_x0len70_100`. All maintained
profiles use `x0_len=70` and the optimized relation
`aggregate_inline_target_replay_compact_research`.

The three maintained tuples are documented in
[docs/current_showing_defaults.md](docs/current_showing_defaults.md). The
showing reports include `ring_degree`, `x0_len`, theorem bits, transcript
buckets, replay selector geometry, and the optimized paper transcript byte
count.

## Artifact Regeneration

Canonical showing artifacts are committed for:

- `N=512, x0_len=70`
- `N=1024, x0_len=70`

Use `cmd/issuance` with explicit output paths when regenerating artifacts. The
issuer and showing verifier validate that public params, B metadata, NTRU
material, credential state, and signatures match the selected ring degree and
`x0_len`.

## Tests

```bash
go test ./ntru/io ./credential ./cmd/issuance ./cmd/showing ./PIOP
```

## Pruned Presets

Removed research labels are invalid and are not mapped to the optimized
profile. Profile names are the public showing selector.
