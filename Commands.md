# Commands

## Issuance

```bash
go run ./cmd/issuance setup-intgenisis-public
go run ./cmd/issuance setup-ntru-keys
go run ./cmd/issuance holder-commit
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
```

The maintained issuance flow is the committed-message IntGenISIS protocol:
the holder sends `c = C_M*M + A_s*s + e`, proves this commitment is well
formed, and the issuer signs `T = c + h_tran(mu_sig, x0, x1)`.

## Showing

```bash
go run ./cmd/showing -preset n512-compact96
go run ./cmd/showing -preset n1024-compact96
go run ./cmd/showing -preset n1024-compact125
```

The showing command requires one of the maintained IntGenISIS presets. Removed
x0len70 showing profiles are invalid.

## Benchmarks And Gates

```bash
go run ./cmd/issuance benchmark-intgenisis-e2e \
  -preset n512-compact96 \
  -artifact-dir "$(mktemp -d)" \
  -force
```

```bash
go run ./cmd/issuance gate-degree1024-maintained-presets \
  -artifact-root "$(mktemp -d)"
```

## Tests

```bash
go test ./...
```
