# Command Programs

## `cmd/issuance`

`cmd/issuance` is the canonical operational CLI for committed-message
IntGenISIS:

```bash
go run ./cmd/issuance setup-intgenisis-public
go run ./cmd/issuance setup-ntru-keys
go run ./cmd/issuance holder-commit
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n512-compact96
go run ./cmd/issuance gate-degree1024-maintained-presets
```

The maintained preset names are:

```text
n512-compact96
n1024-compact96
n1024-compact125
```

## `cmd/showing`

`cmd/showing` is the canonical presentation CLI for IntGenISIS credential
states:

```bash
go run ./cmd/showing -preset n512-compact96
go run ./cmd/showing -preset n1024-compact96
go run ./cmd/showing -preset n1024-compact125
```
