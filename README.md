# SPRUCE

This repository contains the maintained ARC-SPRUCE IntGenISIS prototype. The
public surface is intentionally narrow: committed-message issuance, IntGenISIS
showing, and the three promoted compact presets.

## Maintained Presets

```text
n512-compact96
n1024-compact96
n1024-compact125
```

`n512-compact96` is the compact 96-bit engineering preset. The maintained
high-security preset is `n1024-compact125`; it is a live 125+ preset, not a
128-bit claim.

## Commands

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

The showing CLI now requires a maintained IntGenISIS preset. Old x0len70
showing profiles, challenge-style issuance commands, and sweep selectors are
not public interfaces.

## Useful Checks

```bash
go test ./...
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n512-compact96 -artifact-dir "$(mktemp -d)" -force
go run ./cmd/issuance gate-degree1024-maintained-presets -artifact-root "$(mktemp -d)"
```

See [docs/protocol.md](docs/protocol.md),
[docs/intgenisis_protocol_h_tran.md](docs/intgenisis_protocol_h_tran.md),
[docs/intgenisis_lattice_security.md](docs/intgenisis_lattice_security.md),
[docs/modulus_choice.md](docs/modulus_choice.md), and
[docs/degree1024_maintained_presets.md](docs/degree1024_maintained_presets.md)
for the canonical protocol and parameter notes.
