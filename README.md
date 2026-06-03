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
go run ./cmd/issuance setup-intgenisis-public -preset n1024-compact125
go run ./cmd/issuance setup-ntru-keys -preset n1024-compact125
go run ./cmd/issuance holder-commit -preset n1024-compact125
go run ./cmd/issuance holder-prove
go run ./cmd/issuance issuer-verify-sign
go run ./cmd/issuance holder-finalize
go run ./cmd/issuance benchmark-intgenisis-e2e -preset n1024-compact125
go run ./cmd/issuance gate-degree1024-maintained-presets
go run ./cmd/showing -preset n1024-compact125
```

Commands that create preset-dependent material require one of the maintained
IntGenISIS presets. Tuning flags and research selectors are not public
interfaces.

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
