# Claim Reproduction Map

This file maps reviewer-facing paper claims to the artifact command and JSON
field that reproduces them.

| Claim | Command | JSON field or check |
| --- | --- | --- |
| Maintained preset list | `go run ./cmd/issuance benchmark-intgenisis-e2e -h` | supported `-preset` names |
| `n512-compact96` showing transcript bytes | `./scripts/validate-artifact.sh` | `showing.paper_transcript_bytes == 21754` |
| `n1024-compact96` showing transcript bytes | `./scripts/validate-artifact.sh` | `showing.paper_transcript_bytes == 25882` |
| `n1024-compact125` showing transcript bytes | `./scripts/validate-artifact.sh` | `showing.paper_transcript_bytes == 34853` |
| Degree-1024 96-bit theorem accounting | `go run ./cmd/issuance gate-maintained-presets` | `showing.theorem_total_bits >= 96` |
| Degree-1024 125+ theorem accounting | `go run ./cmd/issuance gate-maintained-presets` | `showing.theorem_total_bits >= 125` |
| SmallWood 2025 transcript mode | any benchmark JSON report | `showing.transcript_security_status == "smallwood_2025_1085_live"` |
| Fixed-size transcript byte stability | repeat benchmark for same preset | `showing.paper_transcript_bytes` unchanged |
| Replay protection | any benchmark JSON report | `replay_rejected == true` |
| Maintained public CLI surface | `go run ./cmd/issuance help` and `go run ./cmd/showing -h` | listed commands and flags |
| Go code health | `./scripts/validate-artifact.sh` | tests, vet, staticcheck, and deadcode all pass |

The primary paper-facing size metric is `paper_transcript_bytes`. The JSON
`proof_bytes` field measures the serialized implementation proof and is useful
for implementation inspection, but it is not the paper transcript byte count.

