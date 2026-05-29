# Protocol Surface

The maintained protocol is the committed-message IntGenISIS flow described in
[`intgenisis_protocol_h_tran.md`](intgenisis_protocol_h_tran.md).

The holder commits to the hidden message material with an Ajtai/MLWE-style
commitment:

```text
c = C_M*M + A_s*s + e
```

The issuer samples the rational-hash data:

```text
mu_sig, x0, x1
```

and signs the target:

```text
T = c + h_tran(mu_sig, x0, x1)
```

The holder proves that the commitment was well formed before the issuer signs.
The final showing proof proves possession of the signed committed-message
credential and the PRF relation without revealing `M`, `s`, `e`, `mu_sig`,
`x0`, `x1`, the NTRU preimage, or the target.

## Maintained Presets

The public IntGenISIS preset registry contains exactly:

```text
n512-compact96
n1024-compact96
n1024-compact125
```

`n512-compact96` is the maintained 96-bit engineering preset. The maintained
high-security preset is `n1024-compact125`; it is a 125+ live preset, not a
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
go run ./cmd/showing -preset n1024-compact125
```

Removed public labels and challenge-style issuance commands are invalid rather
than aliases.
