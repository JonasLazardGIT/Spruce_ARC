# Modulus Choice

The maintained IntGenISIS implementation uses one shared 20-bit field modulus:

```text
q = 1017857 = 2048 * 497 + 1 = 0xf8801
```

This modulus is used by:

- NTRU signing and verification
- `h_tran` target arithmetic
- SmallWood/PACS proof arithmetic
- the PRF used during showing

## Requirements

The modulus satisfies the live implementation constraints:

- `q` is prime.
- `q ≡ 1 mod 2048`, so `N=1024` NTTs work and `N=512` NTTs also work.
- `q ≡ 2 mod 3`, so the cubic PRF exponent is compatible with the field.
- `q < 2^20`, so packed transcript residues use a 20-bit ceiling.

## Maintained Degrees

The maintained ring degrees are:

```text
N=512   compact 96-bit engineering preset
N=1024  compact 96-bit and 125+ presets
```

The public preset names are:

```text
n512-compact96
n1024-compact96
n1024-compact125
```

## Protocol Interaction

The signed target is:

```text
T = c + h_tran(mu_sig, x0, x1)
c = C_M*M + A_s*s + e
```

Using one modulus avoids cross-field encodings between the holder commitment,
issuer hash data, NTRU target, proof rows, and PRF constraints. The current
implementation therefore treats `q=1017857` as shared infrastructure rather
than as an isolated signature parameter.
