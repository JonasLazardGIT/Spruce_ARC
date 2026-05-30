# IntGenISIS Lattice Security Estimates

Run date: 2026-05-29

This note records the lattice-estimator checks for the maintained IntGenISIS
profiles:

```text
intgenisis_profile_b  N=512   used by n512-compact96
intgenisis_profile_c  N=1024  used by n1024-compact96 and n1024-compact125
```

The reproducible command is:

```bash
python3 tools/intgenisis_lattice_security_estimator.py --pretty
```

The estimator source is `malb/lattice-estimator` at commit
`14c2c10e6f2f7a39072130627b2cec5495704701`, using rough estimates.

## Profile Inputs

| Profile | N | q | ell_M | k_s | n_c | Commitment B | ell_x0 | NTRU beta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | 512 | 1,017,857 | 1 | 2 | 1 | 4 | 2 | 6,002 |
| `intgenisis_profile_c` | 1024 | 1,017,857 | 1 | 1 | 1 | 1 | 1 | 6,142 |

## Commitment Security

The commitment model is the implemented Ajtai/MLWE commitment:

```text
c = C_M*M + A_s*s + e
```

with `M`, `s`, and `e` bounded by the profile commitment bound.

| Profile | MLWE hiding bits | MLWE attack | MSIS binding bits | Statistical hiding | Statistical hiding slack | Statistical binding slack |
| --- | ---: | --- | ---: | --- | ---: | ---: |
| `intgenisis_profile_b` | 203.816 | `usvp` | 586.336 | no | -5,605.032 | 1,846.913 |
| `intgenisis_profile_c` | 131.113 | `dual_hybrid` | `inf` | no | -17,446.071 | 13,303.111 |

Interpretation:

1. Neither maintained commitment is statistically hiding. The hiding claim is
   computational MLWE hiding.
2. Profile B has ample margin for a 96-bit target, but its live use should
   remain the 96-bit engineering preset.
3. Profile C has enough MLWE hiding margin for the maintained 125+ preset.
4. MSIS binding is not the bottleneck in either maintained profile. Profile C
   returns no finite rough-estimator attack at the configured commitment bound.

## NTRU/vSIS Signature Surface

The showing proof uses the issuer signature relation:

```text
A*u = T
A = (-h, 1)
u = (s1, s2)
```

The estimator model is a SIS/ISIS surrogate over `R_q^{1 x 2}`. It estimates
short-preimage hardness and does not model trapdoor leakage.

| Profile | SIS L∞ bound | SIS L∞ bits | C-style L2 bound | SIS L2 bits |
| --- | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | 6,002 | 103.368 | 55,506.651 | 119.428 |
| `intgenisis_profile_c` | 6,142 | 240.900 | 78,498.259 | 276.524 |

Interpretation:

1. Profile B clears the 96-bit target under both modeled NTRU/vSIS views.
   It does not clear a 125-bit target under the L∞ beta model.
2. Profile C is well above the 125-bit target under both modeled views.
3. The L∞ beta model is the conservative number to track for showing, because
   the proof exposes a public coefficient bound through `IntGenISIS.signature_bound`.

## `h_tran` Rational Hash Surface

The live rational-hash equation is:

```text
h_tran(mu_sig, x0, x1)
  = B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z
Z * (B3 - x1) = 1
```

The current implementation samples `mu_sig`, `x0`, and `x1` uniformly over
`R_q`, and `Z` is the inverse of `B3-x1`. There is no range bound on `Z`.
Because of that, the live `h_tran` relation is not directly expressible as the
kind of bounded SIS/vSIS instance that `lattice-estimator` estimates.

For orientation only, the estimator script also computes a bounded-linear
surrogate where deltas for `mu_sig`, `x0`, and `Z` are artificially bounded by
`14`, matching two differences of old `[-7,7]` seed-bounded variables. This is
not a proof of live `h_tran` security.

| Profile | Surrogate rows | Surrogate L∞ bits | Surrogate L2 bits |
| --- | ---: | ---: | ---: |
| `intgenisis_profile_b` | 4 | 585.168 | 450.556 |
| `intgenisis_profile_c` | 3 | `inf` | `inf` |

Interpretation:

1. The public linear part of `h_tran` is not the limiting lattice surface when
   all deltas are assumed bounded.
2. The live rational inverse relation still needs to be treated separately:
   the current estimator result does not prove a bounded-vSIS reduction for
   uniform `mu_sig`, `x0`, `x1`, and unbounded `Z`.
3. In the maintained protocol, holder binding does not rely on the holder
   finding an `h_tran` collision. The holder does not choose the issuer
   rational-hash data. The binding path is the commitment opening, the
   issuer-signed NTRU/vSIS target, and the showing proof equations.

## Verdict

Profile B is consistent with the maintained 96-bit engineering target:

```text
commitment MLWE hiding: 203.816 bits
commitment MSIS binding: 586.336 bits
NTRU/vSIS L∞ short-preimage: 103.368 bits
```

Profile C is consistent with the maintained degree-1024 96-bit and 125+ target:

```text
commitment MLWE hiding: 131.113 bits
commitment MSIS binding: inf in rough estimator
NTRU/vSIS L∞ short-preimage: 240.900 bits
```

The main caveat is `h_tran`: the local lattice estimator can only provide a
bounded-linear surrogate, not a proof for the live rational inverse relation
with uniform `R_q` witnesses and unbounded inverse witness `Z`.
