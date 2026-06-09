# IntGenISIS Protocol And `h_tran` Inputs

This note describes the current committed-message IntGenISIS issuance and
showing protocol as implemented in the repository. It is intentionally
separate from the older direct shared-randomness `bb_tran` surface where the
holder message `mu = m || k` entered the rational hash directly.

The current IntGenISIS protocol has a different shape:

```text
holder message/opening  -> hidden Ajtai/MLWE commitment c
issuer hash data        -> rational BB-tran value h_tran(mu_sig, x0, x1)
issuer signature target -> T = c + h_tran(mu_sig, x0, x1)
showing proof           -> proves the whole equation without revealing c, T,
                           message, signature preimage, or hash witnesses
```

The most important naming point is this:

```text
M, m, k      holder semantic message material
mu_sig       issuer-sampled rational-hash input
```

`mu_sig` is not the holder's PRF key, not the semantic message, and not the old
shared-randomness `mu = m || k`. In the IntGenISIS code it is an issuer-side
uniform polynomial used only by the BB-tran rational hash layer.

## Algebraic Setting

All main equations live over the cyclotomic ring:

```text
R_q = Z_q[X] / (X^N + 1)
```

The current IntGenISIS profiles use the shared modulus:

```text
q = 1,017,857
```

and maintained profile-dependent dimensions:

```text
profile B: N=512,  ell_x0=2, live B=1
profile C: N=1024, ell_x0=1, live B=1
```

All profiles currently use:

```text
ell_mu_sig = 1
ell_x1     = 1
n_c        = 1
```

The public BB-tran matrix/vector has length:

```text
B = (B0, B1, B2[0], ..., B2[ell_x0-1], B3)
len(B) = 3 + ell_x0
```

In code this shape is enforced by `SampleSignatureHashData` and
`ComputeIntGenISISTarget` in
[`issuance/intgenisis.go`](../issuance/intgenisis.go).

## Maintained Profile Parameters

The live profile registry contains only profile B and profile C. Profile B is
the compact 96-bit engineering profile; profile C is the degree-1024 profile
used by both the compact 96-bit and maintained 125+ presets.

| Profile | Used By | N | q | ell_M | k_s | n_c | B | ell_mu_sig | ell_x0 | ell_x1 | Signature preimage |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `intgenisis_profile_b` | `n512-compact96` | 512 | 1,017,857 | 1 | 2 | 1 | 4 | 1 | 2 | 1 | 2 |
| `intgenisis_profile_c` | `n1024-compact96`, `n1024-compact125` | 1024 | 1,017,857 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 2 |

The commitment part has matrix shape:

```text
C_M in R_q^{n_c x ell_M}
A_s in R_q^{n_c x k_s}
M   in R_q^{ell_M}
s   in R_q^{k_s}
e,c in R_q^{n_c}
```

So all maintained profiles commit to one target row (`n_c=1`) and one packed
semantic message row (`ell_M=1`). Profile B spends two randomness rows
(`k_s=2`) with live ternary `s,e`. Profile C uses one randomness row and the
larger ring dimension supplies the security margin while keeping the target and
rational-hash shape narrow. In both profiles, ordinary message coefficients are
ternary and the PRF key is a separate 48-coefficient `[-4,4]` seed tail inside
the committed message row.

The implementation records the following commitment-security estimates for the
Ajtai/MLWE commitment `c = C_M*M + A_s*s + e`:

| Profile | MLWE hiding bits | Hiding attack | MSIS binding bits | Statistical hiding | Statistical binding slack |
| --- | ---: | --- | ---: | --- | ---: |
| `intgenisis_profile_b` | 131.113 | `dual_hybrid` | infinite in rough estimator | no | 5,415.133 bits |
| `intgenisis_profile_c` | 131.113 | `dual_hybrid` | infinite in rough estimator | no | 13,255.516 bits |

These are not statistical-hiding commitments. The hiding claim is
computational MLWE hiding. The statistical-hiding slack is negative for both
profiles because bounded `s,e` do not provide enough entropy to statistically
cover the full `R_q^{n_c}` codomain plus the 128-bit margin. Binding is tracked
through the MSIS model on `[C_M | A_s | I]`; profile C's tighter ternary bound
and larger `N` make the rough estimator return no finite short-kernel attack at
the configured bound.

## Maintained 96-bit and 125-bit Presets

The public preset registry contains:

```text
n512-compact96
n1024-compact96
n1024-compact125
```

The preset knobs split into two groups:

- Issuance knobs prove the commitment opening and semantic constraints before
  the issuer signs. Issuance intentionally keeps the dense-compatible transcript
  path: no PRF companion rows, no signature-shortness rows, no compressed rows,
  and no replay projection.
- Showing knobs prove the final credential relation, including the hidden
  NTRU preimage, rational-hash witnesses, commitment contribution, and PRF tag.
  Showing therefore adds shortness rows, PRF companion rows, replay projection,
  and the small-field 2025-1085 transcript mode.

| Preset | Profile | Target | LVCS cols | Leaves | eta | theta | rho | ell/ell' | kappa | Showing shortness | Compression | Projection |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | ---: | --- |
| `n512-compact96` | B | 96 | 36 | 262,144 | 36 | 5 | 1 | 7/1 | `{0,0,6,8}` | R7/L5 | 0 | `project_u_digits_and_y_view_v3` |
| `n1024-compact96` | C | 96 | 43 | 230,208 | 40 | 5 | 1 | 7/1 | `{0,0,6,11}` | R7/L5 | 1 | `project_u_digits_y_w_residual_v5` |
| `n1024-compact125` | C | 125+ | 46 | 608,192 | 48 | 7 | 1 | 9/1 | `{0,0,0,5}` | R11/L4 | 1 | `project_u_digits_y_w_residual_v5` |

The main effects of these knobs are:

- `LVCS cols` controls the column width of the vector commitment layer. Larger
  values increase committed-column capacity and can reduce proof-shaping
  pressure, but they raise commitment work.
- `Leaves` is the explicit-domain size used by the PACS/SmallWood transcript.
  The 125+ preset spends many more leaves to keep theorem accounting above the
  target with low per-round grinding.
- `eta`, `theta`, `rho`, `ell`, `ell'`, and `kappa` are the SmallWood theorem
  and repetition parameters. They determine how rows are bucketed into rounds
  and how the live theorem bits are computed.
- `Showing shortness` decomposes the NTRU preimage digits so the showing proof
  can prove the signature is short without revealing the preimage. `R7/L5`
  means radix 7 with 5 digits; `R11/L4` uses a wider radix and fewer digits.
- `Compression=1` packs some profile-C showing rows so degree-1024 proofs stay
  below the maintained byte gates. Issuance keeps compression off.
- `Projection` is the replay constraint shape. The degree-1024 presets use the
  residual projection because the proof must connect the NTRU preimage,
  commitment contribution, and rational-hash target without revealing any of
  those internal values.

## Public Setup

The common public parameters include:

```text
R_q parameters: N, q
BB-tran parameters: B0, B1, B2[], B3
commitment matrices: C_M, A_s
commitment bound: B
hash relation label: bb_tran
PRF parameters
SmallWood/PACS showing parameters
issuer NTRU public key
```

The issuer additionally holds the NTRU trapdoor/signing key. The holder does
not choose `B`, `C_M`, `A_s`, or the NTRU public key. These are setup / issuer
infrastructure values that become verifier-facing public parameters.

## Holder Commitment Phase

The holder chooses or receives the semantic credential data and samples the
commitment opening:

```text
m      attribute/message rows
k      hidden PRF seed row: 48 coefficients in [-4,4], packed base-9 into 8 PRF lanes
M      packed semantic message row, with M = m + k in the implemented layout
s      Ajtai/MLWE commitment randomness
e      Ajtai/MLWE commitment error
```

The holder then computes the target-shaped MLWE/Ajtai commitment:

```text
c = C_M * M + A_s * s + e
```

In code this is the `PrepareIntGenISISCommit` path:

```text
issuance.IntGenISISInputs{M, MAttr, K, S, E}
commitment.CommitMessage(...)
```

The holder sends only the public commitment request:

```text
Com = c
```

The holder keeps:

```text
M, m, k, s, e
```

secret.

## Holder Pre-Sign Proof

Before the issuer signs anything, the holder proves in zero knowledge that the
commitment is well formed. The pre-sign proof statement binds:

```text
c = C_M * M + A_s * s + e
M = m + k
m, k, s, e are in the required coefficient ranges
semantic layout constraints hold
```

The issuer verifies this proof against the public commitment `c`, public
matrices `C_M, A_s`, and the public bounds. This phase does not contain the
issuer's `h_tran` randomness. There is no IntGenISIS issuer-challenge artifact
analogous to the older shared-randomness flow.

Implementation pointer:

```text
cmd/issuance/flow_helpers.go: holderProveIntGenISIS
cmd/issuance/flow_helpers.go: issuerVerifySignIntGenISIS
PIOP.BuildIntGenISISPreSign / PIOP.VerifyIntGenISISPreSign
```

## The Rational Hash `h_tran`

After accepting the pre-sign proof, the issuer samples the BB-tran
rational-hash data:

```text
mu_sig in R_q
x0     in R_q^{ell_x0}
x1     in R_q
```

The current sampler draws these polynomials uniformly over `R_q` and resamples
`x1` until the denominator is invertible:

```text
B3 - x1 is invertible in R_q
```

The inverse witness is:

```text
Z = (B3 - x1)^(-1)
```

Then the rational hash value is:

```text
h_tran(mu_sig, x0, x1)
  = B0 + B1 * mu_sig + sum_i B2[i] * x0[i] + Z
```

with:

```text
Z * (B3 - x1) = 1
```

This is called "rational" because one term is an inverse in the ring, not just
a linear polynomial term. The hash input ownership is:

| Value | Generated By | Revealed To Holder? | Public In Final Showing? | Role |
| --- | --- | --- | --- | --- |
| `B0, B1, B2[], B3` | setup / public params | yes | yes | public rational-hash parameters |
| `mu_sig` | issuer | yes, in issuer response | no, hidden witness | linear BB-tran input |
| `x0[]` | issuer | yes, in issuer response | no, hidden witness | linear BB-tran input |
| `x1` | issuer | yes, in issuer response | no, hidden witness | denominator input |
| `Z` | derived from `x1` and `B3` | not serialized as response data in the current path | no, hidden witness | inverse witness |

The holder's semantic message is not an input to this `h_tran` call. The
holder's contribution is the additive commitment `c`.

## Issuer Signature Target

The issuer computes:

```text
T = c + h_tran(mu_sig, x0, x1)
```

or expanded:

```text
T = C_M*M + A_s*s + e
  + B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z
```

The issuer then uses the NTRU trapdoor sampler to produce a short preimage:

```text
u = (s1, s2)
```

satisfying the public signature equation:

```text
A * u = T
```

In the implemented NTRU representation, `A` is formed from the public NTRU key
row. The benchmark helper builds:

```text
A = (-h, 1)
```

so the verification equation is the corresponding public-key linear relation
on `(s1, s2)` against `T`.

The issuer response sent to the holder includes:

```text
mu_sig
x0
x1
signature preimage coefficients s1, s2
issuer NTRU public key
```

The current IntGenISIS response deliberately does not serialize `T`. The holder
can recompute `T`, and the final showing proof does not reveal it.

## Holder Finalization

The holder finalizes by recomputing its commitment:

```text
c = C_M*M + A_s*s + e
```

checking that it matches the original commit request, then recomputing:

```text
Z = (B3 - x1)^(-1)
T = c + B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z
```

and verifying the issuer's signature against `T`.

The stored IntGenISIS credential state keeps:

```text
M, m, k, s, e
mu_sig, x0, x1
s1, s2
NTRU public key
public parameter paths and profile metadata
```

It intentionally does not store:

```text
c
T
old r0/r1 split randomness
old LHL metadata
```

This matches [`credential/intgenisis_state.go`](../credential/intgenisis_state.go).

## Showing Protocol

During showing, the holder proves knowledge of a credential state satisfying
the full issuance equation without revealing the target, the message, the PRF
key, the signature preimage, or the rational-hash witnesses.

The private showing witness contains:

```text
u = (s1, s2)
M, m, k
s, e
mu_sig, x0, x1
Z = (B3 - x1)^(-1)
```

The public showing inputs contain:

```text
A                  issuer NTRU public-key matrix
B                  public BB-tran parameters
C_M, A_s           public commitment matrices
nonce, tag         verifier/application showing challenge material
coefficient bounds
profile and relation metadata
```

The proof enforces the following core equations:

```text
M = m + k

Y = C_M*M + A_s*s + e

Z * (B3 - x1) = 1

A*u = Y + B0 + B1*mu_sig + sum_i B2[i]*x0[i] + Z

tag = PRF(k, nonce)
```

where `Y` is the hidden commitment contribution. Notice that final showing does
not need to publish the issuance-time commitment `c`. The proof reconstructs
the same commitment contribution privately as `Y`, and the NTRU signature
equation binds it to the issuer-signed target. If a prover tried to show a
different message, it would need another bounded opening producing the same
hidden `Y` inside a valid signed target, which is exactly the binding surface
the Ajtai/MLWE commitment and signature relation are meant to protect.

The SmallWood/PACS proof commits to row encodings of these witnesses and checks
the relations through the current small-field 2025-1085-aligned constraint
system. The transcript exposes proof commitments, openings, challenges, the
public tag, and public parameters; it does not expose `T`, `Y`, `mu_sig`, `x0`,
`x1`, `Z`, `M`, `k`, `s`, `e`, `s1`, or `s2`.

## Ownership Summary

| Phase | Holder Generates | Issuer Generates | Public / Verifier-Facing |
| --- | --- | --- | --- |
| Setup | none, unless holder participates in CRS generation | NTRU keypair may be issuer-side | `N, q, live B=1, C_M, A_s, PRF params, proof params, NTRU public key` |
| Commit | `m, k, M, s, e, c` | none | `c` in commit request |
| Pre-sign proof | ZK proof of `c` opening and semantic constraints | verifies proof | proof transcript for issuer |
| Hash/sign | none new | `mu_sig, x0, x1`, derived `Z`, target `T`, signature `u` | response to holder contains `mu_sig, x0, x1, u, NTRU public key`; `T` is not serialized |
| Finalize | recomputes `c, Z, T`; verifies signature | none | credential state remains holder-local |
| Showing | ZK proof over state; PRF tag from `k` and nonce | none, except verifier may provide nonce | verifier sees public params, nonce, tag, proof |

## Contrast With The Older Shared-Randomness Flow

The older `bb_tran` issuance relation looked like:

```text
A*u = B0 + B1*mu + sum_i B2[i]*r0_i + Z
Z*(B3-r1) = 1
```

where `mu = m || k` was directly inside the rational hash, and holder/issuer
randomness was split into values like `r0H/r1H` and `r0I/r1I`.

The current IntGenISIS relation instead separates roles:

```text
holder semantic material -> c = C_M*M + A_s*s + e
issuer rational hash data -> h_tran(mu_sig, x0, x1)
signature target -> T = c + h_tran(mu_sig, x0, x1)
```

So if someone asks "what are the inputs to `h_tran`?" in the current
IntGenISIS protocol, the precise answer is:

```text
h_tran inputs:
  public B = (B0, B1, B2[], B3)
  issuer-sampled mu_sig
  issuer-sampled x0[]
  issuer-sampled x1
  derived inverse Z = (B3 - x1)^(-1)

not h_tran inputs:
  holder message m
  holder PRF seed k
  packed holder message M
  Ajtai randomness s
  Ajtai error e
```

The holder values enter the final target through the additive commitment
contribution `c`, not through the rational hash input slots.

## Implementation Caveat: Issuer Randomness

The protocol role is clear: `mu_sig`, `x0`, and `x1` are issuer-generated
signature-hash data. The current CLI/benchmark implementation calls:

```text
issuance.SampleSignatureHashData(..., newLocalRNG(0))
```

inside `issuerVerifySignIntGenISIS`.

That is suitable for deterministic local fixtures and repeatable benchmarks,
but it is not the right production entropy source. A production implementation
should replace this with a CSPRNG or a domain-separated transcript derivation
that binds the public parameters, commitment request, pre-sign proof, issuer
identity, and session context. The replacement should preserve the same
ownership and equations:

```text
issuer controls mu_sig, x0, x1
x1 is accepted only when B3-x1 is invertible
holder receives mu_sig, x0, x1 and recomputes Z and T
showing proof keeps them hidden from the verifier
```
