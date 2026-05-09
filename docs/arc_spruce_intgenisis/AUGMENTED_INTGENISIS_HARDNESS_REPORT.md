# Augmented IntGenISIS Hardness Estimation for ARC-SPRUCE

Date: 2026-05-09

This note explains how to estimate the hardness of the ARC-SPRUCE committed-message signature relation

```tex
A u - C w = h_{\mu,\chi}(B),
```

where

```tex
C = [C_M | A_s | I],
w = (M,s,e).
```

The central point:

```text
The Ajtai commitment makes the correct relation augmented SIS/IntGenISIS.
It does not reduce signature unforgeability to the small MSIS binding of C alone.
```

## Correct Algebraic Object

ARC verifies

```tex
A u = h_{\mu,\chi}(B) + C_M M + A_s s + e.
```

Equivalently,

```tex
[A | -C] (u,w)^T = h_{\mu,\chi}(B).
```

This means the natural direct hardness object is inhomogeneous SIS/ISIS over the augmented matrix

```tex
D = [A | -C].
```

The adversary seeks bounded witness material satisfying the rational-hash inverse equation and the augmented
preimage equation.

## Why This Is Not Just Commitment Binding

Commitment binding asks for a nonzero short vector

```tex
y != 0
```

such that

```tex
C y = 0.
```

That is the double-opening problem for the commitment.

Signature forgery asks for

```tex
A u - C w = h_{\mu,\chi}(B).
```

This can have one valid opening only. No double opening is required. So commitment MSIS binding does not
directly rule it out.

Correct relation uses `[A | -C]`, not just `C`.

## Why This Is Not Just MLWE Hiding

MLWE hiding says honest commitments hide `M` from an honest issuer:

```tex
C_M M + A_s s + e
```

is pseudorandom as a function of bounded `s,e`.

Unforgeability is different. A malicious prover can choose bounded `M,s,e` directly and only needs to satisfy
the final verification relation. So privacy does not imply preimage hardness.

## Estimator Models

No public estimator directly prices strong hinted-vSIS / IntGenISIS with rational-function oracle structure.
We therefore use SIS/ISIS proxies. These are heuristic concrete attack estimates, not full proofs.

### Model 1: Base DKLW Proxy

This is the old non-augmented DKLW estimate:

```tex
A u = h_{\mu,\chi}(B).
```

For compact BB-tran:

```tex
L_DKLW = 3 + ell_m + ell_r.
```

With `ell_m=1`, `ell_r=2`:

```tex
L_DKLW = 6.
```

Estimator instance:

```python
SIS.Parameters(
    n = N,
    m = N * L_DKLW,
    q = q,
    length_bound = beta_sig,
    norm = 2,
)
```

with

```tex
eta = sqrt(log(4*N*(1+2^lambda))/pi),
s_trap = alpha * sqrt(q) * eta,
beta_sig = s_trap * sqrt(N * L_DKLW).
```

This is DKLW-table aligned, but it is not exact ARC relation.

### Model 2: DKLW IntGenISIS Lift Proxy

Committed-message opening contributes

```tex
gamma = B * sqrt(N * (ell_M + k_s + n_c)).
```

DKLW-style bound loss:

```tex
beta_prime = beta_sig + gamma.
```

Estimator instance:

```python
SIS.Parameters(
    n = N,
    m = N * L_DKLW,
    q = q,
    length_bound = beta_prime,
    norm = 2,
)
```

This is closest to the DKLW theorem-side reduction language.

### Model 3: Augmented Tuple, Coarse Bound

Add opening columns to the matrix:

```tex
L_open = ell_M + k_s + n_c.
L_aug = L_DKLW + L_open.
```

Estimator instance:

```python
SIS.Parameters(
    n = N,
    m = N * L_aug,
    q = q,
    length_bound = beta_prime,
    norm = 2,
)
```

This directly represents the augmented matrix `[A | -C]`, but still uses the coarse DKLW bound.

### Model 4: Augmented Tuple, Heterogeneous Bound

ARC has heterogeneous bounds:

```text
u:              trapdoor Gaussian scale
mu, x0, x1:     protocol coefficient bound if proof/paper bounds them by B
M, s, e:        commitment coefficient bound B
```

Then compute block-wise l2 bounds:

```tex
beta_u = s_trap * sqrt(2N).
```

For rational-hash bounded variables:

```tex
L_rat = ell_m + ell_r + 1
beta_rat = B * sqrt(N * L_rat).
```

For commitment opening:

```tex
L_open = ell_M + k_s + n_c
gamma = B * sqrt(N * L_open).
```

Tight combined l2 bound:

```tex
beta_aug_l2 = sqrt(beta_u^2 + beta_rat^2 + gamma^2).
```

Conservative triangle bound:

```tex
beta_aug_sum = beta_u + beta_rat + gamma.
```

Estimator instance:

```python
SIS.Parameters(
    n = N,
    m = N * (2 + L_rat + L_open),
    q = q,
    length_bound = beta_aug_l2,
    norm = 2,
)
```

or, more conservatively:

```python
length_bound = beta_aug_sum
```

This is probably the most faithful ARC-specific generic lattice estimate, but it requires the paper proof
to justify heterogeneous norm accounting. Until then, treat it as an exploratory tighter estimate.

## Reference Formulas

Python-like formula block:

```python
def augmented_bounds(N, q, B, ell_M, k_s, n_c, ell_m, ell_r, alpha, lambda_bits):
    eta = sqrt(log(4*N*(1 + 2**lambda_bits)) / pi)
    s_trap = alpha * sqrt(q) * eta

    L_open = ell_M + k_s + n_c
    L_rat = ell_m + ell_r + 1
    L_dklw = 2 + L_rat
    L_aug = L_dklw + L_open

    beta_u = s_trap * sqrt(2*N)
    beta_rat = B * sqrt(N * L_rat)
    gamma = B * sqrt(N * L_open)

    beta_aug_l2 = sqrt(beta_u**2 + beta_rat**2 + gamma**2)
    beta_aug_sum = beta_u + beta_rat + gamma

    beta_dklw_coarse = s_trap * sqrt(N * L_dklw)
    beta_prime = beta_dklw_coarse + gamma

    return {
        "eta": eta,
        "s_trap": s_trap,
        "L_open": L_open,
        "L_rat": L_rat,
        "L_dklw": L_dklw,
        "L_aug": L_aug,
        "beta_u": beta_u,
        "beta_rat": beta_rat,
        "gamma": gamma,
        "beta_aug_l2": beta_aug_l2,
        "beta_aug_sum": beta_aug_sum,
        "beta_dklw_coarse": beta_dklw_coarse,
        "beta_prime": beta_prime,
    }
```

Estimator model list:

```python
models = [
    ("dklw_coarse", N * L_dklw, beta_dklw_coarse),
    ("intgen_lift", N * L_dklw, beta_prime),
    ("augmented_coarse", N * L_aug, beta_prime),
    ("augmented_hetero_l2", N * L_aug, beta_aug_l2),
    ("augmented_hetero_sum", N * L_aug, beta_aug_sum),
]
```

## Concrete Numbers

Parameters:

```text
B = 8
ell_M = 1
k_s = 2
n_c = 1
ell_m = 1
ell_r = 2
lambda = 128
```

### Coarse DKLW and IntGenISIS Bound-loss Models

| N | q | alpha | model | m | beta | beta/q | full SIS bits |
|---:|---:|---:|---|---:|---:|---:|---:|
| 512 | 1054721 | 1.15 | base DKLW | 3072 | 362512.041 | 0.343704 | 95.054 |
| 512 | 1054721 | 1.15 | IntGenISIS beta+gamma | 3072 | 362874.080 | 0.344047 | 95.054 |
| 512 | 1054721 | 1.15 | augmented coarse | 5120 | 362874.080 | 0.344047 | 95.054 |
| 1024 | 1054721 | 1.15 | base DKLW | 6144 | 514510.275 | 0.487816 | 194.448 |
| 1024 | 1054721 | 1.15 | IntGenISIS beta+gamma | 6144 | 515022.275 | 0.488302 | 194.448 |
| 1024 | 1054721 | 1.15 | augmented coarse | 10240 | 515022.275 | 0.488302 | 194.448 |
| 1024 | 1161217 | 1.23 | base DKLW | 6144 | 577416.539 | 0.497251 | 192.221 |
| 1024 | 1161217 | 1.23 | IntGenISIS beta+gamma | 6144 | 577928.539 | 0.497692 | 191.943 |
| 1024 | 1161217 | 1.23 | augmented coarse | 10240 | 577928.539 | 0.497692 | 191.943 |

Adding commitment columns and `gamma` barely changes the result because `gamma` is tiny relative to
the coarse DKLW `beta_sig`.

### Heterogeneous ARC-specific Augmented Model

For `N=512`, `q=1054721`, `alpha=1.15`:

```text
s_trap      = 6540.513
beta_u      = 209296.425
beta_rat    = 362.039
gamma       = 362.039
beta_aug_l2 = 209297.051
```

For `N=1024`, `q=1054721`, `alpha=1.15`:

```text
s_trap      = 6563.998
beta_u      = 297052.646
beta_rat    = 512.000
gamma       = 512.000
beta_aug_l2 = 297053.528
```

Estimator results:

| N | q | alpha | model | m | beta | full SIS bits |
|---:|---:|---:|---|---:|---:|---:|
| 512 | 1054721 | 1.15 | fixed target u+w | 3072 | 209296.738 | 104.470 |
| 512 | 1054721 | 1.15 | full augmented hetero l2 | 5120 | 209297.051 | 104.470 |
| 512 | 1054721 | 1.15 | full augmented hetero sum | 5120 | 210020.502 | 104.468 |
| 1024 | 1054721 | 1.15 | fixed target u+w | 6144 | 297053.087 | 214.835 |
| 1024 | 1054721 | 1.15 | full augmented hetero l2 | 10240 | 297053.528 | 214.835 |
| 1024 | 1054721 | 1.15 | full augmented hetero sum | 10240 | 298076.646 | 214.557 |

The heterogeneous model improves `N=512`, but only from about 95 bits to about 104 bits. It still does
not reach 128 bits.

## Alpha Sensitivity Under Heterogeneous Model

For `N=512`, `q=1054721`, heterogeneous augmented l2 model:

| alpha | beta | full SIS bits |
|---:|---:|---:|
| 1.15 | 209297.051 | 104.470 |
| 1.00 | 181997.611 | 106.964 |
| 0.80 | 145598.413 | 111.398 |
| 0.60 | 109199.335 | 117.500 |
| 0.50 | 90999.886 | 121.660 |
| 0.45 | 81900.201 | 124.158 |
| 0.40 | 72800.557 | 126.935 |
| 0.35 | 63700.970 | 130.542 |

So `N=512` needs roughly `alpha=0.38` even under the tighter heterogeneous model. That is not
Antrag-admissible.

## Recommended Pipeline Columns

Add a dedicated augmented hardness output, for example `signature_augmented_N*.csv`, with:

```text
N
q
log2_q
ell_M
k_s
n_c
ell_m
ell_r
B
alpha
eta
s_trap
L_open
L_rat
L_dklw
L_aug
beta_u
beta_rat
gamma
beta_dklw_coarse
beta_prime
beta_aug_l2
beta_aug_sum
model
model_n
model_m
model_beta
model_norm
model_attack
model_log2_rop
model_log2_red
model_log2_mem
model_bkz_beta
accepted
notes
```

Recommended accepted estimate policy:

```text
Final conservative claim:
  require dklw_coarse or intgen_lift >= 128,
  unless paper proof explicitly adopts heterogeneous ARC-specific norm accounting.

Exploratory ARC-specific claim:
  report augmented_hetero_l2 and augmented_hetero_sum,
  clearly label as heuristic/tighter model.
```

## Caveats

These SIS estimator rows do not prove strong hinted-vSIS or IntGenISIS. They only price generic lattice
attacks against related SIS/ISIS-shaped instances.

Remaining proof obligations:

```text
DKLW rational-function predicate conditions
strong linear independence / hinted-vSIS conditions
denominator invertibility and admissibility error
IntGenISIS oracle-model reduction
one-more committed-message issuance security
trapdoor sampler admissibility
coefficient infinity norm to l2 norm conversion
heterogeneous norm accounting if used
```

## Bottom Line

The correct augmented equation is:

```tex
[A | -C] z = h_{\mu,\chi}(B).
```

Compute it with augmented matrix dimensions and block-wise bounds.

But current numbers show:

```text
N=512:
  coarse DKLW/IntGenISIS model       about 95 bits
  heterogeneous augmented l2 model   about 104 bits

N=1024:
  coarse model                       about 192-194 bits
  heterogeneous model                about 212-215 bits
```

So augmented hardness accounting improves precision, but does not rescue `N=512` for 128-bit security under
Antrag-admissible trapdoor quality.
