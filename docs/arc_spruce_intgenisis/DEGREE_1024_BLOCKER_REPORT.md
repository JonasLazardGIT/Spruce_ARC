# ARC-SPRUCE Degree-1024 Parameter Blocker Report

Date: 2026-05-09

This note records why the current ARC-SPRUCE IntGenISIS/MLWE parameter search is pushed to ring degree
`N=1024` when we keep the current paper shape:

```text
t = n = n_c = 1
ell_M = 1
ell_m = 1
ell_r = 2
```

The short version is:

```text
The blocker is the DKLW/BB-tran short-preimage SIS/IntGenISIS estimate.
It is not commitment hiding, not commitment binding, not SmallWood row accounting.
```

At `N=512`, the correct l2 short-preimage estimate is only about 95 bits under the coarse
DKLW bound. Even with a tighter ARC-specific heterogeneous augmented bound, it rises only to about
104 bits. At `N=1024`, the same mechanism gives about 190 to 215 bits depending on the bound model.

## Current Paper Target

ARC-SPRUCE does not sign the bare DKLW target

```tex
A u = h_{\mu,\chi}(B).
```

The current paper signs the committed-message target

```tex
A u = h_{\mu,\chi}(B) + C_M M + A_s s + e.
```

The commitment is

```tex
c = C_M M + A_s s + e.
```

The BB-tran rational-hash part is

```tex
h_{\mu,\chi}(B) = B_0 + B_1 \mu + B_2 x_0 + Z,
Z = (B_3 - 1_n x_1)^{-1}.
```

The full signed target is therefore

```tex
T = B_0 + B_1 \mu + B_2 x_0 + Z + C_M M + A_s s + e.
```

The showing relation reconstructs this target internally. The public showing statement does not expose
the original issuance commitment `c`; the proof carries the opening `(M,s,e)` and checks the target
equation directly.

## Security Layers

The parameter search must separate four different security questions.

### 1. Commitment Hiding

The commitment hides `M` because, for fixed `M`,

```tex
c = C_M M + A_s s + e
```

is a deterministic offset plus `A_s s + e`. Under the MLWE hiding assumption, this is computationally
indistinguishable from uniform plus that offset, hence independent of `M`.

This protects issuer-view privacy. It is not the signature unforgeability bottleneck.

### 2. Commitment Binding

Two bounded openings of the same commitment give

```tex
C_M(M-M') + A_s(s-s') + (e-e') = 0.
```

This is a short MSIS relation for

```tex
[C_M | A_s | I].
```

This prevents equivocation of the committed message. It does not prove hardness of finding a new
signature preimage for a fresh committed target.

### 3. DKLW/BB-tran Short-Preimage Hardness

The DKLW compact BB-tran layer has tuple length

```tex
L_DKLW = 3 + ell_m + ell_r.
```

For the compact ARC profile:

```tex
ell_m = 1
ell_r = 2
L_DKLW = 6.
```

The standard DKLW-style estimator instance is

```python
SIS.Parameters(
    n = N,
    m = N * (3 + ell_m + ell_r),
    q = q,
    length_bound = beta_sig,
    norm = 2,
)
```

with

```tex
eta = sqrt(log(4*N*(1 + 2^lambda)) / pi),
s_trap = alpha * sqrt(q) * eta,
beta_sig = s_trap * sqrt(N * (3 + ell_m + ell_r)).
```

This is the current concrete bottleneck.

### 4. Committed-message IntGenISIS / One-more Issuance Security

The final ARC issuance relation is not bare DKLW. It is an augmented target:

```tex
A u = h_{\mu,\chi}(B) + C w,
w = (M,s,e),
C = [C_M | A_s | I].
```

Equivalently,

```tex
[A | -C] (u,w)^T = h_{\mu,\chi}(B).
```

This is an augmented SIS/ISIS-shaped assumption. It is the right final assumption for the raw
committed-message credential relation.

The DKLW IntGenISIS lift accounts for the committed-message offset with

```tex
gamma = B * sqrt(N * (ell_M + k_s + n_c)),
beta_prime = beta_sig + gamma.
```

For current parameters, `gamma` is tiny compared to `beta_sig`, so this does not change the security
estimate much.

## Numeric State

Local estimator probe used the malb/lattice-estimator code present at `lattice-estimator-main`.

Parameters:

```text
q = 1054721
B = 8
ell_M = 1
ell_m = 1
ell_r = 2
n_c = 1
lambda = 128
alpha = 1.15
```

For `N=512`, use primary paper commitment shape `k_s=2`.
For `N=256`, tested compact shape `k_s=4`.

| N | k_s | m = 6N | beta_sig | gamma | beta_prime | full SIS bits |
|---:|---:|---:|---:|---:|---:|---:|
| 256 | 4 | 1536 | 255410.991 | 313.535 | 255724.526 | 50.164 |
| 512 | 2 | 3072 | 362512.041 | 362.039 | 362874.080 | 95.054 |
| 1024 | 2 | 6144 | 514510.275 | 512.000 | 515022.275 | 194.448 |

This explains the degree jump. `N=512` is not near 128 bits under the coarse DKLW l2 bound.
`N=1024` passes with large SIS margin.

## Why Lowering q Does Not Rescue N=512

For fixed `N`, `alpha`, `ell_m`, and `ell_r`:

```tex
beta_sig = c * sqrt(q).
```

The modulus slack condition behaves as

```tex
beta_sig / (q/2) = 2c / sqrt(q).
```

So lowering `q` lowers `beta_sig`, but it lowers `q/2` faster. The ratio gets worse.

In probes, moving `N=512` from `q=1054721` down near `q=520193` improved the SIS estimate only
slightly, from about 95.05 bits to about 95.56 bits. This is nowhere near 128 bits.

## Why Raising ell_m or ell_r Does Not Rescue N=512

Increasing `ell_m` or `ell_r` increases

```tex
L_DKLW = 3 + ell_m + ell_r,
m = N * L_DKLW,
beta_sig = s_trap * sqrt(N * L_DKLW).
```

Both the number of columns and the norm bound increase. In estimator probes, this made the problem
easier, not harder.

For `N=512`, `q=1054721`, `alpha=1.15`:

| L_DKLW | full SIS bits |
|---:|---:|
| 6 | 95.054 |
| 8 | 92.841 |
| 10 | 91.179 |
| 12 | 90.071 |

So raising the rational-hash lengths worsens security and increases proof/signature size.

## Why Lowering alpha Does Not Rescue N=512

The trapdoor quality `alpha` controls `s_trap`, hence `beta_sig`. Smaller `alpha` helps.

But Antrag-style NTRU trapdoor quality has a concrete floor near 1. The relevant source targets are
around:

```text
N=512:  alpha about 1.15
N=1024: alpha about 1.23 in the Antrag-style table
```

Under the coarse DKLW bound, `N=512` would need `alpha` around `0.20` to cross 128 bits. Under the
tighter heterogeneous augmented bound, `N=512` still needs around `0.38`. Both are below the
meaningful trapdoor-quality range.

## Cost of N=1024

Moving from `N=512` to `N=1024` roughly doubles all ring-polynomial row costs.

Primary showing inventory without PRF auxiliary rows:

```text
u:      2
M:      1
s:      2
e:      1
mu:     1
x0:     2
x1:     1
Z:      1
total: 11 ring polynomials
```

With SmallWood packing `s_SW=16`:

```text
N=512:  11 * 512 / 16  = 352 rows
N=1024: 11 * 1024 / 16 = 704 rows
```

Signature size formula:

```tex
sig_bits = (2 + ell_r) * N * log2(beta_sig)
         = 4 * N * log2(beta_sig).
```

Approximate sizes:

| profile | sig KiB | pk KiB | non-PRF showing rows |
|---|---:|---:|---:|
| N=512, q=1054721, alpha=1.15 | 4.62 | 1.25 | 352 |
| N=1024, q=1054721, alpha=1.15 | 9.49 | 2.50 | 704 |
| N=1024, q=1161217, alpha=1.23 | 9.57 | 2.52 | 704 |

## Paper-level Statement

The paper should not claim that the final ARC credential relation is secured directly by bare

```tex
A u = h_{\mu,\chi}(B).
```

The right statement is:

```tex
ARC-SPRUCE assumes committed-message IntGenISIS / one-more unforgeability for
A u = h_{\mu,\chi}(B) + C_M M + A_s s + e.
```

The DKLW bare estimate remains useful as a proof proxy, with the IntGenISIS bound loss `beta_prime`.

## Final Blocker

All allowed knobs fail under `t=n=n_c=1`:

```text
lower q:          tiny SIS improvement, worse beta/q slack
raise ell_m/r:    worsens SIS and size
lower alpha:      would need impossible alpha below 1
use commitment:   changes assumption, but gamma is tiny
MLWE/MSIS:        solves privacy/binding, not preimage hardness
t=2:              target-dimension expansion, outside current paper shape
```

Therefore conservative 128-bit ARC-SPRUCE parameters currently require:

```text
N = 1024
t = n = n_c = 1
```

unless we change the assumption model, trapdoor family, target dimension, or protocol shape.
