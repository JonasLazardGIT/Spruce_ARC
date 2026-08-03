# Preset Results

## Current Measurements

The short labels below are paper-facing names. The executable selector remains
the canonical preset ID shown next to it. Sizes are paper-transcript bytes, not
serialized JSON proof sizes.

| Label |  Security statement | RO budget per phase | Issuance | Showing | Combined | Reported theorem result | Derived CROM soundness work |
| --- |  --- | ---: | ---: | ---: | ---: | --- | ---: |
| `N1024-WF128` | 128-bit work-factor target | No fixed cap | 26,758 | 38,092 | 64,850 | 133.44 bits | about 131.72 bits |
| `N1024-Q64-R128` | 128 residual bits at Q64 | `[2^64]*5` | 39,504 | 56,584 | 96,088 | 130.00 composed bits | about 132 bits |
| `N1024-Q96-R128` | 128 residual bits at Q96 | `[2^96]*5` | 52,106 | 73,456 | 125,562 | 130.92 composed bits | about 164 bits |
| `N1024-Q128-R128` | 128 residual bits at Q128 | `[2^128]*5` | 61,429 | 85,386 | 146,815 | 130.56 composed bits | about 196 bits |

WF-128 expresses attack work rather than residual failure at one selected
query count. An attack with substantial success should cost about `2^128`
oracle-work units.

WF-128 still accounts for offline Fiat-Shamir search (collisions). Its soundness work is about 131.72 bits, but the zero-knowledge term from a 128-bit hidden tape would cap the combined proof-layer work near 128 bits.

## Transcript Widths

The main 128-bit comparison uses these executed widths:

| Profile | DECS/Merkle hash output | Fiat-Shamir XOF output | Collision width `c` charged in Theorem 9 | DECS tape/nonce width | Salt |
| --- | ---: | ---: | ---: | ---: | ---: |
| `N1024-WF128` | 264 bits (33 bytes) | 512-bit SHAKE256 squeeze | 264 bits | 128 bits (16 bytes) | 256 bits (32 bytes) |
| `N1024-Q64-R128` | 264 bits (33 bytes) | 512-bit SHAKE256 squeeze | 264 bits | 200 bits (25 bytes) | 200 bits (25 bytes) |
| `N1024-Q96-R128` | 328 bits (41 bytes) | 512-bit SHAKE256 squeeze | 328 bits | 232 bits (29 bytes) | 200 bits (25 bytes) |
| `N1024-Q128-R128` | 392 bits (49 bytes) | 512-bit SHAKE256 squeeze | 392 bits | 264 bits (33 bytes) | 200 bits (25 bytes) |

**Width legend**

- **DECS/Merkle hash output:** This is the actual output length used by the
  SHAKE256-based DECS leaf and internal-node hashes. A leaf commits to the
  polynomial evaluations, mask evaluations, leaf index, and leaf nonce. The
  Merkle root and every authentication-path node have exactly this width, so it
  directly affects transcript size. This is `DECSHashBits` in the code.
- **Fiat-Shamir XOF output:** SmallWood has four chained Fiat-Shamir rounds.
  They derive the DECS combination challenge, the PIOP batching challenge, the
  polynomial-evaluation challenge, and the final opening challenge. The current
  implementation domain-separates these rounds and always squeezes 64 bytes
  from SHAKE256 (`fsDigestBytes = 64`). Therefore the 264/328/392 values are not
  the physical Fiat-Shamir digest lengths.
- **Collision width `c`:** `FSCollisionBits` is a conservative accounting width.
  Theorem 9 charges `(Q_0^2 + ... + Q_4^2)/2^c`; the implementation uses the
  minimum effective width shared by the DECS hash and Fiat-Shamir accounting.
  In these presets the DECS width is the bottleneck, so `c` is respectively
  264, 328, or 392 bits even though the Fiat-Shamir SHAKE256 squeeze is 512
  bits. Fiat-Shamir digests are reconstructible and are not charged as full
  extra digests in the optimized paper-transcript size.
- **DECS tape/nonce width:** In the SmallWood paper, every Merkle leaf receives
  an independent random tape `rho_j`; only tapes for opened leaves are revealed.
  Guessing an unopened tape gives the zero-knowledge term approximately
  `Q/2^t`, where `t` is this width. In the current implementation, all leaf
  nonces are instead derived from one `t`-bit `NonceSeed`, and that seed is
  serialized once in the opening. This is a transcript optimization, but it is
  not the paper's independent-hidden-tape distribution. The paper's
  `Q/2^t` zero-knowledge bound therefore does not apply directly. An ordinary
  PRG argument is not enough once the seed itself is revealed, because the
  verifier can then derive every unopened tape. Recovering the paper claim
  requires sending only independently sampled tapes for opened leaves, or a
  different selectively openable construction with its own proof. Until then,
  the soundness work factors above should not be read as a fully established
  NIZK work factor.
- **Salt:** This is one fresh prover-chosen value transmitted with each proof.
  It initializes the first Fiat-Shamir round and separates otherwise identical
  transcripts; it does not limit offline grinding because a malicious prover
  can choose many salts. The SmallWood specification also feeds the global salt
  into each Merkle-leaf hash. The current implementation does not: its DECS
  leaves use their derived nonces, while the global salt enters the Fiat-Shamir
  chain. This difference should be covered by a proof or aligned with the paper
  before making a theorem-level zero-knowledge claim. Independently, an
  `s`-bit salt has generic birthday work near `2^(s/2)`; the 200-bit salts are
  scoped to at most `2^32` honest proofs per context rather than to an unbounded
  128-bit collision claim.

## What Q Means

SmallWood's Fiat-Shamir analysis has five random-oracle domains. `Q_0` counts
queries to the DECS/Merkle hash, while `Q_1` through `Q_4` count queries to the
four Fiat-Shamir challenge domains.

`Q_i` counts all adversarial oracle calls in the security game. It includes
offline grinding, rejected prefixes, and proof attempts that are never sent to
a verifier. It is therefore not a server-side request limit and cannot be
enforced by counting submitted credentials. Offline work is unobservable, but
it is not free: each query still consumes adversarial computation.

A label such as Q64-R128 is a fixed-budget residual statement:

```text
after up to 2^64 queries in each of the five domains,
the bounded proof failure remains at most about 2^-128.
```

Using SmallWood Theorem 9's bound `epsilon_SW(Q_0,...,Q_4)`, residual bits are
`-log2(epsilon_SW(Q))` at one fixed query budget, whereas WF bits minimize
`log2(W(Q)/min(1,epsilon_SW(Q)))` over all budgets, with `W(Q)` denoting total
oracle-query work. Replacing `R128` with `WF128` in the Q64, Q96, or Q128 names
would discard the property those presets were tuned to certify. If named only
by their derived soundness work, they would be roughly WF132, WF164, and WF196,
not three copies of WF128.

## What WF Means

WF-128 targets roughly `2^128` classical random-oracle operations for an attack
with substantial success, rather than `2^-128` residual failure at one selected
query count. It includes offline Fiat-Shamir grinding: the queries need not be
online, observable, or rate-limited.

Two different mechanisms must be distinguished. Generic collision work against
a `c`-bit hash output is about `2^(c/2)`, so a 256-bit output gives conventional
128-bit collision resistance; this preset uses `c=264`, giving about 132 bits.
SmallWood's zero-knowledge model separately gives every DECS leaf a fresh,
independently sampled 128-bit random value and does not reveal the values for
unopened leaves. The relevant attack is guessing such a value, not finding a
hash collision, so this guessing term caps the paper-model combined proof-layer
work near 128 bits.

SmallWood Theorem 9 first bounds classical-ROM extraction failure by

```text
epsilon_SW(Q) <= sum(i=0..4) Q_i^2 / 2^c
                 + sum(i=1..4) Q_i * epsilon_i / 2^kappa_i,
```

where the four `epsilon_i` values come from Equation (8), `kappa_i` is the
grinding applied to round `i`, and `c` is the effective collision width. For a
phase, define the pre-query algebraic coefficient by
`2^-a = sum(i=1..4) epsilon_i/2^kappa_i`. Under a normalized total classical
query envelope `T`, `sum Q_i^2 <= T^2` and the theorem is conservatively reduced
to

```text
B(T) = min(1, T^2 * 2^-c + T * 2^-a),
```

The derived work exponent minimizes `log2(T/B(T))`. Since `B` is capped at one,
the minimum occurs near the first `T` for which the bound reaches one. Writing
`x = log2(T)`, this is found numerically from

```text
2^(2*x-c) + 2^(x-a) = 1.
```

For a bounded profile reported at `Q_i=2^b`, its pre-query exponent is recovered
as `a = b + algebraic_residual_bits`. This gives `(c,a)=(264,133.35)` and
`x=131.72` for WF128; approximately `(264,195.54)`, `(328,229.21)`, and
`(392,260.45)` for Q64-R128, Q96-R128, and Q128-R128, where the collision term
dominates and gives about 132, 164, and 196 bits. These are theorem-derived
classical-oracle work bounds, not timings or demonstrated attack costs. SC125
must therefore remain an `SC` label: its 126.92-bit result at `Q_i = 1` is not a
125-bit work factor because its 144-bit collision space reaches the birthday
scale near `2^72` queries.

This is why `N1024-WF128` is a reasonable target name, subject to resolving the
tape-seed and salt-model differences described above. These are CROM values;
they are not QROM results.

## Research Basis

- [SmallWood, Theorems 9 and 10](https://eprint.iacr.org/2025/1085): explicit
  query-dependent knowledge-soundness and zero-knowledge bounds.
- [NIST security-strength definition](https://csrc.nist.gov/glossary/term/security_strength):
  security strength is fundamentally an amount-of-work measure.
- [Concrete non-interactive FRI analysis](https://eprint.iacr.org/2024/1161.pdf):
  distinguishes non-interactive query-work security from a fixed interactive
  soundness error.
- [Ligero](https://acmccs.github.io/papers/p2087-amesA.pdf): another
  Fiat-Shamir system with explicit linear and quadratic random-oracle query
  losses.
- [Fiat-Shamir in the QROM](https://arxiv.org/abs/1902.07556): illustrates why
  a large classical query allowance is not a substitute for a quantum-query
  proof.
