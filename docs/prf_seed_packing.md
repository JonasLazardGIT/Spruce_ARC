# PRF Seed Packing

The maintained showing proof uses entropy from a 48-coefficient PRF seed, not
from eight small Poseidon key lanes.

```text
K_seed in [-4,4]^48
```

The seed is packed into the eight Poseidon key lanes consumed by the PRF:

```text
k_i = sum_{j=0}^{5} (s_{i,j} + 4) * 9^j
```

Each packed lane is below `9^6 = 531441`, while the shared field modulus is
`q = 1017857`, so the base-9 packing is injective and has no modular wrap.

The proof system enforces:

```text
K_seed in [-4,4]^48
K_key = Pack9(K_seed)
tag = PRF(K_key, nonce)
```

Ordinary message, `s`, and `e` coefficients remain in the maintained live
ternary domain. Only PRF seed-tail slots use the wider `[-4,4]` domain.

