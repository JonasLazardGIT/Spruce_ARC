# credential

`credential/` defines the persisted public parameters, holder state, preset
registry, and verifier keys used by the maintained committed-message
IntGenISIS flow.

## Maintained Profiles

The live profiles are:

- `intgenisis_profile_b`: `N=512`, live `B=1`, used by `n512-compact96`
- `intgenisis_profile_c`: `N=1024`, live `B=1`, used by the degree-1024 presets

The PRF key entropy is a separate 48-coefficient seed in `[-4,4]`, packed
base-9 into the eight Poseidon key lanes.

The public preset registry contains exactly:

```text
n512-compact96
n1024-compact96
n1024-compact125
```

## Public Parameters

IntGenISIS public parameters store:

- `Profile`
- `Modulus`
- `HashRelation = bb_tran`
- `BPath`
- `BoundB` / `CommitmentBound` for ordinary `M`, `s`, and `e`
- `C_M`, `A_s`
- `ell_M`, `k_s`, `n_c`
- `ell_mu_sig`, `ell_x0`, `ell_x1`
- `ring_degree`

The issuer signs:

```text
T = c + h_tran(mu_sig, x0, x1)
```

where `c = C_M*M + A_s*s + e`.

## State

The IntGenISIS holder state stores the committed message witness, issuer hash
data, NTRU signature rows, public NTRU key material, and runtime anchors needed
to build a showing proof. It must not contain issuer trapdoor material.

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/intgenisis_protocol_h_tran.md](../docs/intgenisis_protocol_h_tran.md)
- [../docs/intgenisis_lattice_security.md](../docs/intgenisis_lattice_security.md)
- [../docs/degree1024_maintained_presets.md](../docs/degree1024_maintained_presets.md)
