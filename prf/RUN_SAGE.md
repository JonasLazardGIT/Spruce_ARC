# Running `generate_params.sage` for the PRF

This note explains how to produce the Poseidon2-like parameters (MDS matrices
and round constants) required by the PRF `F(k, n)` and export them into the
JSON blob consumed by the Go PRF package.

## Shipped Profile

- Field modulus `q`: `1_017_857 = 0xf8801`
- S-box exponent `d`: `3`
- Width `t = lenkey + lennonce = 20`
- `lenkey = 8`
- `lennonce = 12`
- `lentag = 7`

The paper rule is: choose the smallest `d >= 3` such that `gcd(d, q-1) = 1`.
For `q = 1_017_857`, that gives the cubic PRF because `gcd(3, q-1) = 1`.

## Round Sweep

To confirm the round counts for the shipped profile:

```bash
sage prf/sweep_rounds.sage 20 0xf8801 3 128 20 20 7
```

At the current target this yields:

- `RF = 8`
- `RP = 19`

## Regenerate The Shipped Parameters

From the repository root run:

```bash
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7
```

This writes `prf/prf_params.json`.

## Faster Iteration

If you only need parameters quickly, skip the expensive checks:

```bash
sage prf/generate_params.sage 1 0 20 20 3 128 0xf8801 8 12 7 nochecks
```

## CLI Arguments

The generator expects:

```bash
sage prf/generate_params.sage <field> <s_box> <field_bits> <num_cells> <alpha> <security_level> <modulus_hex> [lenkey lennonce lentag] [fixed] [nochecks]
```

- `field = 1` for `GF(p)`
- `s_box = 0` for `x^alpha`
- `field_bits = 20` for `q = 0xf8801`
- `num_cells = t`
- `alpha = d`
- `security_level = 128`
- `modulus_hex = 0xf8801`
- optional `lenkey lennonce lentag` must satisfy `lenkey + lennonce = t`
- `fixed` forces paper/example rounds instead of the swept rounds
- `nochecks` disables the expensive MDS trail checks

## Exported JSON

The script writes a machine-readable `prf/prf_params.json`. After regenerating:

1. load it in Go via `prf.LoadParamsFromFile`
2. validate it in tests
3. keep one deterministic `(key, nonce) -> tag` regression under the shipped
   cubic profile

## Notes

- If `t` changes, keep `lenkey + lennonce = t`.
- The script prints two quick sanity checks:
  - truncation bound: `t - lentag > lambda / log2(q)`
  - permutation heuristic: `t * log2(q) / 3`
