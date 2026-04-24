# V11 Pair-Packing And Lookup Roadmap

This is the current forward plan for shrinking aligned full showing proofs after
the V7/V8/V9/V10/V12/V13 cleanup.

## Live Surface

Live showing families:

- V6 hidden shortness baseline/control: `go run ./cmd/showing -full`
- Aggregate V6 measurement/control: `go run ./cmd/showing -showing-preset aggregate_v6_research`
- V11 direct-target private profile: `go run ./cmd/showing -showing-preset aggregate_v11_direct_target_research`

Removed or de-lived families:

- V7 compact full inlined target-hiding
- V8 public `THatHeads`
- V9 Ajtai private-head bridge
- V10 grouped inlined target-hiding scaffold
- V12 two-oracle/multi-domain prototype
- V13 lookup scaffold

The V12 two-oracle direction is not the near-term size path. Its separate root
and sidecar openings made the proof roughly `82 KB`, larger than current V11,
and the initial theta setting did not provide acceptable effective soundness.

## Current Cost Model

Current post-cleanup measurements on the canonical `lhl_default` artifacts:

- default reduced: `31,859` bytes (`31.11 KB`) paper transcript
- maintained full V6: `56,251` bytes (`54.93 KB`) paper transcript,
  `87,287` bytes verifier payload
- aggregate V6 control: `46,496` bytes (`45.41 KB`) paper transcript,
  `75,688` bytes verifier payload
- V11 direct target: `49,988` bytes (`48.82 KB`) paper transcript,
  `115,592` bytes verifier payload

Maintained full V6 bucket decomposition:

- `SigShortness=14,170`
- `Pdecs=10,913`
- `VTargets=10,594`
- `R=10,325`
- `Q=5,628`

Current V11 direct target is private and paper-aligned, but it still carries the
private shortness relation inside the main witness surface:

- dominant buckets: `Pdecs=16,123`, `Q=12,066`, `VTargets=9,586`, `R=7,224`
- witness rows: `605`
- digit rows: `384 = 2 components * 64 blocks * 3 digits`
- `SigShortness` payload: effectively zero

This means the next savings must come from row geometry and `Q` degree, not
from shrinking a separate shortness payload.

## Target Profile

Use a new versioned profile, not a silent V11 change:

- candidate preset: `aggregate_v11_pair_lookup_research`
- candidate mode: `sig_shortness_v14_pair_lookup_direct_target_hiding`
- base relation: direct shared-randomness `bb_tran`
- replay: full direct-target aggregate replay
- main domain: unchanged 16-column single root
- privacy: no public digits, no `T`, no `THat`, no `THatHeads`

It should remain opt-in until proof size, soundness accounting, and tamper tests
are stable.

## Single-Root Digit-Pair Packing

Do not widen the row domain. The failed V12 direction widened the signature
domain and then paid for a second oracle. The V11 pair path keeps one root and
packs two old 16-column digit blocks into each 16-column row by packing two
digits inside each field element.

Current V11 digit row:

```text
D[c, b, lane](j) = d[c, b, lane, j]
```

Pair-packed row for group `g = floor(b/2)`:

```text
P[c, g, lane](j) = d0 + BASE * d1
d0 = d[c, 2g,   lane, j]
d1 = d[c, 2g+1, lane, j]
```

Target row count:

```text
current V11:      2 * 64 * 3 = 384 digit rows
pair-packed V11:  2 * 32 * 3 = 192 digit rows
```

The direct-target bridge must privately extract `d0` and `d1` from `P` and feed
the correct one into the output coordinate:

```text
b      = output block
g      = b / 2
parity = b mod 2
digit  = extract_parity(P[c,g,lane](j))
A*u    = B0 + TargetMR0Hat + ZHat
```

The extracted digits must not be public witness openings. They are internal
constraint values in the same committed oracle.

## Lookup Or Range Membership

Naively proving packed-pair membership with one exact product polynomial over
all valid pairs would likely make `dQ` worse. Current V11 already has
`dQ` around `807`; the target is to bring `Q` closer to aggregate V6 levels,
roughly `5-6 KB`.

Preferred design:

- keep radix profile `R24,L3` first;
- define a small private lookup/range subargument for valid packed pairs;
- table rows are Fiat-Shamir-bound by a lookup table digest;
- prove each packed value belongs to `{d0 + BASE*d1 : d0,d1 in DigitSet_l}`;
- expose no table witness values publicly;
- keep direct-target constraints using extracted low-degree digit components.

Fallback if lookup is too invasive:

- use low-degree range constraints for `d0,d1` plus a linear packing equation;
- this costs extra private rows for extracted digits but avoids a high-degree
  product-set polynomial;
- measure whether extra rows are smaller than current `Q`.

Do not promote `R111,L2` until membership degree is controlled. It reduces rows
but can increase `Q` enough to lose overall.

## Fiat-Shamir Binding

The transcript must bind:

- mode/version and preset label;
- row layout digest, including pair group size and `BASE`;
- lookup/range parameter digest;
- direct-target replay layout with `TargetMR0Hat`, `RHat1`, and `ZHat`;
- all row roots and row-opening requests;
- the same challenge coefficients used by packed extraction, lookup/range
  checks, and direct-target equations.

The verifier reconstructs the lookup/range table digest and direct-target
bridge from public `A`, `B0`, `B1`, `B2`, replay layout, and the mode metadata.
It never reconstructs or receives `T`, `THat`, or digit heads.

## Expected Bucket Movement

Pair packing should reduce:

- `Pdecs`: fewer committed witness rows and fewer row-opening columns
- `VTargets`: fewer K-point target rows
- `BarSets`: smaller row/evaluation request surface
- prover and verifier time: fewer shortness rows and bridge evaluations

Lookup/range membership should reduce:

- `Q`: lower constraint degree than exact digit membership
- possibly verifier payload if the smaller `Q` opening compresses better

Expected size path:

- current V11: about `48-50 KB`
- pair packing only: likely low/mid `40 KB`, depending opening overhead
- pair packing plus lookup/range: target `34-39 KB`
- sub-34 KB likely needs a deeper signature decomposition or PRF/carrier
  constraint redesign.

## Tests Required

- resolver test for the new opt-in profile and unchanged V6/V11 defaults;
- shape tests rejecting V6 openings, public heads, Ajtai payloads, and two-root
  V12 material;
- honest end-to-end verification;
- tamper one packed digit row and require direct-target verification failure;
- tamper `TargetMR0Hat`, `ZHat`, and `RHat1` independently;
- lookup table digest mismatch rejection;
- out-of-range packed digit rejection;
- malformed pair packing metadata rejection;
- report tests asserting row count moves from `384` to `192` and `dQ` drops
  versus current V11 before any promotion.
