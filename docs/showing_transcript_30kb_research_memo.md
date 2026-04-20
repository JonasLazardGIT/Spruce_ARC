# Showing Transcript Memo

This note is the current-state transcript memo for the shipped showing path. It
tracks the current default proof shape after the landed reduced-path rewrite:

- the legacy signature-source replay basis removed from the reduced witness
- signature bridge families removed from the main transform bridge
- `SigShortness` upgraded to V4
- shortness now authenticates `digits -> sigHat -> THat`

If this memo disagrees with older notes, the current code and the fresh local
measurement below win.

## Current Default Measurement

Fresh local command:

```bash
go run ./cmd/showing -showing-preset soundness_balanced
```

Measured on this checkout on 2026-04-20:

- paper transcript: `80,630` bytes (`78.74 KB`)
- verifier payload: `109,764` bytes (`107.19 KB`)
- transcript buckets:
  - `SigShortness = 42,739`
  - `R = 10,325`
  - `Pdecs = 9,678`
  - `VTargets = 9,082`
  - `Q = 4,637`
  - `Auth = 2,189`
  - `BarSets = 1,711`
- default geometry:
  - witness rows `534`
  - committed witness rows `114`
  - mask rows `24`
  - PCS blocks `6`
  - total rows `138`
  - replay geometry `m = 36`
  - row-opening `pcols = 102`
  - `SigShortness`: `v4`, `slots=96`, `blocks=6`
- replay audit:
  - selected replay rows `16/22`
  - selector reduction `27.27%`
  - active blocks `2/2`
  - top remaining blockers:
    `prf_companion`, `source_product`, `carrier`

These are measured examples from the current checkout, not timeless constants.

## What Landed

The current shipped reduced showing now does the following:

- commits carrier rows, source-product rows, non-sign transform aliases,
  committed `THat`, packed PRF companion rows, and packed signature digit rows
- does not commit the legacy signature-source replay basis on the reduced path
- does not commit hidden `T` source rows on the reduced path
- keeps the retained coeff-native layout name
  `literal_packed_aggregated_v3`
- moves signature authentication out of the main transform bridge and into
  `SigShortness` V4

The main immediate transcript win from that change is geometric:

- witness shrank to `534`
- the PCS witness geometry fell from seven blocks to six
- `Pdecs`, `VTargets`, and `BarSets` all fell with it

## What Still Dominates

`SigShortness` is still the largest paper bucket by a wide margin.

That is no longer because the reduced path pays for the same packed signature
source basis twice. That duplication is already gone. The remaining cost comes
from the current same-root support-slot opening itself:

- the shipped default still saturates all `96` support slots
- shortness still opens six PCS blocks worth of rows
- the opening still carries its own authentication/path material

So the dominant cost is now the support-opening shape, not the old packed
signature replay basis.

## Why The Transcript Is Still Above Target

The current transcript is still far above the long-term `~30 KB` aspiration
for three concrete reasons:

1. `SigShortness` remains large even after the packed-source removal.
2. The packed PRF companion bridge is still live inside replay and `Q`.
3. `source_product` rows still remain in replay under current K-point
   semantics.

The replay audit shows the current blocker map directly:

- `prf_companion` is the largest structural remaining replay family
- `source_product` is still replay-consumed
- `carrier` remains live for decode/key-binding reasons

## Current Next Blocker

The next concrete blocker is the packed PRF companion bridge.

The current reduced path already removed the old signature replay basis, but
the PRF bridge still mixes over packed companion rows even though some PRF
objects also have direct authenticated checks. That keeps PRF rows alive in
replay and in the remaining transcript geometry.

So the next serious transcript-reduction step is no longer "compress the old
signature basis more." It is to redesign how the packed PRF companion bridge is
authenticated so those rows can leave replay honestly.

## Superseded Directions

Older repo notes that focused on:

- an older lower-LVCS shipped default
- the legacy signature-source replay basis as the dominant replay surface
- raw shortness tail replay as the next live route
- earlier low-`40 KB` / mid-`40 KB` transcript snapshots

are now historical only. They no longer describe the current shipped reduced
showing path.
