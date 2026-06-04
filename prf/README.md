# prf

`prf/` implements the Poseidon2-like PRF used in showing proofs.

In the protocol, the hidden key portion of the signed message is reused as the
PRF key. A public nonce produces a deterministic tag:

- `tag = PRF(key, nonce)`

That tag is what lets showings be rate limited without revealing the hidden
credential secret.

## Main Responsibilities

- load and validate PRF parameters
- evaluate the PRF over the shared field `F_q`
- expose grouped S-box checkpoint traces for the packed PRF companion route
  used by the showing proof
- keep the tag relation bound to the same signed `k` used in the live
  shared-randomness credential witness

## Main Entry Points

- `Tag`
- `LoadParamsFromFile`
- `LoadLocalOrDefaultParams`
- `ShouldCheckpointRound`
- `SBoxOutputCountGrouped`

## Current Invariants

- the PRF uses the same modulus as the rest of the protocol
- the shipped migration target uses the cubic S-box (`d = 3`) over `q = 1017857`
- the showing proof uses grouped nonlinear checkpoints
- the shipped command surface assumes `PRFGroupRounds = 2`
- the maintained compact presets use `PRFCompanionMode=direct_full`
- the retained showing path binds those checkpoints through the PRF companion
  relation, not a legacy standalone PRF replay layout
- the PRF key comes from the stored signed message field `k`, not from any
  deprecated aligned-commitment witness slot
- `prf_params.json` is the source parameter file used by Go tests and commands
- Sage parameter generation scripts are retained as source-tree provenance, but
  are excluded from Docker and are not part of the normal proof runtime

## Current protocol role

The live showing statement proves:

- `tag = F(k, nonce)`
- `A u = B0 + B1 * (m || k) + sum_j B2[j] * x0[j] + Z`
- `(B3 - x1) ⊙ Z = 1`

So the PRF package participates in the same witness relation as:

- the hidden signed key `k`
- the vector `x0`
- the inverse witness `Z`

It is not a detached rate-limiting add-on.

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/modulus_choice.md](../docs/modulus_choice.md)
