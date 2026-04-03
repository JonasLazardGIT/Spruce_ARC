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
- expose grouped S-box checkpoint traces for the showing proof

## Main Entry Points

- `Tag`
- `LoadParamsFromFile`
- `LoadLocalOrDefaultParams`
- `Trace`
- `TraceSBoxOutputs`
- `TraceSBoxOutputsGrouped`
- `ShouldCheckpointRound`
- `MaxConstraintDegreeGrouped`

## Current Invariants

- the PRF uses the same modulus as the rest of the protocol
- the shipped migration target uses the cubic S-box (`d = 3`) over `q = 1054721`
- the showing proof uses grouped nonlinear checkpoints
- the shipped command surface assumes `PRFGroupRounds = 2`

## Read Next

- [../docs/protocol.md](../docs/protocol.md)
- [../docs/modulus_choice.md](../docs/modulus_choice.md)
