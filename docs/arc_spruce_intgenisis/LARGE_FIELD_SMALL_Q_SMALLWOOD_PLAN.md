# Large-Field SmallWood Plan For Degree-512 IntGenISIS

Date: 2026-05-12

This note records a concrete implementation plan for keeping the lattice signature and rational-hash
relation over a small scheme modulus while proving the complete IntGenISIS showing statement inside
SmallWood over a larger proof field.

The target profile considered here is:

```text
ring degree N       = 512
scheme modulus q   = 12289
proof modulus P    = a larger NTT-friendly prime
signature norm     = coefficient-domain l2
proof system       = one unified SmallWood PACS statement over F_P
```

The goal is not to change the lattice scheme to modulus `P`. The lattice signature, hash relation,
commitment relation, estimator input, and SIS security model remain over `R_q`. The proof field is only
the arithmetic field used by the NIZK to avoid modular wraparound when certifying integer bounds such as
the signature `l2` norm.

## Executive Summary

The current implementation uses one modulus for both roles:

```text
scheme modulus = proof field modulus = q
```

That is why a direct SmallWood aggregate

```text
sum_i (s1_i^2 + s2_i^2) = beta_l2^2
```

is not sound at `q=12289`: the integer sum is around `25M` to `37M`, but the proof equation would only
hold modulo `12289`.

The viable design is:

```text
scheme equations are still equations modulo q
SmallWood arithmetic is performed over F_P
each modulo-q equation E = 0 mod q is encoded as E - q*k = 0 over F_P
all lifted values and quotient witnesses are range-constrained
the l2 inequality is encoded over F_P with hidden slack
```

The most important rule is that this must be one proof over one committed witness family. Two independent
proofs, one over `F_q` and one over `F_P`, do not bind their hidden witnesses unless a separate binding
commitment layer and composition theorem are added. The cleaner implementation is a single large-field
PACS statement.

## Non-Goals

This plan does not propose:

- changing the lattice signature modulus from `q=12289` to `P`;
- using the SmallWood 2025 small-field extension trick to avoid integer wraparound;
- proving exact norm values to the verifier;
- revealing the signed target;
- relying on two separate hidden-witness proofs;
- claiming final 128-bit conservative security without rerunning the estimator on the final norm bound.

The proof field `P` is a proof-system implementation choice. The lattice security estimator should still use
`N=512`, `q=12289`, and the certified signature/augmented SIS norm bound.

## Why Same-Field F_q Does Not Work

For `N=512`, the signature vector has `2N = 1024` coefficient coordinates. With the current `q=12289`
sampler profile, the fixture measurements give signatures around:

```text
observed l2            ~= 4700 to 5000
raw C-style l2 bound   ~= 6099
raw C-style l2^2       ~= 37.2 million
q                      = 12289
q/2                    = 6144.5
```

A same-field aggregate over `F_q` can only prove:

```text
sum_i (s1_i^2 + s2_i^2) == T mod q
```

It cannot prove integer equality. The wrap factor is large:

```text
37.2M / 12289 ~= 3027
```

Even a single coefficient can wrap:

```text
702^2 = 492804 ~= 40*q
```

Therefore a same-field `l2` aggregate would be a modulo-residue statement, not the integer norm statement
needed by the SIS security estimate.

## Why An Extension Field Over F_q Does Not Fix This

SmallWood 2025/1085 includes a small-field variant where the PACS statement remains over a small base
field and protocol polynomials use an extension field. This is useful for soundness and protocol efficiency,
but it does not change the characteristic. An extension field over `F_q` still has characteristic `q`.

So the equation

```text
sum_i s_i^2 = T
```

would still be an equality modulo `q`, not an integer equality. The fix is not `F_{q^r}`. The fix is to make
the PACS statement itself live over a field whose characteristic exceeds the integer ranges we need to
represent, or to use a CRT-style construction with enough independent characteristics. This plan uses a
single large prime `P`.

## Correct Statement Shape

Let `q` be the scheme modulus and `P` be the proof modulus. All committed witness rows are elements of
`F_P`, but semantically many of them are constrained to be integer lifts of `q`-residues.

The public showing statement contains:

```text
N, q, P
A, B, C_M, A_s              public scheme matrices over R_q, lifted as integers in F_P
BoundMsg                    coefficient bound for M,s,e,mu,x0,x1 style values
BoundSigL2                  signature l2 bound
BoundLift                   loose coefficient lift bound for u, if used
nonce, prf_tag              public PRF statement
SmallWood domain parameters
```

The hidden witness contains:

```text
u = (s1, s2)                signature preimage, centered integer lift
M, m, k_key                 semantic message and key split
s, e                        Ajtai commitment opening
mu_sig, x0, x1              rational-hash bounded values
Z                           inverse witness, canonical q-residue lift
PRF internal rows           q-residue lifts
quotient/carry rows         for every modulo-q equation
delta_norm                  hidden l2 slack
range-decomposition rows    for bounded values, residues, quotients, and slack
```

The verifier should learn:

```text
the public statement
that a valid hidden witness exists
that ||u||_2 <= BoundSigL2
```

The verifier should not learn:

```text
u
the signed target
the exact norm
M,s,e,mu_sig,x0,x1,Z
PRF state
quotients/carries
delta_norm
```

## Core Encoding Principle

Every scheme equation of the form

```text
E == 0 mod q
```

is encoded inside `F_P` as:

```text
E - q*K = 0 over F_P
```

where `K` is a hidden quotient witness with a proven integer range.

This is sound only if:

```text
1. all variables in E are bounded integer lifts;
2. K is bounded;
3. the possible integer value of E - q*K is strictly smaller than P in absolute value;
4. all arithmetic is performed as integer arithmetic embedded into F_P.
```

Without range bounds on `K`, the quotient equation is vacuous because `q` is invertible in `F_P`.

## Proof Field Selection

For `N=512`, Lattigo-style polynomial rings need primes compatible with the ring/domain operations. A safe
default is a prime satisfying:

```text
P = 1 mod 2N
```

Candidate primes found during analysis:

```text
32-bit candidate:
P = 2147493889
P = 1 mod 1024

61-bit candidate:
P = 2305843009213683713
P = 1 mod 1024
```

The recommended first implementation uses the 61-bit prime. This matches the Lattigo v4 NTT-prime size
limit while still making the integer soundness story much simpler because all relevant intermediate values
for `N=512,q=12289` fit comfortably below `P` when
computed with staged modular reductions.

A 32-bit prime may be possible after optimization, but it forces more aggressive carrying/reduction
discipline. It is not the right first implementation.

## Signature l2 Gadget

The proof should certify:

```text
sum_i (s1_i^2 + s2_i^2) <= BoundSigL2^2
```

without revealing the exact sum. Use hidden slack:

```text
sum_i (s1_i^2 + s2_i^2) + delta_norm = BoundSigL2^2
```

where:

```text
delta_norm >= 0
delta_norm <= BoundSigL2^2
```

The slack can be represented by limbs:

```text
delta_norm = sum_j limb_j * B_limb^j
```

and each `limb_j` is range-constrained. For the current raw profile:

```text
BoundSigL2       ~= 6099
BoundSigL2^2     ~= 37.2M
```

So `delta_norm` is only about 26 bits. This is a small range proof.

The aggregate norm constraint is degree 2 in the signature coordinates. This is exactly the kind of
aggregated PACS constraint SmallWood supports efficiently.

## Lift Bounds For Signature Coordinates

The `l2` proof needs the signature coordinates to be interpreted as integers, not arbitrary `F_P` elements.
Therefore the proof must also establish a canonical lift range for `u`.

This lift bound is not the security bound. It is only a uniqueness bound. It can be loose:

```text
|u_i| <= BoundLift
```

with:

```text
BoundLift < q/2
```

For `q=12289`, `q/2 = 6144.5`. Fixture measurements showed maxima around `700`, so initial engineering
choices such as:

```text
BoundLift = 1024
BoundLift = 1536
BoundLift = 2048
```

are plausible. The smaller the lift bound, the smaller quotient ranges become. The bound should be chosen
from a failure-probability analysis of the sampler, not just a 256-sample batch.

The important distinction is:

```text
BoundLift controls integer encoding soundness.
BoundSigL2 controls SIS security.
```

These must be separate public parameters.

## Mod-q Linear Relations Over F_P

The IntGenISIS showing equation is semantically:

```text
A*u = B0 + B1*mu_sig + B2*x0 + Z + C_M*M + A_s*s + e  in R_q
```

In the large-field proof, each coefficient becomes:

```text
coeff(A*u - B0 - B1*mu_sig - B2*x0 - Z - C_M*M - A_s*s - e) - q*K_sig_j = 0 over F_P
```

Important details:

- Public `R_q` coefficients should be lifted consistently, either as `[0,q-1]` or centered representatives.
- Witness values with natural small bounds should use centered lifts.
- Canonical residue variables such as `Z` and PRF state should be constrained to `[0,q-1]`.
- Quotient ranges must be derived from the public coefficient bounds and matrix dimensions.

For example, if a public polynomial coefficient is lifted in `[0,q-1]` and a signature coefficient is bounded
by `BoundLift`, then one coefficient of a negacyclic convolution has absolute value bounded by roughly:

```text
N * (q-1) * BoundLift
```

For `N=512`, `q=12289`, and `BoundLift=2048`, this is about `12.9B`, which is still tiny compared to
a 61-bit `P`. The corresponding quotient bound is about:

```text
12.9B / q ~= 1.05M
```

These bounds are manageable, but they must be computed precisely and enforced.

## BB-tran Inverse Relation

The inverse equation is semantically:

```text
(B3 - x1) * Z = 1 mod q
```

where the implementation may express this as a coefficient/replay Hadamard product depending on the
chosen relation surface.

In `F_P`, each lane becomes:

```text
(B3_lift - x1) * Z - 1 - q*K_inv = 0
```

with:

```text
Z in [0, q-1]
x1 bounded
K_inv bounded
```

The product is small enough for degree-2 constraints over a 61-bit field:

```text
rough size: q^2 ~= 151M
```

This part is straightforward compared to the PRF.

## Commitment Relation

The Ajtai commitment relation:

```text
c = C_M*M + A_s*s + e  in R_q
```

can be proven similarly:

```text
coeff(C_M*M + A_s*s + e - c) - q*K_com_j = 0 over F_P
```

However, in the showing proof the public issuance commitment `c` is not necessarily exposed. The current
showing statement folds the commitment opening into the signed target. Therefore implementation can either:

1. keep the folded target relation only; or
2. explicitly prove the commitment equation if a public commitment is part of a future showing statement.

For the current showing relation, the folded equation is enough.

## PRF Relation Over F_P

The PRF is the most delicate part of the large-field port.

If the PRF remains a `q`-field construction, then each PRF arithmetic step must be represented as a
modulo-`q` relation inside `F_P`.

Do not write:

```text
y = x^5 + c over F_P
```

if the real PRF computes:

```text
y = x^5 + c mod q
```

Instead, use staged reductions:

```text
t2 - x*x       - q*k2 = 0
t4 - t2*t2     - q*k4 = 0
t5 - t4*x      - q*k5 = 0
y  - (t5 + c)  - q*ky = 0
```

with all `t*`, `y` in `[0,q-1]` and all quotients bounded.

This keeps PACS degrees low, typically degree 2, and avoids huge integer monomials such as `q^5`.

The current PRF companion and checkpointing strategy should be reused conceptually, but its arithmetic
must be re-expressed as `F_P` constraints with q-residue range checks and quotient rows.

## Row And Constraint Families

The large-field statement should use these high-level row families:

```text
primary witness rows:
  u, M, m, k_key, s, e, mu_sig, x0, x1, Z

q-residue arithmetic rows:
  PRF state rows
  PRF staged product rows
  replay / transform rows, if retained

range rows:
  signed-lift decomposition rows for u and small centered values
  residue decomposition rows for Z and PRF state
  quotient decomposition rows
  norm-slack limb rows

quotient rows:
  signature equation quotients
  inverse equation quotients
  PRF multiplication/reduction quotients
  optional commitment equation quotients

aggregate rows:
  l2 sum of squares with hidden slack
```

The implementation should initially disable nonessential compression and projection tricks. First prove the
correct relation with a clear row inventory. Optimize after the proof is sound.

## Required Refactor: Separate SchemeQ And ProofP

The current code assumes a single modulus almost everywhere. A large-field implementation needs explicit
dual-modulus plumbing:

```go
type ProofModuli struct {
    SchemeQ uint64 // q = 12289
    ProofP  uint64 // e.g. 2305843009213683713
}
```

The important rule is:

```text
ringQ: used for actual scheme operations, signing, verification, fixture generation
ringP: used for SmallWood row polynomials and PACS constraints
```

Likely files requiring changes:

```text
PIOP/params_helpers.go
PIOP/PACS_Statement.go
PIOP/prover_helper.go
PIOP/VerifyNIZK.go
PIOP/intgenisis_showing.go
PIOP/intgenisis_semantic.go
PIOP/bound_spec.go
PIOP/fpar_membership.go
PIOP/signature_shortness_packed.go
cmd/showing/main.go
cmd/issuance/flow_helpers.go
credential/state.go
```

The implementation should avoid naming the proof ring `ringQ` once this refactor begins. That naming is
currently a source of mistakes.

Recommended names:

```text
schemeRingQ
proofRingP
schemeQ
proofP
```

## Implementation Phases

### Phase 0: Freeze The Degree-512 Scheme Fixture

Before changing the proof system, freeze a reproducible `N=512,q=12289` fixture:

```text
Parameters.json
Bmatrix.json
public_key.json
private_key.json
sample signatures
norm/security report
```

Acceptance checks:

```text
native signature verification passes over q
CheckNormC passes
reported l2 matches direct coefficient scan
estimator cases are reproducible
```

This fixture is the reference object for proof-system tests.

### Phase 1: Add Dual-Modulus Configuration

Add explicit fields for:

```text
scheme_modulus_q
proof_modulus_p
proof_modulus_bits
proof_field_profile
```

Do not remove old single-modulus paths immediately. Add a new large-field mode, for example:

```text
IntGenISISProofFieldMode = "large_p_modq_quotients_v1"
```

Acceptance checks:

```text
old q-field tests still pass
large-field mode constructs ringP with P != q
proof transcript records both q and P
verifier rejects proof if q/P metadata mismatch
```

### Phase 2: Implement Integer Lift And Range Gadgets Over F_P

Implement reusable gadgets:

```text
SignedBoundedLift(value, B): value in [-B,B]
CanonicalResidue(value, q): value in [0,q-1]
UnsignedBounded(value, B): value in [0,B]
LimbDecomposition(value, base, limbs)
```

For the first version, prefer simple limb/radix decomposition over clever lookup compression.

Acceptance checks:

```text
negative signed values are represented correctly in F_P
out-of-range values fail
canonical residue values fail if equal to q or larger
all range gadgets expose precise MaxAbs/MaxValue metadata
```

### Phase 3: Toy Mod-q Equation Over F_P

Before porting IntGenISIS, implement a toy statement:

```text
a*u + b*v - t == 0 mod q
```

proved as:

```text
a*u + b*v - t - q*k = 0 over F_P
```

with all variables bounded.

Acceptance checks:

```text
valid q-equation proves and verifies
invalid q-equation fails
unbounded or wrong quotient cannot be used
changing q in proof metadata fails
changing P in proof metadata fails
```

### Phase 4: Implement Hidden l2 Norm Gadget

Implement:

```text
sum_i u_i^2 + delta = BoundSigL2^2
delta in [0, BoundSigL2^2]
```

Use aggregated PACS constraints for the sum of squares.

Acceptance checks:

```text
proof reveals BoundSigL2 but not exact norm
valid fixture signature passes
tampering one coefficient to exceed BoundSigL2 fails
tampering delta fails
same proof over q is not used for l2
```

### Phase 5: Port The Signature Equation

Port:

```text
A*u = B0 + B1*mu_sig + B2*x0 + Z + C_M*M + A_s*s + e  mod q
```

to `F_P` quotient constraints.

Initial implementation should use coefficient-domain negacyclic convolution with public coefficients lifted
to integers. It is acceptable if this is slower than the q-field implementation. Optimize later.

Acceptance checks:

```text
valid fixture witness proves and verifies
changing one u coefficient fails
changing one M/s/e coefficient fails
changing one quotient row fails
all quotient bounds are derived and checked
no signed target is revealed
```

### Phase 6: Port The Inverse Relation

Port:

```text
(B3 - x1) * Z = 1 mod q
```

with canonical residue constraints for `Z`.

Acceptance checks:

```text
valid inverse witness passes
non-invertible denominator fixture is rejected before proving
wrong Z fails
Z outside [0,q-1] fails
quotient tampering fails
```

### Phase 7: Port PRF Companion Arithmetic

Port the PRF relation with q-residue rows and staged reductions. Keep existing checkpointing ideas, but
do not assume `F_P` arithmetic equals `F_q` arithmetic.

Acceptance checks:

```text
valid nonce/key/tag passes
wrong key fails
wrong nonce fails
wrong public tag fails
intermediate PRF state outside [0,q-1] fails
S-box quotient tampering fails
```

### Phase 8: Combine Into One Unified IntGenISIS Proof

At this point the proof should include:

```text
signature equation modulo q
inverse equation modulo q
commitment/message/key structure
PRF companion relation modulo q
u lift bound
u l2 bound with hidden slack
bounded auxiliary witness predicates
```

Acceptance checks:

```text
one proof, one committed witness family
one verifier path
one extracted witness in the proof theorem
no two-proof witness-binding assumption
```

### Phase 9: Optimize Rows And Proof Size

Only after the large-field statement is correct:

```text
reintroduce packed rows
reintroduce projection/replay optimizations
compress range proofs
compress quotient rows where safe
tune SmallWood ncols, eta, theta, rho, ell
```

Potential optimizations:

- use centered public coefficient lifts to reduce quotient ranges;
- keep public linear maps in replay basis if the replay map is proven injective and q-modular arithmetic is explicit;
- use grouped limb range proofs;
- use lookup-style compressed range rows only after a soundness review;
- batch quotient range checks with shared limb layout.

## Soundness Checklist

Before claiming security, every item below must be true:

```text
There is one SmallWood proof over F_P.
The proof statement records q and P.
The extractor obtains one witness family.
Every q-residue variable is range-constrained.
Every centered integer variable is range-constrained.
Every modulo-q equation has a quotient witness.
Every quotient witness is range-constrained.
Every integer expression is bounded below P.
The l2 bound is proven over F_P without wraparound.
The exact norm is hidden unless intentionally made public.
The signed target is hidden.
The verifier checks the same public q-domain objects used by the scheme.
The SIS estimator uses q, not P.
```

## Expected Security Accounting

With `q=12289,N=512`, proving a true signature `l2` bound around the raw C-style sampler bound gives:

```text
signature l2 bound       ~= 6099
augmented l2 bound       ~= 6120, including small auxiliary bounded parts
```

Previous local estimator runs for this ballpark reported roughly:

```text
MATZOV/full SIS classical        ~= 143.7 bits
ADPS16/CoreSVP classical         ~= 118.3 bits
CoreSVP quantum                  ~= 104.9 bits
```

These numbers are not replaced by the proof-system design. The proof design only ensures that the bound fed
to the estimator is the bound actually proven by the NIZK. Final parameter claims must rerun the estimator
after fixing:

```text
q
N
BoundSigL2
auxiliary bounds
Ajtai/message dimensions
proof soundness loss
```

If the conservative target is 128-bit CoreSVP classical or quantum, the sampler norm, `q`, or dimensions may
still need retuning.

## Main Risks

### Risk 1: Quotient Bounds Are Underestimated

If quotient ranges are too small, honest proofs fail. If they are too large, proof size grows. If they are missing,
soundness fails.

Mitigation:

```text
derive quotient ranges symbolically from public bounds;
emit them in the proof report;
unit-test each bound against direct integer evaluation;
fuzz near the boundaries.
```

### Risk 2: Public Coefficient Lifts Are Inconsistent

The same public `q` coefficient can be lifted as `[0,q-1]` or centered. Both are valid if used consistently,
but mixing them changes quotient values.

Mitigation:

```text
define one lift convention per public matrix;
record it in metadata;
test direct integer evaluation against native mod-q evaluation.
```

### Risk 3: PRF Arithmetic Accidentally Moves To F_P

If the real PRF is over `F_q`, then proving a PRF over `F_P` proves the wrong statement.

Mitigation:

```text
stage every PRF multiplication with q-reduction;
range-constrain every PRF state row to [0,q-1];
test against native PRF traces.
```

### Risk 4: Reintroducing Projection Before Soundness Is Clear

The current implementation contains projection/replay machinery. Porting that too early risks hiding a
missing quotient or missing range constraint.

Mitigation:

```text
first implement the plain coefficient-domain relation;
only optimize after exhaustive equivalence tests.
```

### Risk 5: Treating Large P As A Lattice Modulus

The scheme security remains over `q=12289`. The proof field `P` does not increase or decrease the SIS
modulus. It affects proof soundness and transcript size, not lattice hardness.

Mitigation:

```text
use SchemeQ/ProofP names everywhere;
include both in reports;
make estimator scripts consume SchemeQ only.
```

## Minimal Prototype Milestone

The first meaningful prototype should prove this reduced statement:

```text
Public:
  q, P, N
  one public A in R_q
  one public target t in R_q
  BoundLift
  BoundSigL2

Witness:
  u in R^2 with |u_i| <= BoundLift
  quotient rows K
  delta_norm

Constraints over F_P:
  A*u - t - q*K = 0
  sum_i u_i^2 + delta_norm = BoundSigL2^2
  delta_norm in [0, BoundSigL2^2]
```

This milestone isolates all core mechanisms:

```text
dual modulus plumbing
integer lifts
mod-q quotient equations
l2 aggregate without wraparound
hidden slack
single committed witness
```

Only after this passes should the full IntGenISIS relation be ported.

## Definition Of Done For A Sane Degree-512 Proof

A degree-512 proof implementation is sane when:

```text
1. Native q=12289 signature verification passes.
2. The same hidden u is used in the signature equation and l2 norm equation.
3. The proof certifies ||u||_2 <= BoundSigL2, not merely ||u||_2^2 modulo q.
4. The exact norm is hidden by slack.
5. The signed target is hidden.
6. All q-modular relations are enforced with bounded quotient witnesses over F_P.
7. The verifier rejects malformed q/P metadata.
8. The proof report prints SchemeQ, ProofP, BoundLift, BoundSigL2, quotient ranges, and proof soundness terms.
9. Estimator scripts use SchemeQ and the proven augmented l2 bound.
10. There is no dependency on an unsound two-proof witness-binding assumption.
```

## Recommended Next Step

Implement the reduced prototype in a separate package or mode, not directly inside the production showing
path. A good working name is:

```text
PIOP/intgenisis_largefield
```

or:

```text
CoeffNativeSigModelLargeFieldModQQuotientV1
```

The prototype should deliberately ignore transcript-size optimization. Its purpose is to establish the
correct algebraic surface. Once the reduced prototype is correct, the full IntGenISIS port becomes an
engineering problem rather than an unresolved proof-design problem.
