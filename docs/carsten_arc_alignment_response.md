# Private Internal Memo: Rewriting Responses to the `Carsten:` Comments in `docs/Spruce_ARC.pdf`

This memo re-answers every visible `Carsten:` comment in `docs/Spruce_ARC.pdf` against the live repository as reviewed on March 29, 2026. It is intentionally code-first. When paper prose conflicts with live semantics, the authorities are:

- `credential/state.go`
- `cmd/showing/main.go`
- the retained showing/proof implementation in `PIOP`

Repository prose docs are useful context, but they are not authoritative when they lag the code. In particular, `credential/README.md` still describes an older semantic payload (`Sig/U/X0/X1/PRFKey/NCols`) and should not drive paper wording when it conflicts with `credential.State` and the showing loader. Paper-level security claims are not inferred from code unless the code actually fixes the relevant object or assumption.

## Status Model

- `Code-settled; paper rewrite needed`
  - the live implementation is clear enough to drive manuscript wording
- `Paper-open; code does not settle this`
  - the repo does not fix the needed theorem object, distribution, or reduction statement
- `Editorial/citation only`
  - no technical issue; the paper just needs cleaner writing or citations
- `Research-only / do not overclaim`
  - the current code path exists, but a stronger scientific claim would outrun what is presently justified

## Current Implementation Baseline

### Stable implementation facts

- The retained showing path is `literal_packed_aggregated_v3`.
- The shipped showing preset is `soundness_balanced`.
- The shipped showing CLI default for the PRF companion route is `output_audit`.
- The persisted holder schema is `credential.State`, which stores top-level signed rows `M1`, `M2`, `R0`, `R1`, `T`, `SigS1`, `SigS2`, and `PackedNCols`.
- The retained showing witness surface is `PIOP.CoeffNativeShowingWitness`, with fields `Sig`, `M1`, `M2`, `R0`, `R1`, `T`, and `PackedNCols`.
- `cmd/showing/main.go` rebuilds the showing witness from those signed rows, derives the PRF key from `M2`, samples a public nonce, computes `tag = PRF(key, nonce)`, and verifies one combined proof.
- `PIOP/signed_key_extraction.go` derives the showing-time PRF key directly from the signed `M2` row.
- `PIOP/showing_semantic_rewrite_eval.go` enforces the cleared relation
  - `(B3 - r1) * t - (B0 + B1 * (m1 + m2) + B2 * r0) = 0`
  - at replay time over the committed witness rows.
- `PIOP.PublicInputs` is the live public statement surface for `B`, `T`, `Tag`, `Nonce`, and `BoundB`.
- `PIOP/proof_report.go` reports the live preset, witness geometry, transcript buckets, and the signed-key-source marker `signed_m2`.
- `cmd/showing/integration_test.go` and `PIOP/prf_companion_test.go` confirm the live geometry and the `M2`-row PRF-key binding.

### Representative current run on March 29, 2026

Command used:

```bash
go run ./cmd/showing -coeff-model literal_packed_aggregated_v3
```

Representative output from the current repo:

- paper transcript: `47174` bytes (`46.07 KB`)
- current verifier payload: `63082` bytes (`61.60 KB`)
- stable bucket values in the sampled runs:
  - `VTargets = 15130`
  - `Pdecs = 8249`
  - `BarSets = 2845`
  - `Q = 4127`
- representative run-specific values from the sampled run above:
  - `Auth = 2358`
  - theorem total = `100.16`
  - raw Eq. (8) total = `95.24`
  - geometry = `witness=859`, `post=848`, `prf=11`, `NCols=16`, `LVCSNCols=96`, `NLeaves=4096`, `theta=5`, `eta=63`, `kappa={0,0,0,5}`, `dQ=246`

Observed caveat: `Auth` and the transcript total moved slightly across repeated runs during this review, while the preset, geometry, soundness profile, and the main bucket values above stayed stable. The manuscript should therefore present this block as a representative current run, not as an immutable constant.

## Witness, Constraints, and Commitment/Opening Alignment

This section goes deeper than the `CAR-*` inventory. It targets the paper subsections that still misdescribe the live proof model:

- `4.4` showing protocol
- `5.1` SmallWood formal interface
- `5.2` constraint compilation recipe
- `5.3` issuance constraints
- `5.4` showing constraints
- `5.5` PRF constraints
- Appendix `C.5` to `C.8`

The key paper-side discipline is to separate four objects that the current draft still tends to collapse together:

- the authenticated holder-side witness surface in `credential.State`
- the retained caller-boundary showing witness `PIOP.CoeffNativeShowingWitness`
- the committed row oracle under `Proof.Root`
- the later transcript objects under `Proof.QRoot` and `Proof.PRFCompanion`

The live proof path does still enforce one coherent witness assignment, but it no longer matches the paper's older prose in which the showing witness is just "issuance rows plus extra rows" and the PRF is a pure row-family story with one committed key row per lane.

### Paper Section 4.4: Showing Protocol

- `Paper currently says:`
  - the holder shows with a credential of the form `(mu, k, r0, r1, u)`
  - the post-sign proof directly proves knowledge of `(u, mu, k, r0, r1)`
- `Live code actually does:`
  - `credential.State` persists the authenticated rows `SigS1`, `SigS2`, `M1`, `M2`, `R0`, `R1`, `T`, and `PackedNCols`
  - `cmd/showing/main.go` rebuilds `PIOP.CoeffNativeShowingWitness{Sig, M1, M2, R0, R1, T, PackedNCols}` from that state
  - the PRF key is derived from signed `M2` by `PIOP.ExtractSignedPRFKeyElems`, not supplied as an independent witness object
  - `PIOP.BuildShowingCombined` forces the live one-root companion route by enabling packed PRF witness rows and the PRF companion path
- `What is inconsistent:`
  - the paper still presents the showing witness as a direct issuance tuple
  - it omits the authenticated target row `T` and the signed signature rows at the caller boundary
  - it makes the PRF secret look independent of the authenticated signed message
- `Replacement text:`

```tex
% Replace Section 4.4's opening witness description with the following.
\paragraph{Live showing witness surface.}
In the retained implementation, the holder-side state consumed by the
showing prover is the authenticated signed surface
\[
(\mathrm{Sig}_1,\mathrm{Sig}_2,m_1,m_2,r_0,r_1,T),
\]
where $\mathrm{Sig}_1,\mathrm{Sig}_2$ are the signature rows, $(m_1,m_2)$
are the authenticated message rows, $(r_0,r_1)$ are the authenticated
auxiliary rows, and $T$ is the authenticated hash target. The showing
prover derives the PRF key from the authenticated row $m_2$; it does
not introduce an independent PRF secret.

\paragraph{Showing protocol.}
On input holder-local state for a valid credential and a public nonce
$\mathsf{nonce}$, the holder:
\begin{enumerate}
\item reconstructs the authenticated showing witness
$(\mathrm{Sig}_1,\mathrm{Sig}_2,m_1,m_2,r_0,r_1,T)$;
\item derives the PRF key from the authenticated row $m_2$;
\item computes $\mathsf{tag}=F(k,\mathsf{nonce})$; and
\item produces one post-sign proof whose verification binds the public
tag to the same authenticated rows that also satisfy the signature and
cleared-hash relations.
\end{enumerate}
```

### Paper Section 5.1: What SmallWood Provides

- `Paper currently says:`
  - witness rows are interpolated to polynomials and SmallWood commits to the evaluations of all `P_i`
  - the verifier then checks constraints over `Omega` with spot-checks outside `Omega`
- `Live code actually does:`
  - the retained proof path is explicit-domain only
  - the witness-row oracle is committed under `Proof.Root`
  - the batched `Q` side of the protocol is committed separately under `Proof.QRoot`
  - the combined row opening lives in `Proof.PCSOpening` / `Proof.RowOpening`
  - the `Q` opening lives in `Proof.QOpening`
  - later Fiat-Shamir rounds also bind `Proof.PRFCompanion.CoordDigest`, companion opening payloads, and `Proof.LabelsDigest`
- `What is inconsistent:`
  - the paper makes the proof stack sound like one undifferentiated commitment object
  - it does not distinguish the witness-row oracle from the later `Q` commitment and companion transcript material
- `Replacement text:`

```tex
% Replace Section 5.1 with the following higher-fidelity interface summary.
\subsection{What SmallWood provides in the retained ARC-SPRUCE path}
Fix an evaluation set $\Omega \subset F_q$ of size $s$ and a disjoint
tail set $\Omega' \subset F_q \setminus \Omega$ of size $\ell$. In the
retained implementation, the proof-facing interface is best viewed as
three bound objects:
\begin{enumerate}
\item a witness-row oracle commitment, with Merkle root
$\mathsf{Root}$, that binds all committed witness rows;
\item a separate commitment, with Merkle root $\mathsf{QRoot}$, to the
batched $Q$ polynomials used by the masked $\Omega$-sum side of the
PIOP; and
\item later transcript-bound auxiliary payloads, including PRF
companion digests and openings when the showing statement uses the
live PRF companion route.
\end{enumerate}
Each committed witness row is still represented by a low-degree
polynomial matching the packed values on $\Omega$ and masked tail values
on $\Omega'$. However, the full proof object is not just ``one
commitment to all $P_i$'': it is a row commitment under
$\mathsf{Root}$, a later batched-$Q$ commitment under
$\mathsf{QRoot}$, and transcript-bound opening material that the
verifier checks together.
```

### Paper Section 5.2: Constraint Compilation Recipe

- `Paper currently says:`
  - choose witness rows
  - fix packing
  - add selectors
  - write constraint families
  - add bounds
- `Live code actually does:`
  - the compiler distinguishes three layers:
    - semantic holder-side witness objects
    - committed row expansion
    - replay and companion verification objects
  - `PIOP.BuildShowingCombined` first expands the semantic witness into the committed row layout
  - only after row construction does it build replayable post-sign constraint families and, separately, the PRF companion metadata
- `What is inconsistent:`
  - the current recipe is too generic and invites the reader to think the semantic witness and the committed row matrix are the same object
  - it also makes the PRF path sound like ordinary row-family compilation, which is no longer the whole story
- `Replacement text:`

```tex
% Replace Section 5.2 with the following three-layer compilation recipe.
\subsection{Compilation recipe for the retained proof path}
Given an ARC statement, we compile it in three layers.

\paragraph{Layer 1: semantic witness.}
First specify the authenticated semantic witness consumed by the
statement. For showing, this is the signed surface
$(\mathrm{Sig}_1,\mathrm{Sig}_2,m_1,m_2,r_0,r_1,T)$ rather than the full
issuance witness.

\paragraph{Layer 2: committed rows.}
Next expand that semantic witness into the committed row oracle under
$\mathsf{Root}$. This expansion may introduce packed signature rows,
replay-facing helper rows, boundedness chains, and packed PRF
companion rows.

\paragraph{Layer 3: verifier-side replay objects.}
Finally build the residual families and opening plans checked by the
verifier. In the retained showing path, the post-sign signature/hash
statement is replayed from opened row values, while the PRF side is
completed by transcript-bound companion checks rather than by a
standalone family of committed key-lane rows.
```

### Paper Section 5.3: Issuance (Pre-sign) Constraints

- `Paper currently says:`
  - issuance witness rows are `M1, M2, RU0, RU1, R, R0, R1, K0, K1`
  - `T` is public
  - commit, centering, hash, packing, and bound constraints are enforced
- `Live code actually does:`
  - `issuance/flow.go` and `PIOP/credential_rows.go` still center the pre-sign row order on `M1`, `M2`, `RU0`, `RU1`, `R`, `R0`, `R1`, `K0`, `K1`
  - `T` is public in issuance
  - the pre-sign constraint set is built directly from the committed row polynomials, including the row/tail model used by replay
  - helper rows for replay/boundedness can be appended at row-build time; they are not a reason to treat showing as "issuance plus extra rows"
- `What is inconsistent:`
  - the main issue is not the issuance base order itself
  - the inconsistency is that the paper's issuance narrative leaks into the later showing narrative and makes the showing witness look like a simple extension of issuance
- `Replacement text:`

```tex
% Keep Section 5.3, but replace its lead paragraph with the following.
\paragraph{Issuance row model.}
The pre-sign statement uses the issuance-side rows
\[
M_1, M_2, RU_0, RU_1, R, R_0, R_1, K_0, K_1,
\]
with public target $T$. The verifier-side residuals are built from the
committed row polynomials themselves, so the pre-sign replay already
includes the row-oracle and masked-tail semantics of the retained
SmallWood stack.

\paragraph{Important separation from showing.}
This issuance row model should not be read as the base prefix of the
live showing witness. The retained showing path starts from a different
authenticated semantic witness and then performs its own row expansion.
```

### Paper Section 5.4: Showing (Post-sign) Constraints

- `Paper currently says:`
  - the showing witness is a single matrix arranged as:
    - issuance-style base rows
    - `T`
    - signature rows `U`
    - a PRF witness block consisting of `Key[i]` rows and checkpoint rows `Z[alpha]`
- `Live code actually does:`
  - the caller-boundary showing witness is `PIOP.CoeffNativeShowingWitness{Sig, M1, M2, R0, R1, T, PackedNCols}`
  - `PIOP/showing_coeff_native_literal_packed_runtime.go` then expands it into committed rows that include:
    - packed signature source rows
    - replay-facing signature-evaluation rows
    - explicit signed base rows for `M1`, `M2`, `R0`, `R1`
    - `T` block rows
    - non-sign bound-chain rows
    - packed signature shortness rows
    - packed PRF companion rows
  - in the live companion route, the paper-level PRF key is sourced from signed `M2`, not from a standalone committed key-row family
- `What is inconsistent:`
  - the paper still treats the showing witness as issuance plus extra rows
  - it still lists issuance randomness rows `RU0`, `RU1`, `R`, `K0`, `K1` as if they were the live showing boundary
  - it still treats the PRF key as if it were carried by dedicated committed key-lane rows
- `Replacement text:`

```tex
% Replace Section 5.4 with the following witness/constraint description.
\subsection{Showing (post-sign) witness and constraint families}
The retained showing path distinguishes the semantic witness from the
committed row expansion.

\paragraph{Semantic witness at the caller boundary.}
The showing prover starts from the authenticated signed surface
\[
(\mathrm{Sig}_1,\mathrm{Sig}_2,m_1,m_2,r_0,r_1,T).
\]
These are the holder-side objects that survive issuance and are loaded
from credential state. In particular, the retained showing boundary does
\emph{not} begin from the issuance-side rows
$(RU_0,RU_1,R,K_0,K_1)$.

\paragraph{Committed witness after row expansion.}
From that semantic witness, the prover builds the committed row oracle
under $\mathsf{Root}$. The resulting row set contains:
\begin{enumerate}
\item packed signature source rows;
\item replay-facing signature-evaluation rows;
\item explicit signed base rows for $m_1,m_2,r_0,r_1$;
\item one or more rows carrying the authenticated target $T$;
\item boundedness-chain rows for the non-signature signed rows;
\item packed signature-shortness rows; and
\item packed PRF companion rows.
\end{enumerate}

\paragraph{Replay-checked post-sign relations.}
The verifier replays the post-sign statement from opened row values. The
core replayed families are:
\begin{enumerate}
\item the signature relation linking the signature rows to $T$;
\item the cleared hash relation linking $T$ to the signed rows
$m_1,m_2,r_0,r_1$;
\item the message-split packing selectors;
\item the non-signature bound chains; and
\item the signature shortness chain.
\end{enumerate}
The PRF relation is completed by the companion route described next; it
is not represented in the live baseline as a family of standalone
committed key-lane rows.
```

### Paper Section 5.5: PRF Constraints

- `Paper currently says:`
  - the PRF witness uses committed key-lane rows `Key[0..ell_key-1]`
  - each `Key[i]` is tied to `M2` with a selector constraint
  - checkpoint rows `Z[alpha]` hold S-box outputs
  - the whole PRF is described as a parallel PACS constraint family
- `Live code actually does:`
  - the live one-root showing path uses the PRF companion route
  - `PIOP.PRFCompanionLayout` records `KeySourceSignedSecret` and `SignedKeyMapping{M2Row, Coeffs}`
  - the production baseline `output_audit` mode does not commit one standalone row per key lane; `PIOP/prf_companion_test.go` confirms `KeySlots == 0` and `CheckpointInputSlots == 0` in this route
  - grouped checkpoint data and final-tag material are packed into companion rows
  - the proof carries a companion digest plus opening payloads for checkpoint audits, final tag state, and key truncation
- `What is inconsistent:`
  - the paper still describes an older explicit-key-row design as if it were the retained baseline
  - it also overstates the PACS-only view of the PRF statement: the live proof uses both replay residuals and transcript-bound companion openings
- `Replacement text:`

```tex
% Replace Section 5.5 with the following companion-oriented wording.
\subsection{PRF checks in the retained one-root path}
The retained showing proof does not introduce an independent PRF witness
key. Instead, it derives the PRF key from designated coefficients of the
authenticated signed row $m_2$.

\paragraph{Signed-key source.}
The PRF key source is the signed secret-bearing row $m_2$. The live
baseline should therefore not be described as committing one witness row
per key lane.

\paragraph{Companion rows and packed checkpoints.}
The prover commits packed PRF companion rows containing grouped
checkpoint data and final-tag material. A companion layout records how
those packed slots relate to the signed $m_2$ row and to the public tag.

\paragraph{Verifier-side PRF checks.}
The verifier completes the PRF side in three bound pieces:
\begin{enumerate}
\item signed-key extraction and mapping back to the authenticated
$m_2$ row;
\item transcript-bound bridge checks for the packed checkpoint data; and
\item opening payload checks for sampled checkpoint audits, final tag
state, and key truncation.
\end{enumerate}
Accordingly, the retained PRF path is not just ``a parallel PACS family
with committed key rows and checkpoint rows'': it is a one-root proof in
which the PRF relation is split between replayed residuals and
companion openings, all bound into the same Fiat--Shamir transcript.
```

### Appendix C.5: What DECS/LVCS/PCS Bind in ARC-SPRUCE

- `Paper currently says:`
  - the stack provides a single commitment that simultaneously binds all witness rows used in a statement
  - the same `M2` row is also the row that key-binding constraints connect to the committed PRF key lanes
- `Live code actually does:`
  - the witness-row oracle is committed under `Proof.Root`
  - the batched `Q` side is committed under `Proof.QRoot`
  - `Proof.PRFCompanion` is a later transcript-bound object, not a second witness-row oracle
  - the coherent-witness claim is still true, but the mechanism is now:
    - row binding under `Root`
    - `Q` binding under `QRoot`
    - companion digest/openings in later FS rounds
- `What is inconsistent:`
  - "single commitment" is no longer accurate if it is read literally for the entire proof object
  - the PRF paragraph still assumes explicit committed key rows rather than signed-`M2` extraction plus companion layout
- `Replacement text:`

```tex
% Replace Appendix C.5 with the following more precise binding statement.
\subsection{What the retained proof object binds}
At a high level, the retained ARC-SPRUCE proof binds a single coherent
witness assignment, but it does so through several transcript-bound
objects rather than through one undifferentiated commitment.

\paragraph{Witness-row binding.}
All committed witness rows live under the row-oracle commitment with
Merkle root $\mathsf{Root}$. This is the object that binds the packed
signature rows, signed base rows, boundedness chains, and any packed PRF
companion rows.

\paragraph{Batched-$Q$ binding.}
The PIOP's batched $Q$ side is committed separately under
$\mathsf{QRoot}$. This does not introduce a second witness assignment;
it binds the batch polynomials derived from the same committed rows.

\paragraph{Companion transcript binding.}
When the showing statement uses the live PRF companion route, the proof
also binds companion digests and opening payloads in later Fiat--Shamir
rounds. These payloads are not a second witness oracle. They are
transcript-bound checks tied back to the same authenticated signed row
$m_2$ and the same committed row assignment.
```

### Appendix C.6: Openings Requested in Issuance vs Showing

- `Paper currently says:`
  - both proofs commit all witness rows and then open them at verifier-chosen points
  - the showing witness extends issuance with `T`, `U`, and PRF key/checkpoint rows
- `Live code actually does:`
  - both issuance and showing still use row openings against `Root` and `Q` openings against `QRoot`
  - issuance replays commitment, centering, hash, packing, and bound residuals from the opened rows
  - showing replays signature, hash, packing, non-sign bound-chain, and signature shortness residuals from opened rows
  - the PRF companion side is completed by companion opening payloads, not by opening an explicit committed key-row block
- `What is inconsistent:`
  - the showing half still describes the old explicit-key-row witness
  - it does not distinguish row openings from `Q` openings or mention the companion opening payload
- `Replacement text:`

```tex
% Replace Appendix C.6 with the following issuance/showing split.
\subsection{Openings requested in issuance versus showing}
Both proofs still follow the same high-level pattern:
\begin{enumerate}
\item commit the witness-row oracle under $\mathsf{Root}$;
\item derive Fiat--Shamir challenges;
\item commit the batched $Q$ side under $\mathsf{QRoot}$; and
\item open the committed objects at verifier-chosen coordinates.
\end{enumerate}

\paragraph{Issuance.}
In issuance, the verifier requests row openings sufficient to replay the
commitment, centering, cleared-hash, packing, and boundedness residuals,
and a separate $Q$ opening against $\mathsf{QRoot}$ for the masked
$\Omega$-sum side.

\paragraph{Showing.}
In showing, the verifier requests row openings sufficient to replay the
signature relation, the cleared-hash relation on the signed base rows,
the message-split selectors, the non-signature bound chains, and the
signature shortness chain. The verifier also checks a separate $Q$
opening against $\mathsf{QRoot}$ and, when the live PRF companion route
is enabled, companion opening payloads for the PRF-side audits.
```

### Appendix C.7: PACS/PIOP Interface

- `Paper currently says:`
  - `PACS.PIOPCommitOracleProver` commits `P || M` via a single PCS commitment
  - `PACS.PIOPOpenAndCheck` verifies openings of `P` and `M` and then checks the `Q` side
- `Live code actually does:`
  - the proof object records the row commitment root as `Root`
  - the later `Q` commitment root is recorded separately as `QRoot`
  - row openings and `Q` openings are separate proof fields
  - public inputs are serialized into `LabelsDigest` and fed into the FS chain
  - companion digests and opening payloads are also appended in the live showing route
- `What is inconsistent:`
  - the current appendix algorithm hides the `Root`/`QRoot` split
  - it omits the public-label binding and the companion payload from the live transcript
- `Replacement text:`

```tex
% Replace Appendix C.7 with the following proof-object-oriented interface.
\subsection{PACS/PIOP interface used by the retained proof}
The retained proof object should be described in terms of named transcript
artifacts rather than as a single opaque PCS output.

\paragraph{Step 1: row commitment.}
Commit the witness-row oracle and obtain the row root
$\mathsf{Root}$.

\paragraph{Step 2: batched-$Q$ commitment.}
After the relevant Fiat--Shamir challenges are derived from
$\mathsf{Root}$ and the bound public inputs, commit the batched
$Q$ polynomials and obtain $\mathsf{QRoot}$.

\paragraph{Step 3: openings.}
Output a row opening authenticated against $\mathsf{Root}$ and a
separate $Q$ opening authenticated against $\mathsf{QRoot}$. In the
live showing route, append any required PRF companion digest and
opening payloads to the later transcript rounds.
```

### Appendix C.8: Fiat-Shamir Compilation

- `Paper currently says:`
  - the protocol is compiled with Fiat-Shamir and grinding in the usual SmallWood style
- `Live code actually does:`
  - later transcript rounds bind, in order, the row root, public-label digest, gamma objects, `QRoot`, the companion coordinate digest, the batched-`Q` data, evaluation transcript material, and the companion opening payload
  - `LabelsDigest` is the deterministic hash of the bound public inputs
  - `TailTranscript` carries the final bound transcript material for the last sampled tail/opening round
- `What is inconsistent:`
  - the appendix currently treats Fiat-Shamir too generically and leaves out the live transcript-bound PRF companion material
  - it also does not state that the public input binding is explicit and hashed
- `Replacement text:`

```tex
% Replace the ARC-specific part of Appendix C.8 with the following.
\paragraph{ARC-specific Fiat--Shamir binding.}
In the retained ARC-SPRUCE proof, Fiat--Shamir does not bind only a
generic PCS commitment. It binds:
\begin{enumerate}
\item the row root $\mathsf{Root}$;
\item a digest of the deterministically encoded public inputs;
\item the sampled mixing coefficients for the replay and batch layers;
\item the batched-$Q$ root $\mathsf{QRoot}$;
\item when present, the PRF companion coordinate digest; and
\item the later opening transcript, including the PRF companion opening
payload in the live showing route.
\end{enumerate}
This is the mechanism that keeps the replayed signature/hash checks, the
batched-$Q$ checks, and the PRF companion checks tied to one coherent
statement instance.
```

### Documentary Anchors for This Alignment Pass

- `PIOP/prf_companion_test.go`
  - `TestPRFCompanionLayoutEmission` confirms the live `output_audit` route uses `KeySourceSignedSecret`, `SignedKeyMapping.M2Row`, zero standalone `KeySlots`, and packed companion rows
  - `TestPRFCompanionSignedKeyAlignment` confirms the signed key is extracted from the authenticated `M2` row
- `cmd/showing/integration_test.go`
  - `TestShowingPRFCompanionEnabled` confirms the live showing path expects the PRF companion proof
  - `TestShowingV3ExperimentalShortnessWideLVCS96ResearchBaseline` confirms the current `v3` geometry used by the shipped `soundness_balanced` baseline

## Region A: Introduction and Preliminaries

### CAR-01

- `Carsten remark:` add citations for the generic AC introduction.
- `Status:` `Editorial/citation only`
- `Clear answer:` yes. The paper opens with AC framing but leaves the reader without the standard anchors.
- `What the code actually does:` nothing in the implementation depends on this claim; it is pure paper framing.
- `Paper action:` add standard anonymous-credential citations before introducing ARC-SPRUCE.
- `Editorial action:` cite the general AC literature directly in the opening paragraph instead of leaving this as an inline TODO.

### CAR-02

- `Carsten remark:` cite prior work carefully when discussing practical post-quantum blind signatures.
- `Status:` `Editorial/citation only`
- `Clear answer:` yes. The current codebase is a very specific one-root construction, not evidence that arbitrary post-quantum blind-signature compositions are efficient.
- `What the code actually does:` the live showing path co-designs witness semantics, commitment layout, replay verification, and PRF binding; it is not a black-box composition story.
- `Paper action:` rewrite the introductory claim so it distinguishes generic compositions from the concrete ARC-SPRUCE design.
- `Editorial action:` add citations and rephrase the paragraph so it does not overgeneralize from this implementation to the whole blind-signature landscape.

### CAR-03

- `Carsten remark:` remove the conflicting-notation remark before submission.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The paper should stop apologizing for notation and instead state one explicit policy: `B` names the public hash-key object, while coefficient bounds use `\beta_*` notation.
- `What the code actually does:` the live statement already separates these objects. `PIOP.PublicInputs` carries `B []*ring.Poly` and `BoundB int64` separately, and `PIOP/credential_constraints.go` requires `len(B) == 4` for the cleared relation.
- `Paper action:` delete the remark and replace it with a short notation charter that reserves `B` for the public ARC hash key and keeps implementation-only names such as `BoundB` out of the mathematical notation.
- `Replacement snippet:` use `Snippet B0` below.

### CAR-04

- `Carsten remark:` introduce the `ISIS` problem where it is first referenced.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` yes. The theorem layer currently asks the reader to accept an undefined assumption.
- `What the code actually does:` the repo computes concrete proofs, transcripts, and soundness reports, but it does not define the paper's `ISIS-f` assumption.
- `Paper action:` define `ISIS-f` before it is used, including the witness shape, norm bound, and relation family.
- `Unresolved gap:` the repo does not determine what `ISIS-f` is supposed to mean in the theorem, so no safe exact snippet can be drafted from code alone.

## Region B: Definitions 2.5-2.8 and the Signature Template

### Preliminaries Notation and Domain Discipline

- `Notation charter:`
  - `B` names the public ARC hash-key object only.
  - in the live code, that object is `PIOP.PublicInputs.B []*ring.Poly` and it always has length `4`
  - `BoundB` is a separate implementation scalar bound on the non-sign signed rows; it is not part of the public hash key
  - paper-side norm bounds should therefore use `\beta_*` notation, not `B`-shaped symbols
- `Code-aligned component map:`
  - `B[0]` is the additive constant term
  - `B[1]` multiplies `m_1 + m_2`
  - `B[2]` multiplies `r_0`
  - `B[3]` is the denominator/base term paired with `r_1`
- `Domain discipline:`
  - `Statement domain:` the cleared relation is a ring-level public relation on `B`, `m_1`, `m_2`, `r_0`, `r_1`, and `t`
  - `Implementation storage domain:` the code stores and transports `B` as four public `*ring.Poly` rows through `credential` loading and `PIOP.PublicInputs`
  - `Verifier replay domain:` `PIOP/showing_semantic_rewrite_eval.go` converts the public `B` rows into replay polynomials and evaluates them at explicit proof-system domain points; this replay domain is not the paper's algebraic statement domain
- `Reference discipline:`
  - `docs/2025-356.pdf` is useful as a style reference for one-key notation such as `h_{m,\chi}(B)`
  - when it differs from the retained ARC code path, the code wins and the paper should describe the ARC specialization explicitly

### CAR-05

- `Carsten remark:` add bounds on `B0` and `b1` in Definition 2.5.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` the paper must answer two different questions separately: what the public key `B` looks like, and what bounds the hidden rows satisfy. Those are not the same object in the code or in the proof statement.
- `What the code actually does:` `PIOP.PublicInputs.B` is a four-row public hash key, while `BoundB` is a separate scalar bound. `PIOP.BuildHashConstraints` and `PIOP.BuildHashConstraintsNTT` require `len(B) == 4` and use those four rows as constant, message, randomness, and denominator-side terms.
- `Paper action:` define one public key object `B = (B^{const}, B^{msg}, B^{rnd}, B^{den})`, state its role in the cleared relation, and move all norm bounds to `\beta_*` symbols.
- `Replacement snippet:` use `Snippet B0`, `Snippet B1`, and `Snippet D1` below.

### CAR-06

- `Carsten remark:` add bounds on `m` in Definition 2.5.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The code never works with one undifferentiated message symbol. It persists and proves over the split message `m = (m_1, m_2)`, so the paper should define a bounded product space rather than an abstract unbounded `m`.
- `What the code actually does:` `credential.State` stores `M1` and `M2` separately; `credential.HashMessage` computes the target from `B`, `m_1`, `m_2`, `r_0`, `r_1`; and `cmd/showing/main.go` rebuilds the retained showing witness from those signed rows.
- `Paper action:` define the message space as bounded split rows and say explicitly that `m_2` is the secret-bearing signed component later used for PRF-key extraction.
- `Replacement snippet:` use `Snippet B1` and `Snippet B3`.

### CAR-07

- `Carsten remark:` add bounds on `chi = (x0, x1)` in Definition 2.5.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes, but the more important fix is to stop making the implemented statement look like a floating randomized-hash interface. The live proof works with bounded auxiliary rows `r = (r_0, r_1)` that are part of the authenticated witness surface.
- `What the code actually does:` `credential.State` persists signed `R0` and `R1`; `PIOP.CoeffNativeShowingWitness` carries `R0` and `R1` explicitly; and `PIOP/showing_semantic_rewrite_eval.go` replays the cleared relation over those rows at verifier challenge points.
- `Paper action:` describe bounded auxiliary rows `r_0` and `r_1` directly, and only mention `\chi` as historical notation if the paper explicitly maps it to `(r_0, r_1)`.
- `Replacement snippet:` use `Snippet B1`, `Snippet B3`, and `Snippet B4`.

### CAR-08

- `Carsten remark:` specify compatible dimensions of `B0..B3` in Definition 2.6.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The paper must say that the four public components of `B` and the hidden rows are chosen so every term of the cleared relation lands in the same target ring/module.
- `What the code actually does:` in the retained implementation each component of `B` is one public ring polynomial in `PIOP.PublicInputs.B`, and `BuildHashConstraints` combines them with `m_1`, `m_2`, `r_0`, `r_1`, and `t` into one residual in the same ring. The replay layer then evaluates those public polynomials at explicit verifier points.
- `Paper action:` state the compatibility condition at the statement level, and keep the replay/evaluation-domain explanation separate.
- `Replacement snippet:` use `Snippet B1` and `Snippet B4`.

### CAR-09

- `Carsten remark:` the cleared-denominator definition does not explain `r0`, `r1`, `x0`, `x1`, `B2`, `B3`, and treats a hash as randomized.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` this is a real semantic mismatch. The paper should make the cleared relation primary and should stop describing the live implementation as if it exposed a separate randomized-hash API.
- `What the code actually does:` `credential.HashMessage` computes the target from public `B` and hidden `m_1`, `m_2`, `r_0`, `r_1`; `PIOP.BuildHashConstraints` and `PIOP.BuildHashConstraintsNTT` fix the residual
  - `(B[3] - r_1) \odot t - (B[0] + B[1] \cdot (m_1 + m_2) + B[2] \cdot r_0) = 0`
  - and `PIOP/showing_semantic_rewrite_eval.go` replays that same equation after converting the public `B` rows into replay polynomials over the verifier domain.
- `Paper action:` write the paper-level definition as the public cleared relation on bounded rows, and if the quotient-style view is kept at all, relegate it to a short bridge note.
- `Replacement snippet:` use `Snippet B1`, `Snippet B2`, and `Snippet B4`.

### CAR-10

- `Carsten remark:` explain how the ARC `B0..B3` parameterization matches the earlier BBS-style form.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` the paper should keep one public object `B` throughout. The right bridge to the earlier style is not "two equal notations carried in parallel," but "the generic one-key view specializes in ARC to four public rows with fixed roles."
- `What the code actually does:` `docs/2025-356.pdf` motivates notation of the form `h_{m,\chi}(B)`, but the retained ARC code instantiates that public key as `PIOP.PublicInputs.B` with four rows. The runtime never exposes `(B_0,b_1,x_0,x_1)` as a first-class implementation interface.
- `Paper action:` keep the one-key notation only as a generic reference point, then immediately specialize to the ARC form `B = (B^{const}, B^{msg}, B^{rnd}, B^{den})`.
- `Replacement snippet:` use `Snippet B2`.

### CAR-11

- `Carsten remark:` define the message space `M`.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The paper should define `M` exactly as a bounded split-message space, not as a placeholder set later retrofitted with two different roles.
- `What the code actually does:` `credential.State` stores `M1` and `M2` separately, the showing loader consumes them as distinct authenticated rows, and the PRF key is extracted from signed `M2`.
- `Paper action:` define `M \subseteq R_q^{\ell_{m_1}} \times R_q^{\ell_{m_2}}`, state the bound convention, and keep the semantic roles of `m_1` and `m_2` explicit.
- `Replacement snippet:` use `Snippet B3` and `Snippet C1`.

### CAR-12

- `Carsten remark:` specify the distribution of `chi` in signing.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` yes. The paper cannot leave the auxiliary-row distribution implicit.
- `What the code actually does:` the repo persists concrete rows `R0` and `R1`, proves the cleared relation over them, and keeps `BoundB` as a separate verifier-side bound parameter. It does not expose a finished theorem-level sampler statement for an abstract `\chi`.
- `Paper action:` if the paper keeps `\chi`, define it at the statement level as the source of `(r_0,r_1)`, specify its support and norm bound, and do not confuse that sampler with the later replay/evaluation domain.
- `Unresolved gap:` the code does not identify a canonical theorem-grade distribution statement for `chi`, so the paper must supply that independently.

### CAR-13

- `Carsten remark:` state the condition on `chi` relative to `B`.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` yes. The paper needs an admissibility condition, not only a norm bound.
- `What the code actually does:` the replay verifier checks the cleared relation on already supplied rows and does not separately formalize the quotient-side admissibility predicate. In particular, the code-level `BoundB` bound is not itself that admissibility condition.
- `Paper action:` if the paper retains the rational-function view, define the admissibility predicate as a statement-level condition on `B` and the sampled auxiliary rows, and state the signer rejection rule explicitly.
- `Unresolved gap:` the repo does not tell the paper what admissibility predicate or rejection rule to write down, so no exact final snippet is safe here.

### CAR-14

- `Carsten remark:` can the paper state unforgeability based on prior work?
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` only if the manuscript either cites a prior theorem whose assumptions exactly match this template or writes a new theorem with those assumptions spelled out.
- `What the code actually does:` the code realizes and checks a concrete relation, but it does not encode a reduction argument.
- `Paper action:` either inherit a matching theorem with precise citations or write a new one explicitly.
- `Unresolved gap:` the repo alone does not justify an inheritance claim, so the manuscript must supply the theorem or the citation chain itself.

### Grouped Replacement Snippets for Definitions 2.5-2.8

#### Snippet B0: Notation convention

Use this once near the beginning of the preliminaries cleanup so the later definitions stop reintroducing the same collision.

```tex
\paragraph{Notation convention for ARC hash keys and bounds.}
Throughout this paper, $B$ denotes the public ARC hash key only. In the
retained ARC instantiation, $B$ has four public components,
\[
B = \bigl(B^{\mathrm{const}}, B^{\mathrm{msg}}, B^{\mathrm{rnd}}, B^{\mathrm{den}}\bigr),
\]
which correspond in the current code to the four public rows
$B[0],B[1],B[2],B[3]$. We reserve $\beta$-style notation for norm
bounds on hidden rows. In particular, implementation names such as
\texttt{BoundB} should not be read as mathematical components of the
public key $B$.
```

#### Snippet B1: Code-aligned Definitions 2.5-2.6

Use this to replace the current mixed `B_i` / quotient-style discussion with the ARC specialization the code actually proves.

```tex
\paragraph{Global message and auxiliary-row shape.}
Throughout the hash/signature layer, the authenticated message is split
as $m=(m_1,m_2)$, where $m_1 \in R_q^{\ell_{m_1}}$ carries the holder
attributes and $m_2 \in R_q^{\ell_{m_2}}$ is the secret-bearing
component later used for PRF-key extraction. We also use auxiliary rows
$r_0 \in R_q^{\ell_{r_0}}$ and $r_1 \in R_q^{\ell_{r_1}}$. These hidden
rows are coefficient-wise bounded by public $\beta$-style bounds.

\begin{definition}[ARC cleared relation]
Fix a public ARC hash key
\[
B = \bigl(B^{\mathrm{const}}, B^{\mathrm{msg}},
          B^{\mathrm{rnd}}, B^{\mathrm{den}}\bigr),
\]
with dimensions chosen so that
$B^{\mathrm{const}}$,
$B^{\mathrm{msg}}\cdot(m_1+m_2)$,
$B^{\mathrm{rnd}}\cdot r_0$,
$(B^{\mathrm{den}}-r_1)\odot t$, and $t$
all lie in the same target module. We say that
$(m_1,m_2,r_0,r_1,t)$ satisfies the cleared relation with respect to $B$
if
\[
(B^{\mathrm{den}}-r_1)\odot t -
\bigl(B^{\mathrm{const}} + B^{\mathrm{msg}}\cdot(m_1+m_2)
      + B^{\mathrm{rnd}}\cdot r_0\bigr)=0.
\]
\end{definition}

\paragraph{Current implementation specialization.}
In the retained code path, each component of $B$ is one public ring
polynomial, so the above relation is instantiated over one common copy
of $R_q$.
```

#### Snippet B2: Bridge to the 2025-356 style

Use this if the paper wants to mention the generic one-key rational-hash viewpoint without reviving the old conflicting notation.

```tex
\paragraph{Bridge to the generic one-key notation.}
The notation in \texttt{2025-356.pdf} motivates writing a keyed rational
function as $h_{m,\chi}(B)$ for one public key object $B$. We follow
that discipline here. The retained ARC implementation then specializes
that public key into the four structured public components
\[
B = \bigl(B^{\mathrm{const}}, B^{\mathrm{msg}},
          B^{\mathrm{rnd}}, B^{\mathrm{den}}\bigr),
\]
rather than carrying a second parallel notation based on
$(B_0,b_1,x_0,x_1)$.
```

#### Snippet B3: Revised Definition 2.8

Use this as the replacement signature-template wording until the theorem-level sampler and admissibility details are stated separately.

```tex
\begin{definition}[Code-aligned vSIS-style signature template]
Let
\[
M \subseteq R_q^{\ell_{m_1}} \times R_q^{\ell_{m_2}}
\]
be the bounded split-message space. Let $B$ be the public ARC hash key
from the cleared relation above, and let $\beta_{\mathrm{msg}}$ denote
the public bound regime for the hidden message and auxiliary rows. On
input $(m_1,m_2) \in M$, the signer samples auxiliary rows
$(r_0,r_1)$ according to the instantiated construction, computes a
target $t$ satisfying the cleared relation with respect to $B$, and
outputs a short preimage $u$ such that $Au=t$. Verification checks the
public shortness bound on $u$ together with the cleared relation.
\end{definition}
```

#### Snippet B4: Code/domain note

Use this when the paper needs to distinguish algebraic domains from proof-system replay domains.

```tex
\paragraph{Statement domain versus replay domain.}
The cleared relation above is a statement-level algebraic relation over
the public key $B$ and hidden rows $(m_1,m_2,r_0,r_1,t)$. In the
implementation, these public components are stored as public ring
polynomials and later converted into replay polynomials that are
evaluated at verifier-chosen proof-system domain points. This later
replay domain is part of the proof machinery and should not be confused
with the algebraic domain in which the cleared relation itself is
defined.
```

`Snippet B3` is intentionally conservative. It is not a substitute for the missing theorem-grade sampler and admissibility statements still called out in `CAR-12`, `CAR-13`, and `CAR-14`.

## Region C: ARC Syntax, Credential Contents, Showing, and PRF Placement

### CAR-15

- `Carsten remark:` there is no clear place for the global message split.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` the split is central and should move into the ARC syntax, not remain as a floating note.
- `What the code actually does:` the state schema, showing loader, and PRF-key extraction all treat `M1` and `M2` as separate authenticated rows, with the PRF key derived from `M2`.
- `Paper action:` move `m = (m1, m2)` into the core ARC syntax section.
- `Replacement snippet:` use `Snippet C1`.

### CAR-16

- `Carsten remark:` should the credential also carry a message?
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. In the live repo, the holder state contains authenticated message rows and signed auxiliary witness material, not just an opaque credential token.
- `What the code actually does:` `credential.State` persists `M1`, `M2`, `R0`, `R1`, `T`, `SigS1`, `SigS2`, and `PackedNCols`, and `cmd/showing/main.go` rebuilds the retained showing witness from them.
- `Paper action:` say that the credential authenticates the message split together with the witness material needed for later zero-knowledge showing.
- `Replacement snippet:` use `Snippet C1`.

### CAR-17

- `Carsten remark:` clarify where the nonce comes from.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` the paper should treat the nonce as public and verifier-side. The demo CLI samples it locally only because the command simulates both sides.
- `What the code actually does:` `PIOP.PublicInputs` contains `Nonce`, and `cmd/showing/main.go` samples `nonce`, computes `tag`, and passes both as public inputs to the combined proof.
- `Paper action:` make the nonce public in the syntax and say `Show` is parameterized by it.
- `Replacement snippet:` use `Snippet C1` and `Snippet C3`.

### CAR-18

- `Carsten remark:` keep state in the security game rather than in the ARC syntax line.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` agreed. The live verifier API consumes public inputs, not holder-local secret state.
- `What the code actually does:` holder-local state is loaded privately from `credential_state.json`, while the verifier operates on `vk`, `pres`, `Nonce`, `Tag`, and public matrices/targets.
- `Paper action:` keep holder-local witness material in the game definitions and correctness/security discussions, not in the public syntax tuple.
- `Replacement snippet:` use `Snippet C1`.

### CAR-19

- `Carsten remark:` the blindness-game notation around `cred1` and `cred_b` is confusing.
- `Status:` `Editorial/citation only`
- `Clear answer:` yes. This is a notation cleanup, not a protocol issue.
- `What the code actually does:` nothing in the implementation depends on these labels.
- `Paper action:` normalize the challenge-credential notation and remove duplicate label drift.
- `Editorial action:` rename the challenge credentials so the game has one consistent notation for the left/right branches.

### CAR-20

- `Carsten remark:` add the Poseidon2 citation.
- `Status:` `Editorial/citation only`
- `Clear answer:` yes.
- `What the code actually does:` the repo uses a Poseidon2-like PRF path, but the missing citation is a paper-only defect.
- `Paper action:` cite Poseidon2 at the first definition of the PRF or permutation.
- `Editorial action:` add the Poseidon2 citation at Definition 2.21 or the sentence immediately preceding it.

### CAR-21

- `Carsten remark:` move the PRF constraint-view text to a later section.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The paper should separate the cryptographic PRF definition from the later proof-specific arithmetization.
- `What the code actually does:` the live proof is one combined proof. The showing code binds the PRF relation to the same proof object used for the post-sign relation, and the PRF companion route is part of that one transcript.
- `Paper action:` keep the PRF definition self-contained, and move the proof-facing description to the showing/proof section.
- `Replacement snippet:` use `Snippet C2`.

### Grouped Replacement Snippets for ARC Syntax, Showing, and PRF Placement

#### Snippet C1: Put the message split and credential contents into the ARC syntax

```tex
\paragraph{Global message rule.}
Every authenticated message is split as $m=(m_1,m_2)$. The
component $m_1$ carries the holder attributes. The component $m_2$
is the secret-bearing signed component from which the showing-time
PRF key is derived. We never swap these roles.

\begin{definition}[ARC scheme syntax]
Let $N$ be a finite public nonce space. An ARC scheme is a tuple
$(\mathsf{Setup},\mathsf{IssuerKeyGen},\mathsf{Issue},\mathsf{Show},\mathsf{Verify})$
such that:
\begin{itemize}
\item $\mathsf{Setup}(1^\lambda)$ outputs public parameters.
\item $\mathsf{IssuerKeyGen}$ outputs issuer keys $(vk,sk)$.
\item $\mathsf{Issue}$ is an interactive protocol after which the holder
obtains holder-local state for a credential authenticating
$(m_1,m_2)$ together with the auxiliary witness material needed for
later zero-knowledge showing.
\item $\mathsf{Show}$ takes as input holder-local state for a valid
credential and a public nonce $\mathsf{nonce}\in N$, and outputs a
presentation $\mathsf{pres}$.
\item $\mathsf{Verify}(vk,\mathsf{pres},\mathsf{nonce})$ is deterministic
and public-input only.
\end{itemize}
\end{definition}
```

#### Snippet C2: Keep the PRF definition separate from the proof statement

```tex
\paragraph{PRF definition versus proof-facing statement.}
The PRF definition itself is independent of the proof system. The
proof-specific statement is deferred to the showing section. In the
retained implementation, the showing proof does not introduce an
independent PRF secret. Instead, it derives the PRF key from the
authenticated secret-bearing row $m_2$ and proves the public
relation $\mathsf{tag}=F(k,\mathsf{nonce})$ against the same committed
witness assignment that also satisfies the post-sign relation.
```

#### Snippet C3: Clarify nonce semantics and verifier state

```tex
\paragraph{Nonce semantics and verifier state.}
The nonce is public. Conceptually it is supplied by the verifier or by
the verification environment, even if a local demo command samples it
internally. Verification checks the proof and enforces the applicable
rate policy by recording previously accepted
$(\mathsf{nonce},\mathsf{tag})$ pairs in the relevant policy context.
```

## Region D: Setup, Issuance, Security Theorems, and Blindness

### CAR-22

- `Carsten remark:` specify the ring and SIS parameters in Theorem 3.1.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The theorem must name the public ring family, dimensions, and norm regime instead of saying only that "SIS is hard."
- `What the code actually does:` the live repo fixes concrete proving parameters through the default ring and the `soundness_balanced` showing preset.
- `Paper action:` write the theorem over explicit public parameters and not over an unnamed ambient ring.
- `Replacement snippet:` use `Snippet D1` and `Snippet D2`.

### CAR-23

- `Carsten remark:` define `ISIS-f` and the relevant security properties.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` yes. The paper currently asks the reader to accept an undefined assumption.
- `What the code actually does:` the repo does not and cannot determine the theorem author's intended `ISIS-f` experiment.
- `Paper action:` define `ISIS-f` formally, including the witness relation, norms, and success condition.
- `Unresolved gap:` no exact final snippet is safe until the paper fixes what `ISIS-f` means.

### CAR-24

- `Carsten remark:` define the security requirement for the trapdoor sampler.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` yes. The theorem needs a precise sampler guarantee, not a placeholder phrase.
- `What the code actually does:` the runtime signs and verifies concrete targets, but it does not spell out the sampler's theorem-level distributional guarantee.
- `Paper action:` state the required support, norm bound, statistical or computational closeness property, and failure probability.
- `Unresolved gap:` the repo does not pin down the exact sampler guarantee the paper wants to claim, so the manuscript must provide it independently.

### CAR-25

- `Carsten remark:` specify what "indistinguishable under ..." means in the proof sketch.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` yes. The proof sketch needs a named indistinguishability statement.
- `What the code actually does:` the repo reports concrete proof and soundness metrics, but it does not define the proof sketch's hybrid argument.
- `Paper action:` replace the placeholder with the exact computational or statistical indistinguishability claim and the assumption it relies on.
- `Unresolved gap:` no safe exact wording can be derived from code, because the missing statement is purely theorem-level.

### CAR-26

- `Carsten remark:` say that the ring dimensions and `q` are fixed in advance.
- `Status:` `Code-settled; paper rewrite needed`
- `Clear answer:` yes. The implementation assumes this everywhere.
- `What the code actually does:` the commands load one fixed ring before proving or verifying, and the live preset parameters are defined relative to that fixed ring.
- `Paper action:` move this into `Setup` so the theorem and protocol sections both inherit it.
- `Replacement snippet:` use `Snippet D1`.

### CAR-27

- `Carsten remark:` explain how the hash key `B` is generated and where `beta_msg` comes from.
- `Status:` `Paper-open; code does not settle this`
- `Clear answer:` the paper must move this into setup and define it before any commitment- or message-length claim depends on it.
- `What the code actually does:` the runtime consumes already-populated public matrices and bound metadata from files and state. It does not tell the paper how to present a self-contained key-generation narrative.
- `Paper action:` define `B`, `beta_msg`, and the message-split lengths in `Setup`.
- `Unresolved gap:` the repo does not supply a finished paper-level setup story for `B` generation and `beta_msg`, so the manuscript must write that explicitly.

### CAR-28

- `Carsten remark:` add the blindness reduction to the same hiding problem as BLNS.
- `Status:` `Research-only / do not overclaim`
- `Clear answer:` not from the present code alone. The manuscript should not claim a stronger blindness theorem than the current opening layer supports.
- `What the code actually does:` the live proof is a one-root proof with integrity-bound opening material. The repo does not establish that this is already the final hiding-preserving authenticated-opening design contemplated by the research notes.
- `Paper action:` either provide a full reduction that matches the current proof object or narrow the blindness claim.
- `Unresolved gap:` a stronger blindness claim may require a different or more fully justified opening design, so the current paper should not overclaim here.

### Grouped Replacement Snippets for Setup and Security

#### Snippet D1: Fix setup and parameter discipline first

```tex
\paragraph{Setup and parameter discipline.}
All public parameters fix the ring family
$R_q=\mathbb{Z}_q[X]/(X^N+1)$, the message bound
$\beta_{\mathrm{msg}}$, the message-split lengths, and the dimensions
of the commitment matrices and public hash-key rows before any
security game begins. The setup algorithm publishes the public
hash key
\[
B = \bigl(B^{\mathrm{const}}, B^{\mathrm{msg}},
          B^{\mathrm{rnd}}, B^{\mathrm{den}}\bigr)
\]
together with any commitment
parameters needed by issuance.
```

#### Snippet D2: Conservative boundary for the theorem section

```tex
\paragraph{Conservative theorem boundary.}
The security discussion below should be read as a proof roadmap
unless and until the manuscript explicitly defines:
\begin{enumerate}
\item the exact SIS and ISIS variants used by the reduction,
\item the trapdoor-sampler guarantee,
\item the auxiliary-row distribution and admissibility predicate for the
hash/signature layer, and
\item the precise indistinguishability statement used in the blindness
hybrid.
\end{enumerate}
Until those objects are formalized, the manuscript should avoid
presenting a finalized theorem statement and instead state that the
security claim is conditioned on those instantiated assumptions.
```

#### Snippet D3: Conservative boundary for blindness

```tex
\paragraph{Blindness scope.}
The current implementation gives a one-root proof object with
integrity-bound opening material. A stronger blindness claim that
relies on a fully hiding authenticated-opening layer should be stated
only after that opening design and its reduction are made explicit.
```

## Region E: Full Comment-by-Comment Coverage Map

The items below are already covered in the sections above; this short map is included to make coverage auditing trivial.

- `CAR-01` to `CAR-04`: Region A
- `CAR-05` to `CAR-14`: Region B
- `CAR-15` to `CAR-21`: Region C
- `CAR-22` to `CAR-28`: Region D

Open items that the repo does not settle:

- `CAR-04`
- `CAR-12`
- `CAR-13`
- `CAR-14`
- `CAR-23`
- `CAR-24`
- `CAR-25`
- `CAR-27`

Research-only caution:

- `CAR-28`

## Closing Position

The main paper rewrite should be driven by the live semantics that the code has already fixed:

- authenticated top-level signed rows in `credential.State`
- showing-time witness reconstruction in `cmd/showing/main.go`
- PRF key extraction from signed `M2`
- a single combined proof object over one committed witness assignment
- replay of the cleared relation over `B`, `m1`, `m2`, `r0`, `r1`, and `t`
- a live preset and transcript report that are concrete enough to quote as representative current output

The paper should therefore stop presenting those parts as if they were still abstract design choices. Conversely, it should not let the existence of code trick it into overstating theorem-level facts that remain undefined in the manuscript. Where the code is decisive, rewrite to match it exactly. Where the code is not decisive, say so plainly and keep the claims narrow.
