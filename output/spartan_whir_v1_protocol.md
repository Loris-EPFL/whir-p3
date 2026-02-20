# Spartan+WHIR v1 Frozen Scope (Non-ZK, Sound Model Target)

## Target

v1 target is a **sound, non-zero-knowledge** Spartan+WHIR model for R1CS satisfiability.

Included in scope:
- Spartan Theorem 4 encoding (`G_io,tau`)
- Two-phase sumcheck logic structure (phase-1 and phase-2 APIs)
- WHIR proof path for witness evaluation claim `Z(r_y) = v`

Deferred in v1:
- Zero-knowledge masking/blinding
- Full SPARK memory-check commitments/proofs

## Protocol Spec Matching Current Code

1. R1CS encoding:
- `src/spartan/r1cs.rs` defines sparse matrices and `Z = (w, 1, io, padding)`.
- `src/spartan/encoding.rs` constructs `G_io,tau(x) = F_io(x) * eq(tau, x)` over the boolean hypercube.

2. Spartan phase-1 sumcheck:
- Prover and verifier exchange one univariate per round via `src/spartan/sumcheck.rs`.
- Round check enforced: `p_i(0) + p_i(1) = claim_{i-1}`.
- Challenges are transcript-derived using Fiat-Shamir (`observe_algebra_slice` then `sample`), no constants.
- Running claim is updated as `claim_i = p_i(r_i)` using interpolation from evaluations at `0..d`.
- Final checks enforce consistency of:
  - derived challenges vs proof-stored challenges
  - final point vs challenge sequence
  - final claim vs proof-stored final evaluation

3. Spartan proof object and verification hooks:
- `src/spartan/r1cs_prover.rs` records round polynomials, challenges, final point, and final eval.
- Verifier replays transcript and rejects challenge/final-claim mismatches.

4. WHIR bridge:
- Integration in `src/spartan/tests/integration.rs` commits witness evaluations and verifies WHIR proof.
- Spartan-provided `r_y` is used as the witness evaluation query point for the `Z(r_y)=v` claim path.

## Sumcheck Soundness Changes Completed

- Replaced placeholder verifier challenge (`42`) with Fiat-Shamir challenge derivation.
- Added running-claim verification across rounds.
- Added final-evaluation consistency checks.
- Added tamper-negative tests:
  - reject modified round polynomial coefficient
  - detect modified challenge trace
  - detect modified final evaluation

## Validation

Command run:

```bash
cargo test --lib -- spartan
```

Result:
- All Spartan tests pass, including new tamper-negative tests.
