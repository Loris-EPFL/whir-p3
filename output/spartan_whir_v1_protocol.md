# Spartan+WHIR v1 Frozen Scope (Non-ZK, Sound Model Target)

## Target

v1 target is a **sound, non-zero-knowledge** Spartan+WHIR model for R1CS satisfiability.

## Working Demo Definition

For this repository, a "working demo" means a deterministic integration flow for:
- Spartan phase-1 proof generation and verification (no Spartan phase-2 integration).
- WHIR commitment/opening verification for the Spartan-derived claim `Z(r_y) = v`.
- Deterministic tamper checks that fail verification as expected.

Explicitly out of scope for this demo:
- Zero-knowledge masking/blinding.
- Full SPARK memory-check commitments/proofs integrated into WHIR.
- Full Spartan phase-2 integration.

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
- Canonical demo tests:
  - `test_r1cs_whir_integration` (historical entrypoint)
  - `test_spartan_whir_phase1_zry_demo` (focused smoke alias)

## Demo Acceptance Criteria

The demo is considered "working" only if all conditions hold:
- Happy path passes: Spartan phase-1 verification passes and WHIR verification of `Z(r_y)=v` passes.
- Invalid witness test panics at prover (current v1 behavior).
- Tamper checks all fail as intended:
  - mutated Spartan `r_y` is rejected;
  - mutated WHIR proof payload is rejected;
  - mutated claimed value `v` in statement is rejected.
- Results are deterministic under fixed seeds.

## Sumcheck Soundness Changes Completed

- Replaced placeholder verifier challenge (`42`) with Fiat-Shamir challenge derivation.
- Added running-claim verification across rounds.
- Added final-evaluation consistency checks.
- Added tamper-negative tests:
  - reject modified round polynomial coefficient
  - detect modified challenge trace
  - detect modified final evaluation

## Validation

Demo commands:

```bash
# Full Spartan-related suite
cargo test --lib -- spartan

# Canonical historical integration test
cargo test --lib spartan::tests::integration::test_r1cs_whir_integration

# Focused demo alias test
cargo test --lib spartan::tests::integration::test_spartan_whir_phase1_zry_demo
```

Expected output snippets:
- `test ... test_r1cs_whir_integration ... ok`
- `test ... test_spartan_whir_phase1_zry_demo ... ok`
- `test ... test_r1cs_whir_integration_rejects_invalid_witness - should panic ... ok`

Note:
- Tamper checks are assertion-based negative paths inside the demo test. The test passes only if those tampered proofs are rejected.
