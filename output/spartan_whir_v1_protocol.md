# Spartan+WHIR v1 Soundness-Faithful Scope (Non-ZK)

## Target

Target is a **soundness-faithful, non-zero-knowledge** Spartan+WHIR model for R1CS satisfiability.

## Working Demo Definition

For this repository, a "working integration" means a deterministic integration flow for:
- Spartan phase-1 proof generation and verification.
- Spartan phase-2 sum-check with transcript-derived coefficients and verifier replay.
- WHIR commitment/opening verification for the Spartan-derived claim `Z(r_y) = v`.
- Deterministic tamper checks that fail verification as expected.

Explicitly out of scope for this milestone:
- Zero-knowledge masking/blinding.
- Full paper-level zero-knowledge transformation.

Included in scope:
- Spartan Theorem 4 encoding (`G_io,tau`)
- Faithful two-phase sumcheck replay in prover/verifier transcript
- Public input binding in `R1CSVerifier::verify`
- Standalone compressed SPARK proof artifact format (digest + batched opening + cost profile)
- WHIR proof path for witness evaluation claim `Z(r_y) = v`

Deferred in v1:
- Zero-knowledge masking/blinding
- Paper-level asymptotic/constant-factor optimization tuning beyond current artifact checks

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

4. Spartan phase-2 + WHIR bridge:
- `src/spartan/r1cs_prover.rs` includes a second sum-check proof (`phase2_sumcheck_proof`)
  with transcript-derived coefficients (`phase2_coeffs`) and verifier replay checks.
- `r_y` is derived from phase-2 challenges and fed into the WHIR `Z(r_y)=v` opening bridge.
- Integration in `src/spartan/tests/integration.rs` commits witness evaluations and verifies WHIR proof.
- Spartan-provided `r_y` is used as the witness evaluation query point for the `Z(r_y)=v` claim path.
- Canonical demo tests:
  - `test_r1cs_whir_integration` (historical entrypoint)
  - `test_spartan_whir_phase1_zry_demo` (focused smoke alias)

5. General-shape coverage:
- Non-symmetric R1CS flow is covered by
  `spartan::r1cs_prover::tests::test_r1cs_prove_verify_non_symmetric_instance`.

6. SPARK compressed artifact:
- `src/spartan/spark.rs` defines `SparkProof` as a standalone payload with:
  - matrix commitments for A/B/C
  - transcript-bound compression challenges
  - per-matrix compressed digests
  - batched opening `A + eta*B + eta^2*C`
  - prover cost profile for serialized payload and operation estimates
- `src/spartan/r1cs_prover.rs` samples SPARK compression challenges from transcript and
  enforces verifier replay.
- Verifier rejects mismatches in digest, batching, or cost profile.

## Demo Acceptance Criteria

The integration is considered "working" only if all conditions hold:
- Happy path passes: Spartan phase-1 verification passes and WHIR verification of `Z(r_y)=v` passes.
- Invalid witness test panics at prover (current v1 behavior).
- Tamper checks all fail as intended:
  - mutated Spartan `r_y` is rejected;
  - mutated WHIR proof payload is rejected;
  - mutated claimed value `v` in statement is rejected.
- Public input mismatch is rejected.
- Phase-2 coefficient tampering is rejected.
- Phase-2 terminal-term tampering is rejected.
- Results are deterministic under fixed seeds.

## Faithfulness Matrix

| Feature | Status | Coverage |
|---|---|---|
| Spartan phase-1 transcript replay | Implemented | `spartan::r1cs_prover::tests::test_r1cs_prove_verify` |
| Spartan phase-2 transcript replay | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_tampered_phase2_round` |
| Transcript-derived phase-2 coefficients | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_tampered_phase2_coeffs` |
| Phase-2 terminal relation check | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_tampered_phase2_terminal_terms` |
| Standalone SPARK artifact payload | Implemented | `spartan::r1cs_prover::tests::test_r1cs_proof_contains_spark_payload` |
| SPARK structure checks | Implemented | `spartan::spark::tests::test_memory_in_the_head` |
| SPARK digest compression binding | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_tampered_spark_digest` |
| SPARK batched opening binding | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_tampered_spark_batching` |
| SPARK cost profile consistency | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_tampered_spark_cost_profile` |
| Full-bit eq for sparse index evaluation | Implemented | `spartan::spark::tests::test_compute_eq_poly_index_full_bits` |
| Public input binding | Implemented | `spartan::r1cs_prover::tests::test_r1cs_verifier_rejects_wrong_public_input` |
| Non-symmetric R1CS acceptance | Implemented | `spartan::r1cs_prover::tests::test_r1cs_prove_verify_non_symmetric_instance` |
| Zero-knowledge masking/blinding | Deferred | N/A |

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

# Faithfulness-focused subgroup
cargo test --lib spartan::r1cs_prover::tests
```

Expected output snippets:
- `test ... test_r1cs_whir_integration ... ok`
- `test ... test_spartan_whir_phase1_zry_demo ... ok`
- `test ... test_r1cs_whir_integration_rejects_invalid_witness - should panic ... ok`

Note:
- Tamper checks are assertion-based negative paths inside the demo test. The test passes only if those tampered proofs are rejected.

## Benchmark Harness And Report

Generate benchmark data for prover/verifier cost vs `nnz`, `log m`, and shape:

```bash
# Quick smoke sweep
cargo run --bin spartan_spark_bench -- --quick

# Full sweep
cargo run --bin spartan_spark_bench
```

Generate report artifacts (tables + crossover plots):

```bash
cargo run --bin spartan_spark_report
```

Artifacts are written to:
- `output/benchmarks/spartan_spark/metrics.csv`
- `output/benchmarks/spartan_spark/opening_batch_compare.csv`
- `output/benchmarks/spartan_spark/verifier_query_compare.csv`
- `output/benchmarks/spartan_spark/summary.md`
- `output/benchmarks/spartan_spark/prover_verifier_vs_total_nnz_global.svg`
- `output/benchmarks/spartan_spark/opening_runtime_vs_queries.svg`
- `output/benchmarks/spartan_spark/opening_payload_vs_queries.svg`
- `output/benchmarks/spartan_spark/full_proof_bytes_vs_queries.svg`
- `output/benchmarks/spartan_spark/verifier_vs_queries_logm*.svg`
