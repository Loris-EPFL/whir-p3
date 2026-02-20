//! R1CS Prover using WHIR PCS
//!
//! Implements Spartan's two-phase sum-check protocol integrated with WHIR's
//! polynomial commitment scheme for efficient R1CS proving.

use alloc::vec;
use alloc::vec::Vec;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};

use crate::poly::evals::EvaluationsList;

use super::{
    encoding::{GPoly, eq_poly},
    r1cs::{R1CSInstance, R1CSShape},
    spark::SparkCommitment,
    sumcheck::{SumcheckProof, SumcheckProver, SumcheckVerifier},
};

/// R1CS Proof structure
/// Uses ExtensionField for evaluations since they may not fit in base field
#[derive(Debug, Clone)]
pub struct R1CSProof<F: Field, EF: ExtensionField<F>> {
    /// Fiat-Shamir challenge τ for Theorem 4 encoding.
    pub tau: Vec<F>,
    /// Sum-check proof for Phase 1 (degree-3 polynomial G_io,τ)
    pub sumcheck_proof: SumcheckProof<F>,
    /// Evaluation claims at the end of sum-check
    pub eval_claims: R1CSEvalClaims<F, EF>,
    /// SPARK commitments for sparse matrices.
    pub spark_commitments: Option<SparkCommitments<F>>,
}

/// Evaluation claims from sum-check reduction
/// Uses ExtensionField for evaluations since they may not fit in base field
#[derive(Debug, Clone)]
pub struct R1CSEvalClaims<F: Field, EF: ExtensionField<F>> {
    /// Claimed evaluation Az(rx)
    pub a_eval: EF,
    /// Claimed evaluation Bz(rx)
    pub b_eval: EF,
    /// Claimed value compatible with Cz(rx) in the phase-1 equation check
    pub c_eval: EF,
    /// Challenge point rx (for rows)
    pub rx: Vec<F>,
    /// Challenge point ry (for witness polynomial)
    pub ry: Vec<F>,
    /// Claimed witness evaluation v = Z(ry)
    pub z_eval: EF,
    /// Claimed sparse-matrix polynomial evaluation A(rx, ry)
    pub a_matrix_eval: EF,
    /// Claimed sparse-matrix polynomial evaluation B(rx, ry)
    pub b_matrix_eval: EF,
    /// Claimed sparse-matrix polynomial evaluation C(rx, ry)
    pub c_matrix_eval: EF,
}

/// SPARK commitments for constraint matrices
#[derive(Debug, Clone)]
pub struct SparkCommitments<F: Field> {
    pub a_comm: SparkCommitment<F>,
    pub b_comm: SparkCommitment<F>,
    pub c_comm: SparkCommitment<F>,
}

/// R1CS Prover using WHIR PCS
///
/// Implements the prover side of Spartan's R1CS protocol (Sections 4-5).
/// Uses WHIR's commitment scheme instead of Pedersen commitments.
#[derive(Debug)]
pub struct R1CSProver<F: Field> {
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field> R1CSProver<F> {
    /// Create a new R1CS prover
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }

    /// Prove R1CS instance satisfaction
    ///
    /// This implements the full Spartan protocol:
    /// 1. Compute G_io,τ polynomial from R1CS instance
    /// 2. Run Phase 1 sum-check on G_io,τ (degree 3)
    /// 3. Derive evaluation claims for A, B, C
    /// 4. Derive witness evaluation claim v = Z(ry)
    /// 5. Commit sparse matrices through SPARK commitments
    ///
    /// # Arguments
    /// * `instance` - The R1CS instance with witness
    /// * `challenger` - Fiat-Shamir challenger for randomness
    ///
    /// # Returns
    /// The R1CS proof
    pub fn prove<EF, Challenger>(
        &self,
        instance: &R1CSInstance<F>,
        challenger: &mut Challenger,
    ) -> R1CSProof<F, EF>
    where
        EF: ExtensionField<F>,
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        // Step 1: Generate challenge τ and compute G_io,τ
        let num_cons_vars = instance.shape().num_cons().trailing_zeros() as usize;
        let tau: Vec<F> = (0..num_cons_vars).map(|_| challenger.sample()).collect();

        // Compute G_io,τ polynomial
        let g_poly = GPoly::from_r1cs_instance(instance, tau.clone());

        // Verify that sum is zero (sanity check)
        assert!(
            g_poly.verify_sum_is_zero(),
            "Witness does not satisfy R1CS constraints"
        );

        // Step 2: Run Phase 1 sum-check on G_io,τ
        let g_evals = g_poly.evaluations().to_vec();
        let mut phase1_prover = SumcheckProver::new(g_evals, 3); // Degree 3

        let mut sumcheck_data = super::sumcheck::SpartanSumcheckData::default();

        for _ in 0..num_cons_vars {
            let _ = phase1_prover.prove_round_into_data(&mut sumcheck_data, challenger, 0);
        }
        let challenges = phase1_prover.challenges().to_vec();

        // Step 3: After sum-check, we have evaluation claims
        // The final evaluation point is the sequence of challenges
        let rx = challenges.clone();

        // Build Z vector for computing evaluations
        let z = instance.build_z_vector();
        // Use num_poly_vars_y from the shape (log2 of the matrix column dimension)
        let num_vars_y = instance.shape().num_poly_vars_y();

        // Generate ry challenges
        let ry: Vec<F> = (0..num_vars_y).map(|_| challenger.sample()).collect();

        // Compute Az, Bz, Cz as vectors over the constraint rows, then evaluate at rx.
        let (az_vec, bz_vec, _cz_vec) = compute_abc_vectors(instance.shape(), &z);
        let a_eval = eval_mle_from_hypercube::<EF, F>(&az_vec, &rx);
        let b_eval = eval_mle_from_hypercube::<EF, F>(&bz_vec, &rx);

        let tau_ef: Vec<EF> = tau.iter().copied().map(EF::from).collect();
        let rx_ef: Vec<EF> = rx.iter().copied().map(EF::from).collect();

        let eq_tau_rx = eq_poly::<EF, F>(&tau_ef, &rx_ef);
        let final_eval_ef = EF::from(phase1_prover.final_eval());

        let c_eval = a_eval * b_eval - final_eval_ef * eq_tau_rx.inverse();
        let z_eval = eval_mle_from_hypercube::<EF, F>(&z, &ry);

        let spark_a = SparkCommitment::commit(instance.shape().a());
        let spark_b = SparkCommitment::commit(instance.shape().b());
        let spark_c = SparkCommitment::commit(instance.shape().c());
        
        let a_matrix_eval = EF::from(spark_a.evaluate(&rx, &ry));
        let b_matrix_eval = EF::from(spark_b.evaluate(&rx, &ry));
        let c_matrix_eval = EF::from(spark_c.evaluate(&rx, &ry));

        R1CSProof {
            tau,
            sumcheck_proof: SumcheckProof {
                polynomials: sumcheck_data.round_evaluations,
                challenges: challenges.clone(),
                final_point: rx.clone(),
                final_eval: phase1_prover.final_eval(),
            },
            eval_claims: R1CSEvalClaims {
                a_eval,
                b_eval,
                c_eval,
                rx,
                ry,
                z_eval,
                a_matrix_eval,
                b_matrix_eval,
                c_matrix_eval,
            },
            spark_commitments: Some(SparkCommitments {
                a_comm: spark_a,
                b_comm: spark_b,
                c_comm: spark_c,
            }),
        }
    }

    /// Commit to witness polynomial using WHIR
    ///
    /// This prepares the witness for the WHIR commitment scheme.
    /// The actual commitment is done by the caller using WHIR's CommitmentWriter.
    ///
    /// # Arguments
    /// * `instance` - The R1CS instance with witness
    ///
    /// # Returns
    /// The witness as an EvaluationsList for WHIR commitment
    pub fn prepare_witness(&self, instance: &R1CSInstance<F>) -> EvaluationsList<F> {
        let z = instance.build_z_vector();
        EvaluationsList::new(z)
    }
}

impl<F: Field> Default for R1CSProver<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// R1CS Verifier using WHIR PCS
#[derive(Debug)]
pub struct R1CSVerifier<F: Field> {
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field> R1CSVerifier<F> {
    /// Create a new R1CS verifier
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }

    /// Verify R1CS proof
    ///
    /// This implements the verifier side of Spartan's R1CS protocol:
    /// 1. Run Phase 1 sum-check verification
    /// 2. Check evaluation claims match the expected constraint satisfaction
    /// 3. Verify SPARK-backed matrix-evaluation claims
    /// 4. Check claim/equation consistency
    ///
    /// # Arguments
    /// * `shape` - The R1CS shape (constraint matrices)
    /// * `input` - Public input
    /// * `proof` - The R1CS proof
    /// * `challenger` - Fiat-Shamir challenger (must match prover's)
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, Err otherwise
    pub fn verify<EF, Challenger>(
        &self,
        shape: &R1CSShape<F>,
        _input: &[F],
        proof: &R1CSProof<F, EF>,
        challenger: &mut Challenger,
    ) -> Result<(), &'static str>
    where
        EF: ExtensionField<F>,
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        // Step 1: Regenerate τ and enforce transcript consistency.
        let num_cons_vars = shape.num_cons().trailing_zeros() as usize;
        let tau: Vec<F> = (0..num_cons_vars).map(|_| challenger.sample()).collect();
        if tau != proof.tau {
            return Err("Transcript mismatch: tau");
        }

        // Step 2: Verify Phase 1 sum-check and replay r_x.
        let mut verifier = SumcheckVerifier::new(F::ZERO, num_cons_vars, 3);

        let mut derived_challenges = Vec::with_capacity(proof.sumcheck_proof.polynomials.len());
        for poly in &proof.sumcheck_proof.polynomials {
            let challenge = verifier.verify_round_from_data(poly, challenger)?;
            derived_challenges.push(challenge);
        }

        if derived_challenges != proof.sumcheck_proof.challenges {
            return Err("Sum-check failed: challenge transcript mismatch");
        }
        if proof.sumcheck_proof.final_point != proof.sumcheck_proof.challenges {
            return Err("Sum-check failed: inconsistent final point");
        }
        if verifier.final_point() != proof.sumcheck_proof.final_point.as_slice() {
            return Err("Sum-check failed: final point mismatch");
        }
        if verifier.final_claim() != proof.sumcheck_proof.final_eval {
            return Err("Sum-check failed: final evaluation mismatch");
        }
        if proof.eval_claims.rx != proof.sumcheck_proof.final_point {
            return Err("Transcript mismatch: rx");
        }

        // Step 3: Replay r_y and enforce transcript consistency.
        let num_vars_y = shape.num_poly_vars_y();
        let ry: Vec<F> = (0..num_vars_y).map(|_| challenger.sample()).collect();
        if ry != proof.eval_claims.ry {
            return Err("Transcript mismatch: ry");
        }

        // Step 4: Verify SPARK commitment consistency for matrix evaluations.
        let claims = &proof.eval_claims;
        let spark = proof
            .spark_commitments
            .as_ref()
            .ok_or("Missing SPARK commitments in proof")?;
        let a_from_spark = EF::from(spark.a_comm.evaluate(&claims.rx, &claims.ry));
        let b_from_spark = EF::from(spark.b_comm.evaluate(&claims.rx, &claims.ry));
        let c_from_spark = EF::from(spark.c_comm.evaluate(&claims.rx, &claims.ry));
        if a_from_spark != claims.a_matrix_eval {
            return Err("SPARK check failed: A(rx,ry)");
        }
        if b_from_spark != claims.b_matrix_eval {
            return Err("SPARK check failed: B(rx,ry)");
        }
        if c_from_spark != claims.c_matrix_eval {
            return Err("SPARK check failed: C(rx,ry)");
        }

        // Step 5: Verify Spartan equation:
        // G_io,tau(rx) = (Az(rx) * Bz(rx) - Cz(rx)) * eq(tau, rx).
        let tau_ef: Vec<EF> = proof.tau.iter().copied().map(EF::from).collect();
        let rx_ef: Vec<EF> = claims.rx.iter().copied().map(EF::from).collect();
        let eq_tau_rx = eq_poly::<EF, F>(&tau_ef, &rx_ef);

        let final_eval = EF::from(proof.sumcheck_proof.final_eval);
        let rhs = (claims.a_eval * claims.b_eval - claims.c_eval) * eq_tau_rx;
        if final_eval != rhs {
            return Err("Spartan equation check failed");
        }

        Ok(())
    }
}

fn compute_abc_vectors<F: Field>(shape: &R1CSShape<F>, z: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
    let mut az = vec![F::ZERO; shape.num_cons()];
    let mut bz = vec![F::ZERO; shape.num_cons()];
    let mut cz = vec![F::ZERO; shape.num_cons()];

    for entry in shape.a().entries() {
        az[entry.row] += entry.val * z[entry.col];
    }
    for entry in shape.b().entries() {
        bz[entry.row] += entry.val * z[entry.col];
    }
    for entry in shape.c().entries() {
        cz[entry.row] += entry.val * z[entry.col];
    }

    (az, bz, cz)
}

fn eval_mle_from_hypercube<EF: ExtensionField<F>, F: Field>(values: &[F], point: &[F]) -> EF {
    assert_eq!(
        values.len(),
        1usize << point.len(),
        "values must match hypercube size for point dimension"
    );

    let point_ef: Vec<EF> = point.iter().copied().map(EF::from).collect();
    values
        .iter()
        .enumerate()
        .map(|(idx, &val)| super::encoding::eq_poly_at_index::<EF, F>(idx, &point_ef) * EF::from(val))
        .sum()
}

impl<F: Field> Default for R1CSVerifier<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::r1cs::{R1CSInstance, R1CSShape};
    use alloc::vec;
    use alloc::vec::Vec;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use rand::SeedableRng;

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;
    type Challenger = DuplexChallenger<F, Perm, 16, 8>;

    fn make_square_instance(num_cons: usize) -> (R1CSShape<F>, R1CSInstance<F>, Vec<F>) {
        let num_vars = num_cons;
        let num_inputs = 1usize;

        let a_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );

        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(3);
        witness[1] = F::from_u64(9);
        let input = vec![F::ZERO];
        let instance = R1CSInstance::new(shape.clone(), input.clone(), witness);
        (shape, instance, input)
    }

    #[test]
    fn test_r1cs_prove_verify() {
        let (shape, instance, _input) = make_square_instance(4);

        // Create prover and verifier
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        // Create challenger (using fixed seed for reproducibility)
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());

        // Generate proof
        let proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        // Verify proof (with fresh challenger seeded the same way)
        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &instance.input(),
            &proof,
            &mut verifier_challenger,
        );

        assert!(
            result.is_ok(),
            "R1CS proof verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_r1cs_verifier_rejects_tampered_sumcheck_round() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.sumcheck_proof.polynomials[0][0] += F::ONE;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_r1cs_verifier_rejects_tampered_final_point() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.sumcheck_proof.final_point[0] += F::ONE;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_r1cs_verifier_rejects_wrong_eval_claims() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.eval_claims.a_eval += p3_field::extension::BinomialExtensionField::<F, 4>::ONE;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_r1cs_verifier_rejects_wrong_spark_matrix_claim() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.eval_claims.a_matrix_eval += p3_field::extension::BinomialExtensionField::<F, 4>::ONE;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_r1cs_verifier_rejects_wrong_final_eval() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.sumcheck_proof.final_eval += F::ONE;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_r1cs_verifier_rejects_wrong_challenges() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.sumcheck_proof.challenges[0] += F::ONE;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_r1cs_proof_contains_spark_payload() {
        let (_shape, instance, _input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm);
        let proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        assert!(
            proof.spark_commitments.is_some(),
            "proof should carry SPARK commitments"
        );
    }

    #[test]
    fn test_r1cs_verifier_rejects_missing_spark_payload() {
        let (shape, instance, input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        proof.spark_commitments = None;

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_rounds_logarithmic_smoke() {
        let (shape, instance, input) = make_square_instance(256);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(9));
        let mut prover_challenger = Challenger::new(perm.clone());

        let proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        assert_eq!(
            proof.sumcheck_proof.polynomials.len(),
            shape.num_cons().trailing_zeros() as usize,
            "sumcheck rounds should scale as log2(num_cons)"
        );

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_ok(), "verifier should accept valid proof");
    }

    #[test]
    fn test_r1cs_prove_verify_non_symmetric_instance() {
        let num_cons = 8usize;
        let num_vars = 8usize;
        let num_inputs = 1usize;

        // Two distinct constraints with different row/col structure:
        // row 0: w0 * w1 = w2
        // row 3: w1 * w1 = w3
        let a_entries = vec![
            super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE),
            super::super::r1cs::SparseMatEntry::new(3, 1, F::ONE),
        ];
        let b_entries = vec![
            super::super::r1cs::SparseMatEntry::new(0, 1, F::ONE),
            super::super::r1cs::SparseMatEntry::new(3, 1, F::ONE),
        ];
        let c_entries = vec![
            super::super::r1cs::SparseMatEntry::new(0, 2, F::ONE),
            super::super::r1cs::SparseMatEntry::new(3, 3, F::ONE),
        ];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );

        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(2);
        witness[1] = F::from_u64(5);
        witness[2] = F::from_u64(10); // 2*5
        witness[3] = F::from_u64(25); // 5*5
        let input = vec![F::ZERO];
        let instance = R1CSInstance::new(shape.clone(), input.clone(), witness);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(17));
        let mut prover_challenger = Challenger::new(perm.clone());
        let proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &input,
            &proof,
            &mut verifier_challenger,
        );
        assert!(
            result.is_ok(),
            "non-symmetric instance should verify, got {:?}",
            result.err()
        );
    }
}
