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
    encoding::{GPoly, eq_poly, eq_poly_at_index},
    r1cs::{R1CSInstance, R1CSShape, SparseMatPolynomial},
    spark::{SparkCompressionChallenges, SparkProof},
    sumcheck::{SumcheckProof, SumcheckVerifier},
};

/// R1CS Proof structure
/// Uses ExtensionField for evaluations since they may not fit in base field
#[derive(Debug, Clone)]
pub struct R1CSProof<F: Field, EF: ExtensionField<F>> {
    /// Public input bound into this proof instance.
    pub public_input: Vec<F>,
    /// Fiat-Shamir challenge τ for Theorem 4 encoding.
    pub tau: Vec<F>,
    /// Sum-check proof for Phase 1 (degree-3 polynomial G_io,τ).
    pub phase1_sumcheck_proof: SumcheckProof<F>,
    /// Sum-check proof for Phase 2 (degree-2 polynomial over y).
    pub phase2_sumcheck_proof: SumcheckProof<F>,
    /// Transcript-derived linear combination coefficients for phase-2.
    pub phase2_coeffs: Phase2Coeffs<F>,
    /// Evaluation claims at the end of sum-check
    pub eval_claims: R1CSEvalClaims<F>,
    /// Standalone SPARK proof artifact over sparse matrix commitments/openings.
    pub spark_proof: Option<SparkProof<F>>,
    _phantom: core::marker::PhantomData<EF>,
}

#[derive(Debug, Clone, Copy)]
pub struct Phase2Coeffs<F: Field> {
    pub a: F,
    pub b: F,
    pub c: F,
}

/// Evaluation claims from sum-check reduction
/// Uses ExtensionField for evaluations since they may not fit in base field
#[derive(Debug, Clone)]
pub struct R1CSEvalClaims<F: Field> {
    /// Claimed evaluation Az(rx)
    pub a_eval: F,
    /// Claimed evaluation Bz(rx)
    pub b_eval: F,
    /// Claimed value compatible with Cz(rx) in the phase-1 equation check
    pub c_eval: F,
    /// Challenge point rx (for rows)
    pub rx: Vec<F>,
    /// Challenge point ry (for witness polynomial)
    pub ry: Vec<F>,
    /// Claimed witness evaluation v = Z(ry)
    pub z_eval: F,
    /// Claimed sparse-matrix polynomial evaluation A(rx, ry)
    pub a_matrix_eval: F,
    /// Claimed sparse-matrix polynomial evaluation B(rx, ry)
    pub b_matrix_eval: F,
    /// Claimed sparse-matrix polynomial evaluation C(rx, ry)
    pub c_matrix_eval: F,
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
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }

    /// Prove R1CS instance satisfaction
    ///
    /// This implements the full Spartan protocol:
    /// 1. Compute G_io,τ polynomial from R1CS instance
    /// 2. Run Phase 1 sum-check on G_io,τ (degree 3)
    /// 3. Run Phase 2 sum-check over y to bind A/B/C evaluations to Z(ry)
    /// 4. Derive witness/matrix evaluation claims at r_y
    /// 5. Commit sparse matrices through SPARK commitments
    ///
    /// # Arguments
    /// * `instance` - The R1CS instance with witness
    /// * `challenger` - Fiat-Shamir challenger for randomness
    ///
    /// # Returns
    #[allow(clippy::too_many_lines)]
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

        // Step 2: Run Phase 1 sum-check on G_io,τ with faithful round polynomials.
        // Round i polynomial: h_i(t) = Σ_{b∈{0,1}^{s-i-1}} G_io,τ(r_1..r_{i-1}, t, b)
        let z = instance.build_z_vector();
        let phase1_sumcheck_proof = prove_sumcheck_from_oracle(
            num_cons_vars,
            3,
            F::ZERO,
            challenger,
            |prefix: &[F], t: F| -> F {
                let remaining = num_cons_vars - prefix.len() - 1;
                let mut sum = F::ZERO;
                for b in 0..(1usize << remaining) {
                    let mut x = Vec::with_capacity(num_cons_vars);
                    x.extend_from_slice(prefix);
                    x.push(t);
                    for j in 0..remaining {
                        x.push(if ((b >> j) & 1) == 1 { F::ONE } else { F::ZERO });
                    }
                    sum += evaluate_g_io_tau_at_point(instance.shape(), &tau, &z, &x);
                }
                sum
            },
        );
        let rx = phase1_sumcheck_proof.final_point.clone();
        let phase1_final_eval = phase1_sumcheck_proof.final_eval;

        // Step 3: Compute primary claims at r_x.
        let num_vars_y = instance.shape().num_poly_vars_y();
        let (a_rx_y, b_rx_y, c_rx_y) = compute_matrix_evals_at_rx(instance.shape(), &rx);
        let a_eval = a_rx_y.iter().zip(z.iter()).map(|(a, z_y)| *a * *z_y).sum();
        let b_eval = b_rx_y.iter().zip(z.iter()).map(|(b, z_y)| *b * *z_y).sum();
        let c_eval = c_rx_y.iter().zip(z.iter()).map(|(c, z_y)| *c * *z_y).sum();
        let eq_tau_rx = eq_poly_base(&tau, &rx);
        assert_eq!(
            phase1_final_eval,
            (a_eval * b_eval - c_eval) * eq_tau_rx,
            "internal consistency failure: phase-1 equation must hold"
        );

        // Step 4: Phase-2 sum-check over y with transcript-derived coefficients.
        // Q(y) = Z(y) * (α*A(r_x,y) + β*B(r_x,y) + γ*C(r_x,y))
        let phase2_coeffs = Phase2Coeffs {
            a: challenger.sample(),
            b: challenger.sample(),
            c: challenger.sample(),
        };
        let phase2_initial_claim =
            phase2_coeffs.a * a_eval + phase2_coeffs.b * b_eval + phase2_coeffs.c * c_eval;
        let phase2_sumcheck_proof = prove_sumcheck_from_oracle(
            num_vars_y,
            2,
            phase2_initial_claim,
            challenger,
            |prefix: &[F], t: F| -> F {
                let remaining = num_vars_y - prefix.len() - 1;
                let mut sum = F::ZERO;
                for b in 0..(1usize << remaining) {
                    let mut y = Vec::with_capacity(num_vars_y);
                    y.extend_from_slice(prefix);
                    y.push(t);
                    for j in 0..remaining {
                        y.push(if ((b >> j) & 1) == 1 { F::ONE } else { F::ZERO });
                    }
                    let z_y = eval_mle_from_hypercube::<F, F>(&z, &y);
                    let a_y = eval_sparse_at_point(instance.shape().a(), &rx, &y);
                    let b_y = eval_sparse_at_point(instance.shape().b(), &rx, &y);
                    let c_y = eval_sparse_at_point(instance.shape().c(), &rx, &y);
                    let lin = phase2_coeffs.a * a_y + phase2_coeffs.b * b_y + phase2_coeffs.c * c_y;
                    sum += z_y * lin;
                }
                sum
            },
        );
        let ry = phase2_sumcheck_proof.final_point.clone();
        let phase2_final_eval = phase2_sumcheck_proof.final_eval;

        let z_eval = eval_mle_from_hypercube::<F, F>(&z, &ry);
        let spark_challenges = SparkCompressionChallenges {
            gamma: challenger.sample(),
            eta: challenger.sample(),
        };
        let spark_proof = SparkProof::from_matrices(
            instance.shape().a(),
            instance.shape().b(),
            instance.shape().c(),
            &rx,
            &ry,
            spark_challenges,
        );

        let a_matrix_eval = spark_proof.batch_opening.a_eval;
        let b_matrix_eval = spark_proof.batch_opening.b_eval;
        let c_matrix_eval = spark_proof.batch_opening.c_eval;
        let phase2_terminal_rhs = z_eval
            * (phase2_coeffs.a * a_matrix_eval
                + phase2_coeffs.b * b_matrix_eval
                + phase2_coeffs.c * c_matrix_eval);
        assert_eq!(
            phase2_final_eval, phase2_terminal_rhs,
            "internal consistency failure: phase-2 terminal relation must hold"
        );

        R1CSProof {
            public_input: instance.input().to_vec(),
            tau,
            phase1_sumcheck_proof,
            phase2_sumcheck_proof,
            phase2_coeffs,
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
            spark_proof: Some(spark_proof),
            _phantom: core::marker::PhantomData,
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
    #[must_use] 
    pub const fn new() -> Self {
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
    #[allow(clippy::too_many_lines)]
    /// Ok(()) if verification succeeds, Err otherwise
    pub fn verify<EF, Challenger>(
        &self,
        shape: &R1CSShape<F>,
        input: &[F],
        proof: &R1CSProof<F, EF>,
        challenger: &mut Challenger,
    ) -> Result<(), &'static str>
    where
        EF: ExtensionField<F>,
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        if input != proof.public_input.as_slice() {
            return Err("Public input mismatch");
        }

        // Step 1: Regenerate τ and enforce transcript consistency.
        let num_cons_vars = shape.num_cons().trailing_zeros() as usize;
        let tau: Vec<F> = (0..num_cons_vars).map(|_| challenger.sample()).collect();
        if tau != proof.tau {
            return Err("Transcript mismatch: tau");
        }

        // Step 2: Verify Phase 1 sum-check and replay r_x.
        let mut verifier = SumcheckVerifier::new(F::ZERO, num_cons_vars, 3);

        let mut derived_challenges =
            Vec::with_capacity(proof.phase1_sumcheck_proof.polynomials.len());
        for poly in &proof.phase1_sumcheck_proof.polynomials {
            let challenge = verifier.verify_round_from_data(poly, challenger)?;
            derived_challenges.push(challenge);
        }

        if derived_challenges != proof.phase1_sumcheck_proof.challenges {
            return Err("Sum-check failed: challenge transcript mismatch");
        }
        if proof.phase1_sumcheck_proof.final_point != proof.phase1_sumcheck_proof.challenges {
            return Err("Sum-check failed: inconsistent final point");
        }
        if verifier.final_point() != proof.phase1_sumcheck_proof.final_point.as_slice() {
            return Err("Sum-check failed: final point mismatch");
        }
        if verifier.final_claim() != proof.phase1_sumcheck_proof.final_eval {
            return Err("Sum-check failed: final evaluation mismatch");
        }
        if proof.eval_claims.rx != proof.phase1_sumcheck_proof.final_point {
            return Err("Transcript mismatch: rx");
        }

        // Step 3: Verify Phase 2 sum-check and derive r_y.
        let claims = &proof.eval_claims;
        let derived_coeffs = Phase2Coeffs {
            a: challenger.sample(),
            b: challenger.sample(),
            c: challenger.sample(),
        };
        if derived_coeffs.a != proof.phase2_coeffs.a
            || derived_coeffs.b != proof.phase2_coeffs.b
            || derived_coeffs.c != proof.phase2_coeffs.c
        {
            return Err("Phase-2 coefficient transcript mismatch");
        }

        let phase2_claim = derived_coeffs.a * claims.a_eval
            + derived_coeffs.b * claims.b_eval
            + derived_coeffs.c * claims.c_eval;
        let mut verifier_phase2 = SumcheckVerifier::new(phase2_claim, shape.num_poly_vars_y(), 2);
        let mut derived_phase2_challenges =
            Vec::with_capacity(proof.phase2_sumcheck_proof.polynomials.len());
        for poly in &proof.phase2_sumcheck_proof.polynomials {
            let challenge = verifier_phase2
                .verify_round_from_data(poly, challenger)
                .map_err(|_| "Phase-2 sum-check failed: p(0) + p(1) != claim")?;
            derived_phase2_challenges.push(challenge);
        }
        if derived_phase2_challenges != proof.phase2_sumcheck_proof.challenges {
            return Err("Phase-2 sum-check failed: challenge transcript mismatch");
        }
        if proof.phase2_sumcheck_proof.final_point != proof.phase2_sumcheck_proof.challenges {
            return Err("Phase-2 sum-check failed: inconsistent final point");
        }
        if verifier_phase2.final_point() != proof.phase2_sumcheck_proof.final_point.as_slice() {
            return Err("Phase-2 sum-check failed: final point mismatch");
        }
        if verifier_phase2.final_claim() != proof.phase2_sumcheck_proof.final_eval {
            return Err("Phase-2 sum-check failed: final evaluation mismatch");
        }

        // Enforce transcript consistency for r_y from phase-2 output.
        let num_vars_y = shape.num_poly_vars_y();
        let ry = proof.phase2_sumcheck_proof.final_point.clone();
        if ry.len() != num_vars_y {
            return Err("Transcript mismatch: ry length");
        }
        if ry != proof.eval_claims.ry {
            return Err("Transcript mismatch: ry");
        }

        // Step 4: Verify standalone SPARK artifact and matrix evaluations.
        let spark_challenges = SparkCompressionChallenges {
            gamma: challenger.sample(),
            eta: challenger.sample(),
        };
        let spark = proof
            .spark_proof
            .as_ref()
            .ok_or("Missing SPARK proof in proof payload")?;
        let spark_evals = spark.verify(&claims.rx, &claims.ry, spark_challenges)?;
        if spark_evals.a_eval != claims.a_matrix_eval {
            return Err("SPARK check failed: A(rx,ry)");
        }
        if spark_evals.b_eval != claims.b_matrix_eval {
            return Err("SPARK check failed: B(rx,ry)");
        }
        if spark_evals.c_eval != claims.c_matrix_eval {
            return Err("SPARK check failed: C(rx,ry)");
        }

        // Step 5: Verify Spartan equation:
        // G_io,tau(rx) = (Az(rx) * Bz(rx) - Cz(rx)) * eq(tau, rx).
        let tau_ef: Vec<EF> = proof.tau.iter().copied().map(EF::from).collect();
        let rx_ef: Vec<EF> = claims.rx.iter().copied().map(EF::from).collect();
        let eq_tau_rx = eq_poly::<EF, F>(&tau_ef, &rx_ef);

        let final_eval = EF::from(proof.phase1_sumcheck_proof.final_eval);
        let rhs = (EF::from(claims.a_eval) * EF::from(claims.b_eval) - EF::from(claims.c_eval))
            * eq_tau_rx;
        if final_eval != rhs {
            return Err("Spartan equation check failed");
        }

        // Step 6: Verify phase-2 terminal relation.
        let phase2_terminal_rhs = claims.z_eval
            * (derived_coeffs.a * claims.a_matrix_eval
                + derived_coeffs.b * claims.b_matrix_eval
                + derived_coeffs.c * claims.c_matrix_eval);
        if proof.phase2_sumcheck_proof.final_eval != phase2_terminal_rhs {
            return Err("Phase-2 terminal check failed");
        }

        Ok(())
    }
}

fn compute_matrix_evals_at_rx<F: Field>(
    shape: &R1CSShape<F>,
    rx: &[F],
) -> (Vec<F>, Vec<F>, Vec<F>) {
    let num_y = 1usize << shape.num_poly_vars_y();
    let mut a_vals = vec![F::ZERO; num_y];
    let mut b_vals = vec![F::ZERO; num_y];
    let mut c_vals = vec![F::ZERO; num_y];

    for entry in shape.a().entries() {
        let eq_row = eq_poly_at_index::<F, F>(entry.row, rx);
        a_vals[entry.col] += entry.val * eq_row;
    }
    for entry in shape.b().entries() {
        let eq_row = eq_poly_at_index::<F, F>(entry.row, rx);
        b_vals[entry.col] += entry.val * eq_row;
    }
    for entry in shape.c().entries() {
        let eq_row = eq_poly_at_index::<F, F>(entry.row, rx);
        c_vals[entry.col] += entry.val * eq_row;
    }

    (a_vals, b_vals, c_vals)
}

fn eq_poly_base<F: Field>(t: &[F], x: &[F]) -> F {
    assert_eq!(t.len(), x.len());
    let mut result = F::ONE;
    for i in 0..t.len() {
        result *= t[i] * x[i] + (F::ONE - t[i]) * (F::ONE - x[i]);
    }
    result
}

fn eval_sparse_at_point<F: Field>(mat: &SparseMatPolynomial<F>, rx: &[F], ry: &[F]) -> F {
    mat.entries()
        .iter()
        .map(|entry| {
            entry.val
                * eq_poly_at_index::<F, F>(entry.row, rx)
                * eq_poly_at_index::<F, F>(entry.col, ry)
        })
        .sum()
}

fn evaluate_g_io_tau_at_point<F: Field>(shape: &R1CSShape<F>, tau: &[F], z: &[F], x: &[F]) -> F {
    let a_x = shape
        .a()
        .entries()
        .iter()
        .map(|entry| entry.val * eq_poly_at_index::<F, F>(entry.row, x) * z[entry.col])
        .sum::<F>();
    let b_x = shape
        .b()
        .entries()
        .iter()
        .map(|entry| entry.val * eq_poly_at_index::<F, F>(entry.row, x) * z[entry.col])
        .sum::<F>();
    let c_x = shape
        .c()
        .entries()
        .iter()
        .map(|entry| entry.val * eq_poly_at_index::<F, F>(entry.row, x) * z[entry.col])
        .sum::<F>();
    let f_x = a_x * b_x - c_x;
    f_x * eq_poly_base(tau, x)
}

fn evaluate_univariate_from_samples<F: Field>(samples: &[F], r: F) -> F {
    let degree = samples.len() - 1;
    let mut result = F::ZERO;

    for (i, &y_i) in samples.iter().enumerate() {
        let mut basis = F::ONE;
        let x_i = F::from_usize(i);
        for j in 0..=degree {
            if i == j {
                continue;
            }
            let x_j = F::from_usize(j);
            basis *= (r - x_j) * (x_i - x_j).inverse();
        }
        result += y_i * basis;
    }

    result
}

fn prove_sumcheck_from_oracle<F, Challenger, RoundEvalFn>(
    num_vars: usize,
    degree: usize,
    initial_claim: F,
    challenger: &mut Challenger,
    mut round_eval_fn: RoundEvalFn,
) -> SumcheckProof<F>
where
    F: Field,
    Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    RoundEvalFn: FnMut(&[F], F) -> F,
{
    let mut current_claim = initial_claim;
    let mut challenges = Vec::with_capacity(num_vars);
    let mut round_evals_all = Vec::with_capacity(num_vars);

    for _round in 0..num_vars {
        let prefix = challenges.as_slice();
        let round_evals: Vec<F> = (0..=degree)
            .map(|j| round_eval_fn(prefix, F::from_usize(j)))
            .collect();
        // Prover-side sanity check mirrors verifier recurrence.
        assert_eq!(
            round_evals[0] + round_evals[1],
            current_claim,
            "sumcheck oracle produced inconsistent round claim"
        );

        challenger.observe_algebra_slice(&round_evals);
        let r = challenger.sample();
        current_claim = evaluate_univariate_from_samples(&round_evals, r);
        challenges.push(r);
        round_evals_all.push(round_evals);
    }

    SumcheckProof {
        polynomials: round_evals_all,
        challenges: challenges.clone(),
        final_point: challenges,
        final_eval: current_claim,
    }
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
        .map(|(idx, &val)| {
            super::encoding::eq_poly_at_index::<EF, F>(idx, &point_ef) * EF::from(val)
        })
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

        proof.phase1_sumcheck_proof.polynomials[0][0] += F::ONE;

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

        proof.phase1_sumcheck_proof.final_point[0] += F::ONE;

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

        proof.eval_claims.a_eval += F::ONE;

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

        proof.eval_claims.a_matrix_eval += F::ONE;

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

        proof.phase1_sumcheck_proof.final_eval += F::ONE;

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

        proof.phase1_sumcheck_proof.challenges[0] += F::ONE;

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
    fn test_r1cs_verifier_rejects_tampered_phase2_round() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.phase2_sumcheck_proof.polynomials[0][0] += F::ONE;

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
    fn test_r1cs_verifier_rejects_tampered_phase2_final_eval() {
        let (shape, instance, input) = make_square_instance(4);

        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        proof.phase2_sumcheck_proof.final_eval += F::ONE;

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
    fn test_r1cs_verifier_rejects_tampered_phase2_coeffs() {
        let (shape, instance, input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        proof.phase2_coeffs.a += F::ONE;

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
    fn test_r1cs_verifier_rejects_tampered_phase2_terminal_terms() {
        let (shape, instance, input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        proof.eval_claims.z_eval += F::ONE;

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
            proof.spark_proof.is_some(),
            "proof should carry SPARK proof artifact"
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
        proof.spark_proof = None;

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
    fn test_r1cs_verifier_rejects_tampered_spark_digest() {
        let (shape, instance, input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        proof.spark_proof.as_mut().unwrap().a_digest += F::ONE;

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
    fn test_r1cs_verifier_rejects_tampered_spark_batching() {
        let (shape, instance, input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        proof
            .spark_proof
            .as_mut()
            .unwrap()
            .batch_opening
            .batched_eval += F::ONE;

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
    fn test_r1cs_verifier_rejects_tampered_spark_cost_profile() {
        let (shape, instance, input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );
        proof
            .spark_proof
            .as_mut()
            .unwrap()
            .cost_profile
            .serialized_field_elements += 1;

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
    fn test_r1cs_verifier_rejects_wrong_public_input() {
        let (shape, instance, _input) = make_square_instance(4);
        let prover = super::R1CSProver::new();
        let verifier = super::R1CSVerifier::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(1));
        let mut prover_challenger = Challenger::new(perm.clone());
        let proof = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut prover_challenger,
        );

        let wrong_input = vec![F::ONE];
        let mut verifier_challenger = Challenger::new(perm);
        let result = verifier.verify::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &shape,
            &wrong_input,
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
            proof.phase1_sumcheck_proof.polynomials.len(),
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
