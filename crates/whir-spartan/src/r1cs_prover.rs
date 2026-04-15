//! R1CS Prover using WHIR PCS
//!
//! Implements Spartan's two-phase sum-check protocol integrated with WHIR's
//! polynomial commitment scheme for efficient R1CS proving.

use alloc::vec;
use alloc::vec::Vec;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};
use p3_maybe_rayon::prelude::*;

use crate::poly::evals::EvaluationsList;

use super::{
    encoding::{eq_poly, eq_poly_at_index},
    r1cs::{R1CSInstance, R1CSShape},
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

    /// Prove R1CS instance satisfaction using table-based sumcheck.
    ///
    /// This implements the full Spartan protocol with O(n) per-round prover:
    /// 1. Precompute Az, Bz, Cz, eq(τ,·) tables via sparse mat-vec multiply
    /// 2. Run Phase 1 table-based sum-check on G_io,τ (degree 3)
    /// 3. Run Phase 2 table-based sum-check over y (degree 2)
    /// 4. Derive witness/matrix evaluation claims at r_y
    /// 5. Commit sparse matrices through SPARK commitments
    #[allow(clippy::too_many_lines)]
    pub fn prove<EF, Challenger>(
        &self,
        instance: &R1CSInstance<F>,
        challenger: &mut Challenger,
    ) -> R1CSProof<F, EF>
    where
        EF: ExtensionField<F>,
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        let num_cons = instance.shape().num_cons();
        let num_cons_vars = num_cons.trailing_zeros() as usize;
        let tau: Vec<F> = (0..num_cons_vars).map(|_| challenger.sample()).collect();

        // Step 1: Precompute dense tables — O(nnz + 2^s)
        let z = instance.build_z_vector();
        let size_z = z.len();
        let mut az_table = vec![F::ZERO; num_cons];
        let mut bz_table = vec![F::ZERO; num_cons];
        let mut cz_table = vec![F::ZERO; num_cons];
        for entry in instance.shape().a().entries() {
            if entry.col < size_z {
                az_table[entry.row] += entry.val * z[entry.col];
            }
        }
        for entry in instance.shape().b().entries() {
            if entry.col < size_z {
                bz_table[entry.row] += entry.val * z[entry.col];
            }
        }
        for entry in instance.shape().c().entries() {
            if entry.col < size_z {
                cz_table[entry.row] += entry.val * z[entry.col];
            }
        }
        let mut eq_table = compute_eq_table(&tau);

        // Sanity check: sum of G_io,τ must be zero
        #[cfg(debug_assertions)]
        {
            let g_sum: F = (0..num_cons)
                .map(|i| eq_table[i] * (az_table[i] * bz_table[i] - cz_table[i]))
                .sum();
            assert_eq!(g_sum, F::ZERO, "Witness does not satisfy R1CS constraints");
        }

        // Step 2: Phase 1 table-based sum-check — degree 3
        // G(x) = eq(τ,x) · (Az(x)·Bz(x) - Cz(x))
        let phase1_sumcheck_proof = prove_sumcheck_phase1(
            num_cons_vars,
            &mut az_table,
            &mut bz_table,
            &mut cz_table,
            &mut eq_table,
            challenger,
        );
        let rx = phase1_sumcheck_proof.final_point.clone();
        let phase1_final_eval = phase1_sumcheck_proof.final_eval;

        // After binding, tables are size 1: the MLE evaluations at rx
        let a_eval = az_table[0];
        let b_eval = bz_table[0];
        let c_eval = cz_table[0];
        let eq_tau_rx = eq_table[0];

        assert_eq!(
            phase1_final_eval,
            (a_eval * b_eval - c_eval) * eq_tau_rx,
            "internal consistency failure: phase-1 equation must hold"
        );

        // Step 3: Phase-2 sum-check over y with transcript-derived coefficients.
        // Q(y) = Z(y) · (α·A(rx,y) + β·B(rx,y) + γ·C(rx,y))
        let phase2_coeffs = Phase2Coeffs {
            a: challenger.sample(),
            b: challenger.sample(),
            c: challenger.sample(),
        };
        let phase2_initial_claim =
            phase2_coeffs.a * a_eval + phase2_coeffs.b * b_eval + phase2_coeffs.c * c_eval;

        // Precompute lin_table[y] = α·A(rx,y) + β·B(rx,y) + γ·C(rx,y)
        let num_vars_y = instance.shape().num_poly_vars_y();
        let num_y = 1usize << num_vars_y;
        let mut lin_table = vec![F::ZERO; num_y];
        for entry in instance.shape().a().entries() {
            if entry.col < num_y {
                let eq_row = eq_poly_at_index::<F, F>(entry.row, &rx);
                lin_table[entry.col] += phase2_coeffs.a * entry.val * eq_row;
            }
        }
        for entry in instance.shape().b().entries() {
            if entry.col < num_y {
                let eq_row = eq_poly_at_index::<F, F>(entry.row, &rx);
                lin_table[entry.col] += phase2_coeffs.b * entry.val * eq_row;
            }
        }
        for entry in instance.shape().c().entries() {
            if entry.col < num_y {
                let eq_row = eq_poly_at_index::<F, F>(entry.row, &rx);
                lin_table[entry.col] += phase2_coeffs.c * entry.val * eq_row;
            }
        }
        let mut z_table = z.clone();
        z_table.resize(num_y, F::ZERO);

        let phase2_sumcheck_proof = prove_sumcheck_phase2(
            num_vars_y,
            phase2_initial_claim,
            &mut z_table,
            &mut lin_table,
            challenger,
        );
        let ry = phase2_sumcheck_proof.final_point.clone();
        let phase2_final_eval = phase2_sumcheck_proof.final_eval;

        let z_eval = z_table[0];
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

    /// Prove R1CS instance satisfaction using the naive oracle-based sumcheck.
    ///
    /// This is the original O(2^s · nnz)-per-round prover kept for benchmarking
    /// comparisons against the table-based `prove`. The protocol and proof
    /// format are identical; only the prover's internal algorithm differs.
    #[allow(clippy::too_many_lines)]
    pub fn prove_oracle<EF, Challenger>(
        &self,
        instance: &R1CSInstance<F>,
        challenger: &mut Challenger,
    ) -> R1CSProof<F, EF>
    where
        EF: ExtensionField<F>,
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        let num_cons_vars = instance.shape().num_cons().trailing_zeros() as usize;
        let tau: Vec<F> = (0..num_cons_vars).map(|_| challenger.sample()).collect();

        let z = instance.build_z_vector();

        // Phase 1: oracle-based sumcheck on G_io,τ (degree 3)
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

        // Compute primary claims at r_x.
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

        // Phase-2 sum-check over y
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
                    let z_y: F = eval_mle_from_hypercube::<F, F>(&z, &y);
                    let a_y = eval_sparse_at_point(instance.shape().a(), &rx, &y);
                    let b_y = eval_sparse_at_point(instance.shape().b(), &rx, &y);
                    let c_y = eval_sparse_at_point(instance.shape().c(), &rx, &y);
                    let lin =
                        phase2_coeffs.a * a_y + phase2_coeffs.b * b_y + phase2_coeffs.c * c_y;
                    sum += z_y * lin;
                }
                sum
            },
        );
        let ry = phase2_sumcheck_proof.final_point.clone();
        let phase2_final_eval = phase2_sumcheck_proof.final_eval;

        let z_eval: F = eval_mle_from_hypercube::<F, F>(&z, &ry);
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

/// Precompute eq(τ, i) for all i in {0,1}^s using the binary tree expansion.
///
/// eq(τ, x) = ∏_j (τ_j · x_j + (1-τ_j)·(1-x_j))
///
/// Processes tau in reverse order so that bit j of the index maps to τ_j,
/// matching `eq_poly_at_index`'s LSB-first convention.
pub(crate) fn compute_eq_table<F: Field>(tau: &[F]) -> Vec<F> {
    let s = tau.len();
    let n = 1usize << s;
    let mut table = vec![F::ZERO; n];
    table[0] = F::ONE;

    // Process tau[s-1] first (expands 1→2), then tau[s-2] (2→4), ..., tau[0] last (n/2→n).
    // This places tau[0] in the LSB position.
    for j in (0..s).rev() {
        let tau_j = tau[j];
        let one_minus_tau_j = F::ONE - tau_j;
        let half = 1usize << (s - 1 - j);
        for i in (0..half).rev() {
            table[2 * i + 1] = table[i] * tau_j;
            table[2 * i] = table[i] * one_minus_tau_j;
        }
    }
    table
}

/// Fold a table in-place by binding the LSB variable to `challenge`.
///
/// Adjacent pairs (2i, 2i+1) differ in bit 0. After binding:
///   table[i] = table[2i] + challenge · (table[2i+1] - table[2i])
///
/// This matches `eq_poly_at_index`'s convention where bit 0 = r[0].
/// Minimum table half-size before we switch to parallel iteration.
const PARALLEL_THRESHOLD: usize = 4096;

fn bind_table<F: Field>(table: &mut Vec<F>, challenge: F) {
    let half = table.len() / 2;
    if half >= PARALLEL_THRESHOLD {
        let folded: Vec<F> = table
            .par_chunks(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();
        *table = folded;
    } else {
        for i in 0..half {
            table[i] = table[2 * i] + challenge * (table[2 * i + 1] - table[2 * i]);
        }
        table.truncate(half);
    }
}

/// Phase 1 table-based sumcheck: G(x) = eq(τ,x) · (Az(x)·Bz(x) - Cz(x)), degree 3.
///
/// Each round: scan pairs (i, i+half), evaluate the degree-3 univariate at points 0,1,2,3,
/// then bind all 4 tables with the verifier challenge.
fn prove_sumcheck_phase1<F, Challenger>(
    num_vars: usize,
    az: &mut Vec<F>,
    bz: &mut Vec<F>,
    cz: &mut Vec<F>,
    eq_tau: &mut Vec<F>,
    challenger: &mut Challenger,
) -> SumcheckProof<F>
where
    F: Field,
    Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
{
    let mut current_claim = F::ZERO;
    let mut challenges = Vec::with_capacity(num_vars);
    let mut round_evals_all = Vec::with_capacity(num_vars);

    for _round in 0..num_vars {
        let half = az.len() / 2;

        // Evaluate degree-3 univariate at points 0, 1, 2, 3
        // Adjacent pairs (2i, 2i+1) differ in bit 0 (LSB-first convention)
        let compute_pair = |eq_pair: &[F], az_pair: &[F], bz_pair: &[F], cz_pair: &[F]| {
            let eq_lo = eq_pair[0];
            let eq_hi = eq_pair[1];
            let az_lo = az_pair[0];
            let az_hi = az_pair[1];
            let bz_lo = bz_pair[0];
            let bz_hi = bz_pair[1];
            let cz_lo = cz_pair[0];
            let cz_hi = cz_pair[1];

            let eq_d = eq_hi - eq_lo;
            let az_d = az_hi - az_lo;
            let bz_d = bz_hi - bz_lo;
            let cz_d = cz_hi - cz_lo;

            let e0 = eq_lo * (az_lo * bz_lo - cz_lo);
            let e1 = eq_hi * (az_hi * bz_hi - cz_hi);

            let eq_2 = eq_lo + eq_d.double();
            let az_2 = az_lo + az_d.double();
            let bz_2 = bz_lo + bz_d.double();
            let cz_2 = cz_lo + cz_d.double();
            let e2 = eq_2 * (az_2 * bz_2 - cz_2);

            let eq_3 = eq_2 + eq_d;
            let az_3 = az_2 + az_d;
            let bz_3 = bz_2 + bz_d;
            let cz_3 = cz_2 + cz_d;
            let e3 = eq_3 * (az_3 * bz_3 - cz_3);

            [e0, e1, e2, e3]
        };

        let evals = if half >= PARALLEL_THRESHOLD {
            eq_tau
                .par_chunks(2)
                .zip(az.par_chunks(2))
                .zip(bz.par_chunks(2))
                .zip(cz.par_chunks(2))
                .map(|(((eq_pair, az_pair), bz_pair), cz_pair)| {
                    compute_pair(eq_pair, az_pair, bz_pair, cz_pair)
                })
                .par_fold_reduce(
                    || [F::ZERO; 4],
                    |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]],
                    |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]],
                )
        } else {
            let mut evals = [F::ZERO; 4];
            for i in 0..half {
                let e = compute_pair(
                    &eq_tau[2 * i..2 * i + 2],
                    &az[2 * i..2 * i + 2],
                    &bz[2 * i..2 * i + 2],
                    &cz[2 * i..2 * i + 2],
                );
                evals[0] += e[0];
                evals[1] += e[1];
                evals[2] += e[2];
                evals[3] += e[3];
            }
            evals
        };

        let round_evals = evals.to_vec();

        assert_eq!(
            round_evals[0] + round_evals[1],
            current_claim,
            "phase-1 table sumcheck: round claim mismatch"
        );

        challenger.observe_algebra_slice(&round_evals);
        let r = challenger.sample();
        current_claim = evaluate_univariate_from_samples(&round_evals, r);
        challenges.push(r);
        round_evals_all.push(round_evals);

        // Bind all tables
        bind_table(az, r);
        bind_table(bz, r);
        bind_table(cz, r);
        bind_table(eq_tau, r);
    }

    SumcheckProof {
        polynomials: round_evals_all,
        challenges: challenges.clone(),
        final_point: challenges,
        final_eval: current_claim,
    }
}

/// Phase 2 table-based sumcheck: Q(y) = Z(y) · L(y), degree 2.
///
/// L(y) = α·A(rx,y) + β·B(rx,y) + γ·C(rx,y) is precomputed in lin_table.
fn prove_sumcheck_phase2<F, Challenger>(
    num_vars: usize,
    initial_claim: F,
    z_table: &mut Vec<F>,
    lin_table: &mut Vec<F>,
    challenger: &mut Challenger,
) -> SumcheckProof<F>
where
    F: Field,
    Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
{
    let mut current_claim = initial_claim;
    let mut challenges = Vec::with_capacity(num_vars);
    let mut round_evals_all = Vec::with_capacity(num_vars);

    for _round in 0..num_vars {
        let half = z_table.len() / 2;

        // Evaluate degree-2 univariate at points 0, 1, 2
        // Adjacent pairs (2i, 2i+1) differ in bit 0 (LSB-first convention)
        let compute_pair = |z_pair: &[F], l_pair: &[F]| {
            let z_lo = z_pair[0];
            let z_hi = z_pair[1];
            let l_lo = l_pair[0];
            let l_hi = l_pair[1];

            let z_d = z_hi - z_lo;
            let l_d = l_hi - l_lo;

            let e0 = z_lo * l_lo;
            let e1 = z_hi * l_hi;
            let z_2 = z_lo + z_d.double();
            let l_2 = l_lo + l_d.double();
            let e2 = z_2 * l_2;

            [e0, e1, e2]
        };

        let evals = if half >= PARALLEL_THRESHOLD {
            z_table
                .par_chunks(2)
                .zip(lin_table.par_chunks(2))
                .map(|(z_pair, l_pair)| compute_pair(z_pair, l_pair))
                .par_fold_reduce(
                    || [F::ZERO; 3],
                    |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
                    |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
                )
        } else {
            let mut evals = [F::ZERO; 3];
            for i in 0..half {
                let e = compute_pair(
                    &z_table[2 * i..2 * i + 2],
                    &lin_table[2 * i..2 * i + 2],
                );
                evals[0] += e[0];
                evals[1] += e[1];
                evals[2] += e[2];
            }
            evals
        };

        let round_evals = evals.to_vec();

        assert_eq!(
            round_evals[0] + round_evals[1],
            current_claim,
            "phase-2 table sumcheck: round claim mismatch"
        );

        challenger.observe_algebra_slice(&round_evals);
        let r = challenger.sample();
        current_claim = evaluate_univariate_from_samples(&round_evals, r);
        challenges.push(r);
        round_evals_all.push(round_evals);

        bind_table(z_table, r);
        bind_table(lin_table, r);
    }

    SumcheckProof {
        polynomials: round_evals_all,
        challenges: challenges.clone(),
        final_point: challenges,
        final_eval: current_claim,
    }
}

// NOTE: Packed sumcheck (src/sumcheck/packed.rs) produces k evaluation claims
// per round, which is protocol-incompatible with Spartan's single-point output.
// The packed sumcheck primitive is correct and ready for WHIR integration,
// where prover/verifier are co-designed for the k-claim output format.
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

// ============================================================================
// Oracle-based sumcheck helpers (used by `prove_oracle`)
// ============================================================================

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

fn eval_sparse_at_point<F: Field>(
    mat: &super::r1cs::SparseMatPolynomial<F>,
    rx: &[F],
    ry: &[F],
) -> F {
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
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use rand::SeedableRng;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
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

    #[test]
    fn test_table_and_oracle_provers_produce_identical_proofs() {
        let (_shape, instance, _input) = make_square_instance(4);
        let prover = super::R1CSProver::new();

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(42));

        // Table-based proof
        let mut ch1 = Challenger::new(perm.clone());
        let proof_table = prover.prove::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
            &instance,
            &mut ch1,
        );

        // Oracle-based proof (same seed → same challenger state)
        let mut ch2 = Challenger::new(perm);
        let proof_oracle =
            prover.prove_oracle::<p3_field::extension::BinomialExtensionField<F, 4>, _>(
                &instance,
                &mut ch2,
            );

        // Both must produce bit-identical proofs
        assert_eq!(proof_table.tau, proof_oracle.tau);
        assert_eq!(
            proof_table.phase1_sumcheck_proof.polynomials,
            proof_oracle.phase1_sumcheck_proof.polynomials,
            "Phase 1 round polynomials differ"
        );
        assert_eq!(
            proof_table.phase1_sumcheck_proof.challenges,
            proof_oracle.phase1_sumcheck_proof.challenges,
        );
        assert_eq!(
            proof_table.eval_claims.a_eval,
            proof_oracle.eval_claims.a_eval,
        );
        assert_eq!(
            proof_table.eval_claims.b_eval,
            proof_oracle.eval_claims.b_eval,
        );
        assert_eq!(
            proof_table.eval_claims.c_eval,
            proof_oracle.eval_claims.c_eval,
        );
        assert_eq!(
            proof_table.phase2_sumcheck_proof.polynomials,
            proof_oracle.phase2_sumcheck_proof.polynomials,
            "Phase 2 round polynomials differ"
        );
        assert_eq!(
            proof_table.eval_claims.z_eval,
            proof_oracle.eval_claims.z_eval,
        );
        assert_eq!(
            proof_table.eval_claims.a_matrix_eval,
            proof_oracle.eval_claims.a_matrix_eval,
        );
    }

}
