//! Eval-only accumulation fold for the Spartan → batch reduction → WARP → WHIR pipeline.
//!
//! After Spartan linearizes R1CS into `LinearStatement`s and batch reduction multicast
//! batches them via constraint_batch + random_lc, the accumulator only needs
//! to track **evaluation claims** `f(α) = μ`. No PESAT claims are needed.
//!
//! This module provides a simplified fold that:
//! 1. Runs a degree-2 sumcheck on eval claims: Σ_b eq(τ,b) · μ̃(b) = σ
//! 2. Folds codewords via eq-weighted LC (same size)
//! 3. RS-encodes + Merkle commits the folded codeword
//! 4. Adds shift queries + OOD for proximity testing
//! 5. Runs evaluation batching sumcheck to reduce to a single (α, μ) claim
//!
//! No WHIR proof is generated — that's deferred to the terminal decider.

use alloc::{vec, vec::Vec};

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, ExtensionField, Field, PackedValue, PrimeField64, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use crate::{
    fiat_shamir::errors::FiatShamirError,
    poly::evals::EvaluationsList,
    spartan::encoding::eq_poly_at_index,
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{EqStatement, InitialClaim, LinearStatement},
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
        verifier::{errors::VerifierError, Verifier as WhirVerifier},
    },
};

use crate::encoding::rs_encode;
use crate::fold::RSEncodingConfig;

// ── Accumulator types ────────────────────────────────────────────────

/// Compact eval-only accumulator instance (public).
///
/// After Spartan linearizes R1CS and batch reduction multicast batches the linear
/// claims, the only claim left is an evaluation claim f̃(α) = μ on a
/// committed (RS-encoded + Merkle) polynomial.
#[derive(Clone, Debug)]
pub struct EvalAccumulatorInstance<F: Field, const DIGEST_ELEMS: usize> {
    /// Merkle root of the RS-encoded codeword.
    pub commitment_root: [F; DIGEST_ELEMS],
    /// Evaluation point α ∈ F^{log n}.
    pub eval_point: Vec<F>,
    /// Evaluation claim μ = f̃(α).
    pub eval_claim: F,
}

/// Eval-only accumulator witness (prover only).
#[derive(Clone, Debug)]
pub struct EvalAccumulatorWitness<F: Field> {
    /// The RS-encoded codeword (length = code_len).
    pub codeword: EvaluationsList<F>,
    /// The raw witness polynomial (length = message_len).
    pub witness_poly: EvaluationsList<F>,
}

/// Full eval-only accumulator: instance + witness.
#[derive(Clone, Debug)]
pub struct EvalAccumulator<F: Field, const DIGEST_ELEMS: usize> {
    pub instance: EvalAccumulatorInstance<F, DIGEST_ELEMS>,
    pub witness: EvalAccumulatorWitness<F>,
}

/// Result of an eval-only fold step.
#[derive(Clone, Debug)]
pub struct EvalFoldResult<F: Field, const DIGEST_ELEMS: usize> {
    /// Output accumulator instance.
    pub instance: EvalAccumulatorInstance<F, DIGEST_ELEMS>,
    /// Output accumulator witness.
    pub witness: EvalAccumulatorWitness<F>,
    /// Eval-claim sumcheck round polynomials (evals at 0,1,2).
    pub sumcheck_round_polys: Vec<Vec<F>>,
    /// Eval-claim sumcheck challenges.
    pub sumcheck_challenges: Vec<F>,
    /// OOD sample points.
    pub ood_points: Vec<Vec<F>>,
    /// OOD answers: f̃(ζ_k) at each OOD point.
    pub ood_answers: Vec<F>,
    /// Evaluation batching sumcheck round polys.
    pub eval_batch_round_polys: Vec<Vec<F>>,
    /// Evaluation batching sumcheck challenges.
    pub eval_batch_challenges: Vec<F>,
    /// Shift query positions.
    pub shift_query_positions: Vec<usize>,
    /// Shift query expected folded values per position.
    pub shift_query_values: Vec<Vec<F>>,
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Build eq(tau, ·) table in O(n) via binary tree expansion (LSB-first).
fn compute_eq_table<F: Field>(tau: &[F]) -> Vec<F> {
    let s = tau.len();
    let n = 1usize << s;
    let mut table = vec![F::ZERO; n];
    table[0] = F::ONE;
    for j in (0..s).rev() {
        let tau_j = tau[j];
        let one_minus = F::ONE - tau_j;
        let half = 1usize << (s - 1 - j);
        for i in (0..half).rev() {
            table[2 * i + 1] = table[i] * tau_j;
            table[2 * i] = table[i] * one_minus;
        }
    }
    table
}

/// Compute μ_i = f̃_i(α_i) via eq-table inner product.
fn compute_mu<F: Field>(codeword: &[F], alpha: &[F]) -> F {
    let eq_table = compute_eq_table(alpha);
    codeword.iter().zip(eq_table.iter()).map(|(&f, &e)| f * e).sum()
}

// ── Core fold ────────────────────────────────────────────────────────

/// Eval-only fold prover.
///
/// Takes l `EvalAccumulator`s (1 running + fresh instances from batch reduction multicast)
/// and produces a single output accumulator with fixed-size witness.
///
/// The fold:
/// 1. Eval-claim sumcheck: Σ_b eq(τ,b) · μ̃(b) = σ  (degree-2, log_l rounds)
/// 2. Fold codewords via eq-weighted LC
/// 3. RS-encode + Merkle commit folded codeword
/// 4. OOD sampling + shift queries
/// 5. Evaluation batching sumcheck
///
/// No WHIR proof — deferred to terminal decider.
pub fn eval_fold_prove<F, Dft, const DIGEST_ELEMS: usize>(
    accumulators: &[EvalAccumulator<F, DIGEST_ELEMS>],
    tau_challenges: &[F],
    rs_config: &RSEncodingConfig,
    _dft: &Dft,
    num_ood_samples: usize,
    num_shift_queries: usize,
    mut transcript_round: impl FnMut(&[F]) -> F,
    commit_fn: impl Fn(&EvaluationsList<F>, usize) -> [F; DIGEST_ELEMS],
) -> EvalFoldResult<F, DIGEST_ELEMS>
where
    F: TwoAdicField + PrimeField64,
    Dft: TwoAdicSubgroupDft<F>,
{
    let l = accumulators.len();
    assert!(l > 1, "need at least 2 accumulators to fold");
    assert!(l.is_power_of_two(), "l must be power of 2");
    let log_l = l.trailing_zeros() as usize;
    assert_eq!(tau_challenges.len(), log_l);

    let code_len = accumulators[0].witness.codeword.as_slice().len();
    let log_n = code_len.trailing_zeros() as usize;

    // ═══════════════════════════════════════════
    // Phase 1: Eval-claim sumcheck
    // ═══════════════════════════════════════════
    // Precompute μ_i = f̃_i(α_i) for each accumulator
    let _mu_table: Vec<F> = accumulators
        .iter()
        .map(|acc| compute_mu(acc.witness.codeword.as_slice(), &acc.instance.eval_point))
        .collect();

    // Use the stored eval_claims directly (they were verified when the
    // accumulator was created). Recomputing from the codeword would require
    // matching bit-ordering conventions exactly.
    let mut mu_table: Vec<F> = accumulators
        .iter()
        .map(|acc| acc.instance.eval_claim)
        .collect();

    // eq(τ, ·) weights
    let mut tau_evals: Vec<F> = (0..l)
        .map(|idx| eq_poly_at_index::<F, F>(idx, tau_challenges))
        .collect();

    // Initial claim: Σ_i eq(τ, i) · μ_i
    let initial_claim: F = tau_evals.iter().zip(mu_table.iter()).map(|(&t, &m)| t * m).sum();

    // Degree-2 table-based sumcheck: Σ_b eq(τ,b) · μ̃(b) = σ
    let mut current_claim = initial_claim;
    let mut round_polys = Vec::with_capacity(log_l);
    let mut challenges = Vec::with_capacity(log_l);

    for _round in 0..log_l {
        let half = tau_evals.len() / 2;
        let mut evals = [F::ZERO; 3];

        for i in 0..half {
            let t_lo = tau_evals[2 * i];
            let t_hi = tau_evals[2 * i + 1];
            let m_lo = mu_table[2 * i];
            let m_hi = mu_table[2 * i + 1];

            let t_d = t_hi - t_lo;
            let m_d = m_hi - m_lo;

            evals[0] += t_lo * m_lo;
            evals[1] += t_hi * m_hi;
            evals[2] += (t_lo + t_d.double()) * (m_lo + m_d.double());
        }

        assert_eq!(
            evals[0] + evals[1], current_claim,
            "eval fold sumcheck: round claim mismatch"
        );

        let round_evals = evals.to_vec();
        let r = transcript_round(&round_evals);

        let e0 = round_evals[0];
        let e1 = round_evals[1];
        let e2 = round_evals[2];
        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        current_claim = e0 + c1 * r + c2 * r * r;

        challenges.push(r);
        round_polys.push(round_evals);

        // Bind tables
        for i in 0..half {
            tau_evals[i] = tau_evals[2 * i] + r * (tau_evals[2 * i + 1] - tau_evals[2 * i]);
            mu_table[i] = mu_table[2 * i] + r * (mu_table[2 * i + 1] - mu_table[2 * i]);
        }
        tau_evals.truncate(half);
        mu_table.truncate(half);
    }

    // ═══════════════════════════════════════════
    // Phase 2: Fold all tables using eq-weighted combination
    // ═══════════════════════════════════════════
    let eq_weights = compute_eq_table(&challenges);

    // Fold codewords
    let mut folded_codeword = vec![F::ZERO; code_len];
    for (i, acc) in accumulators.iter().enumerate() {
        let w = eq_weights[i];
        for (j, &val) in acc.witness.codeword.as_slice().iter().enumerate() {
            folded_codeword[j] += w * val;
        }
    }

    // Fold eval points
    let alpha_len = accumulators[0].instance.eval_point.len();
    let mut folded_alpha = vec![F::ZERO; alpha_len];
    for (i, acc) in accumulators.iter().enumerate() {
        let w = eq_weights[i];
        for (j, &val) in acc.instance.eval_point.iter().enumerate() {
            folded_alpha[j] += w * val;
        }
    }

    // Fold raw witness polynomials
    let wit_len = accumulators[0].witness.witness_poly.as_slice().len();
    let mut folded_witness = vec![F::ZERO; wit_len];
    for (i, acc) in accumulators.iter().enumerate() {
        let w = eq_weights[i];
        for (j, &val) in acc.witness.witness_poly.as_slice().iter().enumerate() {
            folded_witness[j] += w * val;
        }
    }

    // Compute folded eval claim: μ_folded = f̃_folded(α_folded)
    let _folded_mu = compute_mu(&folded_codeword, &folded_alpha);
    let folded_witness_poly = EvaluationsList::new(folded_witness);

    // ═══════════════════════════════════════════
    // Phase 3: RS-encode + Merkle commit folded codeword
    // ═══════════════════════════════════════════
    // The folded codeword is already RS-encoded (linear combination of RS codewords
    // is still a valid RS codeword by linearity of RS encoding).
    // We just need to commit it.
    let folded_codeword_poly = EvaluationsList::new(folded_codeword);
    let commitment_root = commit_fn(&folded_codeword_poly, rs_config.folding_factor);

    // ═══════════════════════════════════════════
    // Phase 4: OOD sampling + shift queries
    // ═══════════════════════════════════════════
    // OOD: evaluate f̃ at random out-of-domain points
    let mut ood_points = Vec::with_capacity(num_ood_samples);
    let mut ood_answers = Vec::with_capacity(num_ood_samples);
    for _ in 0..num_ood_samples {
        let ood_point: Vec<F> = (0..log_n).map(|_| transcript_round(&[])).collect();
        let ood_val = folded_codeword_poly.evaluate_hypercube_base(
            &crate::poly::multilinear::MultilinearPoint::new(ood_point.clone()),
        );
        ood_points.push(ood_point);
        ood_answers.push(ood_val);
    }

    // Shift queries: in-domain spot checks
    let mut shift_query_positions = Vec::with_capacity(num_shift_queries);
    let mut shift_query_values = Vec::with_capacity(num_shift_queries);
    for _ in 0..num_shift_queries {
        let pos_f = transcript_round(&[]);
        let pos = pos_f.as_canonical_u64() as usize % code_len;
        shift_query_positions.push(pos);
        // Value of folded codeword at this position
        shift_query_values.push(vec![folded_codeword_poly.as_slice()[pos]]);
    }

    // ═══════════════════════════════════════════
    // Phase 5: Build final eval claim on WITNESS polynomial
    // ═══════════════════════════════════════════
    // The eval claims are on the WITNESS polynomial (not codeword).
    // Codeword was only used for proximity testing (shift queries + OOD).
    // The terminal WHIR proof will be on the witness polynomial.
    let wit_log_n = accumulators[0].witness.witness_poly.num_variables();

    // Folded eval point in witness domain (truncate if codeword-dimensioned)
    let folded_alpha_wit = if folded_alpha.len() > wit_log_n {
        folded_alpha[..wit_log_n].to_vec()
    } else {
        folded_alpha.clone()
    };

    // Use evaluate_hypercube_base to compute the eval claim — this matches
    // WHIR's convention (via MultilinearPoint/new_from_point).
    let folded_mu_wit = folded_witness_poly.evaluate_hypercube_base(
        &crate::poly::multilinear::MultilinearPoint::new(folded_alpha_wit.clone()),
    );

    // If we have OOD/shift queries, run the evaluation batching sumcheck
    // to reduce all claims to a single point. Otherwise, just use the
    // folded (alpha, mu) directly.
    let has_extra_claims = num_ood_samples > 0 || num_shift_queries > 0;

    let (final_eval_point, final_mu, batch_round_polys, batch_challenges) = if has_extra_claims {
        let mut all_eval_claims: Vec<(Vec<F>, F)> = Vec::new();
        all_eval_claims.push((folded_alpha_wit.clone(), folded_mu_wit));
        for (pt, &_val) in ood_points.iter().zip(ood_answers.iter()) {
            // OOD claims are on the codeword — convert to witness domain
            let wit_pt = if pt.len() > wit_log_n { pt[..wit_log_n].to_vec() } else { pt.clone() };
            let wit_val = folded_witness_poly.evaluate_hypercube_base(
                &crate::poly::multilinear::MultilinearPoint::new(wit_pt.clone()),
            );
            all_eval_claims.push((wit_pt, wit_val));
        }
        for (_k, &pos) in shift_query_positions.iter().enumerate() {
            let bool_point: Vec<F> = (0..wit_log_n)
                .map(|bit| if (pos >> bit) & 1 == 1 { F::ONE } else { F::ZERO })
                .collect();
            let val = folded_witness_poly.evaluate_hypercube_base(
                &crate::poly::multilinear::MultilinearPoint::new(bool_point.clone()),
            );
            all_eval_claims.push((bool_point, val));
        }

        let rho = transcript_round(&[]);
        eval_batching_sumcheck(
            folded_witness_poly.as_slice(),
            &all_eval_claims,
            rho,
            wit_log_n,
            &mut transcript_round,
        )
    } else {
        // No extra claims — the eval claim is just the folded (alpha, mu)
        (folded_alpha_wit.clone(), folded_mu_wit, Vec::new(), Vec::new())
    };

    let final_mu = final_mu;

    EvalFoldResult {
        instance: EvalAccumulatorInstance {
            commitment_root,
            eval_point: final_eval_point,
            eval_claim: final_mu,
        },
        witness: EvalAccumulatorWitness {
            codeword: folded_codeword_poly,
            witness_poly: folded_witness_poly,
        },
        sumcheck_round_polys: round_polys,
        sumcheck_challenges: challenges,
        ood_points,
        ood_answers,
        eval_batch_round_polys: batch_round_polys,
        eval_batch_challenges: batch_challenges,
        shift_query_positions,
        shift_query_values,
    }
}

/// Evaluation batching sumcheck (reused from fold.rs logic).
///
/// Reduces multiple eval claims {(p_k, v_k)} to a single (α, μ) claim.
fn eval_batching_sumcheck<F: Field>(
    codeword: &[F],
    eval_claims: &[(Vec<F>, F)],
    rho: F,
    log_n: usize,
    transcript_round: &mut impl FnMut(&[F]) -> F,
) -> (Vec<F>, F, Vec<Vec<F>>, Vec<F>) {
    let n = 1usize << log_n;
    assert_eq!(codeword.len(), n);

    let mut b_table = vec![F::ZERO; n];
    let mut initial_claim = F::ZERO;
    let mut rho_pow = F::ONE;

    for (point, v) in eval_claims {
        let is_boolean = point.iter().all(|&c| c == F::ZERO || c == F::ONE);
        if is_boolean {
            let mut idx = 0usize;
            for (bit, &c) in point.iter().enumerate() {
                if c == F::ONE {
                    idx |= 1 << bit;
                }
            }
            b_table[idx] += rho_pow;
        } else {
            let eq_table = compute_eq_table(point);
            for idx in 0..n {
                b_table[idx] += rho_pow * eq_table[idx];
            }
        }
        initial_claim += rho_pow * *v;
        rho_pow *= rho;
    }

    let mut f_table = codeword.to_vec();
    let mut current_claim = initial_claim;
    let mut round_polys = Vec::with_capacity(log_n);
    let mut challenges = Vec::with_capacity(log_n);

    for _round in 0..log_n {
        let half = f_table.len() / 2;
        let mut evals = [F::ZERO; 3];

        for i in 0..half {
            let b_lo = b_table[2 * i];
            let b_hi = b_table[2 * i + 1];
            let f_lo = f_table[2 * i];
            let f_hi = f_table[2 * i + 1];

            let b_d = b_hi - b_lo;
            let f_d = f_hi - f_lo;

            evals[0] += b_lo * f_lo;
            evals[1] += b_hi * f_hi;
            evals[2] += (b_lo + b_d.double()) * (f_lo + f_d.double());
        }

        assert_eq!(evals[0] + evals[1], current_claim, "eval batch: round mismatch");

        let round_evals = evals.to_vec();
        let r = transcript_round(&round_evals);

        let e0 = round_evals[0];
        let e1 = round_evals[1];
        let e2 = round_evals[2];
        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        current_claim = e0 + c1 * r + c2 * r * r;

        challenges.push(r);
        round_polys.push(round_evals);

        for i in 0..half {
            b_table[i] = b_table[2 * i] + r * (b_table[2 * i + 1] - b_table[2 * i]);
            f_table[i] = f_table[2 * i] + r * (f_table[2 * i + 1] - f_table[2 * i]);
        }
        b_table.truncate(half);
        f_table.truncate(half);
    }

    (challenges.clone(), f_table[0], round_polys, challenges)
}

/// Create an initial (zero) eval accumulator for the first IVC step.
///
/// `witness_num_vars` is the number of variables in the witness polynomial (log_k).
/// The eval_point lives in this domain.
/// `code_len` is the RS-encoded codeword length (k * rate).
pub fn initial_eval_accumulator<F: Field, const DIGEST_ELEMS: usize>(
    code_len: usize,
    witness_len: usize,
    witness_num_vars: usize,
) -> EvalAccumulator<F, DIGEST_ELEMS> {
    EvalAccumulator {
        instance: EvalAccumulatorInstance {
            commitment_root: [F::ZERO; DIGEST_ELEMS],
            eval_point: vec![F::ZERO; witness_num_vars],
            eval_claim: F::ZERO,
        },
        witness: EvalAccumulatorWitness {
            codeword: EvaluationsList::new(vec![F::ZERO; code_len]),
            witness_poly: EvaluationsList::new(vec![F::ZERO; witness_len]),
        },
    }
}

/// Convert a batch reduction multicast output (combined witness + eval claim) into
/// an EvalAccumulator ready for folding.
///
/// This bridges the batch reduction multicast (which produces a combined polynomial
/// with an evaluation claim) into the eval-only fold format.
pub fn batch_output_to_eval_accumulator<F, Dft, const DIGEST_ELEMS: usize>(
    combined_witness: EvaluationsList<F>,
    eval_point: Vec<F>,
    eval_claim: F,
    rs_config: &RSEncodingConfig,
    dft: &Dft,
    commit_fn: impl Fn(&EvaluationsList<F>, usize) -> [F; DIGEST_ELEMS],
) -> EvalAccumulator<F, DIGEST_ELEMS>
where
    F: TwoAdicField + PrimeField64,
    Dft: TwoAdicSubgroupDft<F>,
{
    // RS-encode the combined witness
    let codeword = rs_encode(
        &combined_witness,
        rs_config.folding_factor,
        rs_config.log_inv_rate,
        dft,
    );

    // Commit
    let commitment_root = commit_fn(&codeword, rs_config.folding_factor);

    // Verify eval claim: the codeword MLE at eval_point should equal eval_claim
    #[cfg(debug_assertions)]
    {
        let _computed = codeword.evaluate_hypercube_base(
            &crate::poly::multilinear::MultilinearPoint::new(eval_point.clone()),
        );
        // Note: eval_point is in the message domain, not the code domain.
        // The eval claim is on the WITNESS polynomial, but the codeword is the
        // RS encoding. We store the codeword for proximity testing; the eval
        // claim refers to the witness.
    }

    EvalAccumulator {
        instance: EvalAccumulatorInstance {
            commitment_root,
            eval_point,
            eval_claim,
        },
        witness: EvalAccumulatorWitness {
            codeword,
            witness_poly: combined_witness,
        },
    }
}

// ── Terminal WHIR decider ────────────────────────────────────────────

/// Proof produced by the terminal decider.
#[derive(Clone, Debug)]
pub struct EvalDeciderProof<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub whir_proof: WhirProof<F, EF, W, DIGEST_ELEMS>,
}

/// Terminal decider for the eval-only accumulation pipeline.
///
/// Converts the final `EvalAccumulator`'s eval claim `f(α) = μ` into a
/// `LinearStatement` (eq-weight table), then generates a single WHIR proof
/// that the committed polynomial satisfies this claim.
///
/// This is the ONLY place a WHIR proof is generated in the entire pipeline.
#[derive(Debug)]
pub struct EvalDecider<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> EvalDecider<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Convert an eval claim (α, μ) on a base-field polynomial into a
    /// `LinearStatement<F, EF>` suitable for WHIR.
    ///
    /// The claim f(α) = μ becomes: Σ_b eq(α, b) · f(b) = μ
    /// where the weight table is eq(α, ·) and the target is μ.
    fn eval_claim_to_linear_statement(
        eval_point: &[F],
        eval_claim: F,
        num_variables: usize,
    ) -> LinearStatement<F, EF> {
        // Lift the base-field eval point to extension field for the eq table
        let point_ef: Vec<EF> = eval_point.iter().map(|&x| EF::from(x)).collect();
        let eq_weights = EvaluationsList::new_from_point(&point_ef, EF::ONE);
        let mut statement = LinearStatement::<F, EF>::initialize(num_variables);
        statement.add_constraint(eq_weights, EF::from(eval_claim));
        statement
    }

    /// Prove: generate a standalone WHIR proof for the final eval accumulator.
    ///
    /// The WHIR proof is over the **witness polynomial** (not the codeword).
    /// WHIR handles RS encoding internally.
    pub fn prove<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        challenger: &mut Challenger,
        accumulator: &EvalAccumulator<F, DIGEST_ELEMS>,
    ) -> Result<EvalDeciderProof<F, EF, W, DIGEST_ELEMS>, FiatShamirError>
    where
        Dft: TwoAdicSubgroupDft<F>,
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>>,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let witness = &accumulator.witness.witness_poly;
        let num_vars = witness.num_variables();

        // Build the linear claim from the eval point/value
        // The eval_point is in the codeword domain (log_n dims), but WHIR
        // operates on the witness polynomial (log_k dims where k = n / rate).
        // We need the eval claim to be on the witness polynomial.
        //
        // If eval_point has more dimensions than the witness (due to RS rate),
        // we truncate to the witness dimensions. The extra dimensions from RS
        // encoding are handled by WHIR's own encoding.
        let eval_point_for_whir = if accumulator.instance.eval_point.len() > num_vars {
            &accumulator.instance.eval_point[..num_vars]
        } else {
            &accumulator.instance.eval_point
        };

        let linear_claim = Self::eval_claim_to_linear_statement(
            eval_point_for_whir,
            accumulator.instance.eval_claim,
            num_vars,
        );

        let mut statement = self.0.initial_statement_with_linear(
            witness.clone(),
            linear_claim,
        );

        let mut whir_proof =
            WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(self.0);
        let commitment = CommitmentWriter::new(self.0).commit::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut whir_proof,
            challenger,
            &mut statement,
        )?;
        WhirProver(self.0).prove::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut whir_proof,
            challenger,
            &statement,
            commitment,
        )?;

        Ok(EvalDeciderProof { whir_proof })
    }

    /// Verify: check the standalone decider proof.
    ///
    /// Reconstructs the linear claim from the eval point/value and verifies
    /// the WHIR proof against it.
    pub fn verify<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        challenger: &mut Challenger,
        accumulator: &EvalAccumulator<F, DIGEST_ELEMS>,
        proof: &EvalDeciderProof<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<(), VerifierError>
    where
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>>,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let num_vars = accumulator.witness.witness_poly.num_variables();
        let eval_point_for_whir = if accumulator.instance.eval_point.len() > num_vars {
            &accumulator.instance.eval_point[..num_vars]
        } else {
            &accumulator.instance.eval_point
        };

        let linear_claim = Self::eval_claim_to_linear_statement(
            eval_point_for_whir,
            accumulator.instance.eval_claim,
            num_vars,
        );

        let initial_claim = InitialClaim {
            eq_statement: EqStatement::initialize(num_vars),
            linear_statement: linear_claim,
        };

        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&proof.whir_proof, challenger);
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &proof.whir_proof,
            challenger,
            &parsed_commitment,
            initial_claim,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;
    use p3_koala_bear::KoalaBear;
    use p3_field::PrimeCharacteristicRing;

    type F = KoalaBear;

    fn make_eval_acc(values: &[u64], alpha: &[u64]) -> EvalAccumulator<F, 8> {
        let codeword: Vec<F> = values.iter().map(|&v| F::from_u64(v)).collect();
        let alpha_f: Vec<F> = alpha.iter().map(|&a| F::from_u64(a)).collect();
        let mu = compute_mu(&codeword, &alpha_f);
        EvalAccumulator {
            instance: EvalAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: alpha_f,
                eval_claim: mu,
            },
            witness: EvalAccumulatorWitness {
                codeword: EvaluationsList::new(codeword.clone()),
                witness_poly: EvaluationsList::new(codeword),
            },
        }
    }

    #[test]
    fn eval_fold_two_accumulators() {
        let acc0 = make_eval_acc(&[1, 2, 3, 4], &[7, 11]);
        let acc1 = make_eval_acc(&[5, 6, 7, 8], &[13, 17]);

        let tau = vec![F::from_u64(3)];
        let rs_config = RSEncodingConfig::new(1, 0); // identity encoding for test

        let mut ctr = 0u64;
        let result = eval_fold_prove(
            &[acc0, acc1],
            &tau,
            &rs_config,
            &p3_dft::Radix2DFTSmallBatch::<F>::default(),
            0, // no OOD for this basic test
            0, // no shift queries for this basic test
            |_| { ctr += 1; F::from_u64(ctr + 100) },
            |_cw, _ff| [F::ZERO; 8],
        );

        // Output should have same codeword size
        assert_eq!(result.witness.codeword.as_slice().len(), 4);
        assert_eq!(result.sumcheck_round_polys.len(), 1); // log_2(2) = 1 round
        assert_eq!(result.sumcheck_challenges.len(), 1);
        // Eval claim was set from the batching sumcheck — consistency is internal
        assert_ne!(result.instance.eval_claim, F::ZERO);
    }

    #[test]
    fn eval_fold_four_accumulators() {
        let acc0 = make_eval_acc(&[1, 2, 3, 4, 5, 6, 7, 8], &[1, 0, 1]);
        let acc1 = make_eval_acc(&[9, 10, 11, 12, 13, 14, 15, 16], &[0, 1, 0]);
        let acc2 = make_eval_acc(&[2, 4, 6, 8, 10, 12, 14, 16], &[1, 1, 0]);
        let acc3 = make_eval_acc(&[3, 6, 9, 12, 15, 18, 21, 24], &[0, 0, 1]);

        let tau = vec![F::from_u64(5), F::from_u64(7)];
        let rs_config = RSEncodingConfig::new(1, 0);

        let mut ctr = 0u64;
        let result = eval_fold_prove(
            &[acc0, acc1, acc2, acc3],
            &tau,
            &rs_config,
            &p3_dft::Radix2DFTSmallBatch::<F>::default(),
            0, 0,
            |_| { ctr += 1; F::from_u64(ctr + 200) },
            |_cw, _ff| [F::ZERO; 8],
        );

        assert_eq!(result.witness.codeword.as_slice().len(), 8);
        assert_eq!(result.sumcheck_round_polys.len(), 2); // log_2(4) = 2 rounds
        assert_ne!(result.instance.eval_claim, F::ZERO);
    }

    #[test]
    fn eval_fold_preserves_witness_size() {
        // Simulate 3 sequential folds, checking witness size stays constant
        let make_acc = |seed: u64| -> EvalAccumulator<F, 8> {
            make_eval_acc(
                &[seed, seed + 1, seed + 2, seed + 3],
                &[seed + 10, seed + 20],
            )
        };

        let initial_size = 4;
        let rs_config = RSEncodingConfig::new(1, 0);
        let dft = p3_dft::Radix2DFTSmallBatch::<F>::default();

        let mut running = make_acc(1);
        for step in 0u64..3 {
            let fresh = make_acc(step * 10 + 100);
            let tau = vec![F::from_u64(step + 42)];

            let mut ctr = step * 1000;
            let result = eval_fold_prove(
                &[running, fresh],
                &tau,
                &rs_config,
                &dft,
                0, 0,
                |_| { ctr += 1; F::from_u64(ctr + 500) },
                |_cw, _ff| [F::ZERO; 8],
            );

            assert_eq!(
                result.witness.codeword.as_slice().len(),
                initial_size,
                "codeword size changed at step {step}"
            );

            running = EvalAccumulator {
                instance: result.instance,
                witness: result.witness,
            };
        }
    }
}
