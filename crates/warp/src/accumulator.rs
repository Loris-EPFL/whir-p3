//! WARP accumulator types with fixed-size claims.
//!
//! Unlike the `LinearStatement`-based accumulator in `super::super::accumulator`,
//! these types carry scalar evaluation and PESAT claims that do NOT grow with
//! the number of IVC steps. The witness (codeword + decoded witness) stays at
//! fixed size `n` (code length) / `k` (message length) throughout.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use crate::poly::evals::EvaluationsList;

/// Public instance of a WARP accumulator.
///
/// All fields have fixed size regardless of accumulation depth:
/// - `commitment_root`: Merkle digest of the committed codeword
/// - `eval_point` (α): multilinear evaluation point, length = log(code_len)
/// - `eval_claim` (μ): claimed value f̂(α)
/// - `pesat_tau` (τ): PESAT zerocheck randomness, length = log(num_constraints)
/// - `pesat_x` (x): public input portion of the PESAT point
/// - `pesat_target` (η): claimed PESAT evaluation P*(β, z)
#[derive(Clone, Debug)]
pub struct WarpAccumulatorInstance<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Merkle root of the committed codeword.
    pub commitment_root: [W; DIGEST_ELEMS],

    /// Evaluation point α ∈ F^{log_n} where f̂(α) = μ.
    pub eval_point: Vec<EF>,

    /// Evaluation claim: μ = f̂(α).
    pub eval_claim: EF,

    /// PESAT constraint point — zerocheck randomness τ.
    /// Length = log(M) where M is the number of constraints.
    pub pesat_tau: Vec<F>,

    /// PESAT constraint point — public input x.
    pub pesat_x: Vec<F>,

    /// PESAT target: η = P*(β, z) where β = (τ, x).
    pub pesat_target: EF,
}

/// Private witness of a WARP accumulator (prover only).
///
/// Contains the full codeword and decoded witness vector, both at fixed size.
#[derive(Clone, Debug)]
pub struct WarpAccumulatorWitness<F: Field> {
    /// The codeword f = encode(w), length = code_len (n).
    pub codeword: EvaluationsList<F>,

    /// The decoded witness vector w, length = message_len (k).
    /// Together with the public input x, forms z = (x, w) for PESAT evaluation.
    pub witness: Vec<F>,
}

/// A complete WARP accumulator: public instance + private witness.
#[derive(Clone, Debug)]
pub struct WarpAccumulator<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub instance: WarpAccumulatorInstance<F, EF, W, DIGEST_ELEMS>,
    pub witness: WarpAccumulatorWitness<F>,
}

impl<F, EF, W, const DIGEST_ELEMS: usize> WarpAccumulator<F, EF, W, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub fn new(
        instance: WarpAccumulatorInstance<F, EF, W, DIGEST_ELEMS>,
        witness: WarpAccumulatorWitness<F>,
    ) -> Self {
        Self { instance, witness }
    }

    /// Number of variables in the codeword (log of code length).
    pub fn log_code_len(&self) -> usize {
        self.witness.codeword.num_variables()
    }
}

/// A fresh (unaccumulated) PESAT instance to be folded into the accumulator.
///
/// This represents a single computation step: a witness `w` and public input `x`
/// such that the PESAT relation P*(tau, x, w) = 0 holds for some bundling
/// randomness tau derived during the fold.
#[derive(Clone, Debug)]
pub struct FreshInstance<F: Field> {
    /// Public input for this computation step.
    pub public_input: Vec<F>,

    /// Private witness for this computation step.
    pub witness: Vec<F>,
}

/// Proof produced by a single WARP fold step.
///
/// This is lightweight: NO WHIR proof is included. The proof contains only
/// the data needed for the verifier to reconstruct the output accumulator
/// instance (Merkle root, sumcheck transcripts, OOD answers, shift query
/// Merkle paths).
#[derive(Clone, Debug)]
pub struct WarpFoldProof<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Merkle root of the interleaved fresh codewords.
    pub fresh_commitment_root: [W; DIGEST_ELEMS],

    /// Code evaluations μ_i = f_i[0] for each fresh witness codeword.
    pub fresh_code_evals: Vec<F>,

    /// Twin-constraint sumcheck round polynomials (coefficients per round).
    pub twin_sumcheck_coeffs: Vec<Vec<EF>>,

    /// New accumulator commitment root (Merkle root of folded codeword).
    pub folded_commitment_root: [W; DIGEST_ELEMS],

    /// PESAT target of the folded accumulator.
    pub folded_eta: EF,

    /// OOD evaluation claim ν₀ = f̂(ζ₀) at the initial eval point.
    pub nu_0: EF,

    /// OOD answers: evaluations of f̂ at sampled out-of-domain points.
    pub ood_answers: Vec<EF>,

    /// Shift query answers: codeword evaluations at sampled in-domain indices.
    /// Outer vec: per shift query index. Inner vec: per codeword (all l codewords).
    pub shift_query_answers: Vec<Vec<F>>,

    /// Codeword batching sumcheck round data.
    pub batching_sumcheck_data: Vec<[EF; 3]>,
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_koala_bear::KoalaBear;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn warp_accumulator_instance_is_fixed_size() {
        // Verify that the accumulator instance size does not depend on
        // the number of IVC steps — it only depends on code parameters.
        let log_n = 10; // code length = 2^10
        let log_m = 5; // num constraints = 2^5
        let num_inputs = 8;

        let instance = WarpAccumulatorInstance::<F, EF, F, 8> {
            commitment_root: [F::ZERO; 8],
            eval_point: vec![EF::ZERO; log_n],
            eval_claim: EF::ZERO,
            pesat_tau: vec![F::ZERO; log_m],
            pesat_x: vec![F::ZERO; num_inputs],
            pesat_target: EF::ZERO,
        };

        // These sizes are invariant across all IVC steps:
        assert_eq!(instance.eval_point.len(), log_n);
        assert_eq!(instance.pesat_tau.len(), log_m);
        assert_eq!(instance.pesat_x.len(), num_inputs);
    }

    #[test]
    fn warp_accumulator_witness_is_fixed_size() {
        let code_len = 1 << 10; // n = 1024
        let msg_len = 512; // k = 512

        let witness = WarpAccumulatorWitness::<F> {
            codeword: EvaluationsList::new(vec![F::ZERO; code_len]),
            witness: vec![F::ZERO; msg_len],
        };

        assert_eq!(witness.codeword.as_slice().len(), code_len);
        assert_eq!(witness.witness.len(), msg_len);
    }
}
