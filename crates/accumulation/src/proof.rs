use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use crate::{
    constraint_batch::ConstraintBatchProof, poly::multilinear::MultilinearPoint,
    whir::proof::WhirProof,
};

/// Transcript data used to batch multiple accumulator claims into one.
///
/// Uses a two-phase approach:
/// 1. **Constraint batching** via sumcheck: reduces `ℓ` linear claims to point evaluations.
/// 2. **Codeword batching** via random LC: combines `ℓ` oracles into one of the same size.
#[derive(Clone, Debug)]
pub struct AccumulationTranscript<F: Field, EF: ExtensionField<F>> {
    /// Challenge for weighting the `ℓ` linear claims in the constraint batching sumcheck.
    pub constraint_batching_challenge: F,
    /// Sumcheck proof: round polynomials and individual evaluations `fᵢ(r)`.
    pub constraint_batch_proof: ConstraintBatchProof<EF>,
    /// Challenge for combining the `ℓ` witness oracles via random linear combination.
    pub codeword_batching_challenge: F,
    /// Random out-of-domain point used to bind the combined polynomial.
    pub ood_point: MultilinearPoint<EF>,
    /// Claimed evaluation of the combined polynomial at `ood_point`.
    pub ood_answer: EF,
    /// Random in-domain spot-check indices over the combined polynomial.
    pub shift_query_indices: Vec<usize>,
    /// Claimed evaluations of the combined polynomial at the sampled in-domain indices.
    pub shift_query_answers: Vec<EF>,
}

/// Concrete accumulation proof: batching transcript plus underlying WHIR proof.
#[derive(Clone, Debug)]
pub struct AccumulationProof<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub transcript: AccumulationTranscript<F, EF>,
    pub whir_proof: WhirProof<F, EF, W, DIGEST_ELEMS>,
}
