use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use crate::{poly::multilinear::MultilinearPoint, whir::proof::WhirProof};

/// Transcript data used to batch multiple accumulator claims into one.
#[derive(Clone, Debug)]
pub struct AccumulationTranscript<F: Field, EF: ExtensionField<F>> {
    /// Random linear-combination challenge for batching input claims.
    pub batching_challenge: F,
    /// Random out-of-domain point used to bind the union polynomial.
    pub ood_point: MultilinearPoint<EF>,
    /// Claimed evaluation of the union polynomial at `ood_point`.
    pub ood_answer: EF,
    /// Random in-domain spot-check indices over the union polynomial.
    pub shift_query_indices: Vec<usize>,
    /// Claimed evaluations of the union polynomial at the sampled in-domain indices.
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
