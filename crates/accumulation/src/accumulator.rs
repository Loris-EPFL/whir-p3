use core::marker::PhantomData;
use p3_field::{ExtensionField, Field};

use crate::poly::evals::EvaluationsList;
use crate::whir::constraints::statement::LinearStatement;

/// Accumulator state for Spartan-linearized witness claims.
#[derive(Clone, Debug)]
pub struct Accumulator<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// `acc.x`: The public instance part containing algebraic claims.
    pub public_instance: AccumulatorInstance<F, EF, W, DIGEST_ELEMS>,

    /// `acc.w`: The witness part containing cryptographic commitments and full evaluations.
    /// This is only used by the prover and ignored by the recursive verifier.
    pub witness: AccumulatorWitness<F>,
}

/// The public, algebraic instance part of the accumulator (`acc.x`).
#[derive(Clone, Debug)]
pub struct AccumulatorInstance<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// `rt`: The Merkle root of the witness polynomial.
    pub commitment_root: [W; DIGEST_ELEMS],

    /// Aggregated linear claims over the witness polynomial.
    pub linear_claim: LinearStatement<F, EF>,

    pub _marker: PhantomData<F>,
}

/// The private witness part of the accumulator (`acc.w`).
#[derive(Clone, Debug)]
pub struct AccumulatorWitness<F: Field> {
    /// `f` / `w`: The full evaluations of the multilinear polynomial representing the witness.
    /// In a practical implementation, the `td` (Merkle tree data) is stored implicitly
    /// in the prover's state alongside this polynomial.
    pub poly: EvaluationsList<F>,
}

impl<F, EF, W, const DIGEST_ELEMS: usize> Accumulator<F, EF, W, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Create a new accumulator from an instance and witness.
    pub fn new(
        public_instance: AccumulatorInstance<F, EF, W, DIGEST_ELEMS>,
        witness: AccumulatorWitness<F>,
    ) -> Self {
        Self {
            public_instance,
            witness,
        }
    }
}
