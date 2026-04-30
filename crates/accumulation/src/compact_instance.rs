//! Compact accumulator instance for IVC.
//!
//! Stores `(evaluation_point, evaluation_value)` instead of the full `eq(r, ·)`
//! weight table. This avoids the exponential blowup (`2^m` entries) when hashing
//! the accumulator instance inside the recursive circuit.
//!
//! The full weight table can be reconstructed from the compact form:
//! `weight[b] = eq(evaluation_point, b)` for all `b ∈ {0,1}^m`.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

use crate::poly::{evals::EvaluationsList, multilinear::MultilinearPoint};

use super::accumulator::AccumulatorInstance;

/// Compact representation of an accumulator instance.
///
/// Instead of storing the full `LinearStatement` with a `2^m`-entry weight table,
/// this stores the evaluation point `r` and value `y` such that the claim is
/// `f(r) = y`, encoded as `Σ_b eq(r, b) · f(b) = y`.
#[derive(Clone, Debug)]
pub struct CompactAccumulatorInstance<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Merkle root of the committed polynomial.
    pub commitment_root: [W; DIGEST_ELEMS],
    /// The evaluation point `r ∈ EF^m`.
    pub evaluation_point: MultilinearPoint<EF>,
    /// The claimed evaluation value `y = f(r)`.
    pub evaluation_value: EF,
    pub(crate) _marker: PhantomData<F>,
}

impl<F, EF, W, const DIGEST_ELEMS: usize> CompactAccumulatorInstance<F, EF, W, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Create a new compact instance.
    pub fn new(
        commitment_root: [W; DIGEST_ELEMS],
        evaluation_point: MultilinearPoint<EF>,
        evaluation_value: EF,
    ) -> Self {
        Self {
            commitment_root,
            evaluation_point,
            evaluation_value,
            _marker: PhantomData,
        }
    }

    /// Expand into the full `AccumulatorInstance` by computing `eq(r, ·)` weights.
    pub fn expand(&self) -> AccumulatorInstance<F, EF, W, DIGEST_ELEMS>
    where
        W: Copy,
    {
        use crate::whir::constraints::statement::LinearStatement;

        let num_variables = self.evaluation_point.num_variables();
        let eq_weights = EvaluationsList::new_from_point(self.evaluation_point.as_slice(), EF::ONE);
        let mut statement = LinearStatement::<F, EF>::initialize(num_variables);
        statement.add_constraint(eq_weights, self.evaluation_value);

        AccumulatorInstance {
            commitment_root: self.commitment_root,
            linear_claim: statement,
            _marker: PhantomData,
        }
    }

    /// Number of variables in the evaluation point.
    pub fn num_variables(&self) -> usize {
        self.evaluation_point.num_variables()
    }

    /// Flatten the instance into a vector of base field elements for hashing.
    ///
    /// Layout: `[commitment_root (as F) | evaluation_point limbs | evaluation_value limbs]`
    pub fn to_field_elements(&self) -> Vec<F>
    where
        W: Copy + Into<F>,
        EF: p3_field::BasedVectorSpace<F>,
    {
        let mut elements = Vec::new();

        // Commitment root
        for &w in &self.commitment_root {
            elements.push(w.into());
        }

        // Evaluation point (each EF element → D base field elements)
        for ef in self.evaluation_point.as_slice() {
            elements.extend_from_slice(ef.as_basis_coefficients_slice());
        }

        // Evaluation value
        elements.extend_from_slice(self.evaluation_value.as_basis_coefficients_slice());

        elements
    }
}

/// Create a compact instance directly from an evaluation point and value.
///
/// This is the primary constructor for IVC: the accumulation scheme produces
/// evaluation claims `f(r) = y`, which are stored compactly as `(r, y)`.
/// Use `expand()` to convert to the full `AccumulatorInstance` when needed.
pub fn compact_from_eval_claim<F, EF, W, const DIGEST_ELEMS: usize>(
    commitment_root: [W; DIGEST_ELEMS],
    point: MultilinearPoint<EF>,
    value: EF,
) -> CompactAccumulatorInstance<F, EF, W, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    CompactAccumulatorInstance::new(commitment_root, point, value)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
    use p3_koala_bear::KoalaBear;

    use super::*;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn compact_expand_round_trip() {
        let point = MultilinearPoint::new(vec![EF::from_u64(3), EF::from_u64(7), EF::from_u64(11)]);
        let value = EF::from_u64(42);
        let root = [F::ONE; 8];

        let compact = CompactAccumulatorInstance::<F, EF, F, 8>::new(root, point.clone(), value);
        let expanded = compact.expand();

        // Verify the expanded instance has the correct weights
        let (weights, &target) = expanded.linear_claim.iter().next().unwrap();
        assert_eq!(target, value);

        // Verify eq(r, 0) = Π(1-r_i) = (1-3)*(1-7)*(1-11) = (-2)*(-6)*(-10)
        let expected_eq_at_zero = (EF::ONE - EF::from_u64(3))
            * (EF::ONE - EF::from_u64(7))
            * (EF::ONE - EF::from_u64(11));
        assert_eq!(weights.as_slice()[0], expected_eq_at_zero);
    }

    #[test]
    fn compact_to_field_elements() {
        let point = MultilinearPoint::new(vec![EF::from_u64(3), EF::from_u64(7)]);
        let value = EF::from_u64(99);
        let root = [F::ONE; 8];

        let compact = CompactAccumulatorInstance::<F, EF, F, 8>::new(root, point, value);
        let elements = compact.to_field_elements();

        // 8 root elements + 2*4 point limbs + 4 value limbs = 8 + 8 + 4 = 20
        assert_eq!(elements.len(), 20);
        // First 8 should be F::ONE (the root)
        assert!(elements[..8].iter().all(|&e| e == F::ONE));
    }
}
