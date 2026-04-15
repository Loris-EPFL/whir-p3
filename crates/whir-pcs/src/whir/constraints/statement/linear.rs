use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field, PackedFieldExtension, PackedValue};
use p3_util::log2_strict_usize;

use crate::poly::evals::EvaluationsList;

/// A batched family of arbitrary linear functionals over a multilinear evaluation table.
///
/// Each constraint is represented by a full weight table `lambda` over `{0,1}^k` and
/// a target `sigma`, asserting that `sum_b lambda(b) * f(b) = sigma`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearStatement<F: Field, EF: ExtensionField<F>> {
    num_variables: usize,
    pub weights: Vec<EvaluationsList<EF>>,
    evaluations: Vec<EF>,
    _marker: PhantomData<F>,
}

impl<F: Field, EF: ExtensionField<F>> LinearStatement<F, EF> {
    #[must_use]
    pub const fn initialize(num_variables: usize) -> Self {
        Self {
            num_variables,
            weights: Vec::new(),
            evaluations: Vec::new(),
            _marker: PhantomData,
        }
    }

    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.num_variables
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        debug_assert!(self.weights.len() == self.evaluations.len());
        self.weights.is_empty()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        debug_assert!(self.weights.len() == self.evaluations.len());
        self.weights.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&EvaluationsList<EF>, &EF)> {
        self.weights.iter().zip(self.evaluations.iter())
    }

    pub fn add_constraint(&mut self, weights: EvaluationsList<EF>, evaluation: EF) {
        assert_eq!(weights.num_variables(), self.num_variables);
        self.weights.push(weights);
        self.evaluations.push(evaluation);
    }

    #[must_use]
    pub fn verify(&self, poly: &EvaluationsList<F>) -> bool {
        assert_eq!(poly.num_variables(), self.num_variables);
        self.iter().all(|(weights, expected_eval)| {
            let actual = poly
                .as_slice()
                .iter()
                .zip(weights.as_slice().iter())
                .fold(EF::ZERO, |acc, (&poly_eval, &weight)| {
                    acc + EF::from(poly_eval) * weight
                });
            actual == *expected_eval
        })
    }

    pub fn combine_evals(&self, eval: &mut EF, challenge: EF, shift: usize) {
        for (expected_eval, coeff) in self.evaluations.iter().zip(challenge.powers().skip(shift)) {
            *eval += coeff * *expected_eval;
        }
    }

    pub fn combine<const INITIALIZED: bool>(
        &self,
        combined: &mut EvaluationsList<EF>,
        eval: &mut EF,
        challenge: EF,
        shift: usize,
    ) {
        assert_eq!(combined.num_variables(), self.num_variables);
        self.combine_evals(eval, challenge, shift);

        for (weights, coeff) in self.weights.iter().zip(challenge.powers().skip(shift)) {
            let _ = INITIALIZED;
            combined
                .iter_mut()
                .zip(weights.as_slice().iter())
                .for_each(|(acc, &weight)| *acc += coeff * weight);
        }
    }

    pub fn combine_packed<const INITIALIZED: bool>(
        &self,
        combined: &mut EvaluationsList<EF::ExtensionPacking>,
        eval: &mut EF,
        challenge: EF,
        shift: usize,
    ) where
        EF::ExtensionPacking: PackedFieldExtension<F, EF>,
    {
        self.combine_evals(eval, challenge, shift);

        for (weights, coeff) in self.weights.iter().zip(challenge.powers().skip(shift)) {
            let pack_width = F::Packing::WIDTH;
            let pack_log = log2_strict_usize(pack_width);
            assert_eq!(combined.num_variables(), self.num_variables() - pack_log);
            let packed = EvaluationsList::new(
                weights
                    .as_slice()
                    .chunks(pack_width)
                    .map(EF::ExtensionPacking::from_ext_slice)
                    .collect(),
            );
            let _ = INITIALIZED;
            combined
                .iter_mut()
                .zip(packed.as_slice().iter())
                .for_each(|(acc, &weight)| *acc += weight * coeff);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_koala_bear::KoalaBear;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};

    use super::*;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn linear_statement_verifies_dot_product_claims() {
        let poly =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let mut statement = LinearStatement::<F, EF>::initialize(2);
        let weights = EvaluationsList::new(vec![EF::ONE, EF::from_u64(2), EF::ZERO, EF::ONE]);
        statement.add_constraint(weights, EF::ONE + EF::from_u64(4) + EF::from_u64(4));
        assert!(statement.verify(&poly));
    }

    #[test]
    fn linear_statement_rejects_bad_target() {
        let poly = EvaluationsList::new(vec![F::ONE, F::ONE, F::ONE, F::ONE]);
        let mut statement = LinearStatement::<F, EF>::initialize(2);
        let weights = EvaluationsList::new(vec![EF::ONE; 4]);
        statement.add_constraint(weights, EF::from_u64(5));
        assert!(!statement.verify(&poly));
    }

    #[test]
    fn linear_statement_combines_weights() {
        let mut statement = LinearStatement::<F, EF>::initialize(1);
        statement.add_constraint(
            EvaluationsList::new(vec![EF::ONE, EF::ZERO]),
            EF::from_u64(2),
        );
        statement.add_constraint(
            EvaluationsList::new(vec![EF::ZERO, EF::ONE]),
            EF::from_u64(3),
        );

        let mut combined = EvaluationsList::zero(1);
        let mut eval = EF::ZERO;
        statement.combine::<false>(&mut combined, &mut eval, EF::from_u64(5), 0);

        assert_eq!(combined.as_slice(), &[EF::ONE, EF::from_u64(5)]);
        assert_eq!(eval, EF::from_u64(17));
    }
}
