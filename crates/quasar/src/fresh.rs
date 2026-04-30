use alloc::{vec, vec::Vec};

use p3_field::{ExtensionField, Field};

use crate::{
    accumulation::linearized::linearized_statement_from_spartan_proof,
    poly::evals::EvaluationsList,
    spartan::{encoding::eq_poly_at_index, r1cs::R1CSShape, r1cs_prover::R1CSProof},
    whir::constraints::statement::LinearStatement,
};

fn dense_matrix_row_combination<F: Field>(
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

/// A fresh, not-yet-committed linear witness claim suitable for Quasar-style squashing.
#[derive(Clone, Debug)]
pub struct FreshLinearInstance<F: Field, EF: ExtensionField<F>> {
    pub linear_claim: LinearStatement<F, EF>,
    pub witness_poly: EvaluationsList<F>,
}

/// Public verifier-side view of a fresh Quasar input.
#[derive(Clone, Debug)]
pub struct FreshLinearInstancePublic<F: Field, EF: ExtensionField<F>> {
    pub linear_claim: LinearStatement<F, EF>,
}

impl<F: Field, EF: ExtensionField<F>> FreshLinearInstance<F, EF> {
    #[must_use]
    pub fn new(linear_claim: LinearStatement<F, EF>, witness_poly: EvaluationsList<F>) -> Self {
        assert!(linear_claim.verify(&witness_poly));
        Self {
            linear_claim,
            witness_poly,
        }
    }

    #[must_use]
    pub fn from_spartan_proof(
        shape: &R1CSShape<F>,
        proof: &R1CSProof<F, EF>,
        witness_poly: EvaluationsList<F>,
        batching_challenge: EF,
    ) -> Self {
        let linear_claim =
            linearized_statement_from_spartan_proof(shape, proof, batching_challenge);
        Self::new(linear_claim, witness_poly)
    }

    #[must_use]
    pub fn from_shared_linearization_points(
        shape: &R1CSShape<F>,
        witness_poly: EvaluationsList<F>,
        rx: &[F],
        ry: &[F],
        batching_challenge: EF,
    ) -> Self {
        let (a_vals, b_vals, c_vals) = dense_matrix_row_combination(shape, rx);
        let eq_ry = (0..(1usize << shape.num_poly_vars_y()))
            .map(|idx| eq_poly_at_index::<F, F>(idx, ry))
            .collect::<Vec<_>>();

        let z_eval = witness_poly
            .as_slice()
            .iter()
            .enumerate()
            .fold(F::ZERO, |acc, (idx, &w)| {
                acc + w * eq_poly_at_index::<F, F>(idx, ry)
            });
        let a_eval = witness_poly
            .as_slice()
            .iter()
            .zip(a_vals.iter())
            .fold(F::ZERO, |acc, (&w, &a)| acc + w * a);
        let b_eval = witness_poly
            .as_slice()
            .iter()
            .zip(b_vals.iter())
            .fold(F::ZERO, |acc, (&w, &b)| acc + w * b);
        let c_eval = witness_poly
            .as_slice()
            .iter()
            .zip(c_vals.iter())
            .fold(F::ZERO, |acc, (&w, &c)| acc + w * c);

        let mut combined_weights = EvaluationsList::zero(shape.num_poly_vars_y());
        for (weights, coeff) in [
            (
                eq_ry.iter().copied().map(EF::from).collect::<Vec<_>>(),
                EF::ONE,
            ),
            (
                a_vals.iter().copied().map(EF::from).collect::<Vec<_>>(),
                batching_challenge,
            ),
            (
                b_vals.iter().copied().map(EF::from).collect::<Vec<_>>(),
                batching_challenge.square(),
            ),
            (
                c_vals.iter().copied().map(EF::from).collect::<Vec<_>>(),
                batching_challenge.cube(),
            ),
        ] {
            combined_weights
                .iter_mut()
                .zip(weights.iter())
                .for_each(|(acc, &value)| *acc += coeff * value);
        }

        let mut linear_claim = LinearStatement::<F, EF>::initialize(shape.num_poly_vars_y());
        linear_claim.add_constraint(
            combined_weights,
            EF::from(z_eval)
                + batching_challenge * EF::from(a_eval)
                + batching_challenge.square() * EF::from(b_eval)
                + batching_challenge.cube() * EF::from(c_eval),
        );
        Self::new(linear_claim, witness_poly)
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        self.linear_claim.verify(&self.witness_poly)
    }

    #[must_use]
    pub fn public(&self) -> FreshLinearInstancePublic<F, EF> {
        FreshLinearInstancePublic {
            linear_claim: self.linear_claim.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn make_square_r1cs() -> (R1CSShape<F>, Vec<F>, Vec<F>) {
        use crate::spartan::r1cs::SparseMatEntry;
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 1;
        let a_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(3);
        witness[1] = F::from_u64(9);
        let input = vec![F::ZERO];
        (shape, witness, input)
    }

    fn make_fresh_via_manual_linear_claim() -> FreshLinearInstance<F, EF> {
        let poly =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let mut linear_claim = LinearStatement::<F, EF>::initialize(2);
        let weights = EvaluationsList::new(vec![EF::ONE, EF::from_u64(2), EF::ZERO, EF::ONE]);
        let expected = EF::ONE + EF::from_u64(4) + EF::from_u64(4);
        linear_claim.add_constraint(weights, expected);
        FreshLinearInstance::new(linear_claim, poly)
    }

    #[test]
    fn fresh_new_and_verify() {
        let instance = make_fresh_via_manual_linear_claim();
        assert!(instance.verify());
    }

    #[test]
    #[should_panic]
    fn fresh_new_rejects_invalid() {
        let poly =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let mut linear_claim = LinearStatement::<F, EF>::initialize(2);
        let weights = EvaluationsList::new(vec![EF::ONE; 4]);
        linear_claim.add_constraint(weights, EF::from_u64(999));
        let _ = FreshLinearInstance::new(linear_claim, poly);
    }

    #[test]
    fn fresh_public_preserves_claim() {
        let instance = make_fresh_via_manual_linear_claim();
        let public = instance.public();
        assert_eq!(public.linear_claim, instance.linear_claim);
    }

    #[test]
    fn fresh_from_shared_linearization_points() {
        let (shape, witness, input) = make_square_r1cs();

        let size_z = 2 * shape.num_vars();
        let mut z = vec![F::ZERO; size_z];
        z[..shape.num_vars()].copy_from_slice(&witness);
        z[shape.num_vars()] = F::ONE;
        z[shape.num_vars() + 1..shape.num_vars() + 1 + shape.num_inputs()].copy_from_slice(&input);

        let witness_poly = EvaluationsList::new(z.clone());

        let rx = vec![F::from_u64(2); shape.num_poly_vars_x()];
        let ry = vec![F::from_u64(3); shape.num_poly_vars_y()];
        let batching_challenge = EF::from(F::from_u64(7));

        let instance = FreshLinearInstance::from_shared_linearization_points(
            &shape,
            witness_poly,
            &rx,
            &ry,
            batching_challenge,
        );

        assert!(instance.verify());

        let public = instance.public();
        assert_eq!(public.linear_claim.num_variables(), shape.num_poly_vars_y());
    }

    #[test]
    fn fresh_from_shared_linearization_points_verify_round_trip() {
        let (shape, witness, input) = make_square_r1cs();

        let size_z = 2 * shape.num_vars();
        let mut z = vec![F::ZERO; size_z];
        z[..shape.num_vars()].copy_from_slice(&witness);
        z[shape.num_vars()] = F::ONE;
        z[shape.num_vars() + 1..shape.num_vars() + 1 + shape.num_inputs()].copy_from_slice(&input);
        let witness_poly = EvaluationsList::new(z);

        let rx = vec![F::from_u64(11); shape.num_poly_vars_x()];
        let ry = vec![F::from_u64(13); shape.num_poly_vars_y()];

        for ch in [1u64, 5, 100] {
            let batching_challenge = EF::from(F::from_u64(ch));
            let instance = FreshLinearInstance::from_shared_linearization_points(
                &shape,
                witness_poly.clone(),
                &rx,
                &ry,
                batching_challenge,
            );
            assert!(instance.verify(), "failed for batching_challenge = {ch}");
        }
    }
}
