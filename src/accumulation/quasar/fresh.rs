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
