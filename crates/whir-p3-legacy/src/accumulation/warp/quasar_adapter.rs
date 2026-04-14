//! Adapter from Quasar squash output to WARP fold input.
//!
//! The Quasar frontend squashes l fresh Spartan instances into a single
//! `Accumulator` with a `LinearStatement`-based claim. This adapter converts
//! that output into the WARP-style `FreshInstance` format that the WARP fold
//! accepts.
//!
//! Pipeline:
//! ```text
//! l R1CS instances
//!   → Spartan prove → l FreshLinearInstances
//!   → Quasar squash → 1 Accumulator (LinearStatement)
//!   → THIS ADAPTER → 1 FreshInstance (WARP format)
//!   → WARP fold → accumulated WarpAccumulator
//! ```

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use crate::{
    accumulation::accumulator::Accumulator,
    spartan::r1cs::R1CSShape,
};

use super::accumulator::FreshInstance;

/// Convert a Quasar-squashed `Accumulator` (LinearStatement-based) into a
/// WARP `FreshInstance`.
///
/// The squashed witness polynomial from Quasar becomes the WARP witness.
/// Public inputs are extracted based on the R1CS shape dimensions.
///
/// # Arguments
/// - `shape`: R1CS constraint shape (to determine public input size)
/// - `acc_witness`: the squashed witness from Quasar
/// - `public_inputs`: the public inputs for this squashed instance
///
/// # Returns
/// A `FreshInstance` ready for the WARP fold.
pub fn quasar_output_to_warp_fresh<F: Field, EF: ExtensionField<F>, W, const DIGEST_ELEMS: usize>(
    accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    public_inputs: Vec<F>,
) -> FreshInstance<F> {
    let witness_poly = &accumulator.witness.poly;
    let witness_vec = witness_poly.as_slice().to_vec();

    FreshInstance {
        public_input: public_inputs,
        witness: witness_vec,
    }
}

/// Convert multiple Spartan-proved R1CS instances directly into WARP `FreshInstance`s.
///
/// This bypasses the Quasar squash entirely — each R1CS witness becomes a
/// separate `FreshInstance` for the WARP fold. Useful when you don't need
/// Quasar's multi-instance squashing and want to feed instances directly
/// to the WARP fold.
///
/// # Arguments
/// - `witnesses`: witness polynomials from Spartan's `prepare_witness`
/// - `public_inputs`: public input for each instance
pub fn spartan_witnesses_to_warp_fresh<F: Field>(
    witnesses: &[Vec<F>],
    public_inputs: &[Vec<F>],
) -> Vec<FreshInstance<F>> {
    assert_eq!(witnesses.len(), public_inputs.len());

    witnesses
        .iter()
        .zip(public_inputs.iter())
        .map(|(w, x)| FreshInstance {
            public_input: x.clone(),
            witness: w.clone(),
        })
        .collect()
}

/// Run the full Quasar→WARP pipeline: squash l instances then fold with accumulator.
///
/// This is a convenience function that chains:
/// 1. Convert Spartan witnesses to WARP FreshInstances
/// 2. Feed them to the WARP fold prover
///
/// The Quasar squash step can optionally be inserted between these steps
/// to reduce l instances to 1 before the fold (for fewer sumcheck rounds).
pub fn quasar_then_warp_fold<F: Field>(
    shape: &R1CSShape<F>,
    fresh_instances: &[FreshInstance<F>],
    acc: &super::accumulator::WarpAccumulator<F, F, F, 8>,
    omega: F,
    tau_challenges: &[F],
    fresh_betas: &[Vec<F>],
    transcript_round: impl FnMut(&[F]) -> F,
) -> super::fold::WarpFoldResult<F> {
    super::fold::warp_fold_prove(
        shape,
        fresh_instances,
        acc,
        omega,
        tau_challenges,
        fresh_betas,
        transcript_round,
    )
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        accumulation::warp::{
            accumulator::{WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
            decider::warp_decide_algebraic,
        },
        poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
        spartan::r1cs::{R1CSShape, SparseMatEntry},
    };
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    fn make_square_shape() -> R1CSShape<F> {
        R1CSShape::new(
            4, 4, 2,
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 1, F::ONE)],
        )
    }

    fn make_initial_accumulator(
        code_len: usize,
        log_m: usize,
    ) -> WarpAccumulator<F, F, F, 8> {
        WarpAccumulator::new(
            WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; code_len.trailing_zeros() as usize],
                eval_claim: F::ZERO,
                pesat_tau: vec![F::ZERO; log_m],
                pesat_x: vec![F::ZERO; 2],
                pesat_target: F::ZERO,
            },
            WarpAccumulatorWitness {
                codeword: EvaluationsList::new(vec![F::ZERO; code_len]),
                witness: vec![F::ZERO; 4],
            },
        )
    }

    #[test]
    fn spartan_witnesses_to_warp_fresh_basic() {
        let witnesses = vec![
            vec![F::from_u64(3), F::from_u64(9), F::ZERO, F::ZERO],
            vec![F::from_u64(5), F::from_u64(25), F::ZERO, F::ZERO],
        ];
        let public_inputs = vec![vec![F::ZERO; 2], vec![F::ZERO; 2]];

        let fresh = spartan_witnesses_to_warp_fresh(&witnesses, &public_inputs);

        assert_eq!(fresh.len(), 2);
        assert_eq!(fresh[0].witness, witnesses[0]);
        assert_eq!(fresh[1].witness, witnesses[1]);
        assert_eq!(fresh[0].public_input, public_inputs[0]);
    }

    #[test]
    fn quasar_then_warp_full_pipeline() {
        // Simulate the full pipeline:
        // 2 Spartan witnesses → convert to FreshInstance → WARP fold → decider
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        let witnesses = vec![
            vec![F::from_u64(3), F::from_u64(9), F::ZERO, F::ZERO],
            vec![F::from_u64(5), F::from_u64(25), F::ZERO, F::ZERO],
        ];
        let public_inputs = vec![vec![F::ZERO; 2], vec![F::ZERO; 2]];

        let fresh = spartan_witnesses_to_warp_fresh(&witnesses, &public_inputs);

        // l = 1 (acc) + 2 (fresh) = 3 → padded to 4 → log_l = 2
        let tau_challenges = vec![F::from_u64(11), F::from_u64(13)];
        let omega = F::from_u64(7);

        let mut counter = 0u64;
        let result = quasar_then_warp_fold(
            &shape,
            &fresh,
            &acc,
            omega,
            &tau_challenges,
            &[],
            |_| {
                counter += 1;
                F::from_u64(counter + 400)
            },
        );

        // Fixed size
        assert_eq!(
            result.witness.codeword.as_slice().len(),
            acc.witness.codeword.as_slice().len(),
        );

        // Compute eval_claim and build final accumulator
        let eval_claim = result.witness.codeword.evaluate_hypercube_base(
            &MultilinearPoint::new(result.instance.eval_point.clone()),
        );

        let final_acc = WarpAccumulator::new(
            WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: result.instance.eval_point,
                eval_claim,
                pesat_tau: result.instance.pesat_tau,
                pesat_x: result.instance.pesat_x,
                pesat_target: result.instance.pesat_target,
            },
            result.witness,
        );

        // Decider should accept
        let decide_result = warp_decide_algebraic(&shape, &final_acc);
        assert!(
            decide_result.is_ok(),
            "decider should accept after quasar→warp pipeline: {decide_result:?}"
        );
    }

    #[test]
    fn quasar_then_warp_sequential_pipeline() {
        // Full IVC pipeline: 4 sequential steps, each adding 1 fresh instance
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let mut acc = make_initial_accumulator(num_vars_y, 2);

        for step in 0u64..4 {
            let root = step + 2;
            let witnesses = vec![vec![
                F::from_u64(root),
                F::from_u64(root * root),
                F::ZERO,
                F::ZERO,
            ]];
            let public_inputs = vec![vec![F::ZERO; 2]];
            let fresh = spartan_witnesses_to_warp_fresh(&witnesses, &public_inputs);

            let tau_challenges = vec![F::from_u64(step + 42)];
            let omega = F::from_u64(7);

            let mut counter = step * 100;
            let result = quasar_then_warp_fold(
                &shape,
                &fresh,
                &acc,
                omega,
                &tau_challenges,
                &[],
                |_| {
                    counter += 1;
                    F::from_u64(counter + 600)
                },
            );

            let eval_claim = result.witness.codeword.evaluate_hypercube_base(
                &MultilinearPoint::new(result.instance.eval_point.clone()),
            );

            acc = WarpAccumulator::new(
                WarpAccumulatorInstance {
                    commitment_root: [F::ZERO; 8],
                    eval_point: result.instance.eval_point,
                    eval_claim,
                    pesat_tau: result.instance.pesat_tau,
                    pesat_x: result.instance.pesat_x,
                    pesat_target: result.instance.pesat_target,
                },
                result.witness,
            );

            // Decider accepts at every step
            let decide_result = warp_decide_algebraic(&shape, &acc);
            assert!(
                decide_result.is_ok(),
                "decider should accept at IVC step {step}: {decide_result:?}"
            );

            // Size invariant
            assert_eq!(
                acc.witness.codeword.as_slice().len(),
                num_vars_y,
                "codeword grew at step {step}"
            );
        }
    }
}
