//! Reed-Solomon encoding for WARP accumulation.
//!
//! This module provides standalone RS encoding using WHIR's DFT infrastructure.
//! The encoding expands a witness polynomial from 2^k evaluations to
//! 2^(k + log_inv_rate) evaluations on a smooth multiplicative coset,
//! creating the error-correcting redundancy that makes proximity testing meaningful.
//!
//! The encoding follows exactly the same process as CommitmentWriter::commit
//! (transpose → pad → DFT) but without the Merkle tree or OOD sampling,
//! so it can be used during the fold step where we only need the codeword.

use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::Matrix;

use crate::poly::evals::EvaluationsList;

/// RS-encode a witness polynomial using WHIR's DFT expansion.
///
/// Given a witness polynomial of size 2^num_variables, produces a codeword
/// of size 2^(num_variables + log_inv_rate) by:
/// 1. Reshaping the evaluations into a matrix (transpose for variable ordering)
/// 2. Zero-padding to the expanded domain size (creates the rate blowup)
/// 3. DFT-expanding each row onto the smooth multiplicative subgroup
///
/// The result is a flat vector of field elements representing the RS codeword
/// in the same format that CommitmentWriter::commit would produce before
/// Merkle tree construction.
///
/// # Arguments
/// - `witness`: the witness polynomial as evaluations on {0,1}^num_variables
/// - `folding_factor`: WHIR's initial folding factor (determines matrix width)
/// - `log_inv_rate`: log₂ of the inverse rate (1 → rate 1/2, 2 → rate 1/4, etc.)
/// - `dft`: the DFT engine (Radix2DFTSmallBatch)
///
/// # Returns
/// An EvaluationsList containing the RS codeword of size 2^(num_variables + log_inv_rate).
pub fn rs_encode<F, Dft>(
    witness: &EvaluationsList<F>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Dft,
) -> EvaluationsList<F>
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    let num_variables = witness.num_variables();
    assert!(
        folding_factor <= num_variables,
        "folding_factor ({folding_factor}) must be <= num_variables ({num_variables})"
    );

    // Step 1: Reshape into matrix and transpose
    // Width before transpose: 2^(num_variables - folding_factor)
    // After transpose: width = 2^folding_factor, height = 2^(num_variables - folding_factor)
    let width_before = 1usize << (num_variables - folding_factor);
    let mat = p3_matrix::dense::RowMajorMatrixView::new(witness.as_slice(), width_before)
        .transpose();

    // Step 2: Pad height for rate blowup
    // Padded height: 2^(num_variables + log_inv_rate - folding_factor)
    let padded_height = 1usize << (num_variables + log_inv_rate - folding_factor);
    let mut padded = mat;
    padded.pad_to_height(padded_height, F::ZERO);

    // Step 3: DFT expansion (this is the actual RS encoding)
    let expanded = dft.dft_batch(padded).to_row_major_matrix();

    // Flatten the matrix back to a single vector
    // Total size: height * width = 2^(num_variables + log_inv_rate)
    let total_size = expanded.height() * expanded.width();
    debug_assert_eq!(total_size, 1 << (num_variables + log_inv_rate));

    EvaluationsList::new(expanded.values)
}

/// Verify that a codeword is a valid RS encoding of a witness.
///
/// Re-encodes the witness and checks equality with the claimed codeword.
/// This is the "codeword validity" check in the WARP decider.
pub fn verify_rs_encoding<F, Dft>(
    witness: &EvaluationsList<F>,
    codeword: &EvaluationsList<F>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Dft,
) -> bool
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    let expected = rs_encode(witness, folding_factor, log_inv_rate, dft);
    expected.as_slice() == codeword.as_slice()
}

/// Compute the codeword size from witness parameters.
#[inline]
pub const fn codeword_size(num_variables: usize, log_inv_rate: usize) -> usize {
    1 << (num_variables + log_inv_rate)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    #[test]
    fn rs_encode_produces_correct_size() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 6;
        let log_inv_rate = 1; // rate 1/2
        let folding_factor = 2;

        let witness = EvaluationsList::new(vec![F::ONE; 1 << num_vars]);
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        // Codeword should be 2x larger (rate 1/2)
        assert_eq!(
            codeword.as_slice().len(),
            1 << (num_vars + log_inv_rate),
            "codeword should be 2^(num_vars + log_inv_rate)"
        );
    }

    #[test]
    fn rs_encode_rate_quarter() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 6;
        let log_inv_rate = 2; // rate 1/4
        let folding_factor = 2;

        let witness = EvaluationsList::new(vec![F::from_u64(42); 1 << num_vars]);
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        assert_eq!(
            codeword.as_slice().len(),
            1 << (num_vars + log_inv_rate),
            "codeword should be 4x witness size at rate 1/4"
        );
    }

    #[test]
    fn rs_encode_is_deterministic() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let witness = EvaluationsList::new(
            (0..1u64 << num_vars).map(|i| F::from_u64(i + 1)).collect(),
        );

        let cw1 = rs_encode(&witness, folding_factor, log_inv_rate, &dft);
        let cw2 = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        assert_eq!(cw1.as_slice(), cw2.as_slice(), "encoding should be deterministic");
    }

    #[test]
    fn rs_encode_different_witnesses_differ() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let w1 = EvaluationsList::new(vec![F::ONE; 1 << num_vars]);
        let w2 = EvaluationsList::new(vec![F::from_u64(2); 1 << num_vars]);

        let cw1 = rs_encode(&w1, folding_factor, log_inv_rate, &dft);
        let cw2 = rs_encode(&w2, folding_factor, log_inv_rate, &dft);

        assert_ne!(cw1.as_slice(), cw2.as_slice(), "different witnesses should produce different codewords");
    }

    #[test]
    fn verify_rs_encoding_accepts_valid() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let witness = EvaluationsList::new(
            (0..1u64 << num_vars).map(|i| F::from_u64(i + 1)).collect(),
        );
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        assert!(verify_rs_encoding(&witness, &codeword, folding_factor, log_inv_rate, &dft));
    }

    #[test]
    fn verify_rs_encoding_rejects_tampered() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let witness = EvaluationsList::new(
            (0..1u64 << num_vars).map(|i| F::from_u64(i + 1)).collect(),
        );
        let mut codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        // Tamper with one position
        let vals = codeword.as_mut_slice();
        vals[0] += F::ONE;

        assert!(
            !verify_rs_encoding(&witness, &codeword, folding_factor, log_inv_rate, &dft),
            "should reject tampered codeword"
        );
    }

    #[test]
    fn rs_fold_integration_fixed_size() {
        // Full integration: RS-encode → WARP fold → verify codeword stays fixed size
        use crate::accumulation::warp::{
            accumulator::{FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
            fold::{warp_fold_prove_rs, RSEncodingConfig},
        };
        use crate::spartan::r1cs::{R1CSShape, SparseMatEntry};
        use crate::poly::multilinear::MultilinearPoint;

        let dft = Radix2DFTSmallBatch::<F>::default();
        let folding_factor = 2;
        let log_inv_rate = 1; // rate 1/2

        // Simple squaring R1CS: 4 constraints, 8 vars, 2 inputs
        let shape = R1CSShape::new(
            4, 8, 2,
            vec![SparseMatEntry::new(0, 2, F::ONE)],
            vec![SparseMatEntry::new(0, 2, F::ONE)],
            vec![SparseMatEntry::new(0, 3, F::ONE)],
        );
        let num_vars_y = 1usize << shape.num_poly_vars_y(); // 16
        let log_m = 4usize.next_power_of_two().trailing_zeros() as usize; // 2
        let num_witness = num_vars_y - 2;
        let witness_num_vars = num_witness.next_power_of_two().trailing_zeros() as usize;
        let code_len = codeword_size(witness_num_vars, log_inv_rate);
        let log_n = code_len.trailing_zeros() as usize;

        // Build initial accumulator with RS-sized codeword
        let initial_witness = EvaluationsList::new(vec![F::ZERO; 1 << witness_num_vars]);
        let initial_codeword = rs_encode(&initial_witness, folding_factor, log_inv_rate, &dft);

        let mut acc = WarpAccumulator::new(
            WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; log_n],
                eval_claim: F::ZERO,
                pesat_tau: vec![F::ZERO; log_m],
                pesat_x: vec![F::ZERO; 2],
                pesat_target: F::ZERO,
            },
            WarpAccumulatorWitness {
                codeword: initial_codeword,
                witness: vec![F::ZERO; num_witness],
            },
        );

        let initial_cw_len = acc.witness.codeword.as_slice().len();
        let rs_config = RSEncodingConfig::new(folding_factor, log_inv_rate);

        // Run 3 sequential folds with RS encoding
        for step in 0u64..3 {
            let root = step + 2;
            let mut w = vec![F::ZERO; 1 << witness_num_vars];
            w[0] = F::from_u64(root);
            w[1] = F::from_u64(root * root);

            let fresh = FreshInstance {
                public_input: vec![F::ZERO; 2],
                witness: w,
            };

            let tau = vec![F::from_u64(step + 42)];
            let mut ctr = step * 100;
            let result = warp_fold_prove_rs(
                &shape, &[fresh], &acc, F::from_u64(7), &tau, &rs_config, &dft,
                |_| { ctr += 1; F::from_u64(ctr + 500) },
            );

            // CRITICAL: codeword size stays fixed
            assert_eq!(
                result.witness.codeword.as_slice().len(),
                initial_cw_len,
                "RS codeword grew at step {step}! {} vs {}",
                result.witness.codeword.as_slice().len(), initial_cw_len,
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
        }
    }
}
