//! WARP terminal decider.
//!
//! The decider is the final step in the IVC pipeline. After all accumulation
//! folds, a single accumulated instance remains. The decider checks that the
//! accumulated witness satisfies the accumulated claims:
//!
//! 1. **Evaluation claim**: f̂(α) = μ
//! 2. **PESAT satisfaction**: P*(β, z) = η (bundled R1CS)
//! 3. **Codeword validity**: f = encode(w)
//!
//! The algebraic decider checks these directly with the witness (prover-side).
//! A succinct decider would generate a WHIR proof — deferred to integration
//! with the WHIR PCS layer.
//!
//! Reference: EPFL WARP `decide` function in lib.rs

use p3_field::Field;

use crate::spartan::r1cs::R1CSShape;

use super::{
    accumulator::WarpAccumulator,
    fold::{build_z_vector, evaluate_bundled_r1cs},
};

/// Errors from the terminal decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarpDeciderError {
    /// f̂(α) ≠ μ — the evaluation claim does not hold.
    EvaluationClaimFailed,
    /// P*(β, z) ≠ η — the bundled R1CS check failed.
    PesatSatisfactionFailed,
    /// f ≠ encode(w) — the codeword is not a valid encoding of the witness.
    CodewordValidityFailed,
}

/// Identity-encoding algebraic decider (test-only).
///
/// Uses identity encoding (codeword = witness) instead of RS encoding.
/// Only useful for unit tests that don't go through the full RS pipeline.
/// For production, use `warp_decide_algebraic_rs` or `warp_decide_full_rs`.
#[cfg(test)]
pub fn warp_decide_algebraic<F: Field>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
) -> Result<(), WarpDeciderError> {
    let computed_mu = super::fold::evaluate_mle_lsb(
        &acc.witness.codeword,
        &acc.instance.eval_point,
    );

    if computed_mu != acc.instance.eval_claim {
        return Err(WarpDeciderError::EvaluationClaimFailed);
    }

    let z = build_z_vector(&acc.instance.pesat_x, &acc.witness.witness);
    let computed_eta = evaluate_bundled_r1cs(shape, &acc.instance.pesat_tau, &z);

    if computed_eta != acc.instance.pesat_target {
        return Err(WarpDeciderError::PesatSatisfactionFailed);
    }

    let witness_len = acc.witness.witness.len();
    let codeword_prefix = &acc.witness.codeword.as_slice()[..witness_len];
    if codeword_prefix != acc.witness.witness.as_slice() {
        return Err(WarpDeciderError::CodewordValidityFailed);
    }

    Ok(())
}

/// Algebraic decider for RS-encoded accumulators.
///
/// Checks eval claim and PESAT satisfaction but NOT codeword validity.
/// With RS encoding, verifying `f = RS_encode(w)` requires re-encoding
/// which needs the DFT engine. This check is instead deferred to the
/// terminal WHIR proof which establishes proximity to the RS code.
///
/// Use this when the accumulator was built with `warp_fold_prove_rs*`.
pub fn warp_decide_algebraic_rs<F: Field>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
) -> Result<(), WarpDeciderError> {
    // Check 1: Evaluation claim f̂(α) = μ
    let computed_mu = super::fold::evaluate_mle_lsb(
        &acc.witness.codeword,
        &acc.instance.eval_point,
    );

    if computed_mu != acc.instance.eval_claim {
        return Err(WarpDeciderError::EvaluationClaimFailed);
    }

    // Check 2: PESAT satisfaction P*(β, z) = η
    let z = build_z_vector(&acc.instance.pesat_x, &acc.witness.witness);
    let computed_eta = evaluate_bundled_r1cs(shape, &acc.instance.pesat_tau, &z);

    if computed_eta != acc.instance.pesat_target {
        return Err(WarpDeciderError::PesatSatisfactionFailed);
    }

    // Check 3: Codeword validity deferred to WHIR proof (RS encoding)
    Ok(())
}

/// Full algebraic decider for RS-encoded accumulators: all 3 WARP conditions.
///
/// Checks:
/// 1. **Eval claim**: f̂(α) = μ
/// 2. **PESAT satisfaction**: P*(β, z) = η
/// 3. **Codeword validity**: f = RS_encode(w) (re-encodes witness and compares)
///
/// This is the complete terminal check per the WARP paper's decider D_ACC.
/// Use this at the end of the IVC chain before generating the succinct WHIR proof.
pub fn warp_decide_full_rs<F, Dft>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Dft,
) -> Result<(), WarpDeciderError>
where
    F: p3_field::TwoAdicField + p3_field::PrimeField64,
    Dft: p3_dft::TwoAdicSubgroupDft<F>,
{
    // Check 1: Evaluation claim f̂(α) = μ
    let computed_mu = super::fold::evaluate_mle_lsb(
        &acc.witness.codeword,
        &acc.instance.eval_point,
    );
    if computed_mu != acc.instance.eval_claim {
        return Err(WarpDeciderError::EvaluationClaimFailed);
    }

    // Check 2: PESAT satisfaction P*(β, z) = η
    let z = build_z_vector(&acc.instance.pesat_x, &acc.witness.witness);
    let computed_eta = evaluate_bundled_r1cs(shape, &acc.instance.pesat_tau, &z);
    if computed_eta != acc.instance.pesat_target {
        return Err(WarpDeciderError::PesatSatisfactionFailed);
    }

    // Check 3: Codeword validity f = RS_encode(w)
    // Witness must be padded to power-of-2 for RS encoding (same as fold pipeline).
    let wit_len = acc.witness.witness.len().next_power_of_two();
    let mut wit_padded = acc.witness.witness.clone();
    wit_padded.resize(wit_len, F::ZERO);
    let witness_poly = crate::poly::evals::EvaluationsList::new(wit_padded);
    let expected_codeword = super::encoding::rs_encode(&witness_poly, folding_factor, log_inv_rate, dft);
    if expected_codeword.as_slice() != acc.witness.codeword.as_slice() {
        return Err(WarpDeciderError::CodewordValidityFailed);
    }

    Ok(())
}

/// Terminal WHIR proof errors.
#[derive(Debug, Clone)]
pub enum TerminalWhirError {
    /// The algebraic decider failed before WHIR.
    Decider(WarpDeciderError),
    /// WHIR commitment root does not match the accumulated root.
    RootBindingMismatch,
    /// WHIR prove failed.
    ProveFailed,
    /// WHIR verify failed.
    VerifyFailed,
}

/// Terminal WHIR proof: full prover-side decider + WHIR prove + root binding + WHIR verify.
///
/// This is the complete succinct terminal verification per the WARP paper:
///
/// 1. **Full RS decider**: f̂(α) = μ, P*(β, z) = η, f = RS_encode(w)
/// 2. **WHIR prove**: commit + prove RS proximity on the accumulated witness
/// 3. **Root binding**: WHIR root == accumulated commitment root
/// 4. **WHIR verify**: succinct verification (no witness access)
///
/// After this function returns `Ok(proof)`, anyone holding just the proof and
/// the accumulated instance can verify succinctly via step 4 alone.
pub fn terminal_whir_prove_and_verify<F, EF, Dft, H, C, Challenger>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Dft,
    whir_config: &crate::whir::parameters::WhirConfig<EF, F, H, C, Challenger>,
    mut make_whir_challenger: impl FnMut() -> Challenger,
) -> Result<crate::whir::proof::WhirProof<F, EF, F, 8>, TerminalWhirError>
where
    F: p3_field::TwoAdicField + p3_field::PrimeField64,
    EF: p3_field::ExtensionField<F> + p3_field::TwoAdicField,
    Dft: p3_dft::TwoAdicSubgroupDft<F>,
    H: p3_symmetric::CryptographicHasher<F, [F; 8]>
        + p3_symmetric::CryptographicHasher<<F as p3_field::Field>::Packing, [<F as p3_field::Field>::Packing; 8]>
        + Sync
        + Clone,
    C: p3_symmetric::PseudoCompressionFunction<[F; 8], 2>
        + p3_symmetric::PseudoCompressionFunction<[<F as p3_field::Field>::Packing; 8], 2>
        + Sync
        + Clone,
    <F as p3_field::Field>::Packing: Eq + Send + Sync,
    Challenger: p3_challenger::FieldChallenger<F>
        + p3_challenger::GrindingChallenger<Witness = F>
        + p3_challenger::CanObserve<p3_symmetric::Hash<F, F, 8>>,
{
    use crate::{
        poly::evals::EvaluationsList,
        whir::{
            committer::writer::CommitmentWriter,
            committer::reader::CommitmentReader,
            constraints::statement::{EqStatement, InitialClaim, LinearStatement},
            proof::WhirProof,
            prover::Prover as WhirProver,
            verifier::Verifier as WhirVerifier,
        },
    };

    // Step 1: Full prover-side decider (all 3 WARP conditions)
    warp_decide_full_rs(shape, acc, folding_factor, log_inv_rate, dft)
        .map_err(TerminalWhirError::Decider)?;

    // Step 2: Build witness polynomial and WHIR prove
    let witness_raw = &acc.witness.witness;
    let witness_len = witness_raw.len().next_power_of_two();
    let mut witness_padded = witness_raw.clone();
    witness_padded.resize(witness_len, F::ZERO);
    let witness_poly = EvaluationsList::new(witness_padded);
    let witness_num_vars = witness_poly.num_variables();

    let linear_claim = LinearStatement::<F, EF>::initialize(witness_num_vars);
    let mut statement = whir_config.initial_statement_with_linear(
        witness_poly, linear_claim,
    );
    let mut whir_proof = WhirProof::<F, EF, F, 8>::from_whir_config(whir_config);
    let mut prove_challenger = make_whir_challenger();

    let commitment = CommitmentWriter::new(whir_config)
        .commit::<_, <F as p3_field::Field>::Packing, F, <F as p3_field::Field>::Packing, 8>(
            dft, &mut whir_proof, &mut prove_challenger, &mut statement,
        )
        .map_err(|_| TerminalWhirError::ProveFailed)?;

    WhirProver(whir_config)
        .prove::<_, <F as p3_field::Field>::Packing, F, <F as p3_field::Field>::Packing, 8>(
            dft, &mut whir_proof, &mut prove_challenger, &statement, commitment,
        )
        .map_err(|_| TerminalWhirError::ProveFailed)?;

    // Step 3: Root binding — WHIR root must match accumulated root
    if whir_proof.initial_commitment != acc.instance.commitment_root {
        return Err(TerminalWhirError::RootBindingMismatch);
    }

    // Step 4: WHIR verify (succinct — no witness needed)
    let initial_claim = InitialClaim {
        eq_statement: EqStatement::initialize(witness_num_vars),
        linear_statement: LinearStatement::<F, EF>::initialize(witness_num_vars),
    };
    let mut verify_challenger = make_whir_challenger();
    let parsed = CommitmentReader::new(whir_config)
        .parse_commitment::<F, 8>(&whir_proof, &mut verify_challenger);
    WhirVerifier::new(whir_config)
        .verify_with_initial_claim::<<F as p3_field::Field>::Packing, F, <F as p3_field::Field>::Packing, 8>(
            &whir_proof, &mut verify_challenger, &parsed, initial_claim,
        )
        .map_err(|_| TerminalWhirError::VerifyFailed)?;

    Ok(whir_proof)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::poly::evals::EvaluationsList;
    use crate::accumulation::warp::{
        accumulator::{FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
        fold::warp_fold_prove,
    };
    use crate::spartan::r1cs::{R1CSShape, SparseMatEntry};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    fn make_square_shape() -> R1CSShape<F> {
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 2;
        R1CSShape::new(
            num_cons,
            num_vars,
            num_inputs,
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 1, F::ONE)],
        )
    }

    fn make_square_witness(root: u64) -> FreshInstance<F> {
        let square = root * root;
        FreshInstance {
            public_input: vec![F::ZERO; 2],
            witness: vec![
                F::from_u64(root),
                F::from_u64(square),
                F::ZERO,
                F::ZERO,
            ],
        }
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

    fn run_fold_and_build_acc(
        shape: &R1CSShape<F>,
        acc: &WarpAccumulator<F, F, F, 8>,
        fresh: &FreshInstance<F>,
        step: u64,
    ) -> WarpAccumulator<F, F, F, 8> {
        let tau_challenges = vec![F::from_u64(step + 42)];
        let omega = F::from_u64(7);

        let mut round_counter = step * 100;
        let result = warp_fold_prove(
            shape,
            &[fresh.clone()],
            acc,
            omega,
            &tau_challenges,
            &[],
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 500)
            },
        );

        // Compute eval_claim = f̂(α) using LSB-first convention from fold
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &result.witness.codeword,
            &result.instance.eval_point,
        );

        WarpAccumulator::new(
            WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: result.instance.eval_point,
                eval_claim,
                pesat_tau: result.instance.pesat_tau,
                pesat_x: result.instance.pesat_x,
                pesat_target: result.instance.pesat_target,
            },
            result.witness,
        )
    }

    #[test]
    fn decider_accepts_initial_accumulator() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        // Initial (zeroed) accumulator should pass the decider:
        // - f̂(0) = 0 = μ (zero polynomial at zero point)
        // - P*(0, 0) = 0 = η (trivially satisfied)
        // - codeword = witness (identity encoding of zeros)
        let result = warp_decide_algebraic(&shape, &acc);
        assert!(result.is_ok(), "decider should accept initial accumulator: {result:?}");
    }

    #[test]
    fn decider_accepts_after_single_fold() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);
        let fresh = make_square_witness(3);

        let folded = run_fold_and_build_acc(&shape, &acc, &fresh, 0);

        let result = warp_decide_algebraic(&shape, &folded);
        assert!(result.is_ok(), "decider should accept after 1 fold: {result:?}");
    }

    #[test]
    fn decider_accepts_after_multiple_folds() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let mut acc = make_initial_accumulator(num_vars_y, 2);

        // Run 4 sequential folds
        for step in 0..4 {
            let fresh = make_square_witness(step + 2);
            acc = run_fold_and_build_acc(&shape, &acc, &fresh, step);

            let result = warp_decide_algebraic(&shape, &acc);
            assert!(
                result.is_ok(),
                "decider should accept after fold step {step}: {result:?}"
            );
        }
    }

    #[test]
    fn decider_rejects_tampered_eval_claim() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);
        let fresh = make_square_witness(3);

        let mut folded = run_fold_and_build_acc(&shape, &acc, &fresh, 0);

        // Tamper with the evaluation claim
        folded.instance.eval_claim += F::ONE;

        let result = warp_decide_algebraic(&shape, &folded);
        assert_eq!(
            result,
            Err(WarpDeciderError::EvaluationClaimFailed),
            "decider should reject tampered eval_claim"
        );
    }

    #[test]
    fn decider_rejects_tampered_pesat_target() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);
        let fresh = make_square_witness(3);

        let mut folded = run_fold_and_build_acc(&shape, &acc, &fresh, 0);

        // Tamper with the PESAT target
        folded.instance.pesat_target += F::ONE;

        let result = warp_decide_algebraic(&shape, &folded);
        assert_eq!(
            result,
            Err(WarpDeciderError::PesatSatisfactionFailed),
            "decider should reject tampered pesat_target"
        );
    }

    #[test]
    fn decider_rejects_tampered_witness() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);
        let fresh = make_square_witness(3);

        let mut folded = run_fold_and_build_acc(&shape, &acc, &fresh, 0);

        // Tamper with the witness (but not the claims)
        folded.witness.witness[0] += F::ONE;

        // This should fail because now f̂(α) ≠ μ or P*(β,z) ≠ η
        let result = warp_decide_algebraic(&shape, &folded);
        assert!(
            result.is_err(),
            "decider should reject tampered witness"
        );
    }

    #[test]
    fn decider_fixed_size_across_ivc_steps() {
        // The most important property: the decider works on fixed-size
        // accumulators regardless of how many IVC steps preceded it.
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let initial_code_len = num_vars_y;
        let initial_witness_len = 4;

        let mut acc = make_initial_accumulator(num_vars_y, 2);

        for step in 0..5 {
            let fresh = make_square_witness(step + 2);
            acc = run_fold_and_build_acc(&shape, &acc, &fresh, step);

            // Size invariants
            assert_eq!(
                acc.witness.codeword.as_slice().len(),
                initial_code_len,
                "codeword grew at step {step}"
            );
            assert_eq!(
                acc.witness.witness.len(),
                initial_witness_len,
                "witness grew at step {step}"
            );

            // Decider accepts
            let result = warp_decide_algebraic(&shape, &acc);
            assert!(
                result.is_ok(),
                "decider should accept at step {step}: {result:?}"
            );
        }
    }
}
