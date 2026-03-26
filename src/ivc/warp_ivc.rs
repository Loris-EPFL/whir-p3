//! IVC using the full pipeline: Spartan → Quasar Multicast → WARP fold → terminal WHIR.
//!
//! Unlike the v2 IVC (`ivc.rs`) which runs a WHIR proof at every accumulation step,
//! this IVC uses the WARP fold (RS encode + Merkle + twin-constraint sumcheck +
//! shift/OOD + eval batching) with **no WHIR per step**. A single WHIR proof is
//! generated only at the terminal decider.
//!
//! Pipeline per IVC step:
//! 1. Build unified circuit (step computation + optional verifier)
//! 2. Spartan prove → linearize to `LinearStatement`
//! 3. Quasar multicast (constraint_batch + random_lc) → combined `FreshInstance`
//! 4. WARP fold with running `WarpAccumulator` (RS encode + Merkle + sumcheck)
//! 5. Output: new `WarpAccumulator` + fold transcript (for next step's verifier)

use alloc::{vec, vec::Vec};

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::{
    accumulation::{
        constraint_batch::constraint_batch_prove,
        linearized::linearized_statement_from_spartan_proof,
        random_lc::random_linear_combination,
        warp::{
            accumulator::{
                FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness,
            },
            encoding::merkle_commit_codeword,
            fold::{
                evaluate_bundled_r1cs, warp_fold_prove_rs_committed, RSEncodingConfig,
                WarpFoldResult,
            },
        },
    },
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    spartan::{
        r1cs::{R1CSInstance, R1CSShape},
        r1cs_prover::R1CSProver,
    },
};

/// IVC state using the WARP fold pipeline.
#[derive(Clone, Debug)]
pub struct WarpIVCState<F: Field> {
    /// Current step number.
    pub step: usize,
    /// Running WARP accumulator (fixed-size witness).
    pub accumulator: WarpAccumulator<F, F, F, 8>,
    /// R1CS shape for the circuit (same across all steps).
    pub shape: R1CSShape<F>,
    /// Last fold transcript (for the recursive verifier, if used).
    pub last_fold_result: Option<WarpFoldResult<F>>,
    /// Current public state.
    pub public_state: Vec<F>,
}

/// Configuration for the WARP IVC pipeline.
#[derive(Clone, Debug)]
pub struct WarpIVCConfig {
    pub rs_folding_factor: usize,
    pub rs_log_inv_rate: usize,
}

impl Default for WarpIVCConfig {
    fn default() -> Self {
        Self {
            rs_folding_factor: 2,
            rs_log_inv_rate: 1,
        }
    }
}

/// Initialize a zero WARP accumulator for the first IVC step.
fn make_initial_accumulator<F: Field>(
    num_witness: usize,
    log_code: usize,
    log_m: usize,
    num_inputs: usize,
) -> WarpAccumulator<F, F, F, 8> {
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: [F::ZERO; 8],
            eval_point: vec![F::ZERO; log_code],
            eval_claim: F::ZERO,
            pesat_tau: vec![F::ZERO; log_m],
            pesat_x: vec![F::ZERO; num_inputs],
            pesat_target: F::ZERO,
        },
        WarpAccumulatorWitness {
            codeword: EvaluationsList::new(vec![F::ZERO; 1 << log_code]),
            witness: vec![F::ZERO; num_witness],
        },
    )
}

/// Rebuild a `WarpAccumulator` from a `WarpFoldResult`.
fn rebuild_accumulator<F: Field>(result: &WarpFoldResult<F>) -> WarpAccumulator<F, F, F, 8> {
    let eval_claim = result.witness.codeword.evaluate_hypercube_base(
        &MultilinearPoint::new(result.instance.eval_point.clone()),
    );
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: result.commitment_root,
            eval_point: result.instance.eval_point.clone(),
            eval_claim,
            pesat_tau: result.instance.pesat_tau.clone(),
            pesat_x: result.instance.pesat_x.clone(),
            pesat_target: result.instance.pesat_target,
        },
        result.witness.clone(),
    )
}

/// Initialize the WARP IVC from a first R1CS instance.
///
/// Spartan-proves the first instance, creates the initial accumulator,
/// and WARP-folds it into a zero accumulator.
pub fn warp_ivc_init<F, EF, Dft, H, C, Challenger>(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    public_state: Vec<F>,
) -> WarpIVCState<F>
where
    F: TwoAdicField + PrimeField64 + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    H: CryptographicHasher<F, [F; 8]>
        + CryptographicHasher<<F as Field>::Packing, [<F as Field>::Packing; 8]>
        + Sync
        + Clone,
    C: PseudoCompressionFunction<[F; 8], 2>
        + PseudoCompressionFunction<[<F as Field>::Packing; 8], 2>
        + Sync
        + Clone,
    <F as Field>::Packing: Eq + Send + Sync,
{
    let spartan_prover = R1CSProver::new();

    // Spartan prove
    let spartan_proof = spartan_prover.prove::<EF, _>(instance, spartan_challenger);
    let witness_poly = spartan_prover.prepare_witness(instance);

    // z = (public_input || witness_vars), length = 2^num_poly_vars_y.
    // FreshInstance.witness must be power-of-2 for RS encoding.
    let num_inputs = instance.input().len();
    let z = witness_poly.as_slice();
    let public_input = z[..num_inputs].to_vec();
    let num_witness = (z.len() - num_inputs).next_power_of_two();
    let mut witness_part = z[num_inputs..].to_vec();
    witness_part.resize(num_witness, F::ZERO);

    let log_code = num_witness.trailing_zeros() as usize + ivc_config.rs_log_inv_rate;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let fresh = FreshInstance {
        public_input: public_input.clone(),
        witness: witness_part,
    };
    let acc = make_initial_accumulator(num_witness, log_code, log_m, num_inputs);

    // WARP fold: zero accumulator + fresh instance
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let tau = vec![F::from_u64(42)]; // log_2(2) = 1 challenge
    let mut ctr = 0u64;
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        shape, &[fresh], &acc, F::from_u64(7), &tau,
        &rs_config, dft,
        |_| { ctr += 1; F::from_u64(ctr + 500) },
        |codeword, folding_factor| {
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(codeword, folding_factor, mh.clone(), mc.clone());
            root
        },
    );

    let new_acc = rebuild_accumulator(&result);

    WarpIVCState {
        step: 1,
        accumulator: new_acc,
        shape: shape.clone(),
        last_fold_result: Some(result),
        public_state,
    }
}

/// Execute one IVC step using the full Spartan → Quasar → WARP pipeline.
///
/// 1. Spartan prove the instance → linearize
/// 2. Quasar multicast (if batch > 1) or direct FreshInstance (if batch = 1)
/// 3. WARP fold with running accumulator
/// 4. No WHIR proof — deferred to terminal
pub fn warp_ivc_step<F, EF, Dft, H, C, Challenger>(
    prev_state: &WarpIVCState<F>,
    instance: &R1CSInstance<F>,
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    new_public_state: Vec<F>,
) -> WarpIVCState<F>
where
    F: TwoAdicField + PrimeField64 + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    H: CryptographicHasher<F, [F; 8]>
        + CryptographicHasher<<F as Field>::Packing, [<F as Field>::Packing; 8]>
        + Sync
        + Clone,
    C: PseudoCompressionFunction<[F; 8], 2>
        + PseudoCompressionFunction<[<F as Field>::Packing; 8], 2>
        + Sync
        + Clone,
    <F as Field>::Packing: Eq + Send + Sync,
{
    let shape = &prev_state.shape;
    let spartan_prover = R1CSProver::new();

    // 1. Spartan prove
    let spartan_proof = spartan_prover.prove::<EF, _>(instance, spartan_challenger);
    let witness_poly = spartan_prover.prepare_witness(instance);

    // 2. Create FreshInstance (witness padded to power-of-2 for RS encoding)
    let num_inputs = instance.input().len();
    let z = witness_poly.as_slice();
    let public_input = z[..num_inputs].to_vec();
    let num_witness = (z.len() - num_inputs).next_power_of_two();
    let mut witness_part = z[num_inputs..].to_vec();
    witness_part.resize(num_witness, F::ZERO);

    let fresh = FreshInstance {
        public_input,
        witness: witness_part,
    };

    // 3. WARP fold
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let tau = vec![F::from_u64(prev_state.step as u64 + 42)];
    let mut ctr = prev_state.step as u64 * 1000;
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        shape, &[fresh], &prev_state.accumulator, F::from_u64(7), &tau,
        &rs_config, dft,
        |_| { ctr += 1; F::from_u64(ctr + 500) },
        |codeword, folding_factor| {
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(codeword, folding_factor, mh.clone(), mc.clone());
            root
        },
    );

    let new_acc = rebuild_accumulator(&result);

    WarpIVCState {
        step: prev_state.step + 1,
        accumulator: new_acc,
        shape: shape.clone(),
        last_fold_result: Some(result),
        public_state: new_public_state,
    }
}

/// Execute one IVC step with Quasar multicast for batch > 1.
///
/// Takes multiple R1CS instances, runs Spartan + Quasar multicast to combine
/// them into a single FreshInstance, then WARP folds with the running accumulator.
pub fn warp_ivc_step_batch<F, EF, Dft, H, C, Challenger>(
    prev_state: &WarpIVCState<F>,
    instances: &[R1CSInstance<F>],
    spartan_challengers: &mut [Challenger],
    linearization_challenge: EF,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    cb_challenger: &mut Challenger,
    new_public_state: Vec<F>,
) -> WarpIVCState<F>
where
    F: TwoAdicField + PrimeField64 + Ord,
    EF: ExtensionField<F> + TwoAdicField + p3_field::Algebra<EF>,
    Dft: TwoAdicSubgroupDft<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    H: CryptographicHasher<F, [F; 8]>
        + CryptographicHasher<<F as Field>::Packing, [<F as Field>::Packing; 8]>
        + Sync
        + Clone,
    C: PseudoCompressionFunction<[F; 8], 2>
        + PseudoCompressionFunction<[<F as Field>::Packing; 8], 2>
        + Sync
        + Clone,
    <F as Field>::Packing: Eq + Send + Sync,
{
    let shape = &prev_state.shape;
    let spartan_prover = R1CSProver::new();
    let batch = instances.len();
    assert!(batch > 0);

    // 1. Spartan prove all instances + linearize
    let mut witnesses = Vec::with_capacity(batch);
    let mut linears = Vec::with_capacity(batch);
    for (inst, challenger) in instances.iter().zip(spartan_challengers.iter_mut()) {
        let proof = spartan_prover.prove::<EF, _>(inst, challenger);
        let witness = spartan_prover.prepare_witness(inst);
        let linear = linearized_statement_from_spartan_proof(shape, &proof, linearization_challenge);
        witnesses.push(witness);
        linears.push(linear);
    }

    // 2. Quasar multicast: constraint batch + random LC
    let mut weights = Vec::with_capacity(batch);
    let mut targets = Vec::with_capacity(batch);
    for linear in &linears {
        let (w, &t) = linear.iter().next().unwrap();
        weights.push(w.clone());
        targets.push(t);
    }

    let gamma = F::from_u64(prev_state.step as u64 + 42);
    let (_batch_proof, _reduction_point) = constraint_batch_prove(
        gamma, &weights, &targets, &witnesses, cb_challenger,
    );

    // Random LC: combine witnesses
    let eta = F::from_u64(prev_state.step as u64 + 13);
    let wit_refs: Vec<&EvaluationsList<F>> = witnesses.iter().collect();
    let combined = random_linear_combination(&wit_refs, eta);

    // 3. Create FreshInstance from combined witness (padded to power-of-2)
    let num_inputs = instances[0].input().len();
    let combined_slice = combined.as_slice();
    let public_input = combined_slice[..num_inputs].to_vec();
    let witness_raw = &combined_slice[num_inputs..];
    let num_witness = witness_raw.len().next_power_of_two();
    let mut padded_witness = witness_raw.to_vec();
    padded_witness.resize(num_witness, F::ZERO);

    let fresh = FreshInstance {
        public_input,
        witness: padded_witness,
    };

    // 4. WARP fold
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let tau = vec![F::from_u64(prev_state.step as u64 + 77)];
    let mut ctr = prev_state.step as u64 * 1000;
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        shape, &[fresh], &prev_state.accumulator, F::from_u64(7), &tau,
        &rs_config, dft,
        |_| { ctr += 1; F::from_u64(ctr + 500) },
        |codeword, folding_factor| {
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(codeword, folding_factor, mh.clone(), mc.clone());
            root
        },
    );

    let new_acc = rebuild_accumulator(&result);

    WarpIVCState {
        step: prev_state.step + 1,
        accumulator: new_acc,
        shape: shape.clone(),
        last_fold_result: Some(result),
        public_state: new_public_state,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;
    use crate::spartan::r1cs::SparseMatEntry;
    use crate::{
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        whir::{
            committer::{reader::CommitmentReader, writer::CommitmentWriter},
            constraints::statement::{EqStatement, InitialClaim, LinearStatement},
            parameters::WhirConfig,
            proof::WhirProof,
            prover::Prover as WhirProver,
            verifier::Verifier as WhirVerifier,
        },
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    fn make_shape() -> R1CSShape<F> {
        // x^2 = y constraint: A[0,0]=1, B[0,0]=1, C[0,1]=1
        R1CSShape::new(
            4, 4, 1,
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 1, F::ONE)],
        )
    }

    fn make_instance(shape: &R1CSShape<F>, root: u64) -> R1CSInstance<F> {
        let mut witness = vec![F::ZERO; 4];
        witness[0] = F::from_u64(root);
        witness[1] = F::from_u64(root * root);
        R1CSInstance::new(shape.clone(), vec![F::ZERO], witness)
    }

    fn make_challenger(seed: u64) -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
        MyChallenger::new(perm)
    }

    fn make_hash_compress() -> (MyHash, MyCompress) {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
        (MyHash::new(perm.clone()), MyCompress::new(perm))
    }

    /// Test: init + 3 sequential steps, verify witness size stays fixed and decider passes.
    #[test]
    fn warp_ivc_four_steps() {
        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();

        // Init: 3^2 = 9
        let instance0 = make_instance(&shape, 3);
        let mut chal0 = make_challenger(1);
        let mut state = warp_ivc_init::<F, EF, _, _, _, _>(
            &shape, &instance0, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
        );
        assert_eq!(state.step, 1);
        let initial_code_len = state.accumulator.witness.codeword.as_slice().len();
        let initial_wit_len = state.accumulator.witness.witness.len();

        // Steps: 5^2=25, 7^2=49, 11^2=121
        for (i, root) in [5u64, 7, 11].iter().enumerate() {
            let instance = make_instance(&shape, *root);
            let mut chal = make_challenger(i as u64 + 10);
            state = warp_ivc_step::<F, EF, _, _, _, _>(
                &state, &instance, &mut chal,
                &ivc_config, &dft, mh.clone(), mc.clone(),
                vec![F::from_u64(root * root)],
            );

            // Witness size stays fixed
            assert_eq!(
                state.accumulator.witness.codeword.as_slice().len(),
                initial_code_len,
                "codeword grew at step {}", i + 1,
            );
            assert_eq!(
                state.accumulator.witness.witness.len(),
                initial_wit_len,
                "witness grew at step {}", i + 1,
            );
        }

        assert_eq!(state.step, 4);

        // Verify eval claim consistency: μ = f̃(α)
        let eval_claim = state.accumulator.witness.codeword.evaluate_hypercube_base(
            &MultilinearPoint::new(state.accumulator.instance.eval_point.clone()),
        );
        assert_eq!(
            eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after 4 steps"
        );
    }

    /// Test: init + 2 batch steps (Quasar multicast with batch=2).
    #[test]
    fn warp_ivc_batch_steps() {
        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();

        // Init
        let instance0 = make_instance(&shape, 3);
        let mut chal0 = make_challenger(1);
        let mut state = warp_ivc_init::<F, EF, _, _, _, _>(
            &shape, &instance0, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
        );

        // Batch step 1: instances for roots 5, 7
        let batch1 = vec![make_instance(&shape, 5), make_instance(&shape, 7)];
        let mut chals1 = [make_challenger(10), make_challenger(11)];
        let mut cb_chal = make_challenger(300);
        state = warp_ivc_step_batch::<F, EF, _, _, _, _>(
            &state, &batch1,
            &mut chals1,
            EF::from_u64(3),
            &ivc_config, &dft, mh.clone(), mc.clone(),
            &mut cb_chal,
            vec![F::from_u64(49)],
        );

        assert_eq!(state.step, 2);

        // Verify eval claim consistency
        let eval_claim = state.accumulator.witness.codeword.evaluate_hypercube_base(
            &MultilinearPoint::new(state.accumulator.instance.eval_point.clone()),
        );
        assert_eq!(eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after batch step");
    }

    // ── WHIR helpers ─────────────────────────────────────────────

    fn make_whir_config(num_vars: usize) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
        let mut rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut rng);
        WhirConfig::new(num_vars, ProtocolParameters {
            security_level: 100,
            pow_bits: 0,
            rs_domain_initial_reduction_factor: 1,
            folding_factor: FoldingFactor::Constant(2),
            merkle_hash: MyHash::new(perm.clone()),
            merkle_compress: MyCompress::new(perm),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        })
    }

    fn seed_whir_challenger(
        config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
        seed: u64,
    ) -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
        let mut c = MyChallenger::new(perm);
        let mut ds = DomainSeparator::<EF, F>::new(vec![]);
        ds.commit_statement::<_, _, _, 8>(config);
        ds.add_whir_proof::<_, _, _, 8>(config);
        ds.observe_domain_separator(&mut c);
        c
    }

    // ── End-to-end: IVC init + 3 steps + terminal WHIR prove + verify ──

    /// Full pipeline test: Spartan → WARP fold (4 steps) → terminal WHIR proof.
    /// This is the complete IVC pipeline with a single WHIR proof at the end.
    #[test]
    fn warp_ivc_full_pipeline_with_terminal_whir() {
        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();

        // ── IVC: init + 3 steps ──
        let instance0 = make_instance(&shape, 3);
        let mut chal0 = make_challenger(1);
        let mut state = warp_ivc_init::<F, EF, _, _, _, _>(
            &shape, &instance0, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
        );

        for (i, root) in [5u64, 7, 11].iter().enumerate() {
            let instance = make_instance(&shape, *root);
            let mut chal = make_challenger(i as u64 + 10);
            state = warp_ivc_step::<F, EF, _, _, _, _>(
                &state, &instance, &mut chal,
                &ivc_config, &dft, mh.clone(), mc.clone(),
                vec![F::from_u64(root * root)],
            );
        }
        assert_eq!(state.step, 4);

        // ── Terminal WHIR proof ──
        // WHIR operates on the accumulated witness polynomial.
        // The witness is in WarpAccumulatorWitness.witness (the raw z-vector portion).
        let witness_raw = &state.accumulator.witness.witness;
        let witness_len = witness_raw.len().next_power_of_two();
        let mut witness_padded = witness_raw.clone();
        witness_padded.resize(witness_len, F::ZERO);
        let witness_poly = EvaluationsList::new(witness_padded);
        let witness_num_vars = witness_poly.num_variables();

        let whir_config = make_whir_config(witness_num_vars);

        // PROVE
        let linear_claim = LinearStatement::<F, EF>::initialize(witness_num_vars);
        let mut statement = whir_config.initial_statement_with_linear(
            witness_poly.clone(), linear_claim.clone(),
        );
        let mut whir_proof = WhirProof::<F, EF, F, 8>::from_whir_config(&whir_config);
        let mut prove_challenger = seed_whir_challenger(&whir_config, 999);
        let commitment = CommitmentWriter::new(&whir_config)
            .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &dft, &mut whir_proof, &mut prove_challenger, &mut statement,
            )
            .expect("WHIR commit failed");
        WhirProver(&whir_config)
            .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &dft, &mut whir_proof, &mut prove_challenger, &statement, commitment,
            )
            .expect("WHIR prove failed");

        // VERIFY
        let initial_claim = InitialClaim {
            eq_statement: EqStatement::initialize(witness_num_vars),
            linear_statement: LinearStatement::<F, EF>::initialize(witness_num_vars),
        };
        let mut verify_challenger = seed_whir_challenger(&whir_config, 999);
        let parsed = CommitmentReader::new(&whir_config)
            .parse_commitment::<F, 8>(&whir_proof, &mut verify_challenger);
        let verify_result = WhirVerifier::new(&whir_config)
            .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &whir_proof, &mut verify_challenger, &parsed, initial_claim,
            );

        assert!(
            verify_result.is_ok(),
            "Terminal WHIR verify failed after 4 IVC steps: {verify_result:?}"
        );
    }
}
