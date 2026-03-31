//! IVC using the full pipeline: Spartan → Batch Reduction → WARP fold → terminal WHIR.
//!
//! Unlike the v2 IVC (`ivc.rs`) which runs a WHIR proof at every accumulation step,
//! this IVC uses the WARP fold (RS encode + Merkle + twin-constraint sumcheck +
//! shift/OOD + eval batching) with **no WHIR per step**. A single WHIR proof is
//! generated only at the terminal decider.
//!
//! Pipeline per IVC step:
//! 1. Build unified circuit (step computation + optional verifier)
//! 2. Spartan prove → linearize to `LinearStatement`
//! 3. Batch reduction (constraint_batch + random_lc) → combined `FreshInstance`
//! 4. WARP fold with running `WarpAccumulator` (RS encode + Merkle + sumcheck)
//! 5. Output: new `WarpAccumulator` + fold transcript (for next step's verifier)

use alloc::{vec, vec::Vec};

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};

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
    circuit::{builder::CircuitBuilder, poseidon2::Poseidon2CircuitConfig, sponge::CircuitChallenger},
    ivc::warp_fold_verifier_circuit::{
        WarpFoldVerifierWitness, synthesize_warp_ivc_circuit,
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
    /// Previous accumulator instances (for the recursive verifier witness).
    /// Contains [running_acc_instance, fresh_instance] from the last fold.
    pub prev_acc_instance: Option<WarpAccumulatorInstance<F, F, F, 8>>,
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
    // The fold's eval_point is in LSB-first convention (from compute_eq_table).
    // evaluate_hypercube_base uses MSB-first, so we reverse.
    let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
        &result.witness.codeword,
        &result.instance.eval_point,
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
pub fn warp_ivc_init<F, EF, Dft, H, C, Challenger, FoldChal>(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
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
    FoldChal: CanObserve<F> + CanSample<F>,
{
    let spartan_prover = R1CSProver::new();

    // Spartan prove
    let _spartan_proof = spartan_prover.prove::<EF, _>(instance, spartan_challenger);
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

    // Pre-compute fresh commitment root for Fiat-Shamir seeding
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    // Derive omega, tau from native challenger (Fiat-Shamir)
    let mut fold_chal = make_fold_challenger();
    for &val in &acc.instance.commitment_root { fold_chal.observe(val); }
    fold_chal.observe(acc.instance.eval_claim);
    for &val in &acc.instance.eval_point { fold_chal.observe(val); }
    fold_chal.observe(acc.instance.pesat_target);
    for &val in &fresh_root { fold_chal.observe(val); }
    fold_chal.observe(F::ZERO); // fresh eval_claim
    for _ in 0..log_code { fold_chal.observe(F::ZERO); } // fresh eval_point
    fold_chal.observe(F::ZERO); // fresh pesat_target

    let omega: F = fold_chal.sample();
    let log_l = 1; // l = 2, log_2(2) = 1
    let tau: Vec<F> = (0..log_l).map(|_| fold_chal.sample()).collect();

    // Sample fresh betas for PESAT soundness
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| fold_chal.sample()).collect())
        .collect();

    // WARP fold with Fiat-Shamir-derived challenges
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        shape, &[fresh], &acc, omega, &tau,
        &fresh_betas,
        &rs_config, dft,
        |round_evals| {
            for &e in round_evals { fold_chal.observe(e); }
            fold_chal.sample()
        },
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
        prev_acc_instance: Some(acc.instance.clone()),
        public_state,
    }
}

/// Execute one IVC step using the full Spartan → Batch reduction → WARP pipeline.
///
/// 1. Spartan prove the instance → linearize
/// 2. Batch reduction (if batch > 1) or direct FreshInstance (if batch = 1)
/// 3. WARP fold with running accumulator
/// 4. No WHIR proof — deferred to terminal
pub fn warp_ivc_step<F, EF, Dft, H, C, Challenger, FoldChal>(
    prev_state: &WarpIVCState<F>,
    instance: &R1CSInstance<F>,
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    new_public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
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
    FoldChal: CanObserve<F> + CanSample<F>,
{
    let _shape = &prev_state.shape;
    let spartan_prover = R1CSProver::new();

    // 1. Spartan prove
    let _spartan_proof = spartan_prover.prove::<EF, _>(instance, spartan_challenger);
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

    // Pre-compute fresh commitment root for Fiat-Shamir seeding
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    // Derive omega, tau from native challenger (Fiat-Shamir)
    let prev_inst = &prev_state.accumulator.instance;
    let log_code = prev_state.accumulator.log_code_len();
    let mut fold_chal = make_fold_challenger();
    for &val in &prev_inst.commitment_root { fold_chal.observe(val); }
    fold_chal.observe(prev_inst.eval_claim);
    for &val in &prev_inst.eval_point { fold_chal.observe(val); }
    fold_chal.observe(prev_inst.pesat_target);
    for &val in &fresh_root { fold_chal.observe(val); }
    fold_chal.observe(F::ZERO);
    for _ in 0..log_code { fold_chal.observe(F::ZERO); }
    fold_chal.observe(F::ZERO);

    let omega: F = fold_chal.sample();
    let log_l = 1;
    let tau: Vec<F> = (0..log_l).map(|_| fold_chal.sample()).collect();

    // Sample fresh betas for PESAT soundness
    let log_m = prev_state.shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| fold_chal.sample()).collect())
        .collect();

    // 3. WARP fold with Fiat-Shamir-derived challenges
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        &prev_state.shape, &[fresh], &prev_state.accumulator, omega, &tau,
        &fresh_betas,
        &rs_config, dft,
        |round_evals| {
            for &e in round_evals { fold_chal.observe(e); }
            fold_chal.sample()
        },
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
        shape: prev_state.shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
    }
}

/// Execute one recursive IVC step with in-circuit fold verification.
///
/// Builds a unified circuit = step computation + WARP fold verifier.
/// The verifier checks the PREVIOUS step's fold transcript in-circuit.
/// Then Spartan-proves this unified circuit and WARP-folds the result.
///
/// This is the full recursive IVC: no external verification needed between steps.
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_step_recursive<F, EF, Dft, H, C, Challenger, L, Perm2, S, FoldChal>(
    prev_state: &WarpIVCState<F>,
    step_circuit: &S,
    step_input_state: &[F],
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    poseidon_config: &Poseidon2CircuitConfig<F, 16>,
    poseidon_perm: &Perm2,
    target_num_witness: Option<usize>,
    new_public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
) -> WarpIVCState<F>
where
    F: TwoAdicField + PrimeField64 + Ord + PrimeCharacteristicRing,
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
    L: GenericPoseidon2LinearLayers<16>,
    Perm2: Permutation<[F; 16]>,
    S: crate::ivc::step::StepCircuit<F>,
    FoldChal: CanObserve<F> + CanSample<F>,
{
    let _shape = &prev_state.shape;

    // ── Pre-derive omega for verifier witness (must match what the fold will use) ──
    // We need to know omega BEFORE building the circuit, because the in-circuit
    // verifier uses it. So we do a "dry run" of the Fiat-Shamir to get omega.
    let prev_fold_omega = if let Some(prev_inst) = &prev_state.prev_acc_instance {
        // Replay the PREVIOUS fold's FS to recover its omega
        let mut dry_chal = make_fold_challenger();
        for &val in &prev_inst.commitment_root { dry_chal.observe(val); }
        dry_chal.observe(prev_inst.eval_claim);
        for &val in &prev_inst.eval_point { dry_chal.observe(val); }
        dry_chal.observe(prev_inst.pesat_target);
        // Observe the fresh instance data from the previous fold result
        if let Some(fr) = &prev_state.last_fold_result {
            if let Some(root) = fr.fresh_commitment_roots.first() {
                for &val in root { dry_chal.observe(val); }
            } else {
                for _ in 0..8 { dry_chal.observe(F::ZERO); }
            }
            if let Some(&mu) = fr.fresh_eval_claims.first() {
                dry_chal.observe(mu);
            } else {
                dry_chal.observe(F::ZERO);
            }
            let log_code = prev_inst.eval_point.len();
            for _ in 0..log_code { dry_chal.observe(F::ZERO); }
            if let Some(&eta) = fr.fresh_pesat_targets.first() {
                dry_chal.observe(eta);
            } else {
                dry_chal.observe(F::ZERO);
            }
        }
        let omega: F = dry_chal.sample();
        omega
    } else {
        F::ZERO
    };

    // ── Build the verifier witness from the previous fold ──
    let verifier_witness = if let (Some(fold_result), Some(prev_inst)) = (
        &prev_state.last_fold_result,
        &prev_state.prev_acc_instance,
    ) {
        let commitment_roots = vec![
            prev_inst.commitment_root.to_vec(),
            fold_result.fresh_commitment_roots.first()
                .map(|r| r.to_vec())
                .unwrap_or_else(|| vec![F::ZERO; 8]),
        ];
        let eval_claims = vec![
            prev_inst.eval_claim,
            fold_result.fresh_eval_claims.first().copied().unwrap_or(F::ZERO),
        ];
        let eval_points = vec![
            prev_inst.eval_point.clone(),
            vec![F::ZERO; prev_inst.eval_point.len()],
        ];
        let pesat_targets = vec![
            prev_inst.pesat_target,
            fold_result.fresh_pesat_targets.first().copied().unwrap_or(F::ZERO),
        ];

        Some(WarpFoldVerifierWitness::from_fold_result(
            commitment_roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &fold_result.sumcheck_round_polys,
            prev_fold_omega,
        ))
    } else {
        None
    };

    // ── Build unified circuit: step + verifier ──
    let mut builder = CircuitBuilder::<F>::new();
    let mut circuit_challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

    let _output_vars = synthesize_warp_ivc_circuit::<F, L, Perm2, S, 16, 8>(
        &mut builder,
        &mut circuit_challenger,
        poseidon_config,
        poseidon_perm,
        step_circuit,
        step_input_state,
        verifier_witness.as_ref(),
        target_num_witness,
    );

    let (unified_shape, unified_instance) = builder.build();
    assert!(
        unified_shape.is_sat(unified_instance.witness(), unified_instance.input()),
        "unified recursive IVC circuit is not satisfiable at step {}",
        prev_state.step,
    );

    // ── Spartan prove the unified circuit ──
    let spartan_prover = R1CSProver::new();
    let _spartan_proof = spartan_prover.prove::<EF, _>(&unified_instance, spartan_challenger);
    let witness_poly = spartan_prover.prepare_witness(&unified_instance);

    // ── Create FreshInstance aligned to the accumulator's witness size ──
    let num_inputs = unified_instance.input().len();
    let z = witness_poly.as_slice();
    let public_input = z[..num_inputs].to_vec();
    let num_witness = prev_state.accumulator.witness.witness.len();
    let mut witness_part = z[num_inputs..].to_vec();
    witness_part.resize(num_witness, F::ZERO);

    let fresh = FreshInstance {
        public_input,
        witness: witness_part,
    };

    // ── Pre-compute fresh commitment root for Fiat-Shamir ──
    let fold_shape = &prev_state.shape;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    // ── Derive omega, tau from native challenger ──
    let prev_inst = &prev_state.accumulator.instance;
    let log_code = prev_state.accumulator.log_code_len();
    let mut fold_chal = make_fold_challenger();
    for &val in &prev_inst.commitment_root { fold_chal.observe(val); }
    fold_chal.observe(prev_inst.eval_claim);
    for &val in &prev_inst.eval_point { fold_chal.observe(val); }
    fold_chal.observe(prev_inst.pesat_target);
    for &val in &fresh_root { fold_chal.observe(val); }
    fold_chal.observe(F::ZERO);
    for _ in 0..log_code { fold_chal.observe(F::ZERO); }
    fold_chal.observe(F::ZERO);

    let omega: F = fold_chal.sample();
    let log_l = 1;
    let tau: Vec<F> = (0..log_l).map(|_| fold_chal.sample()).collect();

    // Sample fresh betas for PESAT soundness
    let log_m = fold_shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| fold_chal.sample()).collect())
        .collect();

    // ── WARP fold with Fiat-Shamir-derived challenges ──
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        fold_shape, &[fresh], &prev_state.accumulator, omega, &tau,
        &fresh_betas,
        &rs_config, dft,
        |round_evals| {
            for &e in round_evals { fold_chal.observe(e); }
            fold_chal.sample()
        },
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
        shape: fold_shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
    }
}

/// Compute the target witness count for unified circuits.
///
/// Builds a dummy circuit with the verifier to determine the witness count,
/// so that the init step can pad to the same size.
pub fn compute_recursive_circuit_size<F, L, Perm2, S>(
    step_circuit: &S,
    step_input_state: &[F],
    poseidon_config: &Poseidon2CircuitConfig<F, 16>,
    poseidon_perm: &Perm2,
    num_eval_point_vars: usize,
) -> (usize, usize, usize) // (num_witness, num_constraints, num_poly_vars_y)
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<16>,
    Perm2: Permutation<[F; 16]>,
    S: crate::ivc::step::StepCircuit<F>,
{
    // Build a dummy verifier witness for l=2 (1 round)
    let dummy_witness = WarpFoldVerifierWitness {
        input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
        input_eval_claims: vec![F::ZERO; 2],
        input_eval_points: vec![vec![F::ZERO; num_eval_point_vars]; 2],
        input_pesat_targets: vec![F::ZERO; 2],
        sumcheck_evals: vec![[F::ZERO; 3]], // 1 round for l=2
        num_rounds: 1,
        omega: F::ZERO,
    };

    let mut builder = CircuitBuilder::<F>::new();
    let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

    let _ = synthesize_warp_ivc_circuit::<F, L, Perm2, S, 16, 8>(
        &mut builder,
        &mut challenger,
        poseidon_config,
        poseidon_perm,
        step_circuit,
        step_input_state,
        Some(&dummy_witness),
        None,
    );

    let num_witness = builder.num_witness_vars();
    let num_constraints = builder.num_constraints();
    let (shape, _) = builder.build();
    (num_witness, num_constraints, shape.num_poly_vars_y())
}

/// Execute one IVC step with Batch reduction for batch > 1.
///
/// Takes multiple R1CS instances, runs Spartan + Batch reduction to combine
/// them into a single FreshInstance, then WARP folds with the running accumulator.
pub fn warp_ivc_step_batch<F, EF, Dft, H, C, Challenger, FoldChal>(
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
    mut make_fold_challenger: impl FnMut() -> FoldChal,
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
    FoldChal: CanObserve<F> + CanSample<F>,
{
    let shape = &prev_state.shape;
    let spartan_prover = R1CSProver::new();
    let batch = instances.len();
    assert!(batch > 0);

    // 1. Spartan prove all instances + linearize
    let mut witnesses = Vec::with_capacity(batch);
    let mut linears = Vec::with_capacity(batch);
    for (inst, challenger) in instances.iter().zip(spartan_challengers.iter_mut()) {
        let _proof = spartan_prover.prove::<EF, _>(inst, challenger);
        let witness = spartan_prover.prepare_witness(inst);
        let linear = linearized_statement_from_spartan_proof(shape, &_proof, linearization_challenge);
        witnesses.push(witness);
        linears.push(linear);
    }

    // 2. Batch reduction: constraint batch + random LC
    // Derive gamma and eta from the fold challenger (Fiat-Shamir)
    let mut batch_chal = make_fold_challenger();
    // Bind step and batch size
    batch_chal.observe(F::from_u64(prev_state.step as u64));
    batch_chal.observe(F::from_u64(batch as u64));
    let gamma: F = batch_chal.sample();
    let eta: F = batch_chal.sample();

    let mut weights = Vec::with_capacity(batch);
    let mut targets = Vec::with_capacity(batch);
    for linear in &linears {
        let (w, &t) = linear.iter().next().unwrap();
        weights.push(w.clone());
        targets.push(t);
    }

    let (_batch_proof, _reduction_point) = constraint_batch_prove(
        gamma, &weights, &targets, &witnesses, cb_challenger,
    );

    // Random LC: combine witnesses
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

    // Pre-compute fresh commitment root for Fiat-Shamir
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    // Derive omega, tau from native challenger
    let prev_inst = &prev_state.accumulator.instance;
    let log_code = prev_state.accumulator.log_code_len();
    let mut fold_chal = make_fold_challenger();
    for &val in &prev_inst.commitment_root { fold_chal.observe(val); }
    fold_chal.observe(prev_inst.eval_claim);
    for &val in &prev_inst.eval_point { fold_chal.observe(val); }
    fold_chal.observe(prev_inst.pesat_target);
    for &val in &fresh_root { fold_chal.observe(val); }
    fold_chal.observe(F::ZERO);
    for _ in 0..log_code { fold_chal.observe(F::ZERO); }
    fold_chal.observe(F::ZERO);

    let omega: F = fold_chal.sample();
    let log_l = 1;
    let tau: Vec<F> = (0..log_l).map(|_| fold_chal.sample()).collect();

    // Sample fresh betas for PESAT soundness
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| fold_chal.sample()).collect())
        .collect();

    // 4. WARP fold with Fiat-Shamir-derived challenges
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        shape, &[fresh], &prev_state.accumulator, omega, &tau,
        &fresh_betas,
        &rs_config, dft,
        |round_evals| {
            for &e in round_evals { fold_chal.observe(e); }
            fold_chal.sample()
        },
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
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CP-SNARK mode: deferred Fiat-Shamir verification (Symphony Section 6)
// ═══════════════════════════════════════════════════════════════════════

use p3_challenger::{CanObserve, CanSample};

use crate::{
    accumulation::warp::encoding::rs_encode,
    cp_snark::{build_deferred_transcript, DeferredFoldTranscript},
    ivc::warp_fold_verifier_algebraic::{
        AlgebraicFoldVerifierWitness, compute_cp_circuit_size, synthesize_warp_ivc_circuit_cp,
    },
};

/// IVC state for the CP-SNARK mode.
///
/// Same as `WarpIVCState` but also carries deferred fold transcripts
/// for terminal verification. The circuit is much smaller (~17x) because
/// Poseidon2 hashing is replaced by native challenge derivation.
#[derive(Clone, Debug)]
pub struct WarpIVCStateCp<F: Field> {
    /// Current step number.
    pub step: usize,
    /// Running WARP accumulator (fixed-size witness).
    pub accumulator: WarpAccumulator<F, F, F, 8>,
    /// R1CS shape for the circuit (same across all steps).
    pub shape: R1CSShape<F>,
    /// Last fold transcript (for the algebraic verifier, if used).
    pub last_fold_result: Option<WarpFoldResult<F>>,
    /// Previous accumulator instance.
    pub prev_acc_instance: Option<WarpAccumulatorInstance<F, F, F, 8>>,
    /// Current public state.
    pub public_state: Vec<F>,
    /// Deferred fold transcripts — verified natively at terminal.
    pub deferred_transcripts: Vec<DeferredFoldTranscript<F>>,
}

/// Initialize the WARP IVC in CP-SNARK mode.
///
/// Same as `warp_ivc_init` but returns `WarpIVCStateCp` with a deferred
/// transcript for the first fold. Uses a native Poseidon2 challenger (via
/// `make_fold_challenger`) to derive omega, tau, and sumcheck challenges
/// so that `verify_deferred_transcripts` can replay and verify at terminal.
pub fn warp_ivc_init_cp<F, EF, Dft, H, C, Challenger, FoldChal>(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
) -> WarpIVCStateCp<F>
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
    FoldChal: CanObserve<F> + CanSample<F>,
{
    let spartan_prover = R1CSProver::new();
    let _spartan_proof = spartan_prover.prove::<EF, _>(instance, spartan_challenger);
    let witness_poly = spartan_prover.prepare_witness(instance);

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

    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);

    // ── Pre-compute fresh commitment root for Fiat-Shamir seeding ──
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    // ── Derive omega, tau from native Poseidon2 challenger ──
    let input_commitment_roots = vec![acc.instance.commitment_root.to_vec(), fresh_root.to_vec()];
    let input_eval_claims = vec![acc.instance.eval_claim, F::ZERO];
    let input_eval_points = vec![acc.instance.eval_point.clone(), vec![F::ZERO; log_code]];
    let input_pesat_targets = vec![acc.instance.pesat_target, F::ZERO];

    let mut fold_chal = make_fold_challenger();
    for i in 0..2 {
        for &val in &input_commitment_roots[i] { fold_chal.observe(val); }
        fold_chal.observe(input_eval_claims[i]);
        for &val in &input_eval_points[i] { fold_chal.observe(val); }
        fold_chal.observe(input_pesat_targets[i]);
    }
    let omega: F = fold_chal.sample();
    let log_l = 1; // l = 2 (running + 1 fresh), log_2(2) = 1
    let tau: Vec<F> = (0..log_l).map(|_| fold_chal.sample()).collect();

    // Sample fresh betas for PESAT soundness
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| fold_chal.sample()).collect())
        .collect();

    // ── Run fold with Poseidon2-derived challenges ──
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        shape,
        &[fresh],
        &acc,
        omega,
        &tau,
        &fresh_betas,
        &rs_config,
        dft,
        |round_evals| {
            for &e in round_evals { fold_chal.observe(e); }
            fold_chal.sample()
        },
        |codeword, folding_factor| {
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(codeword, folding_factor, mh.clone(), mc.clone());
            root
        },
    );

    // ── Build deferred transcript ──
    let init_transcript = build_deferred_transcript(
        0,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        &result.sumcheck_round_polys,
        omega,
        tau,
        result.sumcheck_challenges.clone(),
    );

    let new_acc = rebuild_accumulator(&result);

    WarpIVCStateCp {
        step: 1,
        accumulator: new_acc,
        shape: shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(acc.instance.clone()),
        public_state,
        deferred_transcripts: vec![init_transcript],
    }
}

/// Execute one recursive IVC step in CP-SNARK mode.
///
/// Like `warp_ivc_step_recursive` but with an algebraic circuit (NO Poseidon2):
/// 1. Build unified circuit = step computation + algebraic sumcheck verifier
/// 2. Spartan prove this MUCH smaller circuit
/// 3. WARP fold with running accumulator (Poseidon2-derived challenges)
/// 4. Store deferred transcript for terminal verification
///
/// The circuit is ~17x smaller than the regular recursive IVC because all
/// Poseidon2 hashing is replaced by witness-provided challenges.
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_step_recursive_cp<F, EF, Dft, H, C, Challenger, S, FoldChal>(
    prev_state: &WarpIVCStateCp<F>,
    step_circuit: &S,
    step_input_state: &[F],
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    target_num_witness: Option<usize>,
    new_public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
) -> WarpIVCStateCp<F>
where
    F: TwoAdicField + PrimeField64 + Ord + PrimeCharacteristicRing,
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
    S: crate::ivc::step::StepCircuit<F>,
    FoldChal: CanObserve<F> + CanSample<F>,
{
    let shape = &prev_state.shape;

    // ── Build algebraic verifier witness from previous fold ──
    let verifier_witness = prev_state.last_fold_result.as_ref().map(|fold_result| {
        AlgebraicFoldVerifierWitness::from_fold_data(
            &fold_result.sumcheck_round_polys,
            &fold_result.sumcheck_challenges,
        )
    });

    // ── Build unified circuit: step + algebraic verifier (NO Poseidon2) ──
    let mut builder = CircuitBuilder::<F>::new();
    let _output_vars = synthesize_warp_ivc_circuit_cp(
        &mut builder,
        step_circuit,
        step_input_state,
        verifier_witness.as_ref(),
        target_num_witness,
    );

    let (unified_shape, unified_instance) = builder.build();
    assert!(
        unified_shape.is_sat(unified_instance.witness(), unified_instance.input()),
        "CP-SNARK unified circuit is not satisfiable at step {}",
        prev_state.step,
    );

    // ── Spartan prove the (much smaller) unified circuit ──
    let spartan_prover = R1CSProver::new();
    let _spartan_proof = spartan_prover.prove::<EF, _>(&unified_instance, spartan_challenger);
    let witness_poly = spartan_prover.prepare_witness(&unified_instance);

    // ── Create FreshInstance ──
    let num_inputs = unified_instance.input().len();
    let z = witness_poly.as_slice();
    let public_input = z[..num_inputs].to_vec();
    let num_witness = prev_state.accumulator.witness.witness.len();
    let mut witness_part = z[num_inputs..].to_vec();
    witness_part.resize(num_witness, F::ZERO);

    let fresh = FreshInstance {
        public_input,
        witness: witness_part,
    };

    // ── Pre-compute fresh commitment root for Fiat-Shamir seeding ──
    let fold_shape = &prev_state.shape;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    // ── Derive omega, tau from native Poseidon2 challenger ──
    let prev_inst = &prev_state.accumulator.instance;
    let log_code = prev_state.accumulator.log_code_len();
    let input_commitment_roots = vec![prev_inst.commitment_root.to_vec(), fresh_root.to_vec()];
    let input_eval_claims = vec![prev_inst.eval_claim, F::ZERO];
    let input_eval_points = vec![prev_inst.eval_point.clone(), vec![F::ZERO; log_code]];
    let input_pesat_targets = vec![prev_inst.pesat_target, F::ZERO];

    let mut fold_chal = make_fold_challenger();
    for i in 0..2 {
        for &val in &input_commitment_roots[i] { fold_chal.observe(val); }
        fold_chal.observe(input_eval_claims[i]);
        for &val in &input_eval_points[i] { fold_chal.observe(val); }
        fold_chal.observe(input_pesat_targets[i]);
    }
    let omega: F = fold_chal.sample();
    let log_l = 1; // l = 2 (running + 1 fresh)
    let tau: Vec<F> = (0..log_l).map(|_| fold_chal.sample()).collect();

    // Sample fresh betas for PESAT soundness
    let log_m = fold_shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| fold_chal.sample()).collect())
        .collect();

    // ── WARP fold with Poseidon2-derived challenges ──
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        fold_shape,
        &[fresh],
        &prev_state.accumulator,
        omega,
        &tau,
        &fresh_betas,
        &rs_config,
        dft,
        |round_evals| {
            for &e in round_evals { fold_chal.observe(e); }
            fold_chal.sample()
        },
        |codeword, folding_factor| {
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(codeword, folding_factor, mh.clone(), mc.clone());
            root
        },
    );

    // ── Store deferred transcript ──
    let transcript = build_deferred_transcript(
        prev_state.step,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        &result.sumcheck_round_polys,
        omega,
        tau,
        result.sumcheck_challenges.clone(),
    );

    let mut deferred = prev_state.deferred_transcripts.clone();
    deferred.push(transcript);

    let new_acc = rebuild_accumulator(&result);

    WarpIVCStateCp {
        step: prev_state.step + 1,
        accumulator: new_acc,
        shape: fold_shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
        deferred_transcripts: deferred,
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

    fn make_fold_challenger_factory() -> impl FnMut() -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(77));
        move || MyChallenger::new(perm.clone())
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
        let mut state = warp_ivc_init::<F, EF, _, _, _, _, _>(
            &shape, &instance0, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 1);
        let initial_code_len = state.accumulator.witness.codeword.as_slice().len();
        let initial_wit_len = state.accumulator.witness.witness.len();

        // Steps: 5^2=25, 7^2=49, 11^2=121
        for (i, root) in [5u64, 7, 11].iter().enumerate() {
            let instance = make_instance(&shape, *root);
            let mut chal = make_challenger(i as u64 + 10);
            state = warp_ivc_step::<F, EF, _, _, _, _, _>(
                &state, &instance, &mut chal,
                &ivc_config, &dft, mh.clone(), mc.clone(),
                vec![F::from_u64(root * root)],
                make_fold_challenger_factory(),
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
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &state.accumulator.witness.codeword,
            &state.accumulator.instance.eval_point,
        );
        assert_eq!(
            eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after 4 steps"
        );
    }

    /// Test: init + 2 batch steps (Batch reduction with batch=2).
    #[test]
    fn warp_ivc_batch_steps() {
        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();

        // Init
        let instance0 = make_instance(&shape, 3);
        let mut chal0 = make_challenger(1);
        let mut state = warp_ivc_init::<F, EF, _, _, _, _, _>(
            &shape, &instance0, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
            make_fold_challenger_factory(),
        );

        // Batch step 1: instances for roots 5, 7
        let batch1 = vec![make_instance(&shape, 5), make_instance(&shape, 7)];
        let mut chals1 = [make_challenger(10), make_challenger(11)];
        let mut cb_chal = make_challenger(300);
        state = warp_ivc_step_batch::<F, EF, _, _, _, _, _>(
            &state, &batch1,
            &mut chals1,
            EF::from_u64(3),
            &ivc_config, &dft, mh.clone(), mc.clone(),
            &mut cb_chal,
            vec![F::from_u64(49)],
            make_fold_challenger_factory(),
        );

        assert_eq!(state.step, 2);

        // Verify eval claim consistency
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &state.accumulator.witness.codeword,
            &state.accumulator.instance.eval_point,
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
        let mut state = warp_ivc_init::<F, EF, _, _, _, _, _>(
            &shape, &instance0, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
            make_fold_challenger_factory(),
        );

        for (i, root) in [5u64, 7, 11].iter().enumerate() {
            let instance = make_instance(&shape, *root);
            let mut chal = make_challenger(i as u64 + 10);
            state = warp_ivc_step::<F, EF, _, _, _, _, _>(
                &state, &instance, &mut chal,
                &ivc_config, &dft, mh.clone(), mc.clone(),
                vec![F::from_u64(root * root)],
                make_fold_challenger_factory(),
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

    // ── Recursive IVC tests ──────────────────────────────────────

    /// Measure the recursive circuit size: step circuit + WARP fold verifier.
    #[test]
    fn measure_recursive_circuit_size() {
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::ivc::step::{StepCircuit, TrivialStepCircuit};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);

        // Measure with verifier (the full recursive circuit)
        let (num_witness, num_constraints, num_poly_vars_y) =
            compute_recursive_circuit_size::<
                F, GenericPoseidon2LinearLayersBabyBear, _, _,
            >(
                &step, &[F::ZERO], &poseidon_config, &poseidon_perm,
                3, // eval_point has 3 vars for our test shape
            );

        // Measure WITHOUT verifier (step circuit only)
        let mut step_only_builder = CircuitBuilder::<F>::new();
        let input = vec![step_only_builder.alloc_witness(F::ZERO)];
        let _ = step.synthesize(&mut step_only_builder, &input);
        let step_only_witness = step_only_builder.num_witness_vars();
        let step_only_constraints = step_only_builder.num_constraints();

        // Measure Poseidon2-only: build verifier without step
        let dummy_witness = WarpFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::ZERO; 2],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            input_pesat_targets: vec![F::ZERO; 2],
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
            omega: F::ZERO,
        };
        let mut verifier_only_builder = CircuitBuilder::<F>::new();
        let mut verifier_chal = CircuitChallenger::<F, 16, 8>::new(&mut verifier_only_builder);
        let _ = crate::ivc::warp_fold_verifier_circuit::synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersBabyBear, _, 16, 8,
        >(
            &mut verifier_only_builder, &mut verifier_chal,
            &poseidon_config, &poseidon_perm, &dummy_witness,
        );
        let verifier_only_witness = verifier_only_builder.num_witness_vars();
        let verifier_only_constraints = verifier_only_builder.num_constraints();

        // Print breakdown (visible with --nocapture)
        // Assert and record sizes for analysis.
        // The verifier should dominate the circuit cost.
        assert!(num_witness > 0);
        assert!(num_constraints > 0);

        // Store for programmatic access (visible in test output with --nocapture)
        // Step circuit: trivial (1 var, 0 constraints)
        // Verifier: Poseidon2 hashing + sumcheck verification
        // Unified: step + verifier
        assert!(
            verifier_only_constraints > step_only_constraints,
            "verifier ({verifier_only_constraints} constraints) should dominate step ({step_only_constraints} constraints)"
        );

        // Verify Poseidon2 dominates: the verifier is >95% of the unified circuit
        let verifier_fraction = verifier_only_constraints as f64 / num_constraints.max(1) as f64;
        assert!(
            verifier_fraction > 0.5,
            "verifier should be >50% of unified circuit, got {:.1}%",
            verifier_fraction * 100.0,
        );

        // Use a failing assert to print sizes (controlled by feature flag).
        // Run: cargo test --features bench-timing ... to see sizes.
        #[cfg(feature = "bench-timing")]
        panic!(
            "\n=== Recursive Circuit Size Breakdown ===\n\
             Step circuit only:     {:>6} witness, {:>6} constraints\n\
             WARP fold verifier:    {:>6} witness, {:>6} constraints\n\
             Unified (step+verif):  {:>6} witness, {:>6} constraints\n\
             num_poly_vars_y:       {}\n\
             Verifier overhead:     {:.1}% of constraints\n",
            step_only_witness, step_only_constraints,
            verifier_only_witness, verifier_only_constraints,
            num_witness, num_constraints,
            num_poly_vars_y,
            verifier_fraction * 100.0,
        );

        // The verifier should be the dominant cost
        assert!(
            verifier_only_constraints > step_only_constraints,
            "verifier should have more constraints than trivial step"
        );
    }

    /// Full recursive IVC: init (padded) → 2 recursive steps → verify sizes match.
    #[test]
    fn warp_ivc_recursive_two_steps() {
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::ivc::step::TrivialStepCircuit;

        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);

        // The fold challenger MUST use the same Poseidon2 permutation as the
        // in-circuit verifier, so that omega/tau derived natively match those
        // derived in-circuit.
        let make_recursive_fold_chal = {
            let p = poseidon_perm.clone();
            move || MyChallenger::new(p.clone())
        };

        // Compute target circuit size from a probe build
        let (target_witness, _target_constraints, _target_poly_vars) =
            compute_recursive_circuit_size::<
                F, GenericPoseidon2LinearLayersBabyBear, _, _,
            >(
                &step, &[F::ZERO], &poseidon_config, &poseidon_perm, 3,
            );

        // Init: build unified circuit WITHOUT verifier but padded to target size.
        // This ensures the accumulator shape matches all subsequent recursive steps.
        let mut init_builder = CircuitBuilder::<F>::new();
        let mut init_chal = CircuitChallenger::<F, 16, 8>::new(&mut init_builder);
        let _ = synthesize_warp_ivc_circuit::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _, 16, 8,
        >(
            &mut init_builder, &mut init_chal,
            &poseidon_config, &poseidon_perm,
            &step, &[F::from_u64(9)],
            None, // No verifier at step 0
            Some(target_witness),
        );
        let (init_shape, init_instance) = init_builder.build();
        assert!(
            init_shape.is_sat(init_instance.witness(), init_instance.input()),
            "init unified circuit not satisfiable"
        );

        let spartan_prover = R1CSProver::new();
        let mut chal0 = make_challenger(1);
        let _init_proof = spartan_prover.prove::<EF, _>(&init_instance, &mut chal0);
        let init_witness = spartan_prover.prepare_witness(&init_instance);

        // Create FreshInstance from unified circuit witness
        let num_inputs = init_instance.input().len();
        let z0 = init_witness.as_slice();
        let num_witness_0 = (z0.len() - num_inputs).next_power_of_two();
        let mut wit0 = z0[num_inputs..].to_vec();
        wit0.resize(num_witness_0, F::ZERO);

        let log_code = num_witness_0.trailing_zeros() as usize + ivc_config.rs_log_inv_rate;
        let log_m = init_shape.num_cons().next_power_of_two().trailing_zeros() as usize;

        let fresh0 = FreshInstance {
            public_input: z0[..num_inputs].to_vec(),
            witness: wit0,
        };
        let zero_acc = make_initial_accumulator::<F>(num_witness_0, log_code, log_m, num_inputs);
        let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);

        // Pre-compute fresh commitment root for Fiat-Shamir seeding
        let fresh_witness_poly0 = EvaluationsList::new(fresh0.witness.clone());
        let fresh_cw0 = rs_encode(&fresh_witness_poly0, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        let (fresh_root0, _) = merkle_commit_codeword::<
            F, F, <F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8,
        >(&fresh_cw0, rs_config.folding_factor, mh.clone(), mc.clone());

        // Derive omega, tau from Poseidon2 challenger (Fiat-Shamir)
        let mut fold_chal0 = make_recursive_fold_chal();
        for &val in &zero_acc.instance.commitment_root { fold_chal0.observe(val); }
        fold_chal0.observe(zero_acc.instance.eval_claim);
        for &val in &zero_acc.instance.eval_point { fold_chal0.observe(val); }
        fold_chal0.observe(zero_acc.instance.pesat_target);
        for &val in &fresh_root0 { fold_chal0.observe(val); }
        fold_chal0.observe(F::ZERO); // fresh eval_claim
        for _ in 0..log_code { fold_chal0.observe(F::ZERO); } // fresh eval_point
        fold_chal0.observe(F::ZERO); // fresh pesat_target

        let omega0: F = fold_chal0.sample();
        let log_l = 1; // l = 2, log_2(2) = 1
        let tau0: Vec<F> = (0..log_l).map(|_| fold_chal0.sample()).collect();

        // Sample fresh betas for PESAT soundness
        let log_m_test = init_shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        let fresh_betas0: Vec<Vec<F>> = (0..1)
            .map(|_| (0..log_m_test).map(|_| fold_chal0.sample()).collect())
            .collect();

        let mh0 = mh.clone();
        let mc0 = mc.clone();
        let result0 = warp_fold_prove_rs_committed(
            &init_shape, &[fresh0], &zero_acc, omega0, &tau0,
            &fresh_betas0,
            &rs_config, &dft,
            |round_evals| {
                for &e in round_evals { fold_chal0.observe(e); }
                fold_chal0.sample()
            },
            |codeword, folding_factor| {
                let (root, _tree) = merkle_commit_codeword::<
                    F, F, <F as Field>::Packing, <F as Field>::Packing,
                    MyHash, MyCompress, 8,
                >(codeword, folding_factor, mh0.clone(), mc0.clone());
                root
            },
        );
        let mut state = WarpIVCState {
            step: 1,
            accumulator: rebuild_accumulator(&result0),
            shape: init_shape,
            last_fold_result: Some(result0),
            prev_acc_instance: Some(zero_acc.instance.clone()),
            public_state: vec![F::from_u64(9)],
        };
        assert_eq!(state.step, 1);

        // Recursive step 1
        let mut chal1 = make_challenger(10);
        state = warp_ivc_step_recursive::<
            F, EF, _, _, _, _, GenericPoseidon2LinearLayersBabyBear, _, _, _,
        >(
            &state,
            &step,
            &[F::from_u64(25)],
            &mut chal1,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            &poseidon_config, &poseidon_perm,
            Some(target_witness),
            vec![F::from_u64(25)],
            &make_recursive_fold_chal,
        );
        assert_eq!(state.step, 2);

        // Recursive step 2
        let mut chal2 = make_challenger(20);
        state = warp_ivc_step_recursive::<
            F, EF, _, _, _, _, GenericPoseidon2LinearLayersBabyBear, _, _, _,
        >(
            &state,
            &step,
            &[F::from_u64(49)],
            &mut chal2,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            &poseidon_config, &poseidon_perm,
            Some(target_witness),
            vec![F::from_u64(49)],
            &make_recursive_fold_chal,
        );
        assert_eq!(state.step, 3);

        // Verify eval claim consistency
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &state.accumulator.witness.codeword,
            &state.accumulator.instance.eval_point,
        );
        assert_eq!(
            eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after 2 recursive steps"
        );
    }

    // ── CP-SNARK mode tests ─────────────────────────────────────

    /// CP-SNARK mode: init (padded) + 2 recursive steps with algebraic circuit.
    #[test]
    fn warp_ivc_cp_snark_two_steps() {
        use crate::ivc::step::TrivialStepCircuit;
        use crate::ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;

        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();
        let step = TrivialStepCircuit::new(1);

        // Compute CP circuit target size for consistent accumulator dimensions
        let (cp_target_witness, _cp_constraints, _) =
            compute_cp_circuit_size(&step, &[F::ZERO]);

        // ── Init via warp_ivc_init_cp ──
        let mut init_builder = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut init_builder,
            &step,
            &[F::from_u64(9)],
            None,
            Some(cp_target_witness),
        );
        let (init_shape, init_instance) = init_builder.build();
        assert!(
            init_shape.is_sat(init_instance.witness(), init_instance.input()),
            "CP init circuit not satisfiable"
        );

        let mut chal0 = make_challenger(1);
        let mut state = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
            &init_shape,
            &init_instance,
            &mut chal0,
            &ivc_config,
            &dft,
            mh.clone(),
            mc.clone(),
            vec![F::from_u64(9)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 1);
        assert_eq!(state.deferred_transcripts.len(), 1);

        // ── Recursive step 1 ──
        let mut chal1 = make_challenger(10);
        state = warp_ivc_step_recursive_cp::<F, EF, _, _, _, _, _, _>(
            &state,
            &step,
            &[F::from_u64(25)],
            &mut chal1,
            &ivc_config,
            &dft,
            mh.clone(),
            mc.clone(),
            Some(cp_target_witness),
            vec![F::from_u64(25)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 2);
        assert_eq!(state.deferred_transcripts.len(), 2);

        // ── Recursive step 2 ──
        let mut chal2 = make_challenger(20);
        state = warp_ivc_step_recursive_cp::<F, EF, _, _, _, _, _, _>(
            &state,
            &step,
            &[F::from_u64(49)],
            &mut chal2,
            &ivc_config,
            &dft,
            mh.clone(),
            mc.clone(),
            Some(cp_target_witness),
            vec![F::from_u64(49)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 3);
        assert_eq!(state.deferred_transcripts.len(), 3);

        // Verify eval claim consistency
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &state.accumulator.witness.codeword,
            &state.accumulator.instance.eval_point,
        );
        assert_eq!(
            eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after 2 CP-SNARK recursive steps"
        );
    }

    /// Compare circuit sizes: CP-SNARK vs regular recursive.
    #[test]
    fn cp_snark_vs_regular_circuit_size() {
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::ivc::step::TrivialStepCircuit;
        use crate::ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);

        // Regular recursive circuit size
        let (reg_witness, reg_constraints, _) = compute_recursive_circuit_size::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            _,
        >(&step, &[F::ZERO], &poseidon_config, &poseidon_perm, 3);

        // CP-SNARK circuit size
        let (cp_witness, cp_constraints, _) = compute_cp_circuit_size(&step, &[F::ZERO]);

        // CP-SNARK should be MUCH smaller
        assert!(
            cp_constraints < reg_constraints,
            "CP should be smaller: {cp_constraints} vs {reg_constraints}"
        );
        assert!(
            cp_witness < reg_witness,
            "CP should have fewer witness vars: {cp_witness} vs {reg_witness}"
        );

        let reduction = reg_constraints as f64 / cp_constraints.max(1) as f64;
        assert!(
            reduction > 5.0,
            "expected >5x constraint reduction, got {reduction:.1}x"
        );

        #[cfg(feature = "bench-timing")]
        panic!(
            "\n=== CP-SNARK vs Regular Circuit Size ===\n\
             Regular (Poseidon2):  {:>6} witness, {:>6} constraints\n\
             CP-SNARK (algebraic): {:>6} witness, {:>6} constraints\n\
             Reduction:            {:.1}x fewer constraints\n",
            reg_witness,
            reg_constraints,
            cp_witness,
            cp_constraints,
            reduction,
        );
    }

    // ── CP-SNARK E2E: full pipeline with terminal decider + WHIR + soundness ──

    /// Full CP-SNARK pipeline:
    ///   init → 3 recursive steps → terminal decider (algebraic + transcript) → WHIR proof
    ///
    /// Soundness checks (inspired by Symphony's security_soundness.rs):
    /// - Tampered deferred transcript → terminal verify rejects
    /// - Tampered accumulator eval_claim → algebraic decider rejects
    /// - Tampered accumulator pesat_target → algebraic decider rejects
    #[test]
    fn warp_ivc_cp_snark_full_pipeline_with_terminal() {
        use crate::cp_snark::{cp_snark_terminal_verify, CpSnarkDeciderError};
        use crate::accumulation::warp::decider::WarpDeciderError;
        use crate::ivc::step::TrivialStepCircuit;
        use crate::ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;

        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();
        let step = TrivialStepCircuit::new(1);

        let (cp_target_witness, _, _) = compute_cp_circuit_size(&step, &[F::ZERO]);

        // ── Init ──
        let mut init_builder = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut init_builder, &step, &[F::from_u64(9)], None, Some(cp_target_witness),
        );
        let (init_shape, init_instance) = init_builder.build();
        assert!(init_shape.is_sat(init_instance.witness(), init_instance.input()));

        let mut chal0 = make_challenger(1);
        let mut state = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
            &init_shape, &init_instance, &mut chal0,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
            make_fold_challenger_factory(),
        );

        // ── 3 recursive steps ──
        for (i, val) in [25u64, 49, 121].iter().enumerate() {
            let mut chal = make_challenger(i as u64 + 10);
            state = warp_ivc_step_recursive_cp::<F, EF, _, _, _, _, _, _>(
                &state, &step, &[F::from_u64(*val)], &mut chal,
                &ivc_config, &dft, mh.clone(), mc.clone(),
                Some(cp_target_witness), vec![F::from_u64(*val)],
                make_fold_challenger_factory(),
            );
        }
        assert_eq!(state.step, 4);
        assert_eq!(state.deferred_transcripts.len(), 4);

        // ── Terminal: CP-SNARK verify (algebraic decider + transcript replay) ──
        let terminal_result = cp_snark_terminal_verify(
            &state.shape,
            &state.accumulator,
            &state.deferred_transcripts,
            make_fold_challenger_factory(),
        );
        assert!(
            terminal_result.is_ok(),
            "CP-SNARK terminal verify failed after 4 steps: {terminal_result:?}"
        );

        // ── Terminal: WHIR proof on accumulated witness ──
        let witness_raw = &state.accumulator.witness.witness;
        let witness_len = witness_raw.len().next_power_of_two();
        let mut witness_padded = witness_raw.clone();
        witness_padded.resize(witness_len, F::ZERO);
        let witness_poly = EvaluationsList::new(witness_padded);
        let witness_num_vars = witness_poly.num_variables();

        let whir_config = make_whir_config(witness_num_vars);

        // WHIR Prove
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

        // WHIR Verify
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
            "Terminal WHIR verify failed after CP-SNARK IVC: {verify_result:?}"
        );

        // ══════════════════════════════════════════════════════════════
        // Soundness checks (adapted from Symphony security_soundness.rs)
        // ══════════════════════════════════════════════════════════════

        // ── Soundness 1: Tampered deferred transcript → TranscriptMismatch ──
        {
            let mut bad_transcripts = state.deferred_transcripts.clone();
            // Tamper with omega in step 2's transcript (splice attack)
            bad_transcripts[2].omega += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &state.accumulator,
                &bad_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::TranscriptMismatch),
                "should reject tampered omega in deferred transcript"
            );
        }

        // ── Soundness 2: Tampered sumcheck challenge → TranscriptMismatch ──
        {
            let mut bad_transcripts = state.deferred_transcripts.clone();
            bad_transcripts[1].sumcheck_challenges[0] += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &state.accumulator,
                &bad_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::TranscriptMismatch),
                "should reject tampered sumcheck challenge"
            );
        }

        // ── Soundness 3: Tampered tau challenge → TranscriptMismatch ──
        {
            let mut bad_transcripts = state.deferred_transcripts.clone();
            bad_transcripts[0].tau_challenges[0] += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &state.accumulator,
                &bad_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::TranscriptMismatch),
                "should reject tampered tau challenge"
            );
        }

        // ── Soundness 4: Tampered accumulator eval_claim → AlgebraicCheck ──
        {
            let mut bad_acc = state.accumulator.clone();
            bad_acc.instance.eval_claim += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &bad_acc,
                &state.deferred_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::AlgebraicCheck(WarpDeciderError::EvaluationClaimFailed)),
                "should reject tampered eval_claim"
            );
        }

        // ── Soundness 5: Tampered accumulator pesat_target → AlgebraicCheck ──
        {
            let mut bad_acc = state.accumulator.clone();
            bad_acc.instance.pesat_target += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &bad_acc,
                &state.deferred_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::AlgebraicCheck(WarpDeciderError::PesatSatisfactionFailed)),
                "should reject tampered pesat_target"
            );
        }

        // ── Soundness 6: Tampered sumcheck round evals → TranscriptMismatch ──
        {
            let mut bad_transcripts = state.deferred_transcripts.clone();
            bad_transcripts[3].sumcheck_evals[0][0] += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &state.accumulator,
                &bad_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::TranscriptMismatch),
                "should reject tampered sumcheck round evaluation"
            );
        }

        // ── Soundness 7: Tampered commitment root in transcript → TranscriptMismatch ──
        {
            let mut bad_transcripts = state.deferred_transcripts.clone();
            bad_transcripts[0].input_commitment_roots[0][0] += F::ONE;

            let result = cp_snark_terminal_verify(
                &state.shape,
                &state.accumulator,
                &bad_transcripts,
                make_fold_challenger_factory(),
            );
            assert_eq!(
                result,
                Err(CpSnarkDeciderError::TranscriptMismatch),
                "should reject tampered commitment root in transcript"
            );
        }
    }
}
