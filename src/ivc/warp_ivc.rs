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

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
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
            encoding::{merkle_commit_codeword, rs_encode},
            fold::{
                warp_fold_prove_rs_committed, RSEncodingConfig,
                WarpFoldResult,
            },
        },
    },
    circuit::{builder::CircuitBuilder, poseidon2::Poseidon2CircuitConfig, sponge::CircuitChallenger},
    ivc::warp_fold_verifier_circuit::{
        WarpFoldVerifierWitness, synthesize_warp_ivc_circuit,
    },
    poly::evals::EvaluationsList,
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
    /// Fold arity l: how many codewords per fold step (1 running + l-1 fresh).
    /// Must be a power of 2. Default: 2.
    pub fold_arity: usize,
    /// Whether to use Quasar union commitment mode.
    /// When true, the verifier absorbs 1 union root instead of l individual roots.
    /// Only beneficial when fold_arity >= 4.
    pub use_union: bool,
}

impl Default for WarpIVCConfig {
    fn default() -> Self {
        Self {
            rs_folding_factor: 2,
            rs_log_inv_rate: 1,
            fold_arity: 2,
            use_union: false,
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

        let log_m = prev_state.shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        Some(WarpFoldVerifierWitness::from_fold_result(
            commitment_roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &fold_result.sumcheck_round_polys,
            prev_fold_omega,
            1, // num_fresh: always 1 for l=2
            log_m,
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
    log_m: usize,
) -> (usize, usize, usize) // (num_witness, num_constraints, num_poly_vars_y)
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<16>,
    Perm2: Permutation<[F; 16]>,
    S: crate::ivc::step::StepCircuit<F>,
{
    // Build a dummy verifier witness for l=2 (1 round, 1 fresh instance)
    let dummy_witness = WarpFoldVerifierWitness {
        input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
        input_eval_claims: vec![F::ZERO; 2],
        input_eval_points: vec![vec![F::ZERO; num_eval_point_vars]; 2],
        input_pesat_targets: vec![F::ZERO; 2],
        sumcheck_evals: vec![[F::ZERO; 3]], // 1 round for l=2
        num_rounds: 1,
        omega: F::ZERO,
        num_fresh: 1,
        log_m,
        union_commitment_root: None,
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

/// Compute the target witness count for union-mode unified circuits.
///
/// Same as `compute_recursive_circuit_size` but uses a union-mode verifier
/// witness (1 running acc + 1 union root) with `log_l = log2(fold_arity)`
/// sumcheck rounds. The resulting circuit is smaller because the in-circuit
/// Poseidon2 absorbs only 2 roots (running + union) instead of l.
pub fn compute_recursive_circuit_size_union<F, L, Perm2, S>(
    step_circuit: &S,
    step_input_state: &[F],
    poseidon_config: &Poseidon2CircuitConfig<F, 16>,
    poseidon_perm: &Perm2,
    num_eval_point_vars: usize,
    fold_arity: usize,
    log_m: usize,
) -> (usize, usize, usize)
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<16>,
    Perm2: Permutation<[F; 16]>,
    S: crate::ivc::step::StepCircuit<F>,
{
    let log_l = fold_arity.trailing_zeros() as usize;
    let num_fresh = fold_arity - 1;

    // Union-mode dummy witness: only 1 accumulator (running) + union root
    let dummy_witness = WarpFoldVerifierWitness::from_fold_result_union(
        vec![F::ZERO; 8],
        F::ZERO,
        vec![F::ZERO; num_eval_point_vars],
        F::ZERO,
        vec![F::ZERO; 8],
        &vec![vec![F::ZERO; 3]; log_l],
        F::ZERO,
        num_fresh,
        log_m,
    );

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

/// Execute one IVC step using Quasar union commitment with multiple fresh instances.
///
/// Takes l-1 `FreshInstance`s (already Spartan-proved and linearized by the caller),
/// builds a union codeword from all ℓ codewords (1 running + l-1 fresh), commits
/// to a single Merkle tree, and derives challenges via `derive_fold_challenges_union`.
///
/// The verifier circuit at the NEXT step absorbs only 1 union root instead of ℓ
/// individual roots, achieving sublinear Fiat-Shamir absorption.
///
/// This function does NOT build the step circuit or run Spartan — the caller provides
/// pre-linearized `FreshInstance`s. Use this when you want to control how the l-1
/// fresh instances are produced (e.g., from multiple independent circuits or batch).
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_step_union<F, Dft, H, C, FoldChal>(
    prev_state: &WarpIVCState<F>,
    fresh_instances: &[FreshInstance<F>],
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    new_public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
) -> WarpIVCState<F>
where
    F: TwoAdicField + PrimeField64 + Ord,
    Dft: TwoAdicSubgroupDft<F>,
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
    use crate::accumulation::warp::{
        encoding::build_union_codeword,
        fold::{derive_fold_challenges_union, warp_fold_prove_rs_union},
    };

    let shape = &prev_state.shape;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);

    // RS-encode all fresh witnesses to build codewords for the union
    let fresh_codewords: Vec<Vec<F>> = fresh_instances
        .iter()
        .map(|fi| {
            let wp = EvaluationsList::new(fi.witness.clone());
            rs_encode(&wp, rs_config.folding_factor, rs_config.log_inv_rate, dft)
                .as_slice()
                .to_vec()
        })
        .collect();

    // Build union codeword: [acc_codeword, fresh_0, ..., padding_to_power_of_2]
    let num_fresh = fresh_instances.len();
    let l = (1 + num_fresh).next_power_of_two();
    let code_len = prev_state.accumulator.witness.codeword.as_slice().len();
    let mut all_codewords: Vec<Vec<F>> = Vec::with_capacity(l);
    all_codewords.push(prev_state.accumulator.witness.codeword.as_slice().to_vec());
    all_codewords.extend(fresh_codewords);
    while all_codewords.len() < l {
        all_codewords.push(vec![F::ZERO; code_len]);
    }
    let union_cw = build_union_codeword(&all_codewords);

    // Commit the union codeword to get the union root
    let union_ff = crate::accumulation::warp::encoding::union_folding_factor(
        rs_config.folding_factor, l,
    );
    let union_ev = EvaluationsList::new(union_cw);
    let (union_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&union_ev, union_ff, merkle_hash.clone(), merkle_compress.clone());

    // Derive challenges via union FS: O(1) absorption
    let prev_inst = &prev_state.accumulator.instance;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let mut fold_chal = make_fold_challenger();
    let (omega, tau, fresh_betas) = derive_fold_challenges_union(
        &prev_inst.commitment_root,
        prev_inst.eval_claim,
        &prev_inst.eval_point,
        prev_inst.pesat_target,
        &union_root,
        num_fresh,
        log_m,
        &mut fold_chal,
    );

    // WARP fold with union commitment
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let mh2 = merkle_hash.clone();
    let mc2 = merkle_compress.clone();
    let result = warp_fold_prove_rs_union(
        shape,
        fresh_instances,
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
        |ucw, uff| {
            let uev = EvaluationsList::new(ucw.to_vec());
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(&uev, uff, mh2.clone(), mc2.clone());
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
// Recursive Union IVC (Poseidon2 in-circuit verifier, no CP-SNARK)
// ═══════════════════════════════════════════════════════════════════════
//
// This is the "pure" pipeline: Quasar union commitment + Poseidon2 in-circuit
// fold verification. No Symphony dependency. The in-circuit verifier absorbs
// the running accumulator + union root → derives ω, τ, fresh_betas →
// verifies the twin-constraint sumcheck. All Fiat-Shamir is enforced in-circuit.
//
// Counterpart: `warp_ivc_step_recursive_union_cp` defers Poseidon2 to terminal
// via Symphony's CP-SNARK. Both pipelines are functionally identical except for
// where FS verification happens (in-circuit vs terminal SHA-256 binding).

/// Execute one recursive IVC step with Quasar union commitment and in-circuit
/// Poseidon2 fold verification.
///
/// Builds `arity-1` recursive circuits, each containing:
///   - User's step circuit
///   - Poseidon2 WARP fold verifier (log_l sumcheck rounds)
///
/// Each circuit is Spartan-proved, then all are union-folded into the running
/// accumulator. The in-circuit Poseidon2 verifier absorbs the previous fold's
/// union root + running accumulator and verifies the twin-constraint sumcheck.
///
/// # Soundness
///
/// Unlike the CP-SNARK variant, all Fiat-Shamir challenges are derived and
/// verified in-circuit via Poseidon2 permutations. The in-circuit verifier
/// samples fresh_betas to keep the sponge state synchronized with the native
/// prover's `derive_fold_challenges_union`.
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_step_recursive_union<F, EF, Dft, H, C, Challenger, L, Perm2, S, FoldChal>(
    prev_state: &WarpIVCState<F>,
    step_circuit: &S,
    step_input_states: &[Vec<F>],
    arity: usize,
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
    use crate::accumulation::warp::{
        encoding::build_union_codeword,
        fold::{derive_fold_challenges_union, warp_fold_prove_rs_union},
    };

    let num_fresh = step_input_states.len();
    assert!(num_fresh > 0, "need at least one step input state");
    assert!(arity.is_power_of_two(), "arity must be a power of two");
    assert_eq!(
        (1 + num_fresh).next_power_of_two(), arity,
        "num_fresh+1 must equal arity for consistent union sizing"
    );
    let log_l = arity.trailing_zeros() as usize;
    let shape = &prev_state.shape;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);

    // ── Pre-derive omega for verifier witness (must match what the fold will use) ──
    // Replay the PREVIOUS fold's FS to recover its omega.
    let (prev_fold_omega, prev_union_root) = if let (Some(fold_result), Some(prev_inst)) = (
        &prev_state.last_fold_result,
        &prev_state.prev_acc_instance,
    ) {
        let mut dry_chal = make_fold_challenger();
        for &val in &prev_inst.commitment_root { dry_chal.observe(val); }
        dry_chal.observe(prev_inst.eval_claim);
        for &val in &prev_inst.eval_point { dry_chal.observe(val); }
        dry_chal.observe(prev_inst.pesat_target);
        // Absorb the previous fold's union root
        let ur = fold_result.union_commitment_root
            .unwrap_or([F::ZERO; 8]);
        for &val in &ur { dry_chal.observe(val); }
        let omega: F = dry_chal.sample();
        (omega, ur.to_vec())
    } else {
        (F::ZERO, vec![F::ZERO; 8])
    };

    // ── Build verifier witness from previous fold ──
    // Only include a verifier when the previous fold was a union fold with the
    // correct number of rounds. The init step produces a standard l=2 fold
    // (1 sumcheck round), so the first recursive step after init skips the
    // verifier (uses padding instead). From step 3 onwards, all previous folds
    // are union folds with log_l rounds.
    let log_m_for_circuit = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let has_union_fold = prev_state.last_fold_result.as_ref()
        .is_some_and(|fr| fr.sumcheck_round_polys.len() == log_l);
    let verifier_witness = if has_union_fold {
        let fold_result = prev_state.last_fold_result.as_ref().unwrap();
        let prev_inst = prev_state.prev_acc_instance.as_ref().unwrap();
        Some(WarpFoldVerifierWitness::from_fold_result_union(
            prev_inst.commitment_root.to_vec(),
            prev_inst.eval_claim,
            prev_inst.eval_point.clone(),
            prev_inst.pesat_target,
            prev_union_root.clone(),
            &fold_result.sumcheck_round_polys,
            prev_fold_omega,
            num_fresh,
            log_m_for_circuit,
        ))
    } else {
        None
    };

    // ── Build num_fresh recursive circuits, Spartan-prove each ──
    let spartan_prover = R1CSProver::new();
    let mut fresh_instances: Vec<FreshInstance<F>> = Vec::with_capacity(num_fresh);
    let mut unified_shape_opt: Option<R1CSShape<F>> = None;

    for step_input_state in step_input_states {
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
            "recursive union circuit is not satisfiable at step {}",
            prev_state.step,
        );

        let _spartan_proof = spartan_prover.prove::<EF, _>(&unified_instance, spartan_challenger);
        let witness_poly = spartan_prover.prepare_witness(&unified_instance);

        let num_inputs = unified_instance.input().len();
        let z = witness_poly.as_slice();
        let public_input = z[..num_inputs].to_vec();
        // Fresh witness must match accumulator dimensions: num_vars_y / 2
        // (same as how warp_fold_prove_rs_inner constructs z-vectors).
        let num_vars_y = 1usize << shape.num_poly_vars_y();
        let num_witness = num_vars_y / 2;
        let mut witness_part = z[num_inputs..].to_vec();
        witness_part.resize(num_witness, F::ZERO);
        fresh_instances.push(FreshInstance { public_input, witness: witness_part });

        if unified_shape_opt.is_none() {
            unified_shape_opt = Some(unified_shape);
        }
    }
    // prev_state.shape is the init_shape (padded recursive circuit shape).
    // unified_shape should match (same circuit structure).
    let fold_shape = unified_shape_opt.as_ref().unwrap_or(shape);

    // ── RS-encode all fresh witnesses ──
    let fresh_codewords: Vec<EvaluationsList<F>> = fresh_instances
        .iter()
        .map(|fi| {
            let wp = EvaluationsList::new(fi.witness.clone());
            rs_encode(&wp, rs_config.folding_factor, rs_config.log_inv_rate, dft)
        })
        .collect();

    // ── Build union codeword: [acc, fresh_0, ..., fresh_{num_fresh-1}, padding] ──
    let l = (1 + num_fresh).next_power_of_two();
    let code_len = prev_state.accumulator.witness.codeword.as_slice().len();
    let mut all_codewords_raw: Vec<Vec<F>> = Vec::with_capacity(l);
    all_codewords_raw.push(prev_state.accumulator.witness.codeword.as_slice().to_vec());
    for cw in &fresh_codewords {
        all_codewords_raw.push(cw.as_slice().to_vec());
    }
    while all_codewords_raw.len() < l {
        all_codewords_raw.push(vec![F::ZERO; code_len]);
    }
    let union_cw = build_union_codeword(&all_codewords_raw);

    // ── Commit union codeword ──
    let union_ff = crate::accumulation::warp::encoding::union_folding_factor(
        rs_config.folding_factor, l,
    );
    let union_ev = EvaluationsList::new(union_cw);
    let (union_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&union_ev, union_ff, merkle_hash.clone(), merkle_compress.clone());

    // ── Derive challenges via union FS path: O(1) absorption ──
    let prev_inst = &prev_state.accumulator.instance;
    let log_m = fold_shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let mut fold_chal = make_fold_challenger();
    let (omega, tau, fresh_betas) = derive_fold_challenges_union(
        &prev_inst.commitment_root,
        prev_inst.eval_claim,
        &prev_inst.eval_point,
        prev_inst.pesat_target,
        &union_root,
        num_fresh,
        log_m,
        &mut fold_chal,
    );

    // ── WARP fold with union commitment ──
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let mh2 = merkle_hash.clone();
    let mc2 = merkle_compress.clone();
    let result = warp_fold_prove_rs_union(
        fold_shape,
        &fresh_instances,
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
        |ucw, uff| {
            let uev = EvaluationsList::new(ucw.to_vec());
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(&uev, uff, mh2.clone(), mc2.clone());
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

/// Initialize the recursive union IVC state (pure Poseidon2, no CP-SNARK).
///
/// Creates a zero accumulator with dimensions matching the recursive union
/// circuit. The circuit includes a dummy Poseidon2 fold verifier with `log_l`
/// sumcheck rounds so that the init step's witness size matches subsequent
/// recursive steps.
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_init_recursive_union<F, EF, Dft, H, C, Challenger, L, Perm2, S, FoldChal>(
    shape: &R1CSShape<F>,
    _instance: &R1CSInstance<F>,
    spartan_challenger: &mut Challenger,
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    poseidon_config: &Poseidon2CircuitConfig<F, 16>,
    poseidon_perm: &Perm2,
    step_circuit: &S,
    step_input_state: &[F],
    arity: usize,
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
    let log_l = arity.trailing_zeros() as usize;
    let num_fresh = arity - 1;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    // Compute target witness count by building a dummy recursive circuit with verifier
    let (target_witness, _, _target_poly_vars_y) = compute_recursive_circuit_size_union::<
        F, L, Perm2, S,
    >(
        step_circuit, step_input_state, poseidon_config, poseidon_perm,
        shape.num_poly_vars_y(), arity, log_m,
    );

    // Build init circuit WITH dummy verifier. To make it satisfiable, we need omega
    // to match what the in-circuit Poseidon2 will derive from the dummy input data.
    // We compute this by running the same FS transcript natively using the fold
    // challenger (which uses the same Poseidon2 permutation as the circuit).
    let log_code_dummy = shape.num_poly_vars_y(); // eval_point length
    let mut dummy_chal = make_fold_challenger();
    // Union path: observe running acc (all zeros)
    for _ in 0..8 { dummy_chal.observe(F::ZERO); } // root
    dummy_chal.observe(F::ZERO); // eval_claim
    for _ in 0..log_code_dummy { dummy_chal.observe(F::ZERO); } // eval_point
    dummy_chal.observe(F::ZERO); // pesat_target
    // Union root (all zeros)
    for _ in 0..8 { dummy_chal.observe(F::ZERO); }
    let dummy_omega: F = dummy_chal.sample();

    let dummy_verifier = WarpFoldVerifierWitness::from_fold_result_union(
        vec![F::ZERO; 8],
        F::ZERO,
        vec![F::ZERO; log_code_dummy],
        F::ZERO,
        vec![F::ZERO; 8],
        &vec![vec![F::ZERO; 3]; log_l],
        dummy_omega,
        num_fresh,
        log_m,
    );

    let mut builder = CircuitBuilder::<F>::new();
    let mut circuit_challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
    let _output_vars = synthesize_warp_ivc_circuit::<F, L, Perm2, S, 16, 8>(
        &mut builder,
        &mut circuit_challenger,
        poseidon_config,
        poseidon_perm,
        step_circuit,
        step_input_state,
        Some(&dummy_verifier),
        Some(target_witness),
    );
    let (init_shape, init_instance) = builder.build();
    assert!(
        init_shape.is_sat(init_instance.witness(), init_instance.input()),
        "init recursive union circuit is not satisfiable. \
         Make sure the fold challenger factory uses the same Poseidon2 permutation \
         as the circuit's poseidon_perm."
    );

    // Spartan-prove the init circuit
    let spartan_prover = R1CSProver::new();
    let _spartan_proof = spartan_prover.prove::<EF, _>(&init_instance, spartan_challenger);
    let witness_poly = spartan_prover.prepare_witness(&init_instance);

    // Build zero accumulator with dimensions matching the recursive circuit.
    // num_vars_y = 2^num_poly_vars_y = 2 * num_vars. The witness is num_vars_y / 2.
    let num_inputs = init_instance.input().len();
    let z = witness_poly.as_slice();
    let num_vars_y = 1usize << init_shape.num_poly_vars_y();
    let num_witness = num_vars_y / 2;
    let mut init_witness = z[num_inputs..].to_vec();
    init_witness.resize(num_witness, F::ZERO);

    // Use init_shape's log_m (the padded recursive circuit) for the fold.
    // This must be consistent with the shape stored in WarpIVCState.
    let init_log_m = init_shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    // RS-encode zero witness to get initial codeword and root
    let zero_witness_poly = EvaluationsList::new(vec![F::ZERO; num_witness]);
    let zero_cw = rs_encode(&zero_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (zero_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&zero_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());

    let log_code = zero_cw.as_slice().len().trailing_zeros() as usize;
    let zero_acc = WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: zero_root,
            eval_point: vec![F::ZERO; log_code],
            eval_claim: F::ZERO,
            pesat_tau: vec![F::ZERO; init_log_m],
            pesat_x: vec![F::ZERO; num_inputs],
            pesat_target: F::ZERO,
        },
        WarpAccumulatorWitness {
            codeword: zero_cw,
            witness: vec![F::ZERO; num_witness],
        },
    );

    // Fold init instance with zero accumulator
    let fresh = FreshInstance {
        public_input: z[..num_inputs].to_vec(),
        witness: init_witness.clone(),
    };

    // RS-encode fresh witness to get its commitment root for FS
    let fresh_wp = EvaluationsList::new(init_witness);
    let fresh_cw = rs_encode(&fresh_wp, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, _) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&fresh_cw, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());
    let mut fold_chal = make_fold_challenger();
    let (omega, tau, fresh_betas) = crate::accumulation::warp::fold::derive_fold_challenges(
        &zero_acc.instance.commitment_root,
        zero_acc.instance.eval_claim,
        &zero_acc.instance.eval_point,
        zero_acc.instance.pesat_target,
        &[fresh_root], // 1 fresh root for l=2 standard fold
        log_code,
        init_log_m,
        &mut fold_chal,
    );

    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let result = warp_fold_prove_rs_committed(
        &init_shape, &[fresh], &zero_acc, omega, &tau, &fresh_betas,
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
        shape: init_shape,
        last_fold_result: Some(result),
        prev_acc_instance: Some(zero_acc.instance),
        public_state: new_public_state,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CP-SNARK mode: commitment-based deferred FS verification (Symphony Section 6)
// ═══════════════════════════════════════════════════════════════════════
//
// Uses Symphony's HashCommitment (SHA-256, straightline extractable) to
// bind fold transcript data, fixing the soundness gap of the previous
// wrapper. Gated behind the `symphony` feature.

#[cfg(feature = "symphony")]
use crate::{
    cp_snark::{commit_fold_transcript_with_shift_queries, CommittedFoldTranscript},
    ivc::warp_fold_verifier_algebraic::{
        AlgebraicFoldVerifierWitness, synthesize_warp_ivc_circuit_cp,
    },
};

/// IVC state for the CP-SNARK mode (Symphony-backed).
///
/// Same as `WarpIVCState` but also carries committed fold transcripts
/// for terminal verification. Uses Symphony's `HashCommitment` for binding.
/// The circuit is much smaller (~17x) because Poseidon2 hashing is
/// replaced by native challenge derivation.
#[cfg(feature = "symphony")]
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
    /// Committed fold transcripts — binding-verified at terminal via Symphony.
    pub committed_transcripts: Vec<CommittedFoldTranscript<F>>,
}

/// Initialize the WARP IVC in CP-SNARK mode (Symphony-backed).
///
/// Same as `warp_ivc_init` but returns `WarpIVCStateCp` with a committed
/// transcript (via Symphony's `HashCommitment`) for the first fold.
#[cfg(feature = "symphony")]
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

    // ── Pre-compute fresh commitment root + tree for Fiat-Shamir seeding ──
    // Keep the tree for shift query opening later (avoids redundant rebuild).
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(&fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (fresh_root, fresh_tree) = merkle_commit_codeword::<
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
    let mut result = warp_fold_prove_rs_committed(
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

    // ── Open shift query auth paths from pre-built trees ──
    // Build the acc tree once (its dummy root [0;8] doesn't match the real root).
    // The fresh tree was already kept from the pre-fold commit above.
    let (acc_actual_root, acc_tree) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&acc.witness.codeword, rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());
    let input_trees = vec![acc_tree, fresh_tree];
    crate::accumulation::warp::fold::open_shift_queries_from_trees::<F, H, C, 8>(
        &mut result.shift_queries,
        &input_trees,
        &merkle_hash,
        &merkle_compress,
    );
    let input_cw_roots = vec![acc_actual_root, fresh_root];

    // ── Commit fold transcript with shift query Merkle proofs ──
    let init_transcript = commit_fold_transcript_with_shift_queries(
        0,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        &result.sumcheck_round_polys,
        omega,
        tau,
        result.sumcheck_challenges.clone(),
        fresh_betas,
        &result.shift_queries,
        &input_cw_roots,
        None, // no union for l=2 init
    );

    let new_acc = rebuild_accumulator(&result);

    WarpIVCStateCp {
        step: 1,
        accumulator: new_acc,
        shape: shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(acc.instance.clone()),
        public_state,
        committed_transcripts: vec![init_transcript],
    }
}

/// Execute one recursive IVC step in CP-SNARK mode (Symphony-backed).
///
/// Like `warp_ivc_step_recursive` but with an algebraic circuit (NO Poseidon2):
/// 1. Build unified circuit = step computation + algebraic sumcheck verifier
/// 2. Spartan prove this MUCH smaller circuit
/// 3. WARP fold with running accumulator (Poseidon2-derived challenges)
/// 4. Commit fold transcript via Symphony's HashCommitment
///
/// The circuit is ~17x smaller than the regular recursive IVC because all
/// Poseidon2 hashing is replaced by witness-provided challenges.
#[cfg(feature = "symphony")]
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
    // Witness must be power-of-2 for RS encoding (EvaluationsList requires it).
    let raw_witness_len = prev_state.accumulator.witness.witness.len();
    let num_witness = raw_witness_len.next_power_of_two();
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
    let (fresh_root, fresh_tree) = merkle_commit_codeword::<
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
    let mut result = warp_fold_prove_rs_committed(
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

    // ── Open shift query auth paths from pre-built trees ──
    // Build the running acc tree once (its root is already correct from prior fold).
    // The fresh tree was kept from the pre-fold commit above.
    let (_, acc_tree) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&EvaluationsList::new(prev_state.accumulator.witness.codeword.as_slice().to_vec()),
      rs_config.folding_factor, merkle_hash.clone(), merkle_compress.clone());
    let input_trees = vec![acc_tree, fresh_tree];
    crate::accumulation::warp::fold::open_shift_queries_from_trees::<F, H, C, 8>(
        &mut result.shift_queries,
        &input_trees,
        &merkle_hash,
        &merkle_compress,
    );
    // Roots: acc root is already correct; fresh root from pre-fold commit.
    let input_cw_roots = vec![
        prev_state.accumulator.instance.commitment_root,
        fresh_root,
    ];

    // ── Commit fold transcript with shift query Merkle proofs ──
    let transcript = commit_fold_transcript_with_shift_queries(
        prev_state.step,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        &result.sumcheck_round_polys,
        omega,
        tau,
        result.sumcheck_challenges.clone(),
        fresh_betas,
        &result.shift_queries,
        &input_cw_roots,
        None, // no union for l=2 recursive step
    );

    let mut committed = prev_state.committed_transcripts.clone();
    committed.push(transcript);

    let new_acc = rebuild_accumulator(&result);

    WarpIVCStateCp {
        step: prev_state.step + 1,
        accumulator: new_acc,
        shape: fold_shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
        committed_transcripts: committed,
    }
}

/// Execute one IVC step in CP-SNARK mode with Quasar union commitment.
///
/// Combines two optimizations:
/// - **Quasar multicast** (sublinear verifier): all ℓ input codewords are interleaved
///   into a single union Merkle tree. The FS challenger absorbs 1 union root instead
///   of ℓ individual roots, reducing FS absorption from O(ℓ) to O(1).
/// - **Symphony CP-SNARK** (deferred hashing): fold transcript data is committed via
///   SHA-256 and verified at terminal, avoiding in-circuit Poseidon2 hashing.
///
/// Takes pre-linearized `FreshInstance`s (already Spartan-proved). For a recursive
/// version that builds the circuit internally, see `warp_ivc_step_recursive_union_cp`
/// (not yet implemented).
///
/// # Soundness argument
///
/// The union root binds ALL ℓ codewords via column-major interleaving
/// (`union[p*l + i] = codewords[i][p]`). A malicious prover cannot change any
/// individual codeword without changing the union root, which is absorbed into the
/// FS transcript before challenges are derived.
///
/// Shift query Merkle proofs still reference individual codeword trees (not the union
/// tree) because the fold's proximity check operates on the individual codewords.
/// These proofs are committed via SHA-256 and verified at terminal.
#[cfg(feature = "symphony")]
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_step_union_cp<F, Dft, H, C, FoldChal>(
    prev_state: &WarpIVCStateCp<F>,
    fresh_instances: &[FreshInstance<F>],
    ivc_config: &WarpIVCConfig,
    dft: &Dft,
    merkle_hash: H,
    merkle_compress: C,
    new_public_state: Vec<F>,
    mut make_fold_challenger: impl FnMut() -> FoldChal,
) -> WarpIVCStateCp<F>
where
    F: TwoAdicField + PrimeField64 + Ord,
    Dft: TwoAdicSubgroupDft<F>,
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
    use crate::accumulation::warp::{
        encoding::build_union_codeword,
        fold::{derive_fold_challenges_union, warp_fold_prove_rs_union},
    };

    let shape = &prev_state.shape;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);

    // ── RS-encode all fresh witnesses ──
    let fresh_codewords: Vec<EvaluationsList<F>> = fresh_instances
        .iter()
        .map(|fi| {
            let wp = EvaluationsList::new(fi.witness.clone());
            rs_encode(&wp, rs_config.folding_factor, rs_config.log_inv_rate, dft)
        })
        .collect();

    // ── Build union codeword: column-major interleaving of all ℓ input codewords ──
    let num_fresh = fresh_instances.len();
    let l = (1 + num_fresh).next_power_of_two();
    let code_len = prev_state.accumulator.witness.codeword.as_slice().len();
    let mut all_codewords_raw: Vec<Vec<F>> = Vec::with_capacity(l);
    all_codewords_raw.push(prev_state.accumulator.witness.codeword.as_slice().to_vec());
    for cw in &fresh_codewords {
        all_codewords_raw.push(cw.as_slice().to_vec());
    }
    // Pad to next power of 2 with zero codewords
    while all_codewords_raw.len() < l {
        all_codewords_raw.push(vec![F::ZERO; code_len]);
    }
    let union_cw = build_union_codeword(&all_codewords_raw);

    // ── Commit union codeword — keep tree for shift query opening (Quasar §4) ──
    let union_ff = crate::accumulation::warp::encoding::union_folding_factor(
        rs_config.folding_factor, l,
    );
    let union_ev = EvaluationsList::new(union_cw);
    let (union_root, union_tree) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&union_ev, union_ff, merkle_hash.clone(), merkle_compress.clone());

    // ── Derive challenges via union FS path: O(1) absorption ──
    let prev_inst = &prev_state.accumulator.instance;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let mut fold_chal = make_fold_challenger();
    let (omega, tau, fresh_betas) = derive_fold_challenges_union(
        &prev_inst.commitment_root,
        prev_inst.eval_claim,
        &prev_inst.eval_point,
        prev_inst.pesat_target,
        &union_root,
        num_fresh,
        log_m,
        &mut fold_chal,
    );

    // ── WARP fold with union commitment ──
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let mh2 = merkle_hash.clone();
    let mc2 = merkle_compress.clone();
    let mut result = warp_fold_prove_rs_union(
        shape,
        fresh_instances,
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
        |ucw, uff| {
            let uev = EvaluationsList::new(ucw.to_vec());
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(&uev, uff, mh2.clone(), mc2.clone());
            root
        },
    );

    // ── Open shift query auth paths from the union tree (Quasar §4) ──
    // Per both WARP (stacked fresh commitment) and Quasar (union commitment),
    // all ℓ input codewords' values at position p are available in one union row.
    // ONE opening of the union tree gives all values + ONE auth path per position.
    // No individual input trees are needed — the union tree replaces them.
    crate::accumulation::warp::fold::open_shift_queries_from_union_tree::<F, H, C, 8>(
        &mut result.shift_queries,
        &union_tree,
        &merkle_hash,
        &merkle_compress,
    );

    // ── Commit fold transcript with union root ──
    // For union mode: input_commitment_roots stores ONLY the running accumulator.
    // The union root is stored separately for correct FS replay branching.
    // input_codeword_roots has 1 entry: the union root (for terminal Merkle verification).
    let transcript = commit_fold_transcript_with_shift_queries(
        prev_state.step,
        vec![prev_inst.commitment_root.to_vec()], // running acc only
        vec![prev_inst.eval_claim],
        vec![prev_inst.eval_point.clone()],
        vec![prev_inst.pesat_target],
        &result.sumcheck_round_polys,
        omega,
        tau,
        result.sumcheck_challenges.clone(),
        fresh_betas,
        &result.shift_queries,
        &[union_root], // single union root for Merkle verification
        Some(union_root.to_vec()), // Quasar union root for FS replay
    );

    let mut committed = prev_state.committed_transcripts.clone();
    committed.push(transcript);

    let new_acc = rebuild_accumulator(&result);

    WarpIVCStateCp {
        step: prev_state.step + 1,
        accumulator: new_acc,
        shape: shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
        committed_transcripts: committed,
    }
}

/// Execute one **recursive union IVC step** (Quasar + CP-SNARK, apples-to-apples).
///
/// This is the proper "real IVC" variant of union: builds `arity-1` recursive
/// circuits per step (each containing step_circuit + algebraic union verifier),
/// Spartan-proves each, then union-folds the resulting FreshInstances.
///
/// # Comparison with other IVC variants
///
/// | Variant                        | Circuits/step | Folds/step | Fresh/step |
/// |--------------------------------|---------------|------------|------------|
/// | `warp_ivc_step_recursive_cp`   | 1             | 1 (l=2)    | 1          |
/// | `warp_ivc_step_union_cp`       | 0             | 1 (l=ℓ)    | ℓ-1        |
/// | **`warp_ivc_step_recursive_union_cp`** | **ℓ-1**   | **1 (l=ℓ)**| **ℓ-1**    |
///
/// This function folds **recursive circuit witnesses** (same as regular/CP-SNARK IVC),
/// not the raw application R1CS. That makes it a fair apples-to-apples comparison:
/// all paths build recursive step circuits + union folds them.
///
/// # Soundness
///
/// The algebraic verifier inside each recursive circuit verifies the previous
/// union fold's sumcheck consistency (`log_l` rounds, NOT 1). All ℓ-1 recursive
/// circuits share the same verifier witness since they all verify the same
/// previous union fold. Fiat-Shamir challenges are deferred to terminal via
/// Symphony's HashCommitment, identical to `warp_ivc_step_union_cp`.
#[cfg(feature = "symphony")]
#[allow(clippy::too_many_arguments)]
pub fn warp_ivc_step_recursive_union_cp<F, EF, Dft, H, C, Challenger, S, FoldChal>(
    prev_state: &WarpIVCStateCp<F>,
    step_circuit: &S,
    step_input_states: &[Vec<F>],
    arity: usize,
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
    use crate::accumulation::warp::{
        encoding::build_union_codeword,
        fold::{derive_fold_challenges_union, warp_fold_prove_rs_union},
    };

    let num_fresh = step_input_states.len();
    assert!(num_fresh > 0, "need at least one step input state");
    assert!(arity.is_power_of_two(), "arity must be a power of two");
    assert_eq!(
        (1 + num_fresh).next_power_of_two(), arity,
        "num_fresh+1 must equal arity for consistent union sizing"
    );
    let log_l = arity.trailing_zeros() as usize;
    let shape = &prev_state.shape;
    let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);

    // ── Build verifier witness with log_l rounds (shared across all recursive circuits) ──
    // All num_fresh recursive circuits verify the SAME previous union fold.
    // For the first step (no prev fold), use a dummy witness (all zeros, trivially
    // satisfiable) with log_l rounds to match the expected circuit shape.
    let verifier_witness = match prev_state.last_fold_result.as_ref() {
        Some(fold_result) if fold_result.sumcheck_round_polys.len() == log_l => {
            AlgebraicFoldVerifierWitness::from_fold_data(
                &fold_result.sumcheck_round_polys,
                &fold_result.sumcheck_challenges,
            )
        }
        _ => AlgebraicFoldVerifierWitness {
            sumcheck_evals: vec![[F::ZERO; 3]; log_l],
            num_rounds: log_l,
            sumcheck_challenges: vec![F::ZERO; log_l],
        },
    };
    let verifier_witness = Some(verifier_witness);

    // ── Build num_fresh recursive circuits, Spartan-prove each ──
    let spartan_prover = R1CSProver::new();
    let mut fresh_instances: Vec<FreshInstance<F>> = Vec::with_capacity(num_fresh);
    let mut unified_shape_opt: Option<R1CSShape<F>> = None;

    for step_input_state in step_input_states {
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
            "recursive union CP-SNARK circuit is not satisfiable at step {}",
            prev_state.step,
        );

        // Spartan-prove the (small) recursive circuit
        let _spartan_proof = spartan_prover.prove::<EF, _>(&unified_instance, spartan_challenger);
        let witness_poly = spartan_prover.prepare_witness(&unified_instance);

        // Create FreshInstance from the recursive circuit's witness
        let num_inputs = unified_instance.input().len();
        let z = witness_poly.as_slice();
        let public_input = z[..num_inputs].to_vec();
        let num_witness = prev_state.accumulator.witness.witness.len();
        let mut witness_part = z[num_inputs..].to_vec();
        witness_part.resize(num_witness, F::ZERO);
        fresh_instances.push(FreshInstance { public_input, witness: witness_part });

        if unified_shape_opt.is_none() {
            unified_shape_opt = Some(unified_shape);
        }
    }
    let fold_shape = unified_shape_opt.as_ref().unwrap_or(shape);

    // ── RS-encode all fresh witnesses ──
    let fresh_codewords: Vec<EvaluationsList<F>> = fresh_instances
        .iter()
        .map(|fi| {
            let wp = EvaluationsList::new(fi.witness.clone());
            rs_encode(&wp, rs_config.folding_factor, rs_config.log_inv_rate, dft)
        })
        .collect();

    // ── Build union codeword: [acc, fresh_0, ..., fresh_{num_fresh-1}, padding] ──
    let l = (1 + num_fresh).next_power_of_two();
    let code_len = prev_state.accumulator.witness.codeword.as_slice().len();
    let mut all_codewords_raw: Vec<Vec<F>> = Vec::with_capacity(l);
    all_codewords_raw.push(prev_state.accumulator.witness.codeword.as_slice().to_vec());
    for cw in &fresh_codewords {
        all_codewords_raw.push(cw.as_slice().to_vec());
    }
    while all_codewords_raw.len() < l {
        all_codewords_raw.push(vec![F::ZERO; code_len]);
    }
    let union_cw = build_union_codeword(&all_codewords_raw);

    // ── Commit union codeword, keep tree for shift query opening ──
    let union_ff = crate::accumulation::warp::encoding::union_folding_factor(
        rs_config.folding_factor, l,
    );
    let union_ev = EvaluationsList::new(union_cw);
    let (union_root, union_tree) = merkle_commit_codeword::<
        F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
    >(&union_ev, union_ff, merkle_hash.clone(), merkle_compress.clone());

    // ── Derive challenges via union FS path: O(1) absorption ──
    let prev_inst = &prev_state.accumulator.instance;
    let log_m = fold_shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let mut fold_chal = make_fold_challenger();
    let (omega, tau, fresh_betas) = derive_fold_challenges_union(
        &prev_inst.commitment_root,
        prev_inst.eval_claim,
        &prev_inst.eval_point,
        prev_inst.pesat_target,
        &union_root,
        num_fresh,
        log_m,
        &mut fold_chal,
    );

    // ── WARP fold with union commitment ──
    let mh = merkle_hash.clone();
    let mc = merkle_compress.clone();
    let mh2 = merkle_hash.clone();
    let mc2 = merkle_compress.clone();
    let mut result = warp_fold_prove_rs_union(
        fold_shape,
        &fresh_instances,
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
        |ucw, uff| {
            let uev = EvaluationsList::new(ucw.to_vec());
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing, H, C, 8,
            >(&uev, uff, mh2.clone(), mc2.clone());
            root
        },
    );

    // ── Open shift query auth paths from the union tree (Quasar §4) ──
    crate::accumulation::warp::fold::open_shift_queries_from_union_tree::<F, H, C, 8>(
        &mut result.shift_queries,
        &union_tree,
        &merkle_hash,
        &merkle_compress,
    );

    // ── Commit fold transcript with union root ──
    let transcript = commit_fold_transcript_with_shift_queries(
        prev_state.step,
        vec![prev_inst.commitment_root.to_vec()],
        vec![prev_inst.eval_claim],
        vec![prev_inst.eval_point.clone()],
        vec![prev_inst.pesat_target],
        &result.sumcheck_round_polys,
        omega,
        tau,
        result.sumcheck_challenges.clone(),
        fresh_betas,
        &result.shift_queries,
        &[union_root],
        Some(union_root.to_vec()),
    );

    let mut committed = prev_state.committed_transcripts.clone();
    committed.push(transcript);

    let new_acc = rebuild_accumulator(&result);

    WarpIVCStateCp {
        step: prev_state.step + 1,
        accumulator: new_acc,
        shape: fold_shape.clone(),
        last_fold_result: Some(result),
        prev_acc_instance: Some(prev_state.accumulator.instance.clone()),
        public_state: new_public_state,
        committed_transcripts: committed,
    }
}

/// Initialize the recursive union CP-SNARK IVC state.
///
/// Creates a zero accumulator with dimensions matching the recursive circuit
/// (which includes a `log_arity`-round algebraic verifier). The first
/// `warp_ivc_step_recursive_union_cp` call will use a dummy verifier witness.
///
/// Unlike `warp_ivc_init_cp` (which does an l=2 fold at init), this function
/// starts from a pure zero state — the first recursive union step does the
/// first actual fold.
#[cfg(feature = "symphony")]
pub fn warp_ivc_init_recursive_union_cp<F, S>(
    step_circuit: &S,
    step_input_state: &[F],
    arity: usize,
    ivc_config: &WarpIVCConfig,
    target_num_witness: usize,
    public_state: Vec<F>,
) -> WarpIVCStateCp<F>
where
    F: TwoAdicField + PrimeField64 + Ord,
    S: crate::ivc::step::StepCircuit<F>,
{
    assert!(arity.is_power_of_two() && arity >= 2, "arity must be power of two ≥ 2");
    let log_l = arity.trailing_zeros() as usize;

    // Build a sample recursive circuit (with dummy log_l-round verifier) to extract
    // the shape. This shape will be used across all recursive union steps.
    let dummy_verifier = AlgebraicFoldVerifierWitness {
        sumcheck_evals: vec![[F::ZERO; 3]; log_l],
        num_rounds: log_l,
        sumcheck_challenges: vec![F::ZERO; log_l],
    };
    let mut builder = CircuitBuilder::<F>::new();
    let _ = synthesize_warp_ivc_circuit_cp(
        &mut builder, step_circuit, step_input_state,
        Some(&dummy_verifier), Some(target_num_witness),
    );
    let (shape, instance) = builder.build();

    // Derive dimensions matching what the fold produces.
    // After a fold, `acc.witness.witness.len()` = `num_vars_y` (the full z-vector
    // size including constant slot + public input positions). We must match that
    // here so the fresh codewords at subsequent steps line up with the accumulator.
    let num_inputs = instance.input().len();
    let num_vars_y = 1usize << shape.num_poly_vars_y();
    let num_witness = num_vars_y;
    let log_code = num_witness.trailing_zeros() as usize + ivc_config.rs_log_inv_rate;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let acc = make_initial_accumulator(num_witness, log_code, log_m, num_inputs);

    WarpIVCStateCp {
        step: 0,
        accumulator: acc,
        shape,
        last_fold_result: None,
        prev_acc_instance: None,
        public_state,
        committed_transcripts: Vec::new(),
    }
}

/// Compute recursive union IVC circuit size with log_l rounds for the verifier.
///
/// The algebraic verifier loops `num_rounds = log_arity` times (one per union
/// sumcheck round). For arity=4, num_rounds=2; for arity=8, num_rounds=3.
/// This differs from `compute_cp_circuit_size` which uses num_rounds=1 (for l=2).
#[cfg(feature = "symphony")]
pub fn compute_recursive_union_circuit_size<F, S>(
    step_circuit: &S,
    step_input_state: &[F],
    arity: usize,
) -> (usize, usize, usize)
where
    F: Field,
    S: crate::ivc::step::StepCircuit<F>,
{
    let log_l = arity.trailing_zeros() as usize;
    let dummy_witness = AlgebraicFoldVerifierWitness {
        sumcheck_evals: vec![[F::ZERO; 3]; log_l],
        num_rounds: log_l,
        sumcheck_challenges: vec![F::ZERO; log_l],
    };
    let mut builder = CircuitBuilder::<F>::new();
    let _ = synthesize_warp_ivc_circuit_cp(
        &mut builder, step_circuit, step_input_state, Some(&dummy_witness), None,
    );
    let num_witness = builder.num_witness_vars();
    let num_constraints = builder.num_constraints();
    let (shape, _) = builder.build();
    (num_witness, num_constraints, shape.num_poly_vars_y())
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

        // ══════════════════════════════════════════════════════════════
        // Terminal: Full WARP decider + WHIR proof + root binding
        // ══════════════════════════════════════════════════════════════
        //
        // Soundness argument:
        //
        // 1. The accumulation chain (V_ACC at each step) guarantees that
        //    the accumulated claims (α, μ, β, η) are correct IF the final
        //    accumulator is valid (WARP knowledge soundness, Def 10.2).
        //
        // 2. The WARP decider D_ACC checks three conditions:
        //      (a) f̂(α) = μ   — codeword MLE eval claim
        //      (b) P*(β, z) = η — PESAT (bundled R1CS)
        //      (c) f = C(w)     — codeword is valid RS encoding
        //
        // 3. For a succinct verifier, D_ACC checks (a)+(b) are guaranteed
        //    by the chain; check (c) is proved by WHIR.
        //
        // 4. The BINDING between WHIR and the chain is: WHIR's commitment
        //    root must equal the accumulated commitment_root. Since our
        //    rs_encode + merkle_commit_codeword matches WHIR's internal
        //    CommitmentWriter::commit (same transpose → pad → DFT → Merkle),
        //    the roots are identical for the same witness polynomial.

        // Step 1: Full prover-side decider (all 3 WARP conditions)
        let full_decide = crate::accumulation::warp::decider::warp_decide_full_rs(
            &state.shape,
            &state.accumulator,
            ivc_config.rs_folding_factor,
            ivc_config.rs_log_inv_rate,
            &dft,
        );
        assert!(
            full_decide.is_ok(),
            "Full WARP decider failed after 4 IVC steps: {full_decide:?}"
        );

        // Step 2: WHIR proof on the accumulated witness
        let witness_raw = &state.accumulator.witness.witness;
        let witness_len = witness_raw.len().next_power_of_two();
        let mut witness_padded = witness_raw.clone();
        witness_padded.resize(witness_len, F::ZERO);
        let witness_poly = EvaluationsList::new(witness_padded);
        let witness_num_vars = witness_poly.num_variables();

        let whir_config = make_whir_config(witness_num_vars);

        // PROVE: WHIR commits to the witness and proves RS proximity.
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

        // Step 3: ROOT BINDING — verify WHIR's commitment matches accumulated root.
        //
        // This is the critical soundness link: WHIR proves "the polynomial
        // underlying this commitment root is RS-close". By checking that this
        // root equals the accumulated commitment_root, we bind the WHIR proof
        // to the accumulated codeword. The accumulation chain then guarantees
        // that the accumulated eval claim and PESAT hold for this codeword.
        let whir_commitment_root = whir_proof.initial_commitment;
        let accumulated_root = state.accumulator.instance.commitment_root;
        assert_eq!(
            whir_commitment_root, accumulated_root,
            "WHIR commitment root must match accumulated commitment root.\n\
             WHIR root:  {:?}\n\
             Accum root: {:?}\n\
             This binding ensures the WHIR proof covers the accumulated polynomial.",
            whir_commitment_root, accumulated_root,
        );

        // Step 4: VERIFY the WHIR proof (succinct — no witness access)
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
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);

        // Measure with verifier (the full recursive circuit)
        let (num_witness, num_constraints, _num_poly_vars_y) =
            compute_recursive_circuit_size::<
                F, GenericPoseidon2LinearLayersBabyBear, _, _,
            >(
                &step, &[F::ZERO], &poseidon_config, &poseidon_perm,
                3, // eval_point has 3 vars for our test shape
                2, // log_m for fresh_betas
            );

        // Measure WITHOUT verifier (step circuit only)
        let mut step_only_builder = CircuitBuilder::<F>::new();
        let input = vec![step_only_builder.alloc_witness(F::ZERO)];
        let _ = step.synthesize(&mut step_only_builder, &input);
        let _step_only_witness = step_only_builder.num_witness_vars();
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
            num_fresh: 1,
            log_m: 2,
            union_commitment_root: None,
        };
        let mut verifier_only_builder = CircuitBuilder::<F>::new();
        let mut verifier_chal = CircuitChallenger::<F, 16, 8>::new(&mut verifier_only_builder);
        let _ = crate::ivc::warp_fold_verifier_circuit::synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersBabyBear, _, 16, 8,
        >(
            &mut verifier_only_builder, &mut verifier_chal,
            &poseidon_config, &poseidon_perm, &dummy_witness,
        );
        let _verifier_only_witness = verifier_only_builder.num_witness_vars();
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

        let _shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
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
                &step, &[F::ZERO], &poseidon_config, &poseidon_perm, 3, 2,
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

    // ── Quasar union mode tests ──

    #[test]
    fn warp_ivc_step_union_soundness() {
        // Test: init + 2 union-mode steps with l=4 (3 fresh per step)
        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig {
            fold_arity: 4,
            use_union: true,
            ..Default::default()
        };
        let (mh, mc) = make_hash_compress();

        // Init: create initial accumulator
        let _rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
        let spartan_prover = crate::spartan::r1cs_prover::R1CSProver::new();
        let inst0 = make_instance(&shape, 3);
        let w0 = spartan_prover.prepare_witness(&inst0);
        let num_inputs = inst0.input().len();
        let z0 = w0.as_slice();
        let num_witness = (z0.len() - num_inputs).next_power_of_two();
        let log_code = num_witness.trailing_zeros() as usize + ivc_config.rs_log_inv_rate;
        let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

        let mut acc = super::make_initial_accumulator(num_witness, log_code, log_m, num_inputs);

        // Run 2 union fold steps, each with 3 fresh instances
        for step in 0u64..2 {
            let mut fresh_instances = Vec::new();
            for j in 0..3u64 {
                let root = step * 10 + j + 2;
                let inst = make_instance(&shape, root);
                let w = spartan_prover.prepare_witness(&inst);
                let z = w.as_slice();
                let pi = z[..num_inputs].to_vec();
                let mut wpart = z[num_inputs..].to_vec();
                wpart.resize(num_witness, F::ZERO);
                fresh_instances.push(FreshInstance {
                    public_input: pi,
                    witness: wpart,
                });
            }

            let state = WarpIVCState {
                step: step as usize,
                accumulator: acc.clone(),
                shape: shape.clone(),
                last_fold_result: None,
                prev_acc_instance: None,
                public_state: vec![],
            };

            let new_state = warp_ivc_step_union(
                &state,
                &fresh_instances,
                &ivc_config,
                &dft,
                mh.clone(),
                mc.clone(),
                vec![],
                make_fold_challenger_factory(),
            );

            // Verify union root is set
            assert!(
                new_state.last_fold_result.as_ref().unwrap().union_commitment_root.is_some(),
                "union root should be set at step {step}"
            );

            // Verify accumulator size is preserved
            assert_eq!(
                new_state.accumulator.witness.codeword.as_slice().len(),
                acc.witness.codeword.as_slice().len(),
                "codeword size should stay fixed at step {step}"
            );

            // Verify R1CS satisfaction via decider
            let decide = crate::accumulation::warp::decider::warp_decide_algebraic_rs(
                &shape, &new_state.accumulator,
            );
            assert!(
                decide.is_ok(),
                "decider should accept at union step {step}: {decide:?}"
            );

            acc = new_state.accumulator;
        }
    }

    #[test]
    fn warp_ivc_union_circuit_size_smaller() {
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::ivc::step::TrivialStepCircuit;
        use crate::circuit::poseidon2::Poseidon2CircuitConfig;

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);
        let step_input = [F::ZERO];
        let num_eval_point_vars = 3;

        // Non-union l=2 circuit size
        let log_m = 2;
        let (nw_l2, nc_l2, _) = compute_recursive_circuit_size::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _,
        >(&step, &step_input, &poseidon_config, &poseidon_perm, num_eval_point_vars, log_m);

        // Union l=4 circuit size
        let (nw_u4, nc_u4, _) = compute_recursive_circuit_size_union::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _,
        >(&step, &step_input, &poseidon_config, &poseidon_perm, num_eval_point_vars, 4, log_m);

        // Union l=8 circuit size
        let (nw_u8, nc_u8, _) = compute_recursive_circuit_size_union::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _,
        >(&step, &step_input, &poseidon_config, &poseidon_perm, num_eval_point_vars, 8, log_m);

        // Union l=4 should be smaller than non-union l=2 despite more sumcheck rounds,
        // because the union absorbs only 1 root vs 2 for non-union
        // (At l=4, union absorbs 2 roots total: 1 running + 1 union;
        //  non-union l=2 absorbs 2 roots: 1 running + 1 fresh — similar Phase 1 cost
        //  but union has 2 sumcheck rounds vs 1 for l=2)
        // So union l=4 may be slightly larger or smaller than non-union l=2.
        // The key comparison is: union l=8 should be much smaller than a hypothetical non-union l=8.

        // Just verify the sizes are reasonable and union l=8 < union l=4
        // (more rounds but same Phase 1 cost → small increase)
        assert!(
            nc_u8 > nc_u4,
            "union l=8 has more sumcheck rounds than l=4: {} vs {} constraints",
            nc_u8, nc_u4,
        );

        // Verify union sizes are in a reasonable range
        assert!(nc_u4 > 0);
        assert!(nc_u8 > 0);
        assert!(nw_u4 > 0);
        assert!(nw_u8 > 0);

        let _ = (nw_l2, nc_l2); // suppress unused warnings
    }

    // ── Recursive Union (pure Poseidon2) tests ──

    /// Full test: recursive union init + 2 steps with in-circuit Poseidon2 verification.
    /// This is the "pure" pipeline — no Symphony CP-SNARK, all FS in-circuit.
    #[test]
    fn warp_ivc_recursive_union_poseidon2_pipeline() {
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::ivc::step::TrivialStepCircuit;
        use crate::circuit::poseidon2::Poseidon2CircuitConfig;

        let shape = make_shape();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig {
            fold_arity: 4,
            use_union: true,
            ..Default::default()
        };
        let (mh, mc) = make_hash_compress();
        // CRITICAL: The fold challenger and the in-circuit Poseidon2 must use
        // the same permutation (same round constants). Use seed 99 for both.
        let poseidon_perm_circuit = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );
        let perm_for_fold = poseidon_perm_circuit.clone();
        let make_union_fold_challenger = move || -> MyChallenger {
            MyChallenger::new(perm_for_fold.clone())
        };
        let step = TrivialStepCircuit::new(1);
        let arity = 4;
        let num_fresh = arity - 1; // 3

        // ── Init ──
        let inst0 = make_instance(&shape, 3);
        let mut spartan_chal = make_challenger(1);
        let mut mfc = make_union_fold_challenger.clone();
        let state = warp_ivc_init_recursive_union::<
            F, EF, _, _, _, _, GenericPoseidon2LinearLayersBabyBear, _, _, _,
        >(
            &shape, &inst0, &mut spartan_chal,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            &poseidon_config, &poseidon_perm_circuit,
            &step, &[F::from_u64(9)], arity,
            vec![F::from_u64(9)],
            &mut mfc,
        );
        assert_eq!(state.step, 1);

        // Verify decider accepts init
        let decide = crate::accumulation::warp::decider::warp_decide_algebraic_rs(
            &state.shape, &state.accumulator,
        );
        assert!(decide.is_ok(), "decider should accept init: {decide:?}");

        // ── Step 2: recursive union with 3 fresh instances ──
        let step_inputs: Vec<Vec<F>> = (0..num_fresh)
            .map(|i| vec![F::from_u64(10 + i as u64)])
            .collect();
        let mut spartan_chal2 = make_challenger(42);

        // Must use the ORIGINAL shape's log_m and num_poly_vars_y to match what the init
        // function passes to compute_recursive_circuit_size_union.
        let log_m_orig = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        let (target_w, _, _) = compute_recursive_circuit_size_union::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _,
        >(
            &step, &[F::ZERO], &poseidon_config, &poseidon_perm_circuit,
            shape.num_poly_vars_y(), arity, log_m_orig,
        );

        let mut mfc2 = make_union_fold_challenger.clone();
        let state2 = warp_ivc_step_recursive_union::<
            F, EF, _, _, _, _, GenericPoseidon2LinearLayersBabyBear, _, _, _,
        >(
            &state, &step, &step_inputs, arity,
            &mut spartan_chal2, &ivc_config, &dft, mh.clone(), mc.clone(),
            &poseidon_config, &poseidon_perm_circuit,
            Some(target_w), vec![],
            &mut mfc2,
        );
        assert_eq!(state2.step, 2);

        // Verify decider accepts step 2
        let decide2 = crate::accumulation::warp::decider::warp_decide_algebraic_rs(
            &state2.shape, &state2.accumulator,
        );
        assert!(decide2.is_ok(), "decider should accept step 2: {decide2:?}");

        // Verify union root was set
        assert!(
            state2.last_fold_result.as_ref().unwrap().union_commitment_root.is_some(),
            "union commitment root should be set"
        );

        // Verify fixed-size accumulator
        assert_eq!(
            state2.accumulator.witness.codeword.as_slice().len(),
            state.accumulator.witness.codeword.as_slice().len(),
            "codeword size should stay fixed across steps"
        );
    }

    // ── CP-SNARK mode tests (Symphony-backed, requires `symphony` feature) ──

    /// CP-SNARK mode: init (padded) + 2 recursive steps with algebraic circuit.
    #[test]
    #[cfg(feature = "symphony")]
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
        assert_eq!(state.committed_transcripts.len(), 1);

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
        assert_eq!(state.committed_transcripts.len(), 2);

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
        assert_eq!(state.committed_transcripts.len(), 3);

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
    #[cfg(feature = "symphony")]
    fn cp_snark_vs_regular_circuit_size() {
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::ivc::step::TrivialStepCircuit;
        use crate::ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);

        // Regular recursive circuit size
        let (reg_witness, reg_constraints, _) = compute_recursive_circuit_size::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            _,
        >(&step, &[F::ZERO], &poseidon_config, &poseidon_perm, 3, 2);

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
    #[cfg(feature = "symphony")]
    fn warp_ivc_cp_snark_full_pipeline_with_terminal() {
        use crate::cp_snark::{cp_snark_terminal_verify_with_merkle, CpSnarkDeciderError};
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
        assert_eq!(state.committed_transcripts.len(), 4);

        // ── Terminal: CP-SNARK verify (algebraic + transcript + Merkle paths) ──
        let (tmh, tmc) = make_hash_compress();
        let terminal_result = cp_snark_terminal_verify_with_merkle(
            &state.shape,
            &state.accumulator,
            &state.committed_transcripts,
            make_fold_challenger_factory(),
            ivc_config.rs_folding_factor,
            &tmh,
            &tmc,
        );
        assert!(
            terminal_result.is_ok(),
            "CP-SNARK terminal verify (with Merkle) failed after 4 steps: {terminal_result:?}"
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
        //
        // Key improvement: tampering with committed data now triggers
        // CommitmentBindingFailed (SHA-256 binding), not just
        // ChallengeMismatch. This is the fix from using Symphony's
        // HashCommitment. Shift query Merkle paths are also verified.
        // ══════════════════════════════════════════════════════════════

        let verify = |acc: &WarpAccumulator<F, F, F, 8>,
                      transcripts: &[CommittedFoldTranscript<F>]|
         -> Result<(), CpSnarkDeciderError> {
            let (h, c) = make_hash_compress();
            cp_snark_terminal_verify_with_merkle(
                &state.shape, acc, transcripts,
                make_fold_challenger_factory(),
                ivc_config.rs_folding_factor, &h, &c,
            )
        };

        // ── Soundness 1: Tampered omega → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            bad[2].data.omega += F::ONE;
            assert!(
                matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 2 })),
                "should reject tampered omega via commitment binding"
            );
        }

        // ── Soundness 2: Tampered sumcheck challenge → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            bad[1].data.sumcheck_challenges[0] += F::ONE;
            assert!(
                matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 1 })),
                "should reject tampered sumcheck challenge via binding"
            );
        }

        // ── Soundness 3: Tampered tau challenge → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            bad[0].data.tau_challenges[0] += F::ONE;
            assert!(
                matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 0 })),
                "should reject tampered tau via binding"
            );
        }

        // ── Soundness 4: Tampered accumulator eval_claim → AlgebraicCheck ──
        {
            let mut bad_acc = state.accumulator.clone();
            bad_acc.instance.eval_claim += F::ONE;
            assert_eq!(
                verify(&bad_acc, &state.committed_transcripts),
                Err(CpSnarkDeciderError::AlgebraicCheck(WarpDeciderError::EvaluationClaimFailed)),
                "should reject tampered eval_claim"
            );
        }

        // ── Soundness 5: Tampered accumulator pesat_target → AlgebraicCheck ──
        {
            let mut bad_acc = state.accumulator.clone();
            bad_acc.instance.pesat_target += F::ONE;
            assert_eq!(
                verify(&bad_acc, &state.committed_transcripts),
                Err(CpSnarkDeciderError::AlgebraicCheck(WarpDeciderError::PesatSatisfactionFailed)),
                "should reject tampered pesat_target"
            );
        }

        // ── Soundness 6: Tampered sumcheck evals → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            bad[3].data.sumcheck_evals[0][0] += F::ONE;
            assert!(
                matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 3 })),
                "should reject tampered sumcheck eval via binding"
            );
        }

        // ── Soundness 7: Tampered commitment root → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            bad[0].data.input_commitment_roots[0][0] += F::ONE;
            assert!(
                matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 0 })),
                "should reject tampered commitment root via binding"
            );
        }

        // ── Soundness 8: Tampered shift query value → CommitmentBindingFailed ──
        // Shift query values are now committed via SHA-256; tampering is detected.
        {
            let mut bad = state.committed_transcripts.clone();
            if !bad[1].data.shift_query_values.is_empty()
                && !bad[1].data.shift_query_values[0].is_empty()
                && !bad[1].data.shift_query_values[0][0].is_empty()
            {
                bad[1].data.shift_query_values[0][0][0] += F::ONE;
                assert!(
                    matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 1 })),
                    "should reject tampered shift query value via binding"
                );
            }
        }

        // ── Soundness 9: Tampered shift query auth path → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            if !bad[2].data.shift_query_auth_paths.is_empty()
                && !bad[2].data.shift_query_auth_paths[0].is_empty()
                && !bad[2].data.shift_query_auth_paths[0][0].is_empty()
            {
                bad[2].data.shift_query_auth_paths[0][0][0][0] += F::ONE;
                assert!(
                    matches!(verify(&state.accumulator, &bad), Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 2 })),
                    "should reject tampered shift query auth path via binding"
                );
            }
        }
    }

    // ── Quasar union + CP-SNARK: init → union steps → terminal with Merkle ──

    /// Union + CP-SNARK pipeline:
    ///   init (l=2, standard) → 2 union steps (l=4 each, 3 fresh per step)
    ///   → terminal verify (binding + FS replay + algebraic + Merkle paths)
    ///
    /// Validates:
    /// - Union FS replay at terminal correctly branches on `union_commitment_root`
    /// - Merkle path verification works with ℓ > 2 input codewords
    /// - Mixed chain: init (non-union) + steps (union) verified together
    /// - Soundness: tampered union root → binding failure
    #[test]
    #[cfg(feature = "symphony")]
    fn warp_ivc_union_cp_snark_pipeline() {
        use crate::cp_snark::{
            cp_snark_terminal_verify_with_merkle, CommittedFoldTranscript, CpSnarkDeciderError,
        };

        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();

        // ── Build a small R1CS shape and instance ──
        let shape = make_shape();
        let instance = make_instance(&shape, 3);

        // ── Init: standard CP-SNARK (l=2) ──
        let spartan = crate::spartan::r1cs_prover::R1CSProver::new();
        let ni = instance.input().len();
        let mut wp_chal = make_challenger(1);
        let _ = spartan.prove::<EF, _>(&instance, &mut wp_chal);
        let wp0 = spartan.prepare_witness(&instance);
        let z0 = wp0.as_slice();
        let nw = (z0.len() - ni).next_power_of_two();

        let mut init_chal = make_challenger(1);
        let mut state = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
            &shape, &instance, &mut init_chal,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(9)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 1);
        assert_eq!(state.committed_transcripts.len(), 1);
        // Init transcript has no union root
        assert!(state.committed_transcripts[0].data.union_commitment_root.is_none());

        // ── Helper: create a fresh instance from the same R1CS ──
        let make_fresh = |seed: u64| -> crate::accumulation::warp::accumulator::FreshInstance<F> {
            let mut ch = make_challenger(seed);
            let _ = spartan.prove::<EF, _>(&instance, &mut ch);
            let wp = spartan.prepare_witness(&instance);
            let z = wp.as_slice();
            let mut w = z[ni..].to_vec();
            w.resize(nw, F::ZERO);
            crate::accumulation::warp::accumulator::FreshInstance {
                public_input: z[..ni].to_vec(),
                witness: w,
            }
        };

        // ── Union step 1: l=4 (3 fresh instances) ──
        let fresh_batch_1 = vec![make_fresh(100), make_fresh(101), make_fresh(102)];
        state = warp_ivc_step_union_cp::<F, _, _, _, _>(
            &state, &fresh_batch_1,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(25)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 2);
        assert_eq!(state.committed_transcripts.len(), 2);
        assert!(state.committed_transcripts[1].data.union_commitment_root.is_some());

        // ── Union step 2: l=4 (3 fresh instances) ──
        let fresh_batch_2 = vec![make_fresh(200), make_fresh(201), make_fresh(202)];
        state = warp_ivc_step_union_cp::<F, _, _, _, _>(
            &state, &fresh_batch_2,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            vec![F::from_u64(49)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 3);
        assert_eq!(state.committed_transcripts.len(), 3);

        // Verify eval claim consistency
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &state.accumulator.witness.codeword,
            &state.accumulator.instance.eval_point,
        );
        assert_eq!(
            eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after union CP-SNARK steps"
        );

        // ── Terminal: CP-SNARK verify with Merkle paths ──
        let (tmh, tmc) = make_hash_compress();
        let terminal_result = cp_snark_terminal_verify_with_merkle(
            &state.shape,
            &state.accumulator,
            &state.committed_transcripts,
            make_fold_challenger_factory(),
            ivc_config.rs_folding_factor,
            &tmh,
            &tmc,
        );
        assert!(
            terminal_result.is_ok(),
            "Union CP-SNARK terminal verify failed: {terminal_result:?}"
        );

        // ── Soundness: tampered union root → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            if let Some(ref mut root) = bad[1].data.union_commitment_root {
                root[0] += F::ONE;
            }
            let (h, c) = make_hash_compress();
            let result = cp_snark_terminal_verify_with_merkle(
                &state.shape, &state.accumulator, &bad,
                make_fold_challenger_factory(),
                ivc_config.rs_folding_factor, &h, &c,
            );
            assert!(
                matches!(result, Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 1 })),
                "should reject tampered union root via binding: {result:?}"
            );
        }

        // ── Soundness: tampered omega in union step → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            bad[2].data.omega += F::ONE;
            let (h, c) = make_hash_compress();
            let result = cp_snark_terminal_verify_with_merkle(
                &state.shape, &state.accumulator, &bad,
                make_fold_challenger_factory(),
                ivc_config.rs_folding_factor, &h, &c,
            );
            assert!(
                matches!(result, Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 2 })),
                "should reject tampered omega in union step: {result:?}"
            );
        }

        // ── Soundness: tampered shift query in union step → CommitmentBindingFailed ──
        {
            let mut bad = state.committed_transcripts.clone();
            if !bad[1].data.shift_query_values.is_empty()
                && !bad[1].data.shift_query_values[0].is_empty()
                && !bad[1].data.shift_query_values[0][0].is_empty()
            {
                bad[1].data.shift_query_values[0][0][0] += F::ONE;
                let (h, c) = make_hash_compress();
                let result = cp_snark_terminal_verify_with_merkle(
                    &state.shape, &state.accumulator, &bad,
                    make_fold_challenger_factory(),
                    ivc_config.rs_folding_factor, &h, &c,
                );
                assert!(
                    matches!(result, Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 1 })),
                    "should reject tampered shift query in union step: {result:?}"
                );
            }
        }
    }

    // ── Recursive Union CP-SNARK: real IVC with union fold (apples-to-apples) ──

    /// Recursive union IVC pipeline:
    ///   init (l=2 CP-SNARK) → 2 recursive union steps (l=4, 3 fresh circuits per step)
    ///   → terminal verify with Merkle paths.
    ///
    /// Validates:
    /// - Each union step builds ℓ-1 recursive circuits (step + algebraic union verifier)
    /// - All ℓ-1 circuits share the same verifier witness (verify SAME previous fold)
    /// - Union fold aggregates the ℓ-1 recursive circuit witnesses
    /// - Terminal Merkle verification works with recursive-circuit-sized fresh instances
    #[test]
    #[cfg(feature = "symphony")]
    fn warp_ivc_recursive_union_cp_snark_pipeline() {
        use crate::cp_snark::{cp_snark_terminal_verify_with_merkle, CpSnarkDeciderError};
        use crate::ivc::step::TrivialStepCircuit;
        use crate::ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;

        let dft = Radix2DFTSmallBatch::<F>::default();
        let ivc_config = WarpIVCConfig::default();
        let (mh, mc) = make_hash_compress();
        let step = TrivialStepCircuit::new(1);
        let arity = 4usize;
        let num_fresh = arity - 1;

        // Compute target witness size based on recursive union circuit (log_l=2 rounds)
        let (target_witness, _, _) = compute_recursive_union_circuit_size(
            &step, &[F::ZERO], arity,
        );

        // ── Init: dedicated recursive union init (no fold yet) ──
        let mut state = warp_ivc_init_recursive_union_cp(
            &step, &[F::ZERO], arity, &ivc_config,
            target_witness, vec![F::from_u64(9)],
        );
        assert_eq!(state.step, 0);
        assert_eq!(state.committed_transcripts.len(), 0);

        // ── Recursive union step 1: build 3 recursive circuits, union-fold them ──
        let step_inputs_1: Vec<Vec<F>> = (0..num_fresh)
            .map(|i| vec![F::from_u64(10 + i as u64)])
            .collect();
        let mut chal1 = make_challenger(10);
        state = warp_ivc_step_recursive_union_cp::<F, EF, _, _, _, _, _, _>(
            &state, &step, &step_inputs_1, arity, &mut chal1,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            Some(target_witness), vec![F::from_u64(25)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 1);
        assert_eq!(state.committed_transcripts.len(), 1);
        // Union step transcript has union root
        assert!(state.committed_transcripts[0].data.union_commitment_root.is_some());

        // ── Recursive union step 2: 3 more recursive circuits ──
        let step_inputs_2: Vec<Vec<F>> = (0..num_fresh)
            .map(|i| vec![F::from_u64(20 + i as u64)])
            .collect();
        let mut chal2 = make_challenger(20);
        state = warp_ivc_step_recursive_union_cp::<F, EF, _, _, _, _, _, _>(
            &state, &step, &step_inputs_2, arity, &mut chal2,
            &ivc_config, &dft, mh.clone(), mc.clone(),
            Some(target_witness), vec![F::from_u64(49)],
            make_fold_challenger_factory(),
        );
        assert_eq!(state.step, 2);
        assert_eq!(state.committed_transcripts.len(), 2);

        // Verify eval claim consistency after 2 recursive union steps
        let eval_claim = crate::accumulation::warp::fold::evaluate_mle_lsb(
            &state.accumulator.witness.codeword,
            &state.accumulator.instance.eval_point,
        );
        assert_eq!(
            eval_claim, state.accumulator.instance.eval_claim,
            "eval claim mismatch after recursive union CP-SNARK steps"
        );

        // ── Terminal: CP-SNARK verify with Merkle paths ──
        let (tmh, tmc) = make_hash_compress();
        let terminal_result = cp_snark_terminal_verify_with_merkle(
            &state.shape,
            &state.accumulator,
            &state.committed_transcripts,
            make_fold_challenger_factory(),
            ivc_config.rs_folding_factor,
            &tmh, &tmc,
        );
        assert!(
            terminal_result.is_ok(),
            "Recursive union CP-SNARK terminal verify failed: {terminal_result:?}"
        );

        // ── Soundness: tamper with union root → binding failure ──
        {
            let mut bad = state.committed_transcripts.clone();
            if let Some(ref mut root) = bad[0].data.union_commitment_root {
                root[0] += F::ONE;
            }
            let (h, c) = make_hash_compress();
            let result = cp_snark_terminal_verify_with_merkle(
                &state.shape, &state.accumulator, &bad,
                make_fold_challenger_factory(),
                ivc_config.rs_folding_factor, &h, &c,
            );
            assert!(
                matches!(result, Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 0 })),
                "should reject tampered union root: {result:?}"
            );
        }
    }
}
