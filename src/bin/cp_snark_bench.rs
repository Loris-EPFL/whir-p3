//! CP-SNARK (Symphony) + Union (Quasar) vs Regular recursive IVC benchmark.
//!
//! Compares four IVC approaches on synthetic R1CS instances:
//! - **Non-recursive**: Spartan + WARP fold, no recursive circuit
//! - **Regular IVC**: Recursive circuit embeds Poseidon2 FS (~5000+ constraints)
//! - **CP-SNARK IVC**: Algebraic-only recursive circuit (~8 constraints) + terminal SHA-256
//! - **Union CP-SNARK**: Quasar multicast (l=arity) + CP-SNARK, no recursive circuit
//!
//! Table 1 shows per-step breakdown for l=2 paths.
//! Table 2 shows throughput: for T total instances, how fast is each approach?
//!
//! Usage:
//!   cargo run --release --features symphony --bin cp_snark_bench -- <log_sizes> <num_steps> <repeats> [step_muls] [arity]
//!
//! Examples:
//!   cargo run --release --features symphony --bin cp_snark_bench -- "10,12" "2,4,8" 3
//!   cargo run --release --features symphony --bin cp_snark_bench -- "12,14" "4,8,16" 3 1000 4
//!   cargo run --release --features symphony --bin cp_snark_bench -- "14" "4,8,16,32" 3 0 8

use std::{env, time::Instant};

use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};
use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{rngs::SmallRng, SeedableRng};

use whir_p3::{
    accumulation::warp::{
        accumulator::{
            FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness,
        },
        encoding::{merkle_commit_codeword, rs_encode},
        fold::{
            warp_fold_prove_rs_committed, RSEncodingConfig,
            WarpFoldResult,
        },
    },
    circuit::{
        builder::CircuitBuilder, poseidon2::Poseidon2CircuitConfig, sponge::CircuitChallenger,
    },
    cp_snark::{
        commit_fold_transcript_with_shift_queries, cp_snark_terminal_verify_with_merkle,
        CommittedFoldTranscript,
    },
    ivc::{
        step::{StepCircuit, TrivialStepCircuit, WorkloadStepCircuit},
        warp_fold_verifier_algebraic::{
            AlgebraicFoldVerifierWitness, compute_cp_circuit_size, synthesize_warp_ivc_circuit_cp,
        },
        warp_fold_verifier_circuit::{synthesize_warp_ivc_circuit, WarpFoldVerifierWitness},
        warp_ivc::compute_recursive_circuit_size,
    },
    poly::evals::EvaluationsList,
    spartan::{
        r1cs::{R1CSInstance, R1CSShape},
        r1cs_prover::R1CSProver,
    },
};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2KoalaBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;
const DIGEST: usize = 8;
const RS_LOG_INV_RATE: usize = 1;

fn parse_csv(s: &str) -> Vec<usize> {
    s.split(',')
        .filter_map(|x| x.trim().parse().ok())
        .collect()
}

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn make_hc() -> (MyHash, MyCompress) {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    (MyHash::new(p.clone()), MyCompress::new(p))
}

/// Create a consistent (Poseidon2 permutation, circuit config) pair from the same
/// seed. Both must use identical round constants for the in-circuit verifier
/// to produce satisfying R1CS.
/// S-box degree for the configured field's Poseidon2.
/// KoalaBear uses x^3, BabyBear uses x^7.
const SBOX_DEGREE: u64 = 3; // KoalaBear

fn make_poseidon2_pair(seed: u64) -> (Perm, Poseidon2CircuitConfig<F, 16>) {
    use p3_poseidon2::poseidon2_round_numbers_128;
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    let (rounds_f, rounds_p) = poseidon2_round_numbers_128::<F>(16, SBOX_DEGREE)
        .expect("unsupported Poseidon2 parameters for this field");
    let config = Poseidon2CircuitConfig::<F, 16>::from_rng(
        rounds_f, rounds_p, SBOX_DEGREE, &mut SmallRng::seed_from_u64(seed),
    );
    (perm, config)
}

fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}

fn rebuild_acc(r: &WarpFoldResult<F>) -> WarpAccumulator<F, F, F, DIGEST> {
    let ec = whir_p3::accumulation::warp::fold::evaluate_mle_lsb(
        &r.witness.codeword,
        &r.instance.eval_point,
    );
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: r.commitment_root,
            eval_point: r.instance.eval_point.clone(),
            eval_claim: ec,
            pesat_tau: r.instance.pesat_tau.clone(),
            pesat_x: r.instance.pesat_x.clone(),
            pesat_target: r.instance.pesat_target,
        },
        r.witness.clone(),
    )
}

fn make_zero_acc(nw: usize, lc: usize, lm: usize, ni: usize) -> WarpAccumulator<F, F, F, DIGEST> {
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: [F::ZERO; DIGEST],
            eval_point: vec![F::ZERO; lc],
            eval_claim: F::ZERO,
            pesat_tau: vec![F::ZERO; lm],
            pesat_x: vec![F::ZERO; ni],
            pesat_target: F::ZERO,
        },
        WarpAccumulatorWitness {
            codeword: EvaluationsList::new(vec![F::ZERO; 1 << lc]),
            witness: vec![F::ZERO; nw],
        },
    )
}

/// Derive fold challenges from Poseidon2 challenger after observing accumulator + fresh data.
/// Returns (omega, tau, fresh_betas, challenger) -- the challenger is returned for use as
/// the sumcheck transcript_round callback.
fn derive_fold_challenges(
    acc: &WarpAccumulator<F, F, F, DIGEST>,
    fresh_root: &[F; DIGEST],
    log_m: usize,
    mut chal: MyChallenger,
) -> (F, Vec<F>, Vec<Vec<F>>, MyChallenger) {
    let log_code = acc.witness.codeword.num_variables();
    // Observe running accumulator
    for &val in &acc.instance.commitment_root {
        chal.observe(val);
    }
    chal.observe(acc.instance.eval_claim);
    for &val in &acc.instance.eval_point {
        chal.observe(val);
    }
    chal.observe(acc.instance.pesat_target);
    // Observe fresh instance
    for &val in fresh_root {
        chal.observe(val);
    }
    chal.observe(F::ZERO); // fresh eval_claim
    for _ in 0..log_code {
        chal.observe(F::ZERO);
    } // fresh eval_point
    chal.observe(F::ZERO); // fresh pesat_target
    // Derive challenges
    let omega: F = chal.sample();
    let tau: Vec<F> = (0..1).map(|_| chal.sample()).collect(); // log_l = 1
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| chal.sample()).collect())
        .collect();
    (omega, tau, fresh_betas, chal)
}

/// Pre-compute fresh commitment root by RS-encoding and Merkle-committing a witness.
fn precompute_fresh_root(
    witness: &[F],
    rs_config: &RSEncodingConfig,
    dft: &Radix2DFTSmallBatch<F>,
    mh: &MyHash,
    mc: &MyCompress,
) -> [F; DIGEST] {
    let witness_poly = EvaluationsList::new(witness.to_vec());
    let cw = rs_encode(&witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
    let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
        &cw,
        rs_config.folding_factor,
        mh.clone(),
        mc.clone(),
    );
    root
}

/// Run N steps of Spartan linearize → WARP fold (non-recursive baseline).
/// This is the same as compare_bench's "direct_fold" path.
fn run_non_recursive_fold(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    num_steps: usize,
    num_witness: usize,
    log_code: usize,
    log_m: usize,
    num_inputs: usize,
) -> (f64, f64) {
    let spartan = R1CSProver::new();
    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);
    let mut acc = make_zero_acc(num_witness, log_code, log_m, num_inputs);

    let mut spartan_us = 0.0;
    let mut fold_us = 0.0;

    for step in 0..num_steps {
        // Spartan prove
        let t1 = Instant::now();
        let mut ch = make_challenger(step as u64 + 200);
        let _ = spartan.prove::<EF, _>(instance, &mut ch);
        let w = spartan.prepare_witness(instance);
        spartan_us += t1.elapsed().as_micros() as f64;

        let z = w.as_slice();
        let pi = z[..num_inputs].to_vec();
        let mut wpart = z[num_inputs..].to_vec();
        wpart.resize(num_witness, F::ZERO);
        let fresh = FreshInstance {
            public_input: pi,
            witness: wpart,
        };

        // WARP fold with Poseidon2-derived challenges
        let t2 = Instant::now();
        let fresh_root = precompute_fresh_root(
            &fresh.witness, &rs_config, &dft, &mh, &mc,
        );
        let fold_chal = make_challenger(77);
        let (omega, tau, fresh_betas, mut fold_chal) =
            derive_fold_challenges(&acc, &fresh_root, log_m, fold_chal);
        let mhc = mh.clone();
        let mcc = mc.clone();
        let result = warp_fold_prove_rs_committed(
            shape,
            &[fresh],
            &acc,
            omega,
            &tau,
            &fresh_betas,
            &rs_config,
            &dft,
            |round_evals| {
                for &e in round_evals {
                    fold_chal.observe(e);
                }
                fold_chal.sample()
            },
            |cw, ff| {
                let (root, _) =
                    merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                        cw,
                        ff,
                        mhc.clone(),
                        mcc.clone(),
                    );
                root
            },
        );
        fold_us += t2.elapsed().as_micros() as f64;
        acc = rebuild_acc(&result);
    }

    (spartan_us, fold_us)
}

/// Run N steps of Regular recursive IVC (Poseidon2 in-circuit).
/// Returns (spartan_of_synthetic, circuit_build, spartan_of_recursive, fold) in us.
fn run_regular_recursive(
    _shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    num_steps: usize,
    _num_witness: usize,
    _log_code: usize,
    _log_m: usize,
    _num_inputs: usize,
    step_muls: usize,
) -> (f64, f64, f64, f64) {
    let step = WorkloadStepCircuit::new(step_muls);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);
    let (poseidon_perm, poseidon_config) = make_poseidon2_pair(99);

    // Probe the step circuit to determine eval_point size
    let mut probe_builder = CircuitBuilder::<F>::new();
    let probe_in = probe_builder.alloc_witness(F::ZERO);
    let _ = step.synthesize(&mut probe_builder, &[probe_in]);
    let (probe_shape, probe_inst) = probe_builder.build();
    let spartan = R1CSProver::new();
    let probe_w = spartan.prepare_witness(&probe_inst);
    let probe_ni = probe_inst.input().len();
    let probe_nw = (probe_w.num_evals() - probe_ni).next_power_of_two();
    let probe_log_code = probe_nw.trailing_zeros() as usize + RS_LOG_INV_RATE;

    let (target_w, _, _) = compute_recursive_circuit_size::<
        F,
        GenericPoseidon2LinearLayersKoalaBear,
        _,
        _,
    >(&step, &[F::ZERO], &poseidon_config, &poseidon_perm, probe_log_code);

    // Init: padded circuit (no verifier)
    let mut init_builder = CircuitBuilder::<F>::new();
    let mut init_chal = CircuitChallenger::<F, 16, 8>::new(&mut init_builder);
    let _ = synthesize_warp_ivc_circuit::<F, GenericPoseidon2LinearLayersKoalaBear, _, _, 16, 8>(
        &mut init_builder,
        &mut init_chal,
        &poseidon_config,
        &poseidon_perm,
        &step,
        &[F::from_u64(9)],
        None,
        Some(target_w),
    );
    let (init_shape, init_instance) = init_builder.build();
    let mut ch0 = make_challenger(1);
    let _ = spartan.prove::<EF, _>(&init_instance, &mut ch0);
    let init_w = spartan.prepare_witness(&init_instance);
    let ni_rec = init_instance.input().len();
    let z0 = init_w.as_slice();
    let nw_rec = (z0.len() - ni_rec).next_power_of_two();
    let mut w0 = z0[ni_rec..].to_vec();
    w0.resize(nw_rec, F::ZERO);
    let lc_rec = nw_rec.trailing_zeros() as usize + RS_LOG_INV_RATE;
    let lm_rec = init_shape
        .num_cons()
        .next_power_of_two()
        .trailing_zeros() as usize;

    let fresh0 = FreshInstance {
        public_input: z0[..ni_rec].to_vec(),
        witness: w0,
    };
    let zero_acc = make_zero_acc(nw_rec, lc_rec, lm_rec, ni_rec);
    let fresh_root0 = precompute_fresh_root(
        &fresh0.witness, &rs_config, &dft, &mh, &mc,
    );
    let init_fold_chal = make_challenger(99);
    let (omega0, tau0, fresh_betas0, mut init_fold_chal) =
        derive_fold_challenges(&zero_acc, &fresh_root0, lm_rec, init_fold_chal);
    let mh0 = mh.clone();
    let mc0 = mc.clone();
    let r0 = warp_fold_prove_rs_committed(
        &init_shape,
        &[fresh0],
        &zero_acc,
        omega0,
        &tau0,
        &fresh_betas0,
        &rs_config,
        &dft,
        |round_evals| {
            for &e in round_evals {
                init_fold_chal.observe(e);
            }
            init_fold_chal.sample()
        },
        |cw, ff| {
            let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                cw,
                ff,
                mh0.clone(),
                mc0.clone(),
            );
            root
        },
    );
    let mut acc = rebuild_acc(&r0);
    let mut prev_inst = zero_acc.instance.clone();
    let mut last_fold = r0;

    let mut synth_spartan_us = 0.0;
    let mut circuit_us = 0.0;
    let mut rec_spartan_us = 0.0;
    let mut fold_us = 0.0;

    for s in 0..num_steps {
        // 1. Spartan prove the synthetic instance (same as non-recursive)
        let t0 = Instant::now();
        let mut sch = make_challenger(s as u64 + 200);
        let _ = spartan.prove::<EF, _>(instance, &mut sch);
        synth_spartan_us += t0.elapsed().as_micros() as f64;

        // 2. Derive prev_fold_omega by replaying FS on the PREVIOUS fold's data
        //    (must match what the in-circuit Poseidon2 verifier computes)
        let prev_fold_omega = {
            let mut dry_chal = make_challenger(99);
            for &val in &prev_inst.commitment_root {
                dry_chal.observe(val);
            }
            dry_chal.observe(prev_inst.eval_claim);
            for &val in &prev_inst.eval_point {
                dry_chal.observe(val);
            }
            dry_chal.observe(prev_inst.pesat_target);
            // Observe the fresh instance from the previous fold result
            if let Some(root) = last_fold.fresh_commitment_roots.first() {
                for &val in root {
                    dry_chal.observe(val);
                }
            } else {
                for _ in 0..DIGEST {
                    dry_chal.observe(F::ZERO);
                }
            }
            if let Some(&mu) = last_fold.fresh_eval_claims.first() {
                dry_chal.observe(mu);
            } else {
                dry_chal.observe(F::ZERO);
            }
            let log_code_prev = prev_inst.eval_point.len();
            for _ in 0..log_code_prev {
                dry_chal.observe(F::ZERO);
            }
            if let Some(&eta) = last_fold.fresh_pesat_targets.first() {
                dry_chal.observe(eta);
            } else {
                dry_chal.observe(F::ZERO);
            }
            let omega: F = dry_chal.sample();
            omega
        };

        // Build verifier witness using the fresh commitment root from the previous fold
        let fresh_root_for_verifier = last_fold
            .fresh_commitment_roots
            .first()
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![F::ZERO; DIGEST]);
        let vw = WarpFoldVerifierWitness::from_fold_result(
            vec![
                prev_inst.commitment_root.to_vec(),
                fresh_root_for_verifier,
            ],
            vec![
                prev_inst.eval_claim,
                last_fold.fresh_eval_claims.first().copied().unwrap_or(F::ZERO),
            ],
            vec![
                prev_inst.eval_point.clone(),
                vec![F::ZERO; prev_inst.eval_point.len()],
            ],
            vec![
                prev_inst.pesat_target,
                last_fold.fresh_pesat_targets.first().copied().unwrap_or(F::ZERO),
            ],
            &last_fold.sumcheck_round_polys,
            prev_fold_omega,
        );

        let t1 = Instant::now();
        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = synthesize_warp_ivc_circuit::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            _,
            16,
            8,
        >(
            &mut builder,
            &mut challenger,
            &poseidon_config,
            &poseidon_perm,
            &step,
            &[F::from_u64(s as u64 + 10)],
            Some(&vw),
            Some(target_w),
        );
        let (_shape, rec_instance) = builder.build();
        circuit_us += t1.elapsed().as_micros() as f64;

        // 3. Spartan prove the recursive circuit
        let t2 = Instant::now();
        let mut rch = make_challenger(s as u64 + 500);
        let _ = spartan.prove::<EF, _>(&rec_instance, &mut rch);
        let wp = spartan.prepare_witness(&rec_instance);
        rec_spartan_us += t2.elapsed().as_micros() as f64;

        // 4. WARP fold with Poseidon2-derived challenges (seed 99 to match in-circuit)
        let z = wp.as_slice();
        let pi = z[..ni_rec].to_vec();
        let mut wpart = z[ni_rec..].to_vec();
        wpart.resize(nw_rec, F::ZERO);
        let fresh = FreshInstance {
            public_input: pi,
            witness: wpart,
        };

        let t3 = Instant::now();
        let fresh_root = precompute_fresh_root(
            &fresh.witness, &rs_config, &dft, &mh, &mc,
        );
        let fold_chal = make_challenger(99);
        let (omega, tau, fresh_betas, mut fold_chal) =
            derive_fold_challenges(&acc, &fresh_root, lm_rec, fold_chal);
        let mhc = mh.clone();
        let mcc = mc.clone();
        let result = warp_fold_prove_rs_committed(
            &init_shape,
            &[fresh],
            &acc,
            omega,
            &tau,
            &fresh_betas,
            &rs_config,
            &dft,
            |round_evals| {
                for &e in round_evals {
                    fold_chal.observe(e);
                }
                fold_chal.sample()
            },
            |cw, ff| {
                let (root, _) =
                    merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                        cw,
                        ff,
                        mhc.clone(),
                        mcc.clone(),
                    );
                root
            },
        );
        fold_us += t3.elapsed().as_micros() as f64;

        prev_inst = acc.instance.clone();
        acc = rebuild_acc(&result);
        last_fold = result;
    }

    (synth_spartan_us, circuit_us, rec_spartan_us, fold_us)
}

/// Run N steps of CP-SNARK recursive IVC (algebraic-only circuit).
/// Returns (spartan_of_synthetic, circuit_build, spartan_of_recursive, fold, terminal_verify) in us.
/// Terminal verify includes: SHA-256 binding + FS replay + algebraic decider + Merkle path check.
fn run_cp_snark_recursive(
    _shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    num_steps: usize,
    _num_witness: usize,
    _log_code: usize,
    _log_m: usize,
    _num_inputs: usize,
    step_muls: usize,
) -> (f64, f64, f64, f64, f64) {
    let step = WorkloadStepCircuit::new(step_muls);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);
    let spartan = R1CSProver::new();

    let (target_w, _, _) = compute_cp_circuit_size(&step, &[F::ZERO]);

    // Init: padded CP circuit (no verifier)
    let mut init_builder = CircuitBuilder::<F>::new();
    let _ = synthesize_warp_ivc_circuit_cp(
        &mut init_builder,
        &step,
        &[F::from_u64(9)],
        None,
        Some(target_w),
    );
    let (init_shape, init_instance) = init_builder.build();
    let mut ch0 = make_challenger(1);
    let _ = spartan.prove::<EF, _>(&init_instance, &mut ch0);
    let init_w = spartan.prepare_witness(&init_instance);
    let ni_rec = init_instance.input().len();
    let z0 = init_w.as_slice();
    let nw_rec = (z0.len() - ni_rec).next_power_of_two();
    let mut w0 = z0[ni_rec..].to_vec();
    w0.resize(nw_rec, F::ZERO);
    let lc_rec = nw_rec.trailing_zeros() as usize + RS_LOG_INV_RATE;
    let lm_rec = init_shape
        .num_cons()
        .next_power_of_two()
        .trailing_zeros() as usize;

    let fresh0 = FreshInstance {
        public_input: z0[..ni_rec].to_vec(),
        witness: w0.clone(),
    };
    let zero_acc = make_zero_acc(nw_rec, lc_rec, lm_rec, ni_rec);

    // RS-encode fresh witness for Merkle proof materialization
    let fresh_wp0 = EvaluationsList::new(fresh0.witness.clone());
    let fresh_cw0 = rs_encode(&fresh_wp0, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
    let (fresh_root0, fresh_tree0) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
        &fresh_cw0, rs_config.folding_factor, mh.clone(), mc.clone(),
    );

    let init_fold_chal = make_challenger(77);
    let (omega0, tau0, fresh_betas0, mut init_fold_chal) =
        derive_fold_challenges(&zero_acc, &fresh_root0, lm_rec, init_fold_chal);
    let mh0 = mh.clone();
    let mc0 = mc.clone();
    let mut r0 = warp_fold_prove_rs_committed(
        &init_shape,
        &[fresh0],
        &zero_acc,
        omega0,
        &tau0,
        &fresh_betas0,
        &rs_config,
        &dft,
        |round_evals| {
            for &e in round_evals {
                init_fold_chal.observe(e);
            }
            init_fold_chal.sample()
        },
        |cw, ff| {
            let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                cw,
                ff,
                mh0.clone(),
                mc0.clone(),
            );
            root
        },
    );

    // Open shift query auth paths from pre-built trees (no redundant rebuild)
    let (acc_actual_root0, acc_tree0) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
        &zero_acc.witness.codeword, rs_config.folding_factor, mh.clone(), mc.clone(),
    );
    {
        use whir_p3::accumulation::warp::fold::open_shift_queries_from_trees;
        open_shift_queries_from_trees::<F, MyHash, MyCompress, DIGEST>(
            &mut r0.shift_queries, &[acc_tree0, fresh_tree0],
            &mh, &mc,
        );
    }
    let init_transcript = commit_fold_transcript_with_shift_queries(
        0,
        vec![zero_acc.instance.commitment_root.to_vec(), fresh_root0.to_vec()],
        vec![zero_acc.instance.eval_claim, F::ZERO],
        vec![zero_acc.instance.eval_point.clone(), vec![F::ZERO; lc_rec]],
        vec![zero_acc.instance.pesat_target, F::ZERO],
        &r0.sumcheck_round_polys,
        omega0,
        tau0,
        r0.sumcheck_challenges.clone(),
        fresh_betas0,
        &r0.shift_queries,
        &[acc_actual_root0, fresh_root0],
        None, // no union for l=2
    );

    let mut acc = rebuild_acc(&r0);
    let mut last_fold = r0;
    let mut committed_transcripts = vec![init_transcript];

    let mut synth_spartan_us = 0.0;
    let mut circuit_us = 0.0;
    let mut rec_spartan_us = 0.0;
    let mut fold_us = 0.0;

    for s in 0..num_steps {
        // 1. Spartan prove synthetic instance (same as other paths)
        let t0 = Instant::now();
        let mut sch = make_challenger(s as u64 + 200);
        let _ = spartan.prove::<EF, _>(instance, &mut sch);
        synth_spartan_us += t0.elapsed().as_micros() as f64;

        // 2. Build algebraic recursive circuit (NO Poseidon2)
        let vw = AlgebraicFoldVerifierWitness::from_fold_data(
            &last_fold.sumcheck_round_polys,
            &last_fold.sumcheck_challenges,
        );

        let t1 = Instant::now();
        let mut builder = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut builder,
            &step,
            &[F::from_u64(s as u64 + 10)],
            Some(&vw),
            Some(target_w),
        );
        let (_shape, rec_instance) = builder.build();
        circuit_us += t1.elapsed().as_micros() as f64;

        // 3. Spartan prove the (tiny) recursive circuit
        let t2 = Instant::now();
        let mut rch = make_challenger(s as u64 + 500);
        let _ = spartan.prove::<EF, _>(&rec_instance, &mut rch);
        let wp = spartan.prepare_witness(&rec_instance);
        rec_spartan_us += t2.elapsed().as_micros() as f64;

        // 4. WARP fold with Poseidon2-derived challenges
        let z = wp.as_slice();
        let pi = z[..ni_rec].to_vec();
        let mut wpart = z[ni_rec..].to_vec();
        wpart.resize(nw_rec, F::ZERO);
        let fresh = FreshInstance {
            public_input: pi,
            witness: wpart.clone(),
        };

        let t3 = Instant::now();
        // RS-encode fresh for Merkle proof materialization
        let fresh_wp = EvaluationsList::new(fresh.witness.clone());
        let fresh_cw = rs_encode(&fresh_wp, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        let (fresh_root, fresh_tree) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
            &fresh_cw, rs_config.folding_factor, mh.clone(), mc.clone(),
        );

        let fold_chal = make_challenger(77);
        let (omega, tau, fresh_betas, mut fold_chal) =
            derive_fold_challenges(&acc, &fresh_root, lm_rec, fold_chal);

        // Collect FS data for transcript commitment
        let input_commitment_roots = vec![acc.instance.commitment_root.to_vec(), fresh_root.to_vec()];
        let input_eval_claims = vec![acc.instance.eval_claim, F::ZERO];
        let input_eval_points = vec![acc.instance.eval_point.clone(), vec![F::ZERO; lc_rec]];
        let input_pesat_targets = vec![acc.instance.pesat_target, F::ZERO];

        let mhc = mh.clone();
        let mcc = mc.clone();
        let mut result = warp_fold_prove_rs_committed(
            &init_shape,
            &[fresh],
            &acc,
            omega,
            &tau,
            &fresh_betas,
            &rs_config,
            &dft,
            |round_evals| {
                for &e in round_evals {
                    fold_chal.observe(e);
                }
                fold_chal.sample()
            },
            |cw, ff| {
                let (root, _) =
                    merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                        cw,
                        ff,
                        mhc.clone(),
                        mcc.clone(),
                    );
                root
            },
        );

        // Open shift query auth paths from pre-built trees (no redundant rebuild)
        let (_, acc_tree) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
            &EvaluationsList::new(acc.witness.codeword.as_slice().to_vec()),
            rs_config.folding_factor, mh.clone(), mc.clone(),
        );
        use whir_p3::accumulation::warp::fold::open_shift_queries_from_trees;
        open_shift_queries_from_trees::<F, MyHash, MyCompress, DIGEST>(
            &mut result.shift_queries, &[acc_tree, fresh_tree],
            &mh, &mc,
        );
        let input_cw_roots = [acc.instance.commitment_root, fresh_root];
        let transcript = commit_fold_transcript_with_shift_queries(
            s + 1,
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
            None, // no union for l=2
        );
        committed_transcripts.push(transcript);

        fold_us += t3.elapsed().as_micros() as f64;

        acc = rebuild_acc(&result);
        last_fold = result;
    }

    // Terminal verification: binding + FS replay + algebraic decider + Merkle paths
    let t_terminal = Instant::now();
    let terminal_result = cp_snark_terminal_verify_with_merkle(
        &init_shape,
        &acc,
        &committed_transcripts,
        || make_challenger(77),
        rs_config.folding_factor,
        &mh,
        &mc,
    );
    let terminal_us = t_terminal.elapsed().as_micros() as f64;
    assert!(terminal_result.is_ok(), "CP-SNARK terminal verify failed: {terminal_result:?}");

    (synth_spartan_us, circuit_us, rec_spartan_us, fold_us, terminal_us)
}

/// Run union CP-SNARK: each step folds `arity-1` fresh instances via Quasar union.
/// No recursive circuit — takes pre-linearized instances (like non-recursive baseline).
/// Returns (spartan_total, fold_total, terminal) in us.
/// `total_instances` = `num_steps * (arity - 1)` synthetic instances are Spartan-proved.
fn run_union_cp_snark(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    num_steps: usize,
    num_witness: usize,
    log_code: usize,
    log_m: usize,
    num_inputs: usize,
    arity: usize,
) -> (f64, f64, f64) {
    use whir_p3::accumulation::warp::{
        encoding::build_union_codeword,
        fold::{derive_fold_challenges_union, warp_fold_prove_rs_union},
    };

    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);
    let spartan = R1CSProver::new();
    let num_fresh = arity - 1; // running acc + num_fresh = arity

    let mut acc = make_zero_acc(num_witness, log_code, log_m, num_inputs);
    let mut committed_transcripts: Vec<CommittedFoldTranscript<F>> = Vec::new();

    let mut spartan_us = 0.0;
    let mut fold_us = 0.0;

    for step in 0..num_steps {
        // 1. Spartan-prove `num_fresh` synthetic instances
        let t0 = Instant::now();
        let mut fresh_instances = Vec::with_capacity(num_fresh);
        let mut fresh_codewords = Vec::with_capacity(num_fresh);
        for f in 0..num_fresh {
            let mut ch = make_challenger(step as u64 * 100 + f as u64 + 200);
            let _ = spartan.prove::<EF, _>(instance, &mut ch);
            let w = spartan.prepare_witness(instance);
            let z = w.as_slice();
            let mut wpart = z[num_inputs..].to_vec();
            wpart.resize(num_witness, F::ZERO);
            let wp = EvaluationsList::new(wpart.clone());
            let cw = rs_encode(&wp, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
            fresh_codewords.push(cw);
            fresh_instances.push(FreshInstance {
                public_input: z[..num_inputs].to_vec(),
                witness: wpart,
            });
        }
        spartan_us += t0.elapsed().as_micros() as f64;

        // 2. Build union codeword and fold
        let t1 = Instant::now();
        let code_len = acc.witness.codeword.as_slice().len();
        let l = (1 + num_fresh).next_power_of_two();
        let mut all_cw: Vec<Vec<F>> = Vec::with_capacity(l);
        all_cw.push(acc.witness.codeword.as_slice().to_vec());
        for cw in &fresh_codewords {
            all_cw.push(cw.as_slice().to_vec());
        }
        while all_cw.len() < l {
            all_cw.push(vec![F::ZERO; code_len]);
        }
        let union_cw = build_union_codeword(&all_cw);
        let union_ff = whir_p3::accumulation::warp::encoding::union_folding_factor(
            rs_config.folding_factor, l,
        );
        let union_ev = EvaluationsList::new(union_cw);
        let (union_root, union_tree) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
            &union_ev, union_ff, mh.clone(), mc.clone(),
        );

        // Derive union challenges
        let mut fold_chal = make_challenger(77);
        let (omega, tau, fresh_betas) = derive_fold_challenges_union(
            &acc.instance.commitment_root,
            acc.instance.eval_claim,
            &acc.instance.eval_point,
            acc.instance.pesat_target,
            &union_root,
            num_fresh,
            log_m,
            &mut fold_chal,
        );

        let mhc = mh.clone();
        let mcc = mc.clone();
        let mh2 = mh.clone();
        let mc2 = mc.clone();
        let mut result = warp_fold_prove_rs_union(
            shape,
            &fresh_instances,
            &acc,
            omega,
            &tau,
            &fresh_betas,
            &rs_config,
            &dft,
            |round_evals| {
                for &e in round_evals { fold_chal.observe(e); }
                fold_chal.sample()
            },
            |cw, ff| {
                let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                    cw, ff, mhc.clone(), mcc.clone(),
                );
                root
            },
            |ucw, uff| {
                let uev = EvaluationsList::new(ucw.to_vec());
                let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                    &uev, uff, mh2.clone(), mc2.clone(),
                );
                root
            },
        );

        // Open shift queries from union tree — 1 auth path per position (Quasar §4)
        {
            use whir_p3::accumulation::warp::fold::open_shift_queries_from_union_tree;
            open_shift_queries_from_union_tree::<F, MyHash, MyCompress, DIGEST>(
                &mut result.shift_queries, &union_tree,
                &mh, &mc,
            );
        }

        let transcript = commit_fold_transcript_with_shift_queries(
            step,
            vec![acc.instance.commitment_root.to_vec()],
            vec![acc.instance.eval_claim],
            vec![acc.instance.eval_point.clone()],
            vec![acc.instance.pesat_target],
            &result.sumcheck_round_polys,
            omega,
            tau,
            result.sumcheck_challenges.clone(),
            fresh_betas,
            &result.shift_queries,
            &[union_root],     // single union root for Merkle verification
            Some(union_root.to_vec()),
        );
        committed_transcripts.push(transcript);
        fold_us += t1.elapsed().as_micros() as f64;

        acc = rebuild_acc(&result);
    }

    // Terminal verification
    let t_term = Instant::now();
    let terminal_result = cp_snark_terminal_verify_with_merkle(
        shape,
        &acc,
        &committed_transcripts,
        || make_challenger(77),
        rs_config.folding_factor,
        &mh,
        &mc,
    );
    let terminal_us = t_term.elapsed().as_micros() as f64;
    assert!(terminal_result.is_ok(), "Union CP-SNARK terminal verify failed: {terminal_result:?}");

    (spartan_us, fold_us, terminal_us)
}

/// Run **recursive** union CP-SNARK IVC: builds arity-1 recursive circuits per step.
/// This is the apples-to-apples comparison to run_cp_snark_recursive: each path builds
/// recursive circuits (step + algebraic verifier) and folds their witnesses.
///
/// Per step:
///   - arity-1 Spartan proofs of synthetic R1CS (application cost, same as regular)
///   - arity-1 recursive circuit builds
///   - arity-1 Spartan proofs of recursive circuits (each tiny algebraic)
///   - 1 union fold of the arity-1 recursive circuit witnesses
///
/// Returns (synth_spartan, circuit_build, rec_spartan, union_fold, terminal) in us.
fn run_recursive_union_cp_snark(
    _shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    num_steps: usize,
    arity: usize,
    step_muls: usize,
) -> (f64, f64, f64, f64, f64) {
    use whir_p3::accumulation::warp::{
        encoding::build_union_codeword,
        fold::{derive_fold_challenges_union, warp_fold_prove_rs_union, materialize_shift_query_proofs, open_shift_queries_from_union_tree},
    };
    use whir_p3::ivc::warp_fold_verifier_algebraic::AlgebraicFoldVerifierWitness;

    let step = WorkloadStepCircuit::new(step_muls);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);
    let spartan = R1CSProver::new();
    let num_fresh = arity - 1;
    let log_l = arity.trailing_zeros() as usize;

    // Compute recursive union circuit size (with log_l-round verifier)
    use whir_p3::ivc::warp_ivc::compute_recursive_union_circuit_size;
    let (target_witness, _, _) = compute_recursive_union_circuit_size(&step, &[F::ZERO], arity);

    // Build a sample recursive circuit to extract shape/dimensions
    use whir_p3::ivc::warp_fold_verifier_algebraic::synthesize_warp_ivc_circuit_cp;
    let dummy_verifier = AlgebraicFoldVerifierWitness {
        sumcheck_evals: vec![[F::ZERO; 3]; log_l],
        num_rounds: log_l,
        sumcheck_challenges: vec![F::ZERO; log_l],
    };
    let mut probe_builder = CircuitBuilder::<F>::new();
    let _ = synthesize_warp_ivc_circuit_cp(
        &mut probe_builder, &step, &[F::ZERO], Some(&dummy_verifier), Some(target_witness),
    );
    let (init_shape, _) = probe_builder.build();
    let num_inputs = 0usize;
    let num_vars_y = 1usize << init_shape.num_poly_vars_y();
    let num_witness = num_vars_y;
    let log_code = num_witness.trailing_zeros() as usize + RS_LOG_INV_RATE;
    let log_m = init_shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let mut acc = make_zero_acc(num_witness, log_code, log_m, num_inputs);
    let mut last_fold_opt: Option<WarpFoldResult<F>> = None;
    let mut committed_transcripts: Vec<CommittedFoldTranscript<F>> = Vec::new();

    let mut synth_spartan_us = 0.0;
    let mut circuit_us = 0.0;
    let mut rec_spartan_us = 0.0;
    let mut fold_us = 0.0;

    for s in 0..num_steps {
        // 1. Spartan-prove synthetic R1CS × num_fresh (application cost)
        let t0 = Instant::now();
        for f in 0..num_fresh {
            let mut sch = make_challenger(s as u64 * 100 + f as u64 + 200);
            let _ = spartan.prove::<EF, _>(instance, &mut sch);
        }
        synth_spartan_us += t0.elapsed().as_micros() as f64;

        // 2. Build arity-1 recursive circuits with algebraic union verifier
        let verifier_witness = match last_fold_opt.as_ref() {
            Some(fr) if fr.sumcheck_round_polys.len() == log_l => {
                AlgebraicFoldVerifierWitness::from_fold_data(
                    &fr.sumcheck_round_polys, &fr.sumcheck_challenges,
                )
            }
            _ => AlgebraicFoldVerifierWitness {
                sumcheck_evals: vec![[F::ZERO; 3]; log_l],
                num_rounds: log_l,
                sumcheck_challenges: vec![F::ZERO; log_l],
            },
        };

        let t1 = Instant::now();
        let mut rec_instances = Vec::with_capacity(num_fresh);
        for f in 0..num_fresh {
            let mut builder = CircuitBuilder::<F>::new();
            let _ = synthesize_warp_ivc_circuit_cp(
                &mut builder, &step,
                &[F::from_u64(s as u64 * 100 + f as u64 + 10)],
                Some(&verifier_witness), Some(target_witness),
            );
            let (_, rec_inst) = builder.build();
            rec_instances.push(rec_inst);
        }
        circuit_us += t1.elapsed().as_micros() as f64;

        // 3. Spartan-prove each recursive circuit
        let t2 = Instant::now();
        let mut fresh_instances = Vec::with_capacity(num_fresh);
        let mut fresh_codewords = Vec::with_capacity(num_fresh);
        for (f, rec_inst) in rec_instances.iter().enumerate() {
            let mut rch = make_challenger(s as u64 * 100 + f as u64 + 500);
            let _ = spartan.prove::<EF, _>(rec_inst, &mut rch);
            let wp = spartan.prepare_witness(rec_inst);
            let z = wp.as_slice();
            let pi = z[..num_inputs].to_vec();
            let mut wpart = z[num_inputs..].to_vec();
            wpart.resize(num_witness, F::ZERO);
            let wp_list = EvaluationsList::new(wpart.clone());
            let cw = rs_encode(&wp_list, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
            fresh_codewords.push(cw);
            fresh_instances.push(FreshInstance { public_input: pi, witness: wpart });
        }
        rec_spartan_us += t2.elapsed().as_micros() as f64;

        // 4. Build union codeword, commit, union-fold
        let t3 = Instant::now();
        let code_len = acc.witness.codeword.as_slice().len();
        let l = arity;
        let mut all_cw: Vec<Vec<F>> = Vec::with_capacity(l);
        all_cw.push(acc.witness.codeword.as_slice().to_vec());
        for cw in &fresh_codewords {
            all_cw.push(cw.as_slice().to_vec());
        }
        while all_cw.len() < l {
            all_cw.push(vec![F::ZERO; code_len]);
        }
        let union_cw = build_union_codeword(&all_cw);
        let union_ff = whir_p3::accumulation::warp::encoding::union_folding_factor(
            rs_config.folding_factor, l,
        );
        let union_ev = EvaluationsList::new(union_cw);
        let (union_root, union_tree) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
            &union_ev, union_ff, mh.clone(), mc.clone(),
        );

        let mut fold_chal = make_challenger(77);
        let (omega, tau, fresh_betas) = derive_fold_challenges_union(
            &acc.instance.commitment_root, acc.instance.eval_claim,
            &acc.instance.eval_point, acc.instance.pesat_target,
            &union_root, num_fresh, log_m, &mut fold_chal,
        );

        let mhc = mh.clone();
        let mcc = mc.clone();
        let mh2 = mh.clone();
        let mc2 = mc.clone();
        let mut result = warp_fold_prove_rs_union(
            &init_shape, &fresh_instances, &acc, omega, &tau, &fresh_betas,
            &rs_config, &dft,
            |round_evals| {
                for &e in round_evals { fold_chal.observe(e); }
                fold_chal.sample()
            },
            |cw, ff| {
                let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                    cw, ff, mhc.clone(), mcc.clone(),
                );
                root
            },
            |ucw, uff| {
                let uev = EvaluationsList::new(ucw.to_vec());
                let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                    &uev, uff, mh2.clone(), mc2.clone(),
                );
                root
            },
        );
        let _ = materialize_shift_query_proofs::<F, MyHash, MyCompress, DIGEST>;
        open_shift_queries_from_union_tree::<F, MyHash, MyCompress, DIGEST>(
            &mut result.shift_queries, &union_tree, &mh, &mc,
        );

        let transcript = commit_fold_transcript_with_shift_queries(
            s,
            vec![acc.instance.commitment_root.to_vec()],
            vec![acc.instance.eval_claim],
            vec![acc.instance.eval_point.clone()],
            vec![acc.instance.pesat_target],
            &result.sumcheck_round_polys, omega, tau,
            result.sumcheck_challenges.clone(), fresh_betas,
            &result.shift_queries, &[union_root], Some(union_root.to_vec()),
        );
        committed_transcripts.push(transcript);
        fold_us += t3.elapsed().as_micros() as f64;

        acc = rebuild_acc(&result);
        last_fold_opt = Some(result);
    }

    // Terminal verification
    let t_term = Instant::now();
    let terminal_result = cp_snark_terminal_verify_with_merkle(
        &init_shape, &acc, &committed_transcripts,
        || make_challenger(77),
        rs_config.folding_factor, &mh, &mc,
    );
    let terminal_us = t_term.elapsed().as_micros() as f64;
    assert!(terminal_result.is_ok(), "Recursive union CP-SNARK terminal verify failed: {terminal_result:?}");

    (synth_spartan_us, circuit_us, rec_spartan_us, fold_us, terminal_us)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let sizes_str = args.get(1).map(|s| s.as_str()).unwrap_or("10,12");
    let steps_str = args.get(2).map(|s| s.as_str()).unwrap_or("2,4,8");
    let repeats: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let step_muls: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let arity: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(4);
    let sizes = parse_csv(sizes_str);
    let steps_list = parse_csv(steps_str);

    println!("CP-SNARK (Symphony) vs Regular vs Union (Quasar) IVC");
    println!("====================================================");
    println!("Field: KoalaBear, EF: KoalaBear^4 | WARP fold: factor=2, rate=1/2");
    println!("Repeats: {repeats} (+ 1 warmup) | Median timing | Step circuit: {step_muls} muls | Union arity: {arity}");
    println!();

    // ── Circuit sizes ──
    let (poseidon_perm, poseidon_config) = make_poseidon2_pair(99);

    // Compute circuit sizes for both modes, using the configured step circuit.
    let workload = WorkloadStepCircuit::new(step_muls);
    let (reg_w, reg_c, reg_pv) = compute_recursive_circuit_size::<
        F,
        GenericPoseidon2LinearLayersKoalaBear,
        _,
        _,
    >(
        &workload, &[F::ZERO], &poseidon_config, &poseidon_perm, 3,
    );
    let (cp_w, cp_c, cp_pv) = compute_cp_circuit_size(&workload, &[F::ZERO]);

    println!("Recursive verifier circuit overhead (added per IVC step):");
    println!(
        "  Regular (Poseidon2):  {:>6} witness, {:>6} constraints, poly_vars_y={}",
        reg_w, reg_c, reg_pv,
    );
    println!(
        "  CP-SNARK (algebraic): {:>6} witness, {:>6} constraints, poly_vars_y={}",
        cp_w, cp_c, cp_pv,
    );
    println!(
        "  Reduction:            {:.0}x constraints, {:.0}x witness vars",
        reg_c as f64 / cp_c.max(1) as f64,
        reg_w as f64 / cp_w.max(1) as f64,
    );
    println!();
    println!("Four paths compared (all start from same synthetic R1CS):");
    println!("  non_recursive = Spartan(synth) → WARP fold (no recursive circuit)");
    println!("  regular_ivc   = Spartan(synth) → build Poseidon2 circuit → Spartan(rec) → WARP fold");
    println!("  cp_snark_ivc  = Spartan(synth) → build algebraic circuit → Spartan(rec) → WARP fold + terminal");
    println!("  union_cp      = Spartan(synth)×{} → union fold (Quasar l={}) + terminal", arity - 1, arity);
    println!("                  No recursive circuit; union absorbs O(1) roots instead of O(ℓ)");
    println!();

    let _dft = Radix2DFTSmallBatch::<F>::default();

    for &log_size in &sizes {
        let num_cons = 1usize << log_size;
        let num_vars = 1usize << log_size;
        let num_inputs = 8;
        let mut rng = SmallRng::seed_from_u64(5);
        let (shape, instance) =
            R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);
        let spartan = R1CSProver::new();
        let sample_w = spartan.prepare_witness(&instance);
        let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let log_code = witness_num_vars + RS_LOG_INV_RATE;
        let log_m = shape
            .num_cons()
            .next_power_of_two()
            .trailing_zeros() as usize;

        println!(
            "=== log2(constraints)={log_size}, witness=2^{witness_num_vars}, code=2^{log_code} ==="
        );
        println!();
        println!(
            "{:>6} | {:>12} {:>12} | {:>12} {:>12} {:>12} {:>12} | {:>12} {:>12} {:>12} {:>12} {:>12} | {:>7} {:>7}",
            "steps",
            "non_rec", "NR_fold",
            "reg_synth", "reg_circuit", "reg_spartan", "reg_fold",
            "cp_synth", "cp_circuit", "cp_spartan", "cp_fold", "terminal",
            "rec_spd", "total_spd",
        );
        println!("{}", "-".repeat(190));

        let fmt = |v: f64| -> String {
            if v >= 1_000_000.0 {
                format!("{:.1}ms", v / 1000.0)
            } else {
                format!("{:.0}us", v)
            }
        };

        // ── Table 1: per-step breakdown (l=2 paths) ──
        println!(
            "{:>6} | {:>10} {:>10} | {:>10} {:>10} {:>10} {:>10} | {:>10} {:>10} {:>10} {:>10} {:>10} | {:>5} {:>5}",
            "steps",
            "non_rec", "NR_fold",
            "reg_synth", "reg_circ", "reg_spart", "reg_fold",
            "cp_synth", "cp_circ", "cp_spart", "cp_fold", "cp_term",
            "r_spd", "t_spd",
        );
        println!("{}", "-".repeat(170));

        for &num_steps in &steps_list {
            let mut nr_total = Vec::new();
            let mut nr_fold_v = Vec::new();
            let mut reg_total = Vec::new();
            let mut reg_synth_v = Vec::new();
            let mut reg_circuit_v = Vec::new();
            let mut reg_spartan_v = Vec::new();
            let mut reg_fold_v = Vec::new();
            let mut cp_total = Vec::new();
            let mut cp_synth_v = Vec::new();
            let mut cp_circuit_v = Vec::new();
            let mut cp_spartan_v = Vec::new();
            let mut cp_fold_v = Vec::new();
            let mut cp_terminal_v = Vec::new();

            for rep in 0..(repeats + 1) {
                let (nr_sp, nr_fo) = run_non_recursive_fold(
                    &shape, &instance, num_steps, num_witness, log_code, log_m, num_inputs,
                );
                let (rs, rc, rsp, rf) = run_regular_recursive(
                    &shape, &instance, num_steps, num_witness, log_code, log_m, num_inputs, step_muls,
                );
                let (cs, cc, csp, cf, ct_terminal) = run_cp_snark_recursive(
                    &shape, &instance, num_steps, num_witness, log_code, log_m, num_inputs, step_muls,
                );

                if rep > 0 {
                    nr_total.push(nr_sp + nr_fo);
                    nr_fold_v.push(nr_fo);
                    reg_total.push(rs + rc + rsp + rf);
                    reg_synth_v.push(rs);
                    reg_circuit_v.push(rc);
                    reg_spartan_v.push(rsp);
                    reg_fold_v.push(rf);
                    cp_total.push(cs + cc + csp + cf + ct_terminal);
                    cp_synth_v.push(cs);
                    cp_circuit_v.push(cc);
                    cp_spartan_v.push(csp);
                    cp_fold_v.push(cf);
                    cp_terminal_v.push(ct_terminal);
                }
            }

            let nr_t = median(&mut nr_total);
            let nr_f = median(&mut nr_fold_v);
            let rt = median(&mut reg_total);
            let rs = median(&mut reg_synth_v);
            let rc = median(&mut reg_circuit_v);
            let rsp = median(&mut reg_spartan_v);
            let rf = median(&mut reg_fold_v);
            let ct = median(&mut cp_total);
            let cs = median(&mut cp_synth_v);
            let cc = median(&mut cp_circuit_v);
            let csp = median(&mut cp_spartan_v);
            let cf = median(&mut cp_fold_v);
            let ct_term = median(&mut cp_terminal_v);

            let reg_rec_overhead = rc + rsp;
            let cp_rec_overhead = cc + csp;
            let rec_spd = reg_rec_overhead / cp_rec_overhead.max(1.0);
            let total_spd = rt / ct.max(1.0);

            println!(
                "{:>6} | {:>10} {:>10} | {:>10} {:>10} {:>10} {:>10} | {:>10} {:>10} {:>10} {:>10} {:>10} | {:>4.1}x {:>4.1}x",
                num_steps,
                fmt(nr_t), fmt(nr_f),
                fmt(rs), fmt(rc), fmt(rsp), fmt(rf),
                fmt(cs), fmt(cc), fmt(csp), fmt(cf), fmt(ct_term),
                rec_spd, total_spd,
            );
        }
        println!();

        // ── Table 2: Union (Quasar) throughput comparison ──
        // For each `num_steps` total instances, compare:
        //   non_recursive:  num_steps steps × 1 instance
        //   regular_ivc:    num_steps steps × 1 instance
        //   cp_snark_ivc:   num_steps steps × 1 instance
        //   union_cp_snark: ceil(num_steps/(arity-1)) steps × (arity-1) instances
        let fresh_per_step = arity - 1;
        println!(
            "  Throughput comparison: union l={arity} ({fresh_per_step} fresh/step) vs l=2 (1 fresh/step)"
        );
        // Apples-to-apples: all paths build recursive circuits (step + verifier).
        // Union builds arity-1 circuits per step instead of 1, then union-folds them.
        println!(
            "{:>6} {:>6} | {:>9} {:>9} {:>9} | {:>9} {:>9} {:>9} {:>9} {:>9} | {:>5} {:>5}",
            "insts", "u_step",
            "nr_total", "reg_total", "cp_total",
            "ru_synth", "ru_circ", "ru_spart", "ru_fold", "ru_term",
            "vs_reg", "vs_cp",
        );
        println!("{}", "-".repeat(128));

        for &total_instances in &steps_list {
            let union_steps = (total_instances + fresh_per_step - 1) / fresh_per_step;

            let mut nr_t_v = Vec::new();
            let mut reg_t_v = Vec::new();
            let mut cp_t_v = Vec::new();
            let mut ru_sy_v = Vec::new();
            let mut ru_ci_v = Vec::new();
            let mut ru_sp_v = Vec::new();
            let mut ru_fo_v = Vec::new();
            let mut ru_te_v = Vec::new();

            for rep in 0..(repeats + 1) {
                let (nr_sp, nr_fo) = run_non_recursive_fold(
                    &shape, &instance, total_instances, num_witness, log_code, log_m, num_inputs,
                );
                let (rs, rc, rsp, rf) = run_regular_recursive(
                    &shape, &instance, total_instances, num_witness, log_code, log_m, num_inputs, step_muls,
                );
                let (cs, cc, csp, cf, ct_t) = run_cp_snark_recursive(
                    &shape, &instance, total_instances, num_witness, log_code, log_m, num_inputs, step_muls,
                );
                // Recursive union: builds arity-1 recursive circuits per step.
                let (rus, ruc, rusp, ruf, rut) = run_recursive_union_cp_snark(
                    &shape, &instance, union_steps, arity, step_muls,
                );

                if rep > 0 {
                    nr_t_v.push(nr_sp + nr_fo);
                    reg_t_v.push(rs + rc + rsp + rf);
                    cp_t_v.push(cs + cc + csp + cf + ct_t);
                    ru_sy_v.push(rus);
                    ru_ci_v.push(ruc);
                    ru_sp_v.push(rusp);
                    ru_fo_v.push(ruf);
                    ru_te_v.push(rut);
                }
            }

            let nr_t = median(&mut nr_t_v);
            let reg_t = median(&mut reg_t_v);
            let cp_t = median(&mut cp_t_v);
            let ru_sy = median(&mut ru_sy_v);
            let ru_ci = median(&mut ru_ci_v);
            let ru_sp = median(&mut ru_sp_v);
            let ru_fo = median(&mut ru_fo_v);
            let ru_te = median(&mut ru_te_v);
            let ru_total = ru_sy + ru_ci + ru_sp + ru_fo + ru_te;

            let vs_reg = reg_t / ru_total.max(1.0);
            let vs_cp = cp_t / ru_total.max(1.0);

            println!(
                "{:>6} {:>6} | {:>9} {:>9} {:>9} | {:>9} {:>9} {:>9} {:>9} {:>9} | {:>4.1}x {:>4.1}x",
                total_instances, union_steps,
                fmt(nr_t), fmt(reg_t), fmt(cp_t),
                fmt(ru_sy), fmt(ru_ci), fmt(ru_sp), fmt(ru_fo), fmt(ru_te),
                vs_reg, vs_cp,
            );
        }
        println!();
    }

    println!("Legend (Table 1):");
    println!("  All l=2 paths: 1 instance per step. Times are totals across all steps.");
    println!("  r_spd = (reg_circuit+reg_spartan) / (cp_circuit+cp_spartan)");
    println!("  t_spd = reg_total / cp_total");
    println!();
    println!("Legend (Table 2) — Recursive Union IVC (apples-to-apples):");
    println!("  insts     = Total synthetic instances processed");
    println!("  u_step    = Union fold steps (= ceil(insts / (arity-1)))");
    println!("  ru_synth  = Spartan(synthetic R1CS) × (arity-1) per step");
    println!("  ru_circ   = Build arity-1 recursive circuits per step");
    println!("  ru_spart  = Spartan of the arity-1 recursive circuits per step");
    println!("  ru_fold   = Union fold of arity-1 recursive circuit witnesses");
    println!("  ru_term   = Terminal verify (SHA-256 binding + FS replay + decider + Merkle)");
    println!("  vs_reg    = reg_total / recursive_union_total  (>1 = union faster)");
    println!("  vs_cp     = cp_total  / recursive_union_total  (>1 = union faster)");
}
