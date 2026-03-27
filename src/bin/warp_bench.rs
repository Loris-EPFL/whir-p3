//! Benchmark comparing WARP fixed-size IVC vs non-folded independent WHIR proofs.
//!
//! Both pipelines use the same WHIR PCS for commitment and proof generation:
//! - **warp_fold**: Sumcheck fold per step (no WHIR proof) + 1 terminal WHIR proof
//! - **no_fold**: Full WHIR commit+prove per instance (independent proofs)
//!
//! Usage:
//!   cargo run --release --bin warp_bench -- <sizes> <steps> <repeats> <batch>
//!
//! Examples:
//!   cargo run --release --bin warp_bench -- "8,10" "4,8" 5 1
//!   cargo run --release --bin warp_bench -- "10,12" "4,8,16" 10 1

use std::{env, mem::size_of, time::Instant};

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{rngs::SmallRng, SeedableRng};

use whir_p3::{
    accumulation::{
        constraint_batch::constraint_batch_prove,
        linearized::linearized_statement_from_spartan_proof,
        random_lc::random_linear_combination,
        warp::{
            accumulator::{FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
            decider::warp_decide_algebraic,
            encoding::{codeword_size, merkle_commit_codeword},
            fold::{warp_fold_prove_rs_committed, warp_fold_verify, FreshInstancePublic, RSEncodingConfig, WarpFoldResult},
        },
    },
    circuit::poseidon2::Poseidon2CircuitConfig,
    fiat_shamir::domain_separator::DomainSeparator,
    ivc::warp_ivc::{
        warp_ivc_init, warp_ivc_step_recursive, compute_recursive_circuit_size,
        WarpIVCConfig,
    },
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    spartan::{
        r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
        r1cs_prover::R1CSProver,
    },
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
const DIGEST: usize = 8;
const RS_FOLDING_FACTOR: usize = 2;
const RS_LOG_INV_RATE: usize = 1; // rate = 1/2

fn parse_csv(s: &str) -> Vec<usize> {
    s.split(',').map(str::trim).filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("invalid usize")).collect()
}

fn human_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 { format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0)) }
    else if bytes >= 1024 { format!("{:.2} KiB", bytes as f64 / 1024.0) }
    else { format!("{bytes} B") }
}

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

// ============================================================================
// WHIR setup helpers
// ============================================================================

fn make_whir_config(num_variables: usize) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    WhirConfig::new(num_variables, ProtocolParameters {
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

fn make_domain_sep(config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>) -> DomainSeparator<EF, F> {
    let mut ds = DomainSeparator::<EF, F>::new(vec![]);
    ds.commit_statement::<_, _, _, DIGEST>(config);
    ds.add_whir_proof::<_, _, _, DIGEST>(config);
    ds
}

fn seed_challenger(seed: u64, ds: &DomainSeparator<EF, F>) -> MyChallenger {
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    let mut c = MyChallenger::new(perm);
    ds.observe_domain_separator(&mut c);
    c
}

// ============================================================================
// R1CS helpers
// ============================================================================

fn make_shape(num_cons: usize, num_vars: usize, num_inputs: usize) -> R1CSShape<F> {
    let mut a = Vec::new(); let mut b = Vec::new(); let mut c = Vec::new();
    for i in 0..num_cons {
        a.push(SparseMatEntry::new(i, num_inputs + i, F::ONE));
        b.push(SparseMatEntry::new(i, num_inputs + i, F::ONE));
        c.push(SparseMatEntry::new(i, num_inputs + num_cons + i, F::ONE));
    }
    R1CSShape::new(num_cons, num_vars, num_inputs, a, b, c)
}

fn make_witness_poly(num_cons: usize, num_witness: usize, seed: u64) -> EvaluationsList<F> {
    let padded_len = num_witness.next_power_of_two();
    let mut w = vec![F::ZERO; padded_len];
    for i in 0..num_cons.min(num_witness / 2) {
        let val = F::from_u64((i as u64 + seed + 2) % 100);
        w[i] = val;
        if num_cons + i < num_witness { w[num_cons + i] = val * val; }
    }
    EvaluationsList::new(w)
}

fn make_fresh(num_cons: usize, num_witness: usize, num_inputs: usize, seed: u64) -> FreshInstance<F> {
    let public_input: Vec<F> = (0..num_inputs).map(|i| F::from_u64(i as u64 + 1)).collect();
    let mut witness = vec![F::ZERO; num_witness];
    for i in 0..num_cons.min(num_witness / 2) {
        let val = F::from_u64((i as u64 + seed + 2) % 100);
        witness[i] = val;
        if num_cons + i < num_witness { witness[num_cons + i] = val * val; }
    }
    FreshInstance { public_input, witness }
}

// ============================================================================
// NO-FOLD pipeline: full WHIR commit+prove per instance
// ============================================================================

fn run_no_fold(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    num_instances: usize,
    num_cons: usize,
    num_witness: usize,
) -> (f64, f64) {
    let ds = make_domain_sep(config);
    let dft = Radix2DFTSmallBatch::<F>::default();

    // PROVE: commit + WHIR prove for each instance
    let prove_start = Instant::now();
    let mut proofs_and_claims = Vec::with_capacity(num_instances);
    for i in 0..num_instances {
        let poly = make_witness_poly(num_cons, num_witness, i as u64);
        let linear_claim = LinearStatement::<F, EF>::initialize(poly.num_variables());

        let mut statement = config.initial_statement_with_linear(poly, linear_claim.clone());
        let verifier_claim = statement.normalize_claim();

        let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(config);
        let mut challenger = seed_challenger(100 + i as u64, &ds);

        let commitment = CommitmentWriter::new(config)
            .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &dft, &mut proof, &mut challenger, &mut statement,
            ).unwrap();

        WhirProver(config)
            .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &dft, &mut proof, &mut challenger, &statement, commitment,
            ).unwrap();

        proofs_and_claims.push((proof, verifier_claim));
    }
    let prove_us = prove_start.elapsed().as_micros() as f64;

    // VERIFY: parse commitment + WHIR verify for each instance
    let verify_start = Instant::now();
    for (i, (proof, claim)) in proofs_and_claims.iter().enumerate() {
        let mut challenger = seed_challenger(100 + i as u64, &ds);
        let parsed = CommitmentReader::new(config)
            .parse_commitment::<F, DIGEST>(proof, &mut challenger);
        WhirVerifier::new(config)
            .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                proof, &mut challenger, &parsed, claim.clone(),
            ).unwrap();
    }
    let verify_us = verify_start.elapsed().as_micros() as f64;

    (prove_us, verify_us)
}

// ============================================================================
// WARP pipeline: sumcheck folds + 1 terminal WHIR proof
// ============================================================================

fn make_initial_acc(num_witness: usize, log_code: usize, log_m: usize, num_inputs: usize) -> WarpAccumulator<F, F, F, DIGEST> {
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: [F::ZERO; DIGEST],
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

fn rebuild_acc(result: &WarpFoldResult<F>) -> WarpAccumulator<F, F, F, DIGEST> {
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

fn run_warp(
    shape: &R1CSShape<F>,
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    num_steps: usize,
    batch: usize,
    num_cons: usize,
    num_witness: usize,
    num_inputs: usize,
) -> (f64, f64, f64, usize, bool) {
    let witness_num_vars = num_witness.trailing_zeros() as usize;
    let log_code = witness_num_vars + RS_LOG_INV_RATE;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let rs_config = RSEncodingConfig::new(RS_FOLDING_FACTOR, RS_LOG_INV_RATE);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    let merkle_hash = MyHash::new(perm.clone());
    let merkle_compress = MyCompress::new(perm);

    let mut acc = make_initial_acc(num_witness, log_code, log_m, num_inputs);
    let initial_wit_bytes = acc.witness.witness.len() * size_of::<F>();

    // Per-phase timing accumulators (only active with bench-timing feature)
    #[cfg(feature = "bench-timing")]
    let (mut phase_rs, mut phase_merkle, mut phase_twin, mut phase_shift,
         mut phase_ood, mut phase_eval_batch, mut phase_clone) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);

    // FOLD STEPS with RS encoding + Merkle commitment
    let fold_start = Instant::now();
    for step in 0..num_steps {
        let fresh: Vec<FreshInstance<F>> = (0..batch)
            .map(|b| {
                let mut inst = make_fresh(num_cons, num_witness, num_inputs, step as u64 * 100 + b as u64);
                inst.witness.resize(num_witness, F::ZERO);
                inst
            }).collect();

        let l = (1 + batch).next_power_of_two();
        let log_l = l.trailing_zeros() as usize;
        let tau: Vec<F> = (0..log_l).map(|i| F::from_u64(step as u64 * 10 + i as u64 + 42)).collect();

        let mh = merkle_hash.clone();
        let mc = merkle_compress.clone();
        let mut ctr = step as u64 * 1000;
        let result = warp_fold_prove_rs_committed(shape, &fresh, &acc, F::from_u64(7), &tau,
            &rs_config, &dft,
            |_| { ctr += 1; F::from_u64(ctr + 500) },
            |codeword, folding_factor| {
                let (root, _tree) = merkle_commit_codeword::<
                    F, F, <F as Field>::Packing, <F as Field>::Packing,
                    MyHash, MyCompress, DIGEST,
                >(codeword, folding_factor, mh.clone(), mc.clone());
                root
            },
        );
        #[cfg(feature = "bench-timing")]
        {
            use whir_p3::accumulation::warp::fold::WarpFoldTimings;
            let t = &result.timings;
            phase_rs += t.rs_encode_us;
            phase_merkle += t.merkle_fresh_us + t.merkle_folded_us;
            phase_twin += t.twin_sumcheck_us;
            phase_shift += t.shift_queries_us;
            phase_ood += t.ood_sampling_us;
            phase_eval_batch += t.eval_batch_us;
            phase_clone += t.codeword_clone_us;
        }
        acc = rebuild_acc(&result);
    }
    let fold_us = fold_start.elapsed().as_micros() as f64;

    // TERMINAL WHIR PROOF (once at the end)
    let ds = make_domain_sep(config);

    // TERMINAL WHIR PROOF on the accumulated raw witness (WHIR handles RS encoding internally)
    // Pad to power-of-2 (the folded witness may be num_vars_y - num_inputs which isn't pow2)
    let mut witness_vec = acc.witness.witness.clone();
    let padded_len = witness_vec.len().next_power_of_two();
    witness_vec.resize(padded_len, F::ZERO);
    let witness_poly = EvaluationsList::new(witness_vec);
    let decide_start = Instant::now();
    let terminal_proof = {
        let linear_claim = LinearStatement::<F, EF>::initialize(witness_num_vars);
        let mut statement = config.initial_statement_with_linear(
            witness_poly.clone(),
            linear_claim,
        );
        let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(config);
        let mut challenger = seed_challenger(999, &ds);

        let commitment = CommitmentWriter::new(config)
            .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &dft, &mut proof, &mut challenger, &mut statement,
            ).unwrap();

        WhirProver(config)
            .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &dft, &mut proof, &mut challenger, &statement, commitment,
            ).unwrap();
        proof
    };
    let decide_us = decide_start.elapsed().as_micros() as f64;

    // VERIFY terminal proof (reuse the proof, don't re-prove)
    let verify_start = Instant::now();
    {
        let initial_claim = InitialClaim {
            eq_statement: EqStatement::initialize(witness_num_vars),
            linear_statement: LinearStatement::<F, EF>::initialize(witness_num_vars),
        };
        let mut v_challenger = seed_challenger(999, &ds);
        let parsed = CommitmentReader::new(config)
            .parse_commitment::<F, DIGEST>(&terminal_proof, &mut v_challenger);
        WhirVerifier::new(config)
            .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &terminal_proof, &mut v_challenger, &parsed, initial_claim,
            ).unwrap();
    }
    let verify_us = verify_start.elapsed().as_micros() as f64;

    let final_wit_bytes = acc.witness.witness.len().next_power_of_two() * size_of::<F>();
    let fixed = final_wit_bytes == initial_wit_bytes;

    #[cfg(feature = "bench-timing")]
    {
        let total = phase_rs + phase_merkle + phase_twin + phase_shift
            + phase_ood + phase_eval_batch + phase_clone;
        eprintln!(
            "  [phase breakdown] rs_encode={phase_rs}us merkle={phase_merkle}us twin_sc={phase_twin}us \
             shift={phase_shift}us ood={phase_ood}us eval_batch={phase_eval_batch}us \
             clone={phase_clone}us | accounted={total}us / fold={:.0}us",
            fold_us,
        );
    }

    (fold_us, decide_us, verify_us, final_wit_bytes, fixed)
}

// ============================================================================
// FULL PIPELINE: Spartan → Batch reduction → WARP fold → 1 terminal WHIR
// ============================================================================

fn run_full_pipeline(
    shape: &R1CSShape<F>,
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    num_steps: usize,
    batch: usize,
    num_cons: usize,
    num_witness: usize,
    num_inputs: usize,
) -> (f64, f64, f64, f64) {
    // Returns (spartan_us, quasar_us, fold_us, whir_us)
    let witness_num_vars = num_witness.trailing_zeros() as usize;
    let log_code = witness_num_vars + RS_LOG_INV_RATE;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let rs_config = RSEncodingConfig::new(RS_FOLDING_FACTOR, RS_LOG_INV_RATE);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    let merkle_hash = MyHash::new(perm.clone());
    let merkle_compress = MyCompress::new(perm);

    let spartan_prover = R1CSProver::new();

    // Build a satisfying synthetic R1CS instance (reuse for all steps).
    let mut rng = SmallRng::seed_from_u64(5);
    let (_synth_shape, synth_instance) =
        R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, shape.num_vars(), num_inputs, &mut rng);
    debug_assert!(
        shape.is_sat(synth_instance.witness(), synth_instance.input()),
        "synthetic instance does not satisfy R1CS"
    );

    // ── Phase 1: Spartan linearize all instances ──
    let spartan_start = Instant::now();
    let total = num_steps * batch;
    let mut all_witnesses = Vec::with_capacity(total);
    let mut all_linears = Vec::with_capacity(total);
    for i in 0..total {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(i as u64 + 200));
        let mut challenger = MyChallenger::new(perm);
        let proof = spartan_prover.prove::<EF, _>(&synth_instance, &mut challenger);
        let witness = spartan_prover.prepare_witness(&synth_instance);
        let linear = linearized_statement_from_spartan_proof(shape, &proof, EF::from_u64(3));
        all_witnesses.push(witness);
        all_linears.push(linear);
    }
    let spartan_us = spartan_start.elapsed().as_micros() as f64;

    // ── Phase 2: Batch reduction (per step) + WARP fold ──
    let mut acc = make_initial_acc(num_witness, log_code, log_m, num_inputs);

    let mut batch_reduce_total_us = 0f64;
    let mut fold_total_us = 0f64;

    for step in 0..num_steps {
        let start_idx = step * batch;
        let end_idx = start_idx + batch;

        // Batch reduction: constraint_batch + random_lc
        let batch_reduce_start = Instant::now();

        let step_witnesses = &all_witnesses[start_idx..end_idx];
        let step_linears = &all_linears[start_idx..end_idx];

        // Extract weights and targets
        let mut weights = Vec::with_capacity(batch);
        let mut targets = Vec::with_capacity(batch);
        for linear in step_linears {
            let (w, &t) = linear.iter().next().unwrap();
            weights.push(w.clone());
            targets.push(t);
        }

        let gamma = F::from_u64(step as u64 + 42);
        let cb_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(step as u64 + 300));
        let mut cb_challenger = MyChallenger::new(cb_perm);
        let (_batch_proof, _reduction_point) = constraint_batch_prove(
            gamma, &weights, &targets,
            &step_witnesses.iter().cloned().collect::<Vec<_>>(),
            &mut cb_challenger,
        );

        // Random LC: combine witnesses into one
        let eta = F::from_u64(step as u64 + 13);
        let wit_refs: Vec<&EvaluationsList<F>> = step_witnesses.iter().collect();
        let combined = random_linear_combination(&wit_refs, eta);

        batch_reduce_total_us += batch_reduce_start.elapsed().as_micros() as f64;

        // Create FreshInstance from the combined witness.
        // prepare_witness returns z = (public_input || witness || padding),
        // so the combined poly includes the public input portion.
        // FreshInstance wants separate public_input and witness fields.
        let combined_slice = combined.as_slice();
        let public_input = combined_slice[..num_inputs].to_vec();
        let mut combined_witness = combined_slice[num_inputs..].to_vec();
        combined_witness.resize(num_witness, F::ZERO);

        let fresh = vec![FreshInstance {
            public_input,
            witness: combined_witness,
        }];

        // WARP fold
        let fold_start = Instant::now();

        let l = (1usize + 1).next_power_of_two(); // 1 acc + 1 fresh = 2
        let log_l = l.trailing_zeros() as usize;
        let tau: Vec<F> = (0..log_l).map(|i| F::from_u64(step as u64 * 10 + i as u64 + 42)).collect();

        let mh = merkle_hash.clone();
        let mc = merkle_compress.clone();
        let mut ctr = step as u64 * 1000;
        let result = warp_fold_prove_rs_committed(shape, &fresh, &acc, F::from_u64(7), &tau,
            &rs_config, &dft,
            |_| { ctr += 1; F::from_u64(ctr + 500) },
            |codeword, folding_factor| {
                let (root, _tree) = merkle_commit_codeword::<
                    F, F, <F as Field>::Packing, <F as Field>::Packing,
                    MyHash, MyCompress, DIGEST,
                >(codeword, folding_factor, mh.clone(), mc.clone());
                root
            },
        );

        fold_total_us += fold_start.elapsed().as_micros() as f64;
        acc = rebuild_acc(&result);
    }

    // ── Phase 3: Terminal WHIR proof ──
    let ds = make_domain_sep(config);
    let mut witness_vec = acc.witness.witness.clone();
    let padded_len = witness_vec.len().next_power_of_two();
    witness_vec.resize(padded_len, F::ZERO);
    let witness_poly = EvaluationsList::new(witness_vec);

    let whir_start = Instant::now();
    {
        let linear_claim = LinearStatement::<F, EF>::initialize(witness_num_vars);
        let mut statement = config.initial_statement_with_linear(witness_poly, linear_claim);
        let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(config);
        let mut challenger = seed_challenger(999, &ds);
        let commitment = CommitmentWriter::new(config)
            .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &dft, &mut proof, &mut challenger, &mut statement,
            ).unwrap();
        WhirProver(config)
            .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &dft, &mut proof, &mut challenger, &statement, commitment,
            ).unwrap();
    }
    let whir_us = whir_start.elapsed().as_micros() as f64;

    (spartan_us, batch_reduce_total_us, fold_total_us, whir_us)
}

// ============================================================================
// RECURSIVE IVC: unified circuit (step + Poseidon2 verifier) + WARP fold
// ============================================================================

fn run_recursive_ivc(
    shape: &R1CSShape<F>,
    num_steps: usize,
    num_cons: usize,
    num_witness: usize,
    num_inputs: usize,
) -> (f64, f64, f64) {
    // Returns (circuit_build_us, spartan_prove_us, warp_fold_us) — all steps total
    use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
    use whir_p3::ivc::step::TrivialStepCircuit;

    let dft = Radix2DFTSmallBatch::<F>::default();
    let ivc_config = WarpIVCConfig::default();
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    let merkle_hash = MyHash::new(perm.clone());
    let merkle_compress = MyCompress::new(perm.clone());
    let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
    let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
        8, 13, &mut SmallRng::seed_from_u64(99),
    );
    let step_circuit = TrivialStepCircuit::new(1);

    // Compute target witness count for uniform circuit sizing
    let (target_witness, _, _) = compute_recursive_circuit_size::<
        F, GenericPoseidon2LinearLayersBabyBear, _, _,
    >(&step_circuit, &[F::ZERO], &poseidon_config, &poseidon_perm, 3);

    // Build a satisfying R1CS instance for init
    let mut rng = SmallRng::seed_from_u64(5);
    let (_synth_shape, synth_instance) =
        R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, shape.num_vars(), num_inputs, &mut rng);

    // Init step: build padded unified circuit (no verifier) to get consistent shape
    let mut init_builder = whir_p3::circuit::builder::CircuitBuilder::<F>::new();
    let mut init_chal_circuit = whir_p3::circuit::sponge::CircuitChallenger::<F, 16, 8>::new(&mut init_builder);
    let _ = whir_p3::ivc::warp_fold_verifier_circuit::synthesize_warp_ivc_circuit::<
        F, GenericPoseidon2LinearLayersBabyBear, _, _, 16, 8,
    >(
        &mut init_builder, &mut init_chal_circuit, &poseidon_config, &poseidon_perm,
        &step_circuit, &[F::ZERO], None, Some(target_witness),
    );
    let (init_shape, init_instance) = init_builder.build();

    let spartan_prover = R1CSProver::new();
    let mut init_chal = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
    let _init_proof = spartan_prover.prove::<EF, _>(&init_instance, &mut init_chal);
    let init_witness = spartan_prover.prepare_witness(&init_instance);

    let init_num_inputs = init_instance.input().len();
    let z0 = init_witness.as_slice();
    let init_num_witness = (z0.len() - init_num_inputs).next_power_of_two();
    let mut wit0 = z0[init_num_inputs..].to_vec();
    wit0.resize(init_num_witness, F::ZERO);

    let log_code = init_num_witness.trailing_zeros() as usize + ivc_config.rs_log_inv_rate;
    let log_m = init_shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let fresh0 = FreshInstance {
        public_input: z0[..init_num_inputs].to_vec(),
        witness: wit0,
    };
    let zero_acc = make_initial_acc(init_num_witness, log_code, log_m, init_num_inputs);
    let rs_config_init = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
    let tau0 = vec![F::from_u64(42)];
    let mut ctr0 = 0u64;
    let mh0 = merkle_hash.clone();
    let mc0 = merkle_compress.clone();
    let result0 = warp_fold_prove_rs_committed(
        &init_shape, &[fresh0], &zero_acc, F::from_u64(7), &tau0,
        &rs_config_init, &dft,
        |_| { ctr0 += 1; F::from_u64(ctr0 + 500) },
        |codeword, folding_factor| {
            let (root, _tree) = merkle_commit_codeword::<
                F, F, <F as Field>::Packing, <F as Field>::Packing,
                MyHash, MyCompress, DIGEST,
            >(codeword, folding_factor, mh0.clone(), mc0.clone());
            root
        },
    );
    let mut state = whir_p3::ivc::warp_ivc::WarpIVCState {
        step: 1,
        accumulator: rebuild_acc(&result0),
        shape: init_shape,
        last_fold_result: Some(result0),
        prev_acc_instance: Some(zero_acc.instance.clone()),
        public_state: vec![F::ZERO],
    };

    // Recursive steps — measure each phase
    let mut total_circuit_us = 0f64;
    let mut total_spartan_us = 0f64;
    let mut total_fold_us = 0f64;

    for step_idx in 0..num_steps {
        // Phase 1: Circuit synthesis (includes Poseidon2 gadget)
        let circuit_start = Instant::now();

        // Build verifier witness from previous fold
        let verifier_witness = if let (Some(fold_result), Some(prev_inst)) = (
            &state.last_fold_result,
            &state.prev_acc_instance,
        ) {
            let commitment_roots = vec![
                prev_inst.commitment_root.to_vec(),
                fold_result.commitment_root.to_vec(),
            ];
            let eval_claims = vec![prev_inst.eval_claim, F::ZERO];
            let eval_points = vec![
                prev_inst.eval_point.clone(),
                vec![F::ZERO; prev_inst.eval_point.len()],
            ];
            let pesat_targets = vec![prev_inst.pesat_target, F::ZERO];
            Some(whir_p3::ivc::warp_fold_verifier_circuit::WarpFoldVerifierWitness::from_fold_result(
                commitment_roots, eval_claims, eval_points, pesat_targets,
                &fold_result.sumcheck_round_polys, F::from_u64(7),
            ))
        } else {
            None
        };

        let mut builder = whir_p3::circuit::builder::CircuitBuilder::<F>::new();
        let mut circuit_chal = whir_p3::circuit::sponge::CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = whir_p3::ivc::warp_fold_verifier_circuit::synthesize_warp_ivc_circuit::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _, 16, 8,
        >(
            &mut builder, &mut circuit_chal, &poseidon_config, &poseidon_perm,
            &step_circuit, &[F::ZERO], verifier_witness.as_ref(), Some(target_witness),
        );
        let (unified_shape, unified_instance) = builder.build();
        total_circuit_us += circuit_start.elapsed().as_micros() as f64;

        // Phase 2: Spartan prove
        let spartan_start = Instant::now();
        let spartan_prover = R1CSProver::new();
        let mut spartan_chal = MyChallenger::new(Perm::new_from_rng_128(
            &mut SmallRng::seed_from_u64(step_idx as u64 + 200),
        ));
        let _proof = spartan_prover.prove::<EF, _>(&unified_instance, &mut spartan_chal);
        let witness_poly = spartan_prover.prepare_witness(&unified_instance);
        total_spartan_us += spartan_start.elapsed().as_micros() as f64;

        // Phase 3: WARP fold
        let fold_start = Instant::now();
        let num_inp = unified_instance.input().len();
        let z = witness_poly.as_slice();
        let public_input = z[..num_inp].to_vec();
        let acc_wit_len = state.accumulator.witness.witness.len();
        let mut witness_part = z[num_inp..].to_vec();
        witness_part.resize(acc_wit_len, F::ZERO);

        let fresh = FreshInstance { public_input, witness: witness_part };
        let rs_config = RSEncodingConfig::new(ivc_config.rs_folding_factor, ivc_config.rs_log_inv_rate);
        let tau = vec![F::from_u64(step_idx as u64 + 42)];
        let mut ctr = step_idx as u64 * 1000;
        let mh = merkle_hash.clone();
        let mc = merkle_compress.clone();
        let result = warp_fold_prove_rs_committed(
            &state.shape, &[fresh], &state.accumulator, F::from_u64(7), &tau,
            &rs_config, &dft,
            |_| { ctr += 1; F::from_u64(ctr + 500) },
            |codeword, folding_factor| {
                let (root, _tree) = merkle_commit_codeword::<
                    F, F, <F as Field>::Packing, <F as Field>::Packing,
                    MyHash, MyCompress, DIGEST,
                >(codeword, folding_factor, mh.clone(), mc.clone());
                root
            },
        );
        total_fold_us += fold_start.elapsed().as_micros() as f64;

        // Update state
        let new_acc = rebuild_acc(&result);
        state = whir_p3::ivc::warp_ivc::WarpIVCState {
            step: state.step + 1,
            accumulator: new_acc,
            shape: state.shape.clone(),
            last_fold_result: Some(result),
            prev_acc_instance: Some(state.accumulator.instance.clone()),
            public_state: vec![F::ZERO],
        };
    }

    (total_circuit_us, total_spartan_us, total_fold_us)
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = env::args().collect();
    let sizes_str = args.get(1).map(|s| s.as_str()).unwrap_or("8,10");
    let steps_str = args.get(2).map(|s| s.as_str()).unwrap_or("4,8");
    let repeats: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let batch: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);

    let sizes = parse_csv(sizes_str);
    let steps_list = parse_csv(steps_str);

    println!("Accumulation Benchmark: 4 paths compared");
    println!("=========================================");
    println!("Field: BabyBear (31-bit), EF: BabyBear^4");
    println!("WHIR: folding_factor=2, rate=1/2, security=100, pow=0");
    println!("Batch per step: {batch} | Repeats: {repeats}");
    println!();
    println!("Paths (Spartan linearization excluded from first 3):");
    println!("  independent_whir  = N × WHIR commit+prove (baseline, no folding)");
    println!("  direct_fold       = N × WARP fold (l=batch+1) + 1 terminal WHIR");
    println!("  batch_then_fold   = N × (batch reduce to 1 + WARP fold l=2) + 1 terminal WHIR");
    println!("  recursive_ivc     = N × (circuit synthesis + Spartan prove + WARP fold) [full IVC step]");
    println!();

    for &size_log2 in &sizes {
        let num_cons = 1usize << size_log2;
        let num_vars = 2 * num_cons;
        let num_inputs = 8;
        let shape = make_shape(num_cons.min(num_vars / 2), num_vars, num_inputs);
        let num_vars_y: usize = 1 << shape.num_poly_vars_y();
        // Pad witness to power of 2 for RS encoding compatibility
        let num_witness = (num_vars_y - num_inputs).next_power_of_two();
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let log_code = witness_num_vars + RS_LOG_INV_RATE;

        // WHIR config uses witness dimension — WHIR handles its own RS expansion internally.
        // No-fold: raw witness → WHIR (encodes internally)
        // WARP: fold operates on RS codewords (2^log_code), terminal WHIR gets raw witness (2^witness_num_vars)
        let config = make_whir_config(witness_num_vars);

        println!("=== log2(witness) = {size_log2} (n={num_vars_y}, M={num_cons}, code=2^{log_code}) ===");
        println!();
        println!("{:>6} | {:>16} {:>16} {:>16} {:>16} | {:>16} {:>16} {:>16} | {:>10} {:>10} {:>10}",
            "steps",
            "independent_whir", "direct_fold", "batch_then_fold", "recursive_ivc",
            "circuit_synth", "spartan_prove", "ivc_warp_fold",
            "fold/indep", "batch/indep", "ivc/indep",
        );
        println!("{}", "-".repeat(180));

        for &num_steps in &steps_list {
            let total_instances = num_steps * batch;

            // Warm up
            let _ = run_warp(&shape, &config, 1, batch, num_cons, num_witness, num_inputs);
            let _ = run_no_fold(&config, 1, num_cons, num_witness);

            let mut nf_proves = Vec::new();
            let mut warp_totals = Vec::new();
            let mut batch_fold_totals = Vec::new();
            let mut recursive_totals = Vec::new();
            let mut recursive_circuits = Vec::new();
            let mut recursive_spartans = Vec::new();
            let mut recursive_folds = Vec::new();

            for _ in 0..repeats {
                // Path 1: Independent WHIR proofs
                let (nf_p, _nf_v) = run_no_fold(&config, total_instances, num_cons, num_witness);
                nf_proves.push(nf_p);

                // Path 2: Direct WARP fold (all instances at once per step)
                let (fold_us, decide_us, _verify_us, _wit_bytes, _fixed) =
                    run_warp(&shape, &config, num_steps, batch, num_cons, num_witness, num_inputs);
                warp_totals.push(fold_us + decide_us);

                // Path 3: Batch reduce then WARP fold
                let (_sp_us, br_us, fo_us, wh_us) =
                    run_full_pipeline(&shape, &config, num_steps, batch, num_cons, num_witness, num_inputs);
                batch_fold_totals.push(br_us + fo_us + wh_us);

                // Path 4: Recursive IVC (circuit + Spartan + fold)
                let (circ_us, spart_us, fold_us) =
                    run_recursive_ivc(&shape, num_steps, num_cons, num_witness, num_inputs);
                recursive_circuits.push(circ_us);
                recursive_spartans.push(spart_us);
                recursive_folds.push(fold_us);
                recursive_totals.push(circ_us + spart_us + fold_us);
            }

            let indep = median(&mut nf_proves);
            let direct = median(&mut warp_totals);
            let batch_fold = median(&mut batch_fold_totals);
            let recursive = median(&mut recursive_totals);
            let rc = median(&mut recursive_circuits);
            let rs = median(&mut recursive_spartans);
            let rf = median(&mut recursive_folds);

            let fold_vs_indep = indep / direct;
            let batch_vs_indep = indep / batch_fold;
            let ivc_vs_indep = indep / recursive;

            println!(
                "{:>6} | {:>14.0}us {:>14.0}us {:>14.0}us {:>14.0}us | {:>14.0}us {:>14.0}us {:>14.0}us | {:>9.2}x {:>9.2}x {:>9.2}x",
                num_steps,
                indep, direct, batch_fold, recursive,
                rc, rs, rf,
                fold_vs_indep, batch_vs_indep, ivc_vs_indep,
            );
        }
        println!();
    }

    println!("Legend:");
    println!("  independent_whir  = N × WHIR commit+prove (one per instance, no folding)");
    println!("  direct_fold       = N × WARP fold (l=batch+1 per step) + 1 terminal WHIR");
    println!("  batch_then_fold   = N × (constraint_batch + random_lc + WARP fold l=2) + 1 terminal WHIR");
    println!("  recursive_ivc     = N × (circuit synthesis with Poseidon2 verifier + Spartan prove + WARP fold)");
    println!("  circuit_synth     = Build unified R1CS circuit (step + Poseidon2 fold verifier) [all steps]");
    println!("  spartan_prove     = Spartan two-phase sumcheck on the unified circuit [all steps]");
    println!("  ivc_warp_fold     = WARP fold: RS encode + Merkle + twin-constraint sumcheck [all steps]");
    println!("  fold/indep     = independent_whir / direct_fold (>1 = fold wins)");
    println!("  batch/indep    = independent_whir / batch_then_fold (>1 = batch+fold wins)");
    println!("  ivc/indep      = independent_whir / recursive_ivc (>1 = recursive IVC wins)");
    println!("  Note: independent_whir, direct_fold, batch_then_fold exclude Spartan linearization.");
    println!("        recursive_ivc includes everything (circuit + Spartan + fold).");
}
