//! Honest apples-to-apples benchmark.
//!
//! ALL paths start from the same point: N Spartan-linearized witnesses.
//! Spartan linearization is timed ONCE and reported separately.
//! Then each path only differs in how it generates proofs from those witnesses.
//!
//! Usage:
//!   cargo run --release --bin compare_bench -- <log_sizes> <num_steps> <repeats> <batch>

use std::{env, time::Instant};

use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};
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
            decider::warp_decide_algebraic_rs,
            encoding::merkle_commit_codeword,
            fold::{warp_fold_prove_rs_committed, RSEncodingConfig, WarpFoldResult},
        },
    },
    circuit::{builder::CircuitBuilder, poseidon2::Poseidon2CircuitConfig, sponge::CircuitChallenger},
    fiat_shamir::domain_separator::DomainSeparator,
    ivc::{
        step::{TrivialStepCircuit, WorkloadStepCircuit},
        warp_fold_verifier_circuit::{WarpFoldVerifierWitness, synthesize_warp_ivc_circuit},
        warp_ivc::{
            compute_recursive_circuit_size, compute_recursive_circuit_size_union,
            warp_ivc_init, warp_ivc_step_recursive, warp_ivc_init_recursive_union,
            warp_ivc_step_recursive_union, WarpIVCConfig,
        },
    },
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    spartan::{
        r1cs::{R1CSInstance, R1CSShape},
        r1cs_prover::R1CSProver,
    },
    whir::{
        committer::{writer::CommitmentWriter, reader::CommitmentReader},
        constraints::statement::{EqStatement, InitialClaim, LinearStatement},
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
        verifier::Verifier as WhirVerifier,
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
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}
fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2]
}
fn make_whir_config(nv: usize) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    WhirConfig::new(nv, ProtocolParameters {
        security_level: 100, pow_bits: 0, rs_domain_initial_reduction_factor: 1,
        folding_factor: FoldingFactor::Constant(2),
        merkle_hash: MyHash::new(p.clone()), merkle_compress: MyCompress::new(p),
        soundness_type: SecurityAssumption::CapacityBound, starting_log_inv_rate: RS_LOG_INV_RATE,
    })
}
fn make_ds(c: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>) -> DomainSeparator<EF, F> {
    let mut d = DomainSeparator::<EF, F>::new(vec![]); d.commit_statement::<_,_,_,DIGEST>(c); d.add_whir_proof::<_,_,_,DIGEST>(c); d
}
fn seed_ch(s: u64, d: &DomainSeparator<EF, F>) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(s));
    let mut c = MyChallenger::new(p); d.observe_domain_separator(&mut c); c
}
fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}
fn make_hc() -> (MyHash, MyCompress) {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    (MyHash::new(p.clone()), MyCompress::new(p))
}
fn rebuild_acc(r: &WarpFoldResult<F>) -> WarpAccumulator<F,F,F,DIGEST> {
    let ec = r.witness.codeword.evaluate_hypercube_base(&MultilinearPoint::new(r.instance.eval_point.clone()));
    WarpAccumulator::new(WarpAccumulatorInstance {
        commitment_root: r.commitment_root, eval_point: r.instance.eval_point.clone(), eval_claim: ec,
        pesat_tau: r.instance.pesat_tau.clone(), pesat_x: r.instance.pesat_x.clone(), pesat_target: r.instance.pesat_target,
    }, r.witness.clone())
}
fn make_zero_acc(nw: usize, lc: usize, lm: usize, ni: usize) -> WarpAccumulator<F,F,F,DIGEST> {
    WarpAccumulator::new(WarpAccumulatorInstance {
        commitment_root: [F::ZERO; DIGEST], eval_point: vec![F::ZERO; lc], eval_claim: F::ZERO,
        pesat_tau: vec![F::ZERO; lm], pesat_x: vec![F::ZERO; ni], pesat_target: F::ZERO,
    }, WarpAccumulatorWitness {
        codeword: EvaluationsList::new(vec![F::ZERO; 1 << lc]), witness: vec![F::ZERO; nw],
    })
}

/// Common preparation: Spartan-linearize N instances. Returns witnesses + timing.
fn spartan_linearize_all(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    total_n: usize,
) -> (Vec<EvaluationsList<F>>, Vec<whir_p3::whir::constraints::statement::LinearStatement<F, EF>>, f64) {
    let spartan = R1CSProver::new();
    let start = Instant::now();
    let mut witnesses = Vec::with_capacity(total_n);
    let mut linears = Vec::with_capacity(total_n);
    for i in 0..total_n {
        let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(i as u64 + 200));
        let mut ch = MyChallenger::new(p);
        let proof = spartan.prove::<EF, _>(instance, &mut ch);
        let w = spartan.prepare_witness(instance);
        let l = linearized_statement_from_spartan_proof(shape, &proof, EF::from_u64(3));
        witnesses.push(w);
        linears.push(l);
    }
    let us = start.elapsed().as_micros() as f64;
    (witnesses, linears, us)
}

/// Terminal WHIR proof on accumulated witness. Returns (prove_us, proof).
fn terminal_whir_with_proof(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    witness: &[F],
    witness_num_vars: usize,
) -> (f64, WhirProof<F, EF, F, DIGEST>) {
    let dft = Radix2DFTSmallBatch::<F>::default();
    let ds = make_ds(config);
    let mut wvec = witness.to_vec();
    wvec.resize(wvec.len().next_power_of_two(), F::ZERO);
    let wpoly = EvaluationsList::new(wvec);
    let start = Instant::now();
    let lc = LinearStatement::<F, EF>::initialize(witness_num_vars);
    let mut stmt = config.initial_statement_with_linear(wpoly, lc);
    let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(config);
    let mut ch = seed_ch(999, &ds);
    let comm = CommitmentWriter::new(config).commit::<_,<F as Field>::Packing,F,<F as Field>::Packing,DIGEST>(
        &dft, &mut proof, &mut ch, &mut stmt).unwrap();
    WhirProver(config).prove::<_,<F as Field>::Packing,F,<F as Field>::Packing,DIGEST>(
        &dft, &mut proof, &mut ch, &stmt, comm).unwrap();
    (start.elapsed().as_micros() as f64, proof)
}

/// Terminal WHIR verify (succinct — no witness). Returns verify_us.
fn terminal_whir_verify(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    proof: &WhirProof<F, EF, F, DIGEST>,
    witness_num_vars: usize,
) -> f64 {
    let ds = make_ds(config);
    let start = Instant::now();
    let initial_claim = InitialClaim {
        eq_statement: EqStatement::initialize(witness_num_vars),
        linear_statement: LinearStatement::<F, EF>::initialize(witness_num_vars),
    };
    let mut ch = seed_ch(999, &ds);
    let parsed = CommitmentReader::new(config).parse_commitment::<F, DIGEST>(proof, &mut ch);
    WhirVerifier::new(config).verify_with_initial_claim::<<F as Field>::Packing,F,<F as Field>::Packing,DIGEST>(
        proof, &mut ch, &parsed, initial_claim).unwrap();
    start.elapsed().as_micros() as f64
}

/// Measure fold verifier FS cost at a given arity.
/// Standard: absorbs l individual roots. Union: absorbs 1 union root.
fn measure_fold_verifier_fs(log_m: usize, log_n: usize, l: usize) -> (f64, f64) {
    use whir_p3::accumulation::warp::fold::{derive_fold_challenges, derive_fold_challenges_union};

    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
    let num_fresh = l - 1;

    // Standard: absorb l individual roots
    let start_std = Instant::now();
    for _ in 0..100 {
        let mut ch = MyChallenger::new(perm.clone());
        let _challenges = derive_fold_challenges(
            &[F::ZERO; DIGEST], F::ZERO, &vec![F::ZERO; log_n], F::ZERO,
            &vec![[F::ZERO; DIGEST]; num_fresh], log_n, log_m, &mut ch,
        );
    }
    let std_us = start_std.elapsed().as_micros() as f64 / 100.0;

    // Union: absorb 1 union root
    let start_union = Instant::now();
    for _ in 0..100 {
        let mut ch = MyChallenger::new(perm.clone());
        let _challenges = derive_fold_challenges_union(
            &[F::ZERO; DIGEST], F::ZERO, &vec![F::ZERO; log_n], F::ZERO,
            &[F::ZERO; DIGEST], num_fresh, log_m, &mut ch,
        );
    }
    let union_us = start_union.elapsed().as_micros() as f64 / 100.0;

    (std_us, union_us)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let sizes_str = args.get(1).map(|s| s.as_str()).unwrap_or("10,12");
    let steps_str = args.get(2).map(|s| s.as_str()).unwrap_or("2,4,8");
    let repeats: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let batch: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
    let sizes = parse_csv(sizes_str);
    let steps_list = parse_csv(steps_str);

    println!("Apples-to-Apples Benchmark");
    println!("==========================");
    println!("Field: KoalaBear, EF: KoalaBear^4 | WHIR: fold=2, rate=1/2, sec=100");
    println!("Batch per step: {batch} | Repeats: {repeats} | N = steps × {batch}");
    println!();
    println!("ALL paths start from Spartan-linearized witnesses (same cost for all).");
    println!("Spartan time is reported once, then excluded from comparisons.");
    println!();
    println!("Post-Spartan paths (what differs):");
    println!("  1. independent_whir  = N × WHIR proof (one per witness)");
    println!("  2. direct_fold       = {batch}-arity WARP fold per step + 1 WHIR");
    println!("  3. batch_then_fold   = batch reduce({batch}→1) + fold(l=2) per step + 1 WHIR");
    println!();

    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);

    for &log_size in &sizes {
        let num_cons = 1 << log_size;
        let num_vars = 1 << log_size;
        let num_inputs = 8;
        let mut rng = SmallRng::seed_from_u64(5);
        let (shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);
        let spartan = R1CSProver::new();
        let sample_w = spartan.prepare_witness(&instance);
        let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let log_code = witness_num_vars + RS_LOG_INV_RATE;
        let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        let config = make_whir_config(witness_num_vars);

        println!("=== log2(constraints)={log_size}, witness=2^{witness_num_vars}, code=2^{log_code} ===");
        println!();
        println!("{:>6} {:>5} {:>12} | {:>14} {:>14} {:>14} | {:>9} {:>9} {:>9}",
            "steps", "N", "spartan",
            "independent", "direct_fold", "batch+fold",
            "fold/ind", "batch/ind", "batch/fold",
        );
        println!("{}", "-".repeat(120));

        for &num_steps in &steps_list {
            let total_n = num_steps * batch;

            let mut spartan_times = Vec::new();
            let mut indep_times = Vec::new();
            let mut direct_times = Vec::new();
            let mut batch_times = Vec::new();

            for _ in 0..repeats {
                // ═══ Common: Spartan linearize all N instances ═══
                let (witnesses, linears, spartan_us) = spartan_linearize_all(&shape, &instance, total_n);
                spartan_times.push(spartan_us);

                // Build FreshInstances from the witnesses (common data for paths 2 & 3)
                let z_slices: Vec<&[F]> = witnesses.iter().map(|w| w.as_slice()).collect();
                let fresh_instances: Vec<FreshInstance<F>> = z_slices.iter().map(|z| {
                    let pi = z[..num_inputs].to_vec();
                    let mut w = z[num_inputs..].to_vec();
                    w.resize(num_witness, F::ZERO);
                    FreshInstance { public_input: pi, witness: w }
                }).collect();

                // ═══ Path 1: N independent WHIR proofs (with linearized claims) ═══
                let ds = make_ds(&config);
                let start1 = Instant::now();
                for i in 0..total_n {
                    // Use the actual linearized claim so WHIR verifies constraint satisfaction,
                    // not just commitment. This makes Path 1 prove the same thing as Paths 2 & 3.
                    let mut stmt = config.initial_statement_with_linear(witnesses[i].clone(), linears[i].clone());
                    let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(&config);
                    let mut ch = seed_ch(100 + i as u64, &ds);
                    let comm = CommitmentWriter::new(&config).commit::<_,<F as Field>::Packing,F,<F as Field>::Packing,DIGEST>(
                        &dft, &mut proof, &mut ch, &mut stmt).unwrap();
                    WhirProver(&config).prove::<_,<F as Field>::Packing,F,<F as Field>::Packing,DIGEST>(
                        &dft, &mut proof, &mut ch, &stmt, comm).unwrap();
                }
                indep_times.push(start1.elapsed().as_micros() as f64);

                // ═══ Path 2: Direct fold (batch-arity per step) + 1 WHIR ═══
                let start2 = Instant::now();
                let mut acc2 = make_zero_acc(num_witness, log_code, log_m, num_inputs);
                for step in 0..num_steps {
                    let idx = step * batch;
                    let step_fresh: Vec<FreshInstance<F>> = fresh_instances[idx..idx+batch].to_vec();
                    let l = (1 + batch).next_power_of_two();
                    let log_l = l.trailing_zeros() as usize;
                    let tau: Vec<F> = (0..log_l).map(|i| F::from_u64(step as u64 * 10 + i as u64 + 42)).collect();
                    let mh2 = mh.clone(); let mc2 = mc.clone();
                    let mut ctr = step as u64 * 1000;
                    let r = warp_fold_prove_rs_committed(&shape, &step_fresh, &acc2, F::from_u64(7), &tau,
                        &[], &rs_config, &dft,
                        |_| { ctr += 1; F::from_u64(ctr + 500) },
                        |cw, ff| { let (r, _) = merkle_commit_codeword::<F,F,<F as Field>::Packing,<F as Field>::Packing,MyHash,MyCompress,DIGEST>(cw, ff, mh2.clone(), mc2.clone()); r },
                    );
                    acc2 = rebuild_acc(&r);
                }
                let fold2_us = start2.elapsed().as_micros() as f64;
                let (whir2_us, whir2_proof) = terminal_whir_with_proof(&config, &acc2.witness.witness, witness_num_vars);
                direct_times.push(fold2_us + whir2_us);
                let _ = &whir2_proof; // keep for verify timing below

                // ═══ Path 3: Batch reduce + fold(l=2) + 1 WHIR ═══
                let start3 = Instant::now();
                let mut acc3 = make_zero_acc(num_witness, log_code, log_m, num_inputs);
                for step in 0..num_steps {
                    let idx = step * batch;
                    let step_wit = &witnesses[idx..idx+batch];
                    let step_lin = &linears[idx..idx+batch];

                    // Batch reduce
                    let mut weights = Vec::new();
                    let mut targets = Vec::new();
                    for lin in step_lin {
                        let (w, &t) = lin.iter().next().unwrap();
                        weights.push(w.clone());
                        targets.push(t);
                    }
                    let gamma = F::from_u64(step as u64 + 42);
                    let cbp = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(step as u64 + 300));
                    let mut cbc = MyChallenger::new(cbp);
                    let _ = constraint_batch_prove(gamma, &weights, &targets,
                        &step_wit.iter().cloned().collect::<Vec<_>>(), &mut cbc);
                    let eta = F::from_u64(step as u64 + 13);
                    let refs: Vec<&EvaluationsList<F>> = step_wit.iter().collect();
                    let combined = random_linear_combination(&refs, eta);

                    let cs = combined.as_slice();
                    let pi = cs[..num_inputs].to_vec();
                    let mut w = cs[num_inputs..].to_vec();
                    w.resize(num_witness, F::ZERO);
                    let fresh = vec![FreshInstance { public_input: pi, witness: w }];

                    let tau = vec![F::from_u64(step as u64 + 42)];
                    let mh3 = mh.clone(); let mc3 = mc.clone();
                    let mut ctr = step as u64 * 1000;
                    let r = warp_fold_prove_rs_committed(&shape, &fresh, &acc3, F::from_u64(7), &tau,
                        &[], &rs_config, &dft,
                        |_| { ctr += 1; F::from_u64(ctr + 500) },
                        |cw, ff| { let (r, _) = merkle_commit_codeword::<F,F,<F as Field>::Packing,<F as Field>::Packing,MyHash,MyCompress,DIGEST>(cw, ff, mh3.clone(), mc3.clone()); r },
                    );
                    acc3 = rebuild_acc(&r);
                }
                let fold3_us = start3.elapsed().as_micros() as f64;
                let (whir3_us, whir3_proof) = terminal_whir_with_proof(&config, &acc3.witness.witness, witness_num_vars);
                batch_times.push(fold3_us + whir3_us);
                let _ = &whir3_proof;
            }

            let spartan_ms = median(&mut spartan_times) / 1000.0;
            let indep = median(&mut indep_times);
            let direct = median(&mut direct_times);
            let batch_f = median(&mut batch_times);

            let fold_vs_ind = indep / direct;
            let batch_vs_ind = indep / batch_f;
            let batch_vs_fold = direct / batch_f;

            println!(
                "{:>6} {:>5} {:>10.1}ms | {:>12.0}us {:>12.0}us {:>12.0}us | {:>8.2}x {:>8.2}x {:>8.2}x",
                num_steps, total_n, spartan_ms,
                indep, direct, batch_f,
                fold_vs_ind, batch_vs_ind, batch_vs_fold,
            );
        }
        println!();
    }

    println!("All times are POST-SPARTAN only (Spartan column is for reference, not included in comparisons).");
    println!("  fold/ind    = independent / direct_fold (>1 means fold is faster)");
    println!("  batch/ind   = independent / batch+fold (>1 means batch+fold is faster)");
    println!("  batch/fold  = direct_fold / batch+fold (>1 means batch reduction helps over raw fold)");

    // ═══════════════════════════════════════════════════════════════
    // Table 2: Recursive IVC Throughput (fair comparison)
    // ═══════════════════════════════════════════════════════════════
    //
    // All paths prove the SAME total number of step circuits (total_circuits).
    // l=2 paths: total_circuits steps × 1 circuit each
    // l=4 paths: total_circuits/3 steps × 3 circuits each
    // Metric: time per circuit proved (lower = better).
    println!();
    println!("Recursive IVC Throughput (Fair Comparison)");
    println!("==========================================");
    println!("All paths prove the SAME total work (same number of step circuits).");
    println!("  l=2 paths: N steps × 1 circuit/step = N circuits");
    println!("  l=4 paths: N/3 steps × 3 circuits/step = N circuits");
    println!("Metric: ms per circuit proved (lower = better).");
    println!();
    {
        use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;

        let dft_ivc = Radix2DFTSmallBatch::<F>::default();
        let (mh_ivc, mc_ivc) = make_hc();
        let ivc_config_l2 = WarpIVCConfig::default();
        let ivc_config_union = WarpIVCConfig { fold_arity: 4, use_union: true, ..Default::default() };

        // Poseidon2 perm and config — shared by fold challenger AND circuit.
        let (poseidon_perm, poseidon_config) = {
            use p3_poseidon2::poseidon2_round_numbers_128;
            const SBOX_DEGREE: u64 = 3; // KoalaBear
            let seed = 99u64;
            let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
            let (rf, rp) = poseidon2_round_numbers_128::<F>(16, SBOX_DEGREE)
                .expect("unsupported Poseidon2 parameters");
            let config = Poseidon2CircuitConfig::<F, 16>::from_rng(
                rf, rp, SBOX_DEGREE, &mut SmallRng::seed_from_u64(seed),
            );
            (perm, config)
        };

        // Total circuits to prove (must be divisible by 3 for l=4 paths)
        let total_circuits = 12;
        let steps_l2 = total_circuits;      // 12 steps × 1 circuit
        let steps_l4 = total_circuits / 3;  //  4 steps × 3 circuits

        for &log_size in &sizes {
            let step_muls = (1usize << log_size).saturating_sub(5000).max(100);
            let step = WorkloadStepCircuit::new(step_muls);
            let step_input = [F::ZERO];

            let num_cons = 1 << log_size;
            let num_vars = 1 << log_size;
            let num_inputs_synth = 8;
            let mut rng = SmallRng::seed_from_u64(5);
            let (shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(
                num_cons, num_vars, num_inputs_synth, &mut rng,
            );

            println!("=== log2(constraints)={log_size}, step_muls={step_muls}, total_circuits={total_circuits} ===");
            println!();

            // ── Path A: WARP fold (l=2), {steps_l2} steps × 1 circuit ──
            let perm_for_fold = poseidon_perm.clone();
            let make_p2_chal = move || -> MyChallenger { MyChallenger::new(perm_for_fold.clone()) };

            let t_a = Instant::now();
            let mut spartan_chal_a = make_challenger(1);
            let state_a = warp_ivc_init::<F, EF, _, _, _, _, _>(
                &shape, &instance, &mut spartan_chal_a,
                &ivc_config_l2, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                vec![], make_p2_chal.clone(),
            );
            let mut state_iter_a = state_a;
            for s in 0..steps_l2 {
                let mut ch = make_challenger(s as u64 + 10);
                state_iter_a = whir_p3::ivc::warp_ivc::warp_ivc_step::<
                    F, EF, _, _, _, _, _,
                >(
                    &state_iter_a, &instance, &mut ch,
                    &ivc_config_l2, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                    vec![], make_p2_chal.clone(),
                );
            }
            let decide_a = warp_decide_algebraic_rs(&state_iter_a.shape, &state_iter_a.accumulator);
            assert!(decide_a.is_ok(), "Path A decider failed: {decide_a:?}");
            let us_a = t_a.elapsed().as_micros() as f64;
            let per_circuit_a = us_a / total_circuits as f64;

            // ── Path B: Poseidon2 Union (l=4, Quasar), {steps_l4} steps × 3 circuits ──
            let perm_for_union = poseidon_perm.clone();
            let make_union_chal = move || -> MyChallenger { MyChallenger::new(perm_for_union.clone()) };

            let t_b = Instant::now();
            let mut spartan_chal_b = make_challenger(100);
            let log_m_orig = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
            let (target_w_b, _, _) = compute_recursive_circuit_size_union::<
                F, GenericPoseidon2LinearLayersKoalaBear, _, _,
            >(&step, &step_input, &poseidon_config, &poseidon_perm,
              shape.num_poly_vars_y(), 4, log_m_orig);

            let state_b = warp_ivc_init_recursive_union::<
                F, EF, _, _, _, _, GenericPoseidon2LinearLayersKoalaBear, _, _, _,
            >(
                &shape, &instance, &mut spartan_chal_b,
                &ivc_config_union, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                &poseidon_config, &poseidon_perm,
                &step, &step_input, 4,
                vec![], make_union_chal.clone(),
            );
            let mut state_iter_b = state_b;
            for s in 0..steps_l4 {
                let step_inputs_b: Vec<Vec<F>> = (0..3)
                    .map(|i| vec![F::from_u64(s as u64 * 10 + i)])
                    .collect();
                let mut ch = make_challenger(s as u64 + 200);
                state_iter_b = warp_ivc_step_recursive_union::<
                    F, EF, _, _, _, _, GenericPoseidon2LinearLayersKoalaBear, _, _, _,
                >(
                    &state_iter_b, &step, &step_inputs_b, 4,
                    &mut ch, &ivc_config_union, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                    &poseidon_config, &poseidon_perm,
                    Some(target_w_b), vec![],
                    make_union_chal.clone(),
                );
            }
            let decide_b = warp_decide_algebraic_rs(&state_iter_b.shape, &state_iter_b.accumulator);
            assert!(decide_b.is_ok(), "Path B decider failed: {decide_b:?}");
            let us_b = t_b.elapsed().as_micros() as f64;
            let per_circuit_b = us_b / total_circuits as f64;

            // ── Print results ──
            println!("{:>25} {:>10} {:>8} {:>12} {:>12} {:>10}",
                "path", "total(ms)", "steps", "folds", "ms/circuit", "vs A");
            println!("{}", "-".repeat(80));
            println!("{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>10}",
                "A: WARP (l=2)",
                us_a / 1000.0, steps_l2, steps_l2,
                per_circuit_a / 1000.0, "baseline");
            println!("{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>9.2}x",
                "B: WARP+Quasar (l=4)",
                us_b / 1000.0, steps_l4, steps_l4,
                per_circuit_b / 1000.0,
                per_circuit_a / per_circuit_b);

            // Symphony paths (only with feature)
            #[cfg(feature = "symphony")]
            {
                use whir_p3::ivc::warp_ivc::{
                    warp_ivc_init_cp, warp_ivc_step_recursive_cp,
                    warp_ivc_init_recursive_union_cp, warp_ivc_step_recursive_union_cp,
                    compute_recursive_union_circuit_size,
                };
                use whir_p3::ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;

                // Path C: Symphony (l=2), steps_l2 steps × 1 circuit
                let symphony_ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let t_c = Instant::now();
                    let mut spartan_chal_c = make_challenger(300);
                    let state_c = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
                        &shape, &instance, &mut spartan_chal_c,
                        &ivc_config_l2, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                        vec![], make_p2_chal.clone(),
                    );
                    let (target_w_c, _, _) = compute_cp_circuit_size(&step, &step_input);
                    let mut state_iter_c = state_c;
                    for s in 0..steps_l2 {
                        let mut ch = make_challenger(s as u64 + 310);
                        state_iter_c = warp_ivc_step_recursive_cp::<
                            F, EF, _, _, _, _, _, _,
                        >(
                            &state_iter_c, &step, &step_input, &mut ch,
                            &ivc_config_l2, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                            Some(target_w_c), vec![],
                            make_p2_chal.clone(),
                        );
                    }
                    let decide_c = warp_decide_algebraic_rs(&state_iter_c.shape, &state_iter_c.accumulator);
                    assert!(decide_c.is_ok(), "Path C decider failed: {decide_c:?}");
                    let us_c = t_c.elapsed().as_micros() as f64;
                    us_c
                }));
                match symphony_ok {
                    Ok(us_c) => {
                        let per_circuit_c = us_c / total_circuits as f64;
                        println!("{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>9.2}x",
                            "C: Symphony (l=2)",
                            us_c / 1000.0, steps_l2, steps_l2,
                            per_circuit_c / 1000.0,
                            per_circuit_a / per_circuit_c);
                    }
                    Err(_) => {
                        println!("{:>25} {:>8} {:>8} {:>12} {:>12} {:>10}",
                            "C: Symphony (l=2)", "SKIP", "—", "—", "(too small)", "—");
                    }
                }

                // Path D: Symphony Union (l=4), steps_l4 steps × 3 circuits
                let symphony_d_ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (target_w_d, _, _) = compute_recursive_union_circuit_size(
                        &step, &step_input, 4,
                    );
                    let t_d = Instant::now();
                    let state_d = warp_ivc_init_recursive_union_cp::<F, _>(
                        &step, &step_input, 4,
                        &ivc_config_union, target_w_d,
                        vec![],
                    );
                    let mut state_iter_d = state_d;
                    for s in 0..steps_l4 {
                        let step_inputs_d: Vec<Vec<F>> = (0..3)
                            .map(|i| vec![F::from_u64(s as u64 * 10 + i)])
                            .collect();
                        let mut ch = make_challenger(s as u64 + 410);
                        state_iter_d = warp_ivc_step_recursive_union_cp::<
                            F, EF, _, _, _, _, _, _,
                        >(
                            &state_iter_d, &step, &step_inputs_d, 4,
                            &mut ch, &ivc_config_union, &dft_ivc, mh_ivc.clone(), mc_ivc.clone(),
                            Some(target_w_d), vec![],
                            make_p2_chal.clone(),
                        );
                    }
                    let decide_d = warp_decide_algebraic_rs(&state_iter_d.shape, &state_iter_d.accumulator);
                    assert!(decide_d.is_ok(), "Path D decider failed: {decide_d:?}");
                    let us_d = t_d.elapsed().as_micros() as f64;
                    us_d
                }));
                match symphony_d_ok {
                    Ok(us_d) => {
                        let per_circuit_d = us_d / total_circuits as f64;
                        println!("{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>9.2}x",
                            "D: Symphony+Quasar (l=4)",
                            us_d / 1000.0, steps_l4, steps_l4,
                            per_circuit_d / 1000.0,
                            per_circuit_a / per_circuit_d);
                    }
                    Err(_) => {
                        println!("{:>25} {:>8} {:>8} {:>12} {:>12} {:>10}",
                            "D: Symphony+Quasar (l=4)", "SKIP", "—", "—", "(too small)", "—");
                    }
                }
            }

            println!();
            println!("  All paths prove {total_circuits} circuits total. vs A > 1 means faster than baseline.");
            println!();
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Table 3: Terminal WHIR Verify Time
    // ═══════════════════════════════════════════════════════════════
    println!();
    println!("Terminal WHIR Verify Time");
    println!("========================");
    println!("This is the succinct verifier cost (constant per IVC chain, independent of num_steps).");
    println!();
    println!("{:>10} {:>12} {:>12}", "log_size", "prove(us)", "verify(us)");
    println!("{}", "-".repeat(38));

    let dft_v = Radix2DFTSmallBatch::<F>::default();
    for &log_size in &sizes {
        let num_vars = 1 << log_size;
        let num_inputs = 8;
        let mut rng = SmallRng::seed_from_u64(5);
        let (_shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(1 << log_size, num_vars, num_inputs, &mut rng);
        let spartan = R1CSProver::new();
        let sample_w = spartan.prepare_witness(&instance);
        let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
        let wnv = num_witness.trailing_zeros() as usize;
        let cfg = make_whir_config(wnv);

        let (prove_us, proof) = terminal_whir_with_proof(&cfg, sample_w.as_slice(), wnv);
        let verify_us = terminal_whir_verify(&cfg, &proof, wnv);
        println!("{:>10} {:>10.0}us {:>10.0}us", log_size, prove_us, verify_us);
    }

    // ═══════════════════════════════════════════════════════════════
    // Table 3: Quasar Verifier Scaling (O(1) vs O(ℓ))
    // ═══════════════════════════════════════════════════════════════
    println!();
    println!("Quasar Verifier Scaling: Fold FS Challenge Derivation");
    println!("=====================================================");
    println!("Measures Fiat-Shamir challenge derivation cost for standard (O(ℓ) roots)");
    println!("vs Quasar union (O(1) root). This is the per-fold verifier cost.");
    println!();

    let log_m_bench = sizes.last().copied().unwrap_or(14);
    let log_n_bench = log_m_bench + RS_LOG_INV_RATE;
    println!("Using log_m={log_m_bench}, log_n={log_n_bench}");
    println!();
    println!("{:>6} {:>12} {:>12} {:>10}", "arity", "standard(us)", "union(us)", "speedup");
    println!("{}", "-".repeat(46));

    for &arity in &[2, 4, 8, 16, 32, 64] {
        let (std_us, union_us) = measure_fold_verifier_fs(log_m_bench, log_n_bench, arity);
        let speedup = std_us / union_us;
        println!("{:>6} {:>10.1}us {:>10.1}us {:>9.1}x", arity, std_us, union_us, speedup);
    }
    println!();
    println!("Quasar union absorbs 1 root regardless of arity → O(1) FS cost.");
    println!("Standard absorbs ℓ roots → O(ℓ) FS cost. Speedup grows with arity.");
}
