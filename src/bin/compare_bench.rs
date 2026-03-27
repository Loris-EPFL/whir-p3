//! Honest apples-to-apples benchmark.
//!
//! ALL paths start from the same point: N Spartan-linearized witnesses.
//! Spartan linearization is timed ONCE and reported separately.
//! Then each path only differs in how it generates proofs from those witnesses.
//!
//! Usage:
//!   cargo run --release --bin compare_bench -- <log_sizes> <num_steps> <repeats> <batch>

use std::{env, time::Instant};

use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
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
            encoding::merkle_commit_codeword,
            fold::{warp_fold_prove_rs_committed, RSEncodingConfig, WarpFoldResult},
        },
    },
    circuit::{builder::CircuitBuilder, poseidon2::Poseidon2CircuitConfig, sponge::CircuitChallenger},
    fiat_shamir::domain_separator::DomainSeparator,
    ivc::{
        step::TrivialStepCircuit,
        warp_fold_verifier_circuit::{WarpFoldVerifierWitness, synthesize_warp_ivc_circuit},
        warp_ivc::compute_recursive_circuit_size,
    },
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    spartan::{
        r1cs::{R1CSInstance, R1CSShape},
        r1cs_prover::R1CSProver,
    },
    whir::{
        committer::writer::CommitmentWriter,
        constraints::statement::LinearStatement,
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
    },
};

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2BabyBear<16>;
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

/// Terminal WHIR proof on accumulated witness.
fn terminal_whir(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    witness: &[F],
    witness_num_vars: usize,
) -> f64 {
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
    start.elapsed().as_micros() as f64
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
    println!("Field: BabyBear, EF: BabyBear^4 | WHIR: fold=2, rate=1/2, sec=100");
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
                        &rs_config, &dft,
                        |_| { ctr += 1; F::from_u64(ctr + 500) },
                        |cw, ff| { let (r, _) = merkle_commit_codeword::<F,F,<F as Field>::Packing,<F as Field>::Packing,MyHash,MyCompress,DIGEST>(cw, ff, mh2.clone(), mc2.clone()); r },
                    );
                    acc2 = rebuild_acc(&r);
                }
                let fold2_us = start2.elapsed().as_micros() as f64;
                let whir2_us = terminal_whir(&config, &acc2.witness.witness, witness_num_vars);
                direct_times.push(fold2_us + whir2_us);

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
                        &rs_config, &dft,
                        |_| { ctr += 1; F::from_u64(ctr + 500) },
                        |cw, ff| { let (r, _) = merkle_commit_codeword::<F,F,<F as Field>::Packing,<F as Field>::Packing,MyHash,MyCompress,DIGEST>(cw, ff, mh3.clone(), mc3.clone()); r },
                    );
                    acc3 = rebuild_acc(&r);
                }
                let fold3_us = start3.elapsed().as_micros() as f64;
                let whir3_us = terminal_whir(&config, &acc3.witness.witness, witness_num_vars);
                batch_times.push(fold3_us + whir3_us);
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
}
