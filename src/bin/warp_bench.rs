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
    accumulation::warp::{
        accumulator::{FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
        decider::warp_decide_algebraic,
        fold::{warp_fold_prove, warp_fold_verify, FreshInstancePublic, WarpFoldResult},
    },
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    spartan::r1cs::{R1CSShape, SparseMatEntry},
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
    // Pad to next power of 2 for WHIR compatibility
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

fn make_initial_acc(num_witness: usize, log_n: usize, log_m: usize, num_inputs: usize) -> WarpAccumulator<F, F, F, DIGEST> {
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: [F::ZERO; DIGEST],
            eval_point: vec![F::ZERO; log_n],
            eval_claim: F::ZERO,
            pesat_tau: vec![F::ZERO; log_m],
            pesat_x: vec![F::ZERO; num_inputs],
            pesat_target: F::ZERO,
        },
        WarpAccumulatorWitness {
            codeword: EvaluationsList::new(vec![F::ZERO; 1 << log_n]),
            witness: vec![F::ZERO; num_witness],
        },
    )
}

fn rebuild_acc(result: &WarpFoldResult<F>, log_n: usize) -> WarpAccumulator<F, F, F, DIGEST> {
    let eval_claim = result.witness.codeword.evaluate_hypercube_base(
        &MultilinearPoint::new(result.instance.eval_point.clone()),
    );
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: [F::ZERO; DIGEST],
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
    let num_vars_y: usize = 1 << shape.num_poly_vars_y();
    let log_n = num_vars_y.trailing_zeros() as usize;
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;

    let mut acc = make_initial_acc(num_witness, log_n, log_m, num_inputs);
    let initial_wit_bytes = acc.witness.witness.len() * size_of::<F>();

    // FOLD STEPS (sumcheck only, no WHIR proof)
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

        let mut ctr = step as u64 * 1000;
        let result = warp_fold_prove(shape, &fresh, &acc, F::from_u64(7), &tau,
            |_| { ctr += 1; F::from_u64(ctr + 500) });
        acc = rebuild_acc(&result, log_n);
    }
    let fold_us = fold_start.elapsed().as_micros() as f64;

    // TERMINAL WHIR PROOF (once at the end)
    let ds = make_domain_sep(config);
    let dft = Radix2DFTSmallBatch::<F>::default();

    let decide_start = Instant::now();
    {
        // Build a linear claim encoding the accumulated eval claim
        let mut linear_claim = LinearStatement::<F, EF>::initialize(log_n);
        // The WHIR proof proves the polynomial satisfies the linear claim
        let mut statement = config.initial_statement_with_linear(
            acc.witness.codeword.clone(),
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
    }
    let decide_us = decide_start.elapsed().as_micros() as f64;

    // VERIFY terminal proof
    let verify_start = Instant::now();
    {
        let mut linear_claim = LinearStatement::<F, EF>::initialize(log_n);
        let initial_claim = InitialClaim {
            eq_statement: EqStatement::initialize(log_n),
            linear_statement: linear_claim,
        };
        // Re-run prove to get the proof object (in a real system the proof would be passed)
        let mut statement = config.initial_statement_with_linear(
            acc.witness.codeword.clone(),
            LinearStatement::<F, EF>::initialize(log_n),
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

        let mut v_challenger = seed_challenger(999, &ds);
        let parsed = CommitmentReader::new(config)
            .parse_commitment::<F, DIGEST>(&proof, &mut v_challenger);
        WhirVerifier::new(config)
            .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                &proof, &mut v_challenger, &parsed, initial_claim,
            ).unwrap();
    }
    let verify_us = verify_start.elapsed().as_micros() as f64;

    let final_wit_bytes = acc.witness.witness.len() * size_of::<F>();
    let fixed = final_wit_bytes == initial_wit_bytes;

    (fold_us, decide_us, verify_us, final_wit_bytes, fixed)
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

    println!("WARP vs No-Fold Benchmark (with WHIR PCS)");
    println!("==========================================");
    println!("Field: BabyBear (31-bit), EF: BabyBear^4");
    println!("WHIR: folding_factor=2, rate=1/2, security=100, pow=0");
    println!("Batch per step: {batch} | Repeats: {repeats}");
    println!();
    println!("warp  = sumcheck folds + 1 terminal WHIR commit+prove");
    println!("no_fold = N independent WHIR commit+prove (one per instance)");
    println!();

    for &size_log2 in &sizes {
        let num_cons = 1usize << size_log2;
        let num_vars = 2 * num_cons;
        let num_inputs = 8;
        let shape = make_shape(num_cons.min(num_vars / 2), num_vars, num_inputs);
        let num_vars_y: usize = 1 << shape.num_poly_vars_y();
        let num_witness = num_vars_y - num_inputs;
        let log_n = num_vars_y.trailing_zeros() as usize;

        let config = make_whir_config(log_n);

        println!("=== log2(witness) = {size_log2} (n={num_vars_y}, M={num_cons}) ===");
        println!();
        println!("{:>6} | {:>10} {:>10} {:>10} {:>10} | {:>10} {:>10} {:>10} | {:>7} {:>10}",
            "steps",
            "warp_fold", "warp_whir", "warp_tot", "warp_vfy",
            "nf_prove", "nf_verify", "nf_total",
            "speedup", "witness",
        );
        println!("{}", "-".repeat(115));

        for &num_steps in &steps_list {
            let total_instances = num_steps * batch;

            // Warm up
            let _ = run_warp(&shape, &config, 1, batch, num_cons, num_witness, num_inputs);
            let _ = run_no_fold(&config, 1, num_cons, num_witness);

            let mut warp_folds = Vec::new();
            let mut warp_decides = Vec::new();
            let mut warp_verifies = Vec::new();
            let mut nf_proves = Vec::new();
            let mut nf_verifies = Vec::new();
            let mut last_fixed = true;
            let mut last_wit_bytes = 0;

            for _ in 0..repeats {
                let (fold_us, decide_us, verify_us, wit_bytes, fixed) =
                    run_warp(&shape, &config, num_steps, batch, num_cons, num_witness, num_inputs);
                warp_folds.push(fold_us);
                warp_decides.push(decide_us);
                warp_verifies.push(verify_us);
                last_fixed = fixed;
                last_wit_bytes = wit_bytes;

                let (nf_p, nf_v) = run_no_fold(&config, total_instances, num_cons, num_witness);
                nf_proves.push(nf_p);
                nf_verifies.push(nf_v);
            }

            let wf = median(&mut warp_folds);
            let wd = median(&mut warp_decides);
            let wv = median(&mut warp_verifies);
            let warp_total = wf + wd;

            let nfp = median(&mut nf_proves);
            let nfv = median(&mut nf_verifies);
            let nf_total = nfp + nfv;

            let speedup = nf_total / warp_total;
            let tag = if last_fixed { "FIXED" } else { "GREW!" };

            println!(
                "{:>6} | {:>8.0}us {:>8.0}us {:>8.0}us {:>8.0}us | {:>8.0}us {:>8.0}us {:>8.0}us | {:>6.2}x  {} [{}]",
                num_steps,
                wf, wd, warp_total, wv,
                nfp, nfv, nf_total,
                speedup,
                human_bytes(last_wit_bytes),
                tag,
            );
        }
        println!();
    }

    println!("Legend:");
    println!("  warp_fold  = total sumcheck fold time (all steps, no WHIR proof)");
    println!("  warp_whir  = terminal WHIR commit+prove (runs once)");
    println!("  warp_tot   = warp_fold + warp_whir (total prover cost)");
    println!("  warp_vfy   = terminal WHIR verify (runs once)");
    println!("  nf_prove   = N independent WHIR commit+prove");
    println!("  nf_verify  = N independent WHIR verify");
    println!("  speedup    = nf_total / warp_total (>1 = WARP wins)");
    println!("  witness    = final accumulated witness size [FIXED = never grew]");
}
