//! Benchmark: Spartan → Quasar Multicast → Eval Fold → Terminal WHIR
//!
//! Compares:
//! - **no_fold**: N independent WHIR proofs (one per instance)
//! - **pipeline**: Spartan → Quasar multicast → N eval fold steps → 1 WHIR proof
//!
//! Usage:
//!   cargo run --release --bin pipeline_bench -- <log_sizes> <num_steps> <repeats> <batch>
//!
//! Examples:
//!   cargo run --release --bin pipeline_bench -- "8,10" "4,8" 3 2
//!   cargo run --release --bin pipeline_bench -- "10" "8" 5 1

use std::{env, time::Instant};

use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{rngs::SmallRng, SeedableRng};

use whir_p3::{
    accumulation::{
        constraint_batch::constraint_batch_prove,
        linearized::linearized_statement_from_spartan_proof,
        quasar::fresh::FreshLinearInstance,
        random_lc::random_linear_combination,
        warp::{
            encoding::rs_encode,
            eval_fold::{
                eval_fold_prove, initial_eval_accumulator, EvalAccumulator,
                EvalAccumulatorInstance, EvalAccumulatorWitness, EvalDecider,
            },
            fold::RSEncodingConfig,
        },
    },
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    poly::evals::EvaluationsList,
    spartan::{
        r1cs::R1CSInstance,
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

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2KoalaBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

const RS_LOG_INV_RATE: usize = 1;

fn parse_csv(s: &str) -> Vec<usize> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

fn make_whir_config(num_vars: usize) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);
    let params = ProtocolParameters {
        security_level: 100,
        pow_bits: 0,
        rs_domain_initial_reduction_factor: 1,
        folding_factor: FoldingFactor::Constant(2),
        merkle_hash: MyHash::new(perm.clone()),
        merkle_compress: MyCompress::new(perm),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: RS_LOG_INV_RATE,
    };
    WhirConfig::new(num_vars, params)
}

fn seed_challenger(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    seed: u64,
) -> MyChallenger {
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    let mut challenger = MyChallenger::new(perm);
    let mut ds = DomainSeparator::<EF, F>::new(vec![]);
    ds.commit_statement::<_, _, _, 8>(config);
    ds.add_whir_proof::<_, _, _, 8>(config);
    ds.observe_domain_separator(&mut challenger);
    challenger
}

/// Prepare synthetic R1CS material at given size.
fn prepare(log_size: usize) -> (
    whir_p3::spartan::r1cs::R1CSShape<F>,
    Vec<R1CSInstance<F>>,
    Vec<EvaluationsList<F>>,
    usize, // witness_num_vars
) {
    let num_cons = 1 << log_size;
    let num_vars = 1 << log_size;
    let num_inputs = 8;
    let mut rng = SmallRng::seed_from_u64(5);
    let (shape, instance) =
        R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);
    let spartan = R1CSProver::new();
    let witness = spartan.prepare_witness(&instance);
    let witness_num_vars = witness.num_variables();
    (shape, vec![instance], vec![witness], witness_num_vars)
}

/// No-fold baseline: one WHIR proof per instance.
fn run_no_fold(
    witness: &EvaluationsList<F>,
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    num_steps: usize,
) -> f64 {
    let dft = Radix2DFTSmallBatch::<F>::default();
    let start = Instant::now();
    for step in 0..num_steps {
        let linear_claim = LinearStatement::<F, EF>::initialize(witness.num_variables());
        let mut statement = config.initial_statement_with_linear(witness.clone(), linear_claim);
        let mut proof = WhirProof::<F, EF, F, 8>::from_whir_config(config);
        let mut challenger = seed_challenger(config, 100 + step as u64);
        let commitment = CommitmentWriter::new(config)
            .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &dft, &mut proof, &mut challenger, &mut statement,
            )
            .unwrap();
        WhirProver(config)
            .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &dft, &mut proof, &mut challenger, &statement, commitment,
            )
            .unwrap();
    }
    start.elapsed().as_secs_f64() * 1000.0
}

/// Pipeline: Spartan → Quasar multicast → eval folds → 1 WHIR proof.
fn run_pipeline(
    shape: &whir_p3::spartan::r1cs::R1CSShape<F>,
    instances: &[R1CSInstance<F>],
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    num_steps: usize,
    batch: usize,
) -> (f64, f64, f64) {
    let dft = Radix2DFTSmallBatch::<F>::default();
    let rs_config = RSEncodingConfig::new(1, RS_LOG_INV_RATE);
    let spartan = R1CSProver::new();

    // ── Spartan linearize ──
    let spartan_start = Instant::now();
    let mut all_fresh = Vec::new();
    let mut all_witnesses = Vec::new();
    for step in 0..(num_steps * batch) {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(step as u64 + 200));
        let mut challenger = MyChallenger::new(perm);
        let proof = spartan.prove::<EF, _>(&instances[0], &mut challenger);
        let witness = spartan.prepare_witness(&instances[0]);
        let linear = linearized_statement_from_spartan_proof(shape, &proof, EF::from_u64(3));
        all_fresh.push(FreshLinearInstance::new(linear, witness.clone()));
        all_witnesses.push(witness);
    }
    let spartan_ms = spartan_start.elapsed().as_secs_f64() * 1000.0;

    let witness_num_vars = all_witnesses[0].num_variables();
    let code_len = 1 << (witness_num_vars + RS_LOG_INV_RATE);

    // ── Fold steps ──
    let fold_start = Instant::now();
    let mut running: EvalAccumulator<F, 8> =
        initial_eval_accumulator(code_len, 1 << witness_num_vars, witness_num_vars);

    for step in 0..num_steps {
        // Quasar multicast: batch instances for this step
        let start_idx = step * batch;
        let end_idx = start_idx + batch;
        let step_fresh: Vec<_> = all_fresh[start_idx..end_idx].to_vec();
        let step_witnesses: Vec<_> = all_witnesses[start_idx..end_idx].to_vec();

        // Extract weights + targets
        let mut weights = Vec::new();
        let mut targets = Vec::new();
        for inst in &step_fresh {
            let (w, &t) = inst.linear_claim.iter().next().unwrap();
            weights.push(w.clone());
            targets.push(t);
        }

        // Constraint batch sumcheck
        let gamma = F::from_u64(step as u64 + 42);
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(step as u64 + 300));
        let mut challenger = MyChallenger::new(perm);
        let (_batch_proof, _reduction_point) = constraint_batch_prove(
            gamma, &weights, &targets, &step_witnesses, &mut challenger,
        );

        // Random LC
        let eta = F::from_u64(step as u64 + 13);
        let wit_refs: Vec<&EvaluationsList<F>> = step_witnesses.iter().collect();
        let combined = random_linear_combination(&wit_refs, eta);

        // RS-encode + create fresh accumulator
        let codeword = rs_encode(&combined, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        let eval_point = vec![F::ZERO; witness_num_vars];
        let eval_claim = combined.as_slice()[0];

        let fresh_acc = EvalAccumulator {
            instance: EvalAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point,
                eval_claim,
            },
            witness: EvalAccumulatorWitness {
                codeword,
                witness_poly: combined,
            },
        };

        // Eval fold
        let tau = vec![F::from_u64(step as u64 + 7)];
        let mut ctr = step as u64 * 1000;
        let result = eval_fold_prove(
            &[running, fresh_acc],
            &tau, &rs_config, &dft, 0, 0,
            |_| { ctr += 1; F::from_u64(ctr + 500) },
            |_cw, _ff| [F::ZERO; 8],
        );
        running = EvalAccumulator { instance: result.instance, witness: result.witness };
    }
    let fold_ms = fold_start.elapsed().as_secs_f64() * 1000.0;

    // ── Terminal WHIR proof ──
    let whir_start = Instant::now();
    let decider = EvalDecider::<EF, F, MyHash, MyCompress, MyChallenger>::new(config);
    let mut prove_challenger = seed_challenger(config, 999);
    let _proof = decider
        .prove::<_, F, <F as Field>::Packing, _, 8>(
            &dft, &mut prove_challenger, &running,
        )
        .unwrap();
    let whir_ms = whir_start.elapsed().as_secs_f64() * 1000.0;

    (spartan_ms, fold_ms, whir_ms)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let sizes_str = args.get(1).map(|s| s.as_str()).unwrap_or("8,10");
    let steps_str = args.get(2).map(|s| s.as_str()).unwrap_or("4,8");
    let repeats: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let batch: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);

    let sizes = parse_csv(sizes_str);
    let steps_list = parse_csv(steps_str);

    println!("Pipeline Benchmark: Spartan → Quasar → EvalFold → WHIR");
    println!("========================================================");
    println!("Field: KoalaBear (31-bit), EF: KoalaBear^4");
    println!("RS rate: 1/{}, batch: {batch}, repeats: {repeats}", 1 << RS_LOG_INV_RATE);
    println!();
    println!("{:>6} {:>6} {:>12} {:>12} {:>12} {:>12} {:>12} {:>8}",
        "log_n", "steps", "no_fold_ms", "spartan_ms", "fold_ms", "whir_ms", "total_ms", "speedup");
    println!("{}", "-".repeat(86));

    for &log_size in &sizes {
        let (shape, instances, witnesses, witness_num_vars) = prepare(log_size);
        let config = make_whir_config(witness_num_vars);

        for &num_steps in &steps_list {
            // No-fold baseline
            let mut no_fold_total = 0.0;
            for _ in 0..repeats {
                no_fold_total += run_no_fold(&witnesses[0], &config, num_steps * batch);
            }
            let no_fold_ms = no_fold_total / repeats as f64;

            // Pipeline
            let mut spartan_total = 0.0;
            let mut fold_total = 0.0;
            let mut whir_total = 0.0;
            for _ in 0..repeats {
                let (s, f, w) = run_pipeline(&shape, &instances, &config, num_steps, batch);
                spartan_total += s;
                fold_total += f;
                whir_total += w;
            }
            let spartan_ms = spartan_total / repeats as f64;
            let fold_ms = fold_total / repeats as f64;
            let whir_ms = whir_total / repeats as f64;
            let pipeline_total = spartan_ms + fold_ms + whir_ms;
            let speedup = no_fold_ms / pipeline_total;

            println!("{log_size:>6} {num_steps:>6} {no_fold_ms:>12.2} {spartan_ms:>12.2} {fold_ms:>12.2} {whir_ms:>12.2} {pipeline_total:>12.2} {speedup:>8.2}x");
        }
    }
}
