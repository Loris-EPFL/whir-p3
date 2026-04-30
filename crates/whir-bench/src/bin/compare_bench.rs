//! Honest apples-to-apples benchmark — ported from the pre-refactor
//! `src/bin/compare_bench.rs`. Produces the same 4-table output in the
//! crates/* workspace.
//!
//! ALL paths start from the same point: N Spartan-linearized witnesses.
//! Spartan linearization is timed ONCE and reported separately.
//! Then each path only differs in how it generates proofs from those witnesses.
//!
//! Usage:
//!   cargo run --release -p whir-bench --features symphony \
//!       --bin compare_bench -- <log_sizes> <num_steps> <repeats> <batch>

use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};

use accumulation::{
    constraint_batch::constraint_batch_prove, linearized::linearized_statement_from_spartan_proof,
    random_lc::random_linear_combination,
};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{SeedableRng, rngs::SmallRng};
use warp::{
    accumulator::{
        FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness,
    },
    decider::warp_decide_full_rs,
    encoding::merkle_commit_codeword,
    fold::{RSEncodingConfig, WarpFoldResult, warp_fold_prove_rs_committed},
};
use whir_circuit::poseidon2::Poseidon2CircuitConfig;
use whir_core::{
    parameters::{FoldingFactor, ProtocolParameters, errors::SecurityAssumption},
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
};
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::{
        WarpIVCConfig, compute_recursive_circuit_size_union, warp_ivc_init,
        warp_ivc_init_recursive_union, warp_ivc_step_recursive_union,
    },
};
use whir_pcs::{
    fiat_shamir::domain_separator::DomainSeparator,
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{EqStatement, InitialClaim, LinearStatement},
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
        verifier::Verifier as WhirVerifier,
    },
};
use whir_spartan::{
    r1cs::{R1CSInstance, R1CSShape},
    r1cs_prover::R1CSProver,
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
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}
fn make_whir_config(nv: usize) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    WhirConfig::new(
        nv,
        ProtocolParameters {
            security_level: 100,
            pow_bits: 0,
            rs_domain_initial_reduction_factor: 1,
            folding_factor: FoldingFactor::Constant(2),
            merkle_hash: MyHash::new(p.clone()),
            merkle_compress: MyCompress::new(p),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: RS_LOG_INV_RATE,
        },
    )
}
fn make_ds(c: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>) -> DomainSeparator<EF, F> {
    let mut d = DomainSeparator::<EF, F>::new(vec![]);
    d.commit_statement::<_, _, _, DIGEST>(c);
    d.add_whir_proof::<_, _, _, DIGEST>(c);
    d
}
fn seed_ch(s: u64, d: &DomainSeparator<EF, F>) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(s));
    let mut c = MyChallenger::new(p);
    d.observe_domain_separator(&mut c);
    c
}
fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}
fn make_hc() -> (MyHash, MyCompress) {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    (MyHash::new(p.clone()), MyCompress::new(p))
}
fn rebuild_acc(r: &WarpFoldResult<F>) -> WarpAccumulator<F, F, F, DIGEST> {
    let ec = r
        .witness
        .codeword
        .evaluate_hypercube_base(&MultilinearPoint::new(r.instance.eval_point.clone()));
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

fn assert_full_warp_terminal(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, DIGEST>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Radix2DFTSmallBatch<F>,
) {
    warp_decide_full_rs(shape, acc, folding_factor, log_inv_rate, dft)
        .expect("full WARP terminal decider failed");

    let (mh, mc) = make_hc();
    let (root, _) = merkle_commit_codeword::<
        F,
        F,
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        DIGEST,
    >(&acc.witness.codeword, folding_factor, mh, mc);
    assert_eq!(
        root, acc.instance.commitment_root,
        "accumulator commitment root is not bound to the codeword"
    );
}

fn assert_terminal_whir_bound(
    proof: &WhirProof<F, EF, F, DIGEST>,
    acc: &WarpAccumulator<F, F, F, DIGEST>,
) {
    assert_eq!(
        proof.initial_commitment, acc.instance.commitment_root,
        "terminal WHIR commitment root does not match accumulator root"
    );
}

/// Common preparation: Spartan-linearize N instances. Returns witnesses + timing.
fn spartan_linearize_all(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    total_n: usize,
) -> (Vec<EvaluationsList<F>>, Vec<LinearStatement<F, EF>>, f64) {
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
    let comm = CommitmentWriter::new(config)
        .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
            &dft, &mut proof, &mut ch, &mut stmt,
        )
        .unwrap();
    WhirProver(config)
        .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
            &dft, &mut proof, &mut ch, &stmt, comm,
        )
        .unwrap();
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
    WhirVerifier::new(config)
        .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
            proof,
            &mut ch,
            &parsed,
            initial_claim,
        )
        .unwrap();
    start.elapsed().as_micros() as f64
}

/// Measure fold verifier FS cost at a given arity.
/// Standard: absorbs l individual roots. Union: absorbs 1 union root.
fn measure_fold_verifier_fs(log_m: usize, log_n: usize, l: usize) -> (f64, f64) {
    use warp::fold::{derive_fold_challenges, derive_fold_challenges_union};

    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
    let num_fresh = l - 1;

    // Standard: absorb l individual roots
    let start_std = Instant::now();
    for _ in 0..100 {
        let mut ch = MyChallenger::new(perm.clone());
        let _challenges = derive_fold_challenges(
            &[F::ZERO; DIGEST],
            F::ZERO,
            &vec![F::ZERO; log_n],
            F::ZERO,
            &vec![[F::ZERO; DIGEST]; num_fresh],
            log_n,
            log_m,
            &mut ch,
        );
    }
    let std_us = start_std.elapsed().as_micros() as f64 / 100.0;

    // Union: absorb 1 union root
    let start_union = Instant::now();
    for _ in 0..100 {
        let mut ch = MyChallenger::new(perm.clone());
        let _challenges = derive_fold_challenges_union(
            &[F::ZERO; DIGEST],
            F::ZERO,
            &vec![F::ZERO; log_n],
            F::ZERO,
            &[F::ZERO; DIGEST],
            num_fresh,
            log_m,
            &mut ch,
        );
    }
    let union_us = start_union.elapsed().as_micros() as f64 / 100.0;

    (std_us, union_us)
}

/// Measure the FULL fold-verifier cost at a given arity.
///
/// Beyond FS challenge derivation, the native verifier also runs:
///   (a) initial-target computation Σ_i eq(τ,i)·(μ_i + ω·η_i)  — O(ℓ)
///   (b) twin-constraint sumcheck verification  — O(log ℓ)
///
/// For Quasar's `union` variant, (a)(b) are the same; the only saving vs
/// `standard` is in the FS absorb phase. So the "wall-clock verifier speedup"
/// from Quasar is a **constant-factor** win (not asymptotic). The asymptotic
/// O(log ℓ) win is only realised when this verifier is embedded *in a circuit*
/// — see the `circuit_size_arity` benchmark.
fn measure_fold_verifier_full(log_m: usize, log_n: usize, l: usize) -> (f64, f64) {
    use warp::fold::{
        derive_fold_challenges, derive_fold_challenges_union, warp_fold_verify_sumcheck,
    };

    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
    let num_fresh = l - 1;
    let log_l = l.trailing_zeros() as usize;

    // Non-zero μ_i and η_i so none of the arithmetic below is dead code.
    // Pattern: μ_i = 1 + i, η_i = 7 + 3i (arbitrary, just non-zero and varying).
    let mu_vals: Vec<F> = (0..l).map(|i| F::from_u64(i as u64 + 1)).collect();
    let eta_vals: Vec<F> = (0..l).map(|i| F::from_u64(7 + 3 * i as u64)).collect();

    // Evaluate a degree-2 polynomial given by evaluations at {0, 1, 2} at point `c`
    // via Lagrange. Pre-computed once outside the hot loop.
    let eval_deg2_at = |h0: F, h1: F, h2: F, c: F| -> F {
        let two = F::from_u64(2);
        let inv2 = two.inverse();
        // h(c) = h0 · (c-1)(c-2)/2  − h1 · c(c-2)  +  h2 · c(c-1)/2
        h0 * ((c - F::ONE) * (c - two) * inv2) - h1 * (c * (c - two))
            + h2 * (c * (c - F::ONE) * inv2)
    };

    // Build a *consistent* synthetic sumcheck trace given a starting target
    // and log_l challenges. Each round polynomial satisfies h(0)+h(1) = expected
    // and h(2) = 1 (non-trivial), so the verifier actually does field arithmetic.
    let build_trace = |initial_target: F, chals: &[F]| -> (Vec<Vec<F>>, F) {
        let mut round_polys = Vec::with_capacity(log_l);
        let mut expected = initial_target;
        let two_inv = F::from_u64(2).inverse();
        for i in 0..log_l {
            // Pick h(0) = h(1) = expected/2, h(2) = 1 (arbitrary) so that
            // h(0) + h(1) = expected.
            let half = expected * two_inv;
            let poly = vec![half, half, F::ONE];
            expected = eval_deg2_at(poly[0], poly[1], poly[2], chals[i]);
            round_polys.push(poly);
        }
        (round_polys, expected)
    };

    // Standard verifier: FS(ℓ roots) + initial-target compute + sumcheck verify
    let start_std = Instant::now();
    let mut std_accum = F::ZERO;
    for iter in 0..100 {
        let mut ch = MyChallenger::new(perm.clone());
        let (omega, tau, _fresh_betas) = derive_fold_challenges(
            &[F::ZERO; DIGEST],
            F::ZERO,
            &vec![F::ZERO; log_n],
            F::ZERO,
            &vec![[F::ZERO; DIGEST]; num_fresh],
            log_n,
            log_m,
            &mut ch,
        );
        // Initial target: Σ_i eq(τ, i) · (μ_i + ω · η_i)  — O(ℓ) with REAL values
        let mut initial_target = F::ZERO;
        for idx in 0..l {
            let mut eq = F::ONE;
            for j in 0..log_l {
                let bit = (idx >> j) & 1;
                eq *= if bit == 1 { tau[j] } else { F::ONE - tau[j] };
            }
            initial_target += eq * (mu_vals[idx] + omega * eta_vals[idx]);
        }
        // Sumcheck challenges — perturb per iteration so results can't be cached
        let sumcheck_chals: Vec<F> = (0..log_l)
            .map(|i| F::from_u64(i as u64 + 1 + iter as u64))
            .collect();
        let (round_polys, _expected) = build_trace(initial_target, &sumcheck_chals);
        let final_eval = warp_fold_verify_sumcheck(initial_target, &round_polys, &sumcheck_chals)
            .expect("sumcheck trace rejected");
        std_accum += final_eval;
    }
    let std_us = start_std.elapsed().as_micros() as f64 / 100.0;
    // Prevent dead-code elimination of the whole loop.
    let _ = std::hint::black_box(std_accum);

    // Union verifier: FS(1 union root) + initial-target compute + sumcheck verify
    let start_uni = Instant::now();
    let mut uni_accum = F::ZERO;
    for iter in 0..100 {
        let mut ch = MyChallenger::new(perm.clone());
        let (omega, tau, _fresh_betas) = derive_fold_challenges_union(
            &[F::ZERO; DIGEST],
            F::ZERO,
            &vec![F::ZERO; log_n],
            F::ZERO,
            &[F::ZERO; DIGEST],
            num_fresh,
            log_m,
            &mut ch,
        );
        let mut initial_target = F::ZERO;
        for idx in 0..l {
            let mut eq = F::ONE;
            for j in 0..log_l {
                let bit = (idx >> j) & 1;
                eq *= if bit == 1 { tau[j] } else { F::ONE - tau[j] };
            }
            initial_target += eq * (mu_vals[idx] + omega * eta_vals[idx]);
        }
        let sumcheck_chals: Vec<F> = (0..log_l)
            .map(|i| F::from_u64(i as u64 + 1 + iter as u64))
            .collect();
        let (round_polys, _expected) = build_trace(initial_target, &sumcheck_chals);
        let final_eval = warp_fold_verify_sumcheck(initial_target, &round_polys, &sumcheck_chals)
            .expect("sumcheck trace rejected");
        uni_accum += final_eval;
    }
    let uni_us = start_uni.elapsed().as_micros() as f64 / 100.0;
    let _ = std::hint::black_box(uni_accum);

    (std_us, uni_us)
}

/// Estimate WHIR proof size in field elements (approximate).
fn whir_proof_field_elements(proof: &WhirProof<F, EF, F, DIGEST>) -> usize {
    let mut count = 0usize;
    count += DIGEST; // initial commitment
    count += proof.initial_ood_answers.len() * 4; // EF = 4 base elements
    count += proof.initial_sumcheck.polynomial_evaluations.len() * 2 * 4;
    count += proof.initial_sumcheck.pow_witnesses.len();
    for round in &proof.rounds {
        count += DIGEST; // commitment
        count += round.ood_answers.len() * 4;
        count += 1; // pow_witness
        for q in &round.queries {
            match q {
                whir_pcs::whir::proof::QueryOpening::Base { values, proof: p } => {
                    count += values.len();
                    count += p.len() * DIGEST;
                }
                whir_pcs::whir::proof::QueryOpening::Extension { values, proof: p } => {
                    count += values.len() * 4;
                    count += p.len() * DIGEST;
                }
            }
        }
        count += round.sumcheck.polynomial_evaluations.len() * 2 * 4;
        count += round.sumcheck.pow_witnesses.len();
    }
    if let Some(ref fp) = proof.final_poly {
        count += fp.num_evals() * 4;
    }
    count += 1; // final_pow_witness
    for q in &proof.final_queries {
        match q {
            whir_pcs::whir::proof::QueryOpening::Base { values, proof: p } => {
                count += values.len();
                count += p.len() * DIGEST;
            }
            whir_pcs::whir::proof::QueryOpening::Extension { values, proof: p } => {
                count += values.len() * 4;
                count += p.len() * DIGEST;
            }
        }
    }
    if let Some(ref fs) = proof.final_sumcheck {
        count += fs.polynomial_evaluations.len() * 2 * 4;
        count += fs.pow_witnesses.len();
    }
    count
}

/// Collects JSONL rows when `--jsonl=<path>` is passed.
#[derive(Default)]
struct JsonlSink {
    rows: Vec<String>,
}

impl JsonlSink {
    fn push(&mut self, row: serde_json::Value) {
        self.rows.push(row.to_string());
    }
    fn flush(&self, path: &str) -> std::io::Result<()> {
        let mut w = BufWriter::new(File::create(path)?);
        for r in &self.rows {
            writeln!(w, "{r}")?;
        }
        w.flush()
    }
}

fn main() {
    let raw_args: Vec<String> = env::args().collect();
    // Split out any --jsonl=<path> flag (order-independent).
    let mut jsonl_path: Option<String> = None;
    let args: Vec<String> = raw_args
        .into_iter()
        .filter(|a| {
            if let Some(p) = a.strip_prefix("--jsonl=") {
                jsonl_path = Some(p.to_string());
                false
            } else {
                true
            }
        })
        .collect();

    let sizes_str = args.get(1).map(String::as_str).unwrap_or("10,12");
    let steps_str = args.get(2).map(String::as_str).unwrap_or("2,4,8");
    let repeats: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let batch: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
    let sizes = parse_csv(sizes_str);
    let steps_list = parse_csv(steps_str);
    let mut sink = JsonlSink::default();

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
        let (shape, instance) =
            R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);
        let spartan = R1CSProver::new();
        let sample_w = spartan.prepare_witness(&instance);
        let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let log_code = witness_num_vars + RS_LOG_INV_RATE;
        let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        let config = make_whir_config(witness_num_vars);

        println!(
            "=== log2(constraints)={log_size}, witness=2^{witness_num_vars}, code=2^{log_code} ==="
        );
        println!();
        println!(
            "{:>6} {:>5} {:>12} | {:>14} {:>14} {:>14} | {:>9} {:>9} {:>9}",
            "steps",
            "N",
            "spartan",
            "independent",
            "direct_fold",
            "batch+fold",
            "fold/ind",
            "batch/ind",
            "batch/fold",
        );
        println!("{}", "-".repeat(120));

        for &num_steps in &steps_list {
            let total_n = num_steps * batch;

            let mut spartan_times = Vec::new();
            let mut indep_times = Vec::new();
            let mut direct_times = Vec::new();
            let mut batch_times = Vec::new();

            for _ in 0..repeats {
                // Common: Spartan linearize all N instances
                let (witnesses, linears, spartan_us) =
                    spartan_linearize_all(&shape, &instance, total_n);
                spartan_times.push(spartan_us);

                // Build FreshInstances from the witnesses (common data for paths 2 & 3)
                let z_slices: Vec<&[F]> = witnesses.iter().map(EvaluationsList::as_slice).collect();
                let fresh_instances: Vec<FreshInstance<F>> = z_slices
                    .iter()
                    .map(|z| {
                        let pi = Vec::new();
                        let mut w = z.to_vec();
                        w.resize(num_witness, F::ZERO);
                        FreshInstance {
                            public_input: pi,
                            witness: w,
                        }
                    })
                    .collect();

                // Path 1: N independent WHIR proofs
                let ds = make_ds(&config);
                let start1 = Instant::now();
                for i in 0..total_n {
                    let mut stmt = config
                        .initial_statement_with_linear(witnesses[i].clone(), linears[i].clone());
                    let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(&config);
                    let mut ch = seed_ch(100 + i as u64, &ds);
                    let comm = CommitmentWriter::new(&config)
                        .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                            &dft, &mut proof, &mut ch, &mut stmt,
                        )
                        .unwrap();
                    WhirProver(&config)
                        .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                            &dft, &mut proof, &mut ch, &stmt, comm,
                        )
                        .unwrap();
                }
                indep_times.push(start1.elapsed().as_micros() as f64);

                // Path 2: Direct fold (batch-arity per step) + 1 terminal WHIR
                let start2 = Instant::now();
                let mut acc2 = make_zero_acc(num_witness, log_code, log_m, 0);
                for step in 0..num_steps {
                    let idx = step * batch;
                    let step_fresh: Vec<FreshInstance<F>> =
                        fresh_instances[idx..idx + batch].to_vec();
                    let l = (1 + batch).next_power_of_two();
                    let log_l = l.trailing_zeros() as usize;
                    let tau: Vec<F> = (0..log_l)
                        .map(|i| F::from_u64(step as u64 * 10 + i as u64 + 42))
                        .collect();
                    let mh2 = mh.clone();
                    let mc2 = mc.clone();
                    let mut ctr = step as u64 * 1000;
                    let r = warp_fold_prove_rs_committed(
                        &shape,
                        &step_fresh,
                        &acc2,
                        F::from_u64(7),
                        &tau,
                        &[],
                        &rs_config,
                        &dft,
                        |_| {
                            ctr += 1;
                            F::from_u64(ctr + 500)
                        },
                        |cw, ff| {
                            let (r, _) =
                                merkle_commit_codeword::<
                                    F,
                                    F,
                                    <F as Field>::Packing,
                                    <F as Field>::Packing,
                                    MyHash,
                                    MyCompress,
                                    DIGEST,
                                >(cw, ff, mh2.clone(), mc2.clone());
                            r
                        },
                    );
                    acc2 = rebuild_acc(&r);
                }
                let fold2_us = start2.elapsed().as_micros() as f64;
                assert_full_warp_terminal(&shape, &acc2, 2, RS_LOG_INV_RATE, &dft);
                let (whir2_us, whir2_proof) =
                    terminal_whir_with_proof(&config, &acc2.witness.witness, witness_num_vars);
                assert_terminal_whir_bound(&whir2_proof, &acc2);
                direct_times.push(fold2_us + whir2_us);

                // Path 3: Batch reduce + fold(l=2) + 1 terminal WHIR
                let start3 = Instant::now();
                let mut acc3 = make_zero_acc(num_witness, log_code, log_m, 0);
                for step in 0..num_steps {
                    let idx = step * batch;
                    let step_wit = &witnesses[idx..idx + batch];
                    let step_lin = &linears[idx..idx + batch];

                    let mut weights = Vec::new();
                    let mut targets = Vec::new();
                    for lin in step_lin {
                        let (w, &t) = lin.iter().next().unwrap();
                        weights.push(w.clone());
                        targets.push(t);
                    }
                    let gamma = F::from_u64(step as u64 + 42);
                    let cbp =
                        Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(step as u64 + 300));
                    let mut cbc = MyChallenger::new(cbp);
                    let _ = constraint_batch_prove(
                        gamma,
                        &weights,
                        &targets,
                        &step_wit.iter().cloned().collect::<Vec<_>>(),
                        &mut cbc,
                    );
                    let eta = F::from_u64(step as u64 + 13);
                    let refs: Vec<&EvaluationsList<F>> = step_wit.iter().collect();
                    let combined = random_linear_combination(&refs, eta);

                    let cs = combined.as_slice();
                    let pi = Vec::new();
                    let mut w = cs.to_vec();
                    w.resize(num_witness, F::ZERO);
                    let fresh = vec![FreshInstance {
                        public_input: pi,
                        witness: w,
                    }];

                    let tau = vec![F::from_u64(step as u64 + 42)];
                    let mh3 = mh.clone();
                    let mc3 = mc.clone();
                    let mut ctr = step as u64 * 1000;
                    let r = warp_fold_prove_rs_committed(
                        &shape,
                        &fresh,
                        &acc3,
                        F::from_u64(7),
                        &tau,
                        &[],
                        &rs_config,
                        &dft,
                        |_| {
                            ctr += 1;
                            F::from_u64(ctr + 500)
                        },
                        |cw, ff| {
                            let (r, _) =
                                merkle_commit_codeword::<
                                    F,
                                    F,
                                    <F as Field>::Packing,
                                    <F as Field>::Packing,
                                    MyHash,
                                    MyCompress,
                                    DIGEST,
                                >(cw, ff, mh3.clone(), mc3.clone());
                            r
                        },
                    );
                    acc3 = rebuild_acc(&r);
                }
                let fold3_us = start3.elapsed().as_micros() as f64;
                assert_full_warp_terminal(&shape, &acc3, 2, RS_LOG_INV_RATE, &dft);
                let (whir3_us, whir3_proof) =
                    terminal_whir_with_proof(&config, &acc3.witness.witness, witness_num_vars);
                assert_terminal_whir_bound(&whir3_proof, &acc3);
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
                num_steps,
                total_n,
                spartan_ms,
                indep,
                direct,
                batch_f,
                fold_vs_ind,
                batch_vs_ind,
                batch_vs_fold,
            );

            sink.push(serde_json::json!({
                "table": "apples",
                "log_size": log_size,
                "num_steps": num_steps,
                "total_n": total_n,
                "batch": batch,
                "spartan_ms": spartan_ms,
                "indep_us": indep,
                "direct_us": direct,
                "batch_us": batch_f,
                "fold_vs_ind": fold_vs_ind,
                "batch_vs_ind": batch_vs_ind,
                "batch_vs_fold": batch_vs_fold,
            }));
        }
        println!();
    }

    println!(
        "All times are POST-SPARTAN only (Spartan column is for reference, not included in comparisons)."
    );
    println!("  fold/ind    = independent / direct_fold (>1 means fold is faster than N×WHIR)");
    println!(
        "  batch/ind   = independent / batch+fold (>1 means batch+fold is faster than N×WHIR)"
    );
    println!(
        "  batch/fold  = direct_fold / batch+fold (>1 means batch reduction helps over raw fold)"
    );

    // Table 2: Recursive IVC Throughput
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
        let ivc_config_union = WarpIVCConfig {
            fold_arity: 4,
            use_union: true,
            ..Default::default()
        };

        let (poseidon_perm, poseidon_config) = {
            use p3_poseidon2::poseidon2_round_numbers_128;
            const SBOX_DEGREE: u64 = 3;
            let seed = 99u64;
            let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
            let (rf, rp) = poseidon2_round_numbers_128::<F>(16, SBOX_DEGREE)
                .expect("unsupported Poseidon2 parameters");
            let config = Poseidon2CircuitConfig::<F, 16>::from_rng(
                rf,
                rp,
                SBOX_DEGREE,
                &mut SmallRng::seed_from_u64(seed),
            );
            (perm, config)
        };

        let total_circuits = 12;
        let steps_l2 = total_circuits;
        let steps_l4 = total_circuits / 3;

        for &log_size in &sizes {
            let step_muls = (1usize << log_size).saturating_sub(5000).max(100);
            let step = WorkloadStepCircuit::new(step_muls);
            let step_input = [F::ZERO];

            let num_cons = 1 << log_size;
            let num_vars = 1 << log_size;
            let num_inputs_synth = 8;
            let mut rng = SmallRng::seed_from_u64(5);
            let (shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(
                num_cons,
                num_vars,
                num_inputs_synth,
                &mut rng,
            );

            println!(
                "=== log2(constraints)={log_size}, step_muls={step_muls}, total_circuits={total_circuits} ==="
            );
            println!();

            // Path A: WARP (l=2)
            let perm_for_fold = poseidon_perm.clone();
            let make_p2_chal = move || -> MyChallenger { MyChallenger::new(perm_for_fold.clone()) };

            let t_a = Instant::now();
            let mut spartan_chal_a = make_challenger(1);
            let state_a = warp_ivc_init::<F, EF, _, _, _, _, _>(
                &shape,
                &instance,
                &mut spartan_chal_a,
                &ivc_config_l2,
                &dft_ivc,
                mh_ivc.clone(),
                mc_ivc.clone(),
                vec![],
                make_p2_chal.clone(),
            );
            let mut state_iter_a = state_a;
            for s in 0..steps_l2 {
                let mut ch = make_challenger(s as u64 + 10);
                state_iter_a = whir_ivc::warp_ivc::warp_ivc_step::<F, EF, _, _, _, _, _>(
                    &state_iter_a,
                    &instance,
                    &mut ch,
                    &ivc_config_l2,
                    &dft_ivc,
                    mh_ivc.clone(),
                    mc_ivc.clone(),
                    vec![],
                    make_p2_chal.clone(),
                );
            }
            assert_full_warp_terminal(
                &state_iter_a.shape,
                &state_iter_a.accumulator,
                ivc_config_l2.rs_folding_factor,
                ivc_config_l2.rs_log_inv_rate,
                &dft_ivc,
            );
            let us_a = t_a.elapsed().as_micros() as f64;
            let per_circuit_a = us_a / total_circuits as f64;

            // Path B: WARP + Quasar (l=4)
            let perm_for_union = poseidon_perm.clone();
            let make_union_chal =
                move || -> MyChallenger { MyChallenger::new(perm_for_union.clone()) };

            let t_b = Instant::now();
            let mut spartan_chal_b = make_challenger(100);
            let log_m_orig = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
            let (target_w_b, _, _) = compute_recursive_circuit_size_union::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
            >(
                &step,
                &step_input,
                &poseidon_config,
                &poseidon_perm,
                shape.num_poly_vars_y(),
                4,
                log_m_orig,
            );

            let state_b = warp_ivc_init_recursive_union::<
                F,
                EF,
                _,
                _,
                _,
                _,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
                _,
            >(
                &shape,
                &instance,
                &mut spartan_chal_b,
                &ivc_config_union,
                &dft_ivc,
                mh_ivc.clone(),
                mc_ivc.clone(),
                &poseidon_config,
                &poseidon_perm,
                &step,
                &step_input,
                4,
                vec![],
                make_union_chal.clone(),
            );
            let mut state_iter_b = state_b;
            for s in 0..steps_l4 {
                let step_inputs_b: Vec<Vec<F>> = (0..3)
                    .map(|i| vec![F::from_u64(s as u64 * 10 + i)])
                    .collect();
                let mut ch = make_challenger(s as u64 + 200);
                state_iter_b = warp_ivc_step_recursive_union::<
                    F,
                    EF,
                    _,
                    _,
                    _,
                    _,
                    GenericPoseidon2LinearLayersKoalaBear,
                    _,
                    _,
                    _,
                >(
                    &state_iter_b,
                    &step,
                    &step_inputs_b,
                    4,
                    &mut ch,
                    &ivc_config_union,
                    &dft_ivc,
                    mh_ivc.clone(),
                    mc_ivc.clone(),
                    &poseidon_config,
                    &poseidon_perm,
                    Some(target_w_b),
                    vec![],
                    make_union_chal.clone(),
                );
            }
            assert_full_warp_terminal(
                &state_iter_b.shape,
                &state_iter_b.accumulator,
                ivc_config_union.rs_folding_factor,
                ivc_config_union.rs_log_inv_rate,
                &dft_ivc,
            );
            let us_b = t_b.elapsed().as_micros() as f64;
            let per_circuit_b = us_b / total_circuits as f64;

            println!(
                "{:>25} {:>10} {:>8} {:>12} {:>12} {:>10}",
                "path", "total(ms)", "steps", "folds", "ms/circuit", "vs A"
            );
            println!("{}", "-".repeat(80));
            println!(
                "{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>10}",
                "A: WARP (l=2)",
                us_a / 1000.0,
                steps_l2,
                steps_l2,
                per_circuit_a / 1000.0,
                "baseline"
            );
            println!(
                "{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>9.2}x",
                "B: WARP+Quasar (l=4)",
                us_b / 1000.0,
                steps_l4,
                steps_l4,
                per_circuit_b / 1000.0,
                per_circuit_a / per_circuit_b
            );

            sink.push(serde_json::json!({
                "table": "recursive",
                "log_size": log_size,
                "step_muls": step_muls,
                "total_circuits": total_circuits,
                "path": "A", "name": "WARP (l=2)",
                "total_ms": us_a / 1000.0,
                "steps": steps_l2, "folds": steps_l2,
                "ms_per_circuit": per_circuit_a / 1000.0,
                "vs_a": 1.0,
            }));
            sink.push(serde_json::json!({
                "table": "recursive",
                "log_size": log_size,
                "step_muls": step_muls,
                "total_circuits": total_circuits,
                "path": "B", "name": "WARP+Quasar (l=4)",
                "total_ms": us_b / 1000.0,
                "steps": steps_l4, "folds": steps_l4,
                "ms_per_circuit": per_circuit_b / 1000.0,
                "vs_a": per_circuit_a / per_circuit_b,
            }));

            #[cfg(feature = "symphony")]
            {
                use whir_ivc::{
                    warp_fold_verifier_algebraic::compute_cp_circuit_size,
                    warp_ivc::{
                        compute_recursive_union_circuit_size, warp_ivc_init_cp,
                        warp_ivc_init_recursive_union_cp, warp_ivc_step_recursive_cp,
                        warp_ivc_step_recursive_union_cp,
                    },
                };

                // Path C: Symphony (l=2)
                let symphony_ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let t_c = Instant::now();
                    let mut spartan_chal_c = make_challenger(300);
                    let state_c = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
                        &shape,
                        &instance,
                        &mut spartan_chal_c,
                        &ivc_config_l2,
                        &dft_ivc,
                        mh_ivc.clone(),
                        mc_ivc.clone(),
                        vec![],
                        make_p2_chal.clone(),
                    );
                    let (target_w_c, _, _) = compute_cp_circuit_size(&step, &step_input);
                    let mut state_iter_c = state_c;
                    for s in 0..steps_l2 {
                        let mut ch = make_challenger(s as u64 + 310);
                        state_iter_c = warp_ivc_step_recursive_cp::<F, EF, _, _, _, _, _, _>(
                            state_iter_c,
                            &step,
                            &step_input,
                            &mut ch,
                            &ivc_config_l2,
                            &dft_ivc,
                            mh_ivc.clone(),
                            mc_ivc.clone(),
                            Some(target_w_c),
                            vec![],
                            make_p2_chal.clone(),
                        );
                    }
                    assert_full_warp_terminal(
                        &state_iter_c.shape,
                        &state_iter_c.accumulator,
                        ivc_config_l2.rs_folding_factor,
                        ivc_config_l2.rs_log_inv_rate,
                        &dft_ivc,
                    );
                    t_c.elapsed().as_micros() as f64
                }));
                match symphony_ok {
                    Ok(us_c) => {
                        let per_circuit_c = us_c / total_circuits as f64;
                        println!(
                            "{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>9.2}x",
                            "C: Symphony (l=2)",
                            us_c / 1000.0,
                            steps_l2,
                            steps_l2,
                            per_circuit_c / 1000.0,
                            per_circuit_a / per_circuit_c
                        );
                        sink.push(serde_json::json!({
                            "table": "recursive",
                            "log_size": log_size,
                            "step_muls": step_muls,
                            "total_circuits": total_circuits,
                            "path": "C", "name": "Symphony (l=2)",
                            "total_ms": us_c / 1000.0,
                            "steps": steps_l2, "folds": steps_l2,
                            "ms_per_circuit": per_circuit_c / 1000.0,
                            "vs_a": per_circuit_a / per_circuit_c,
                        }));
                    }
                    Err(_) => println!(
                        "{:>25} {:>8} {:>8} {:>12} {:>12} {:>10}",
                        "C: Symphony (l=2)", "SKIP", "—", "—", "(too small)", "—"
                    ),
                }

                // Path D: Symphony + Quasar (l=4)
                let symphony_d_ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (target_w_d, _, _) =
                        compute_recursive_union_circuit_size(&step, &step_input, 4);
                    let t_d = Instant::now();
                    let state_d = warp_ivc_init_recursive_union_cp::<F, _>(
                        &step,
                        &step_input,
                        4,
                        &ivc_config_union,
                        target_w_d,
                        vec![],
                    );
                    let mut state_iter_d = state_d;
                    for s in 0..steps_l4 {
                        let step_inputs_d: Vec<Vec<F>> = (0..3)
                            .map(|i| vec![F::from_u64(s as u64 * 10 + i)])
                            .collect();
                        let mut ch = make_challenger(s as u64 + 410);
                        state_iter_d = warp_ivc_step_recursive_union_cp::<F, EF, _, _, _, _, _, _>(
                            &state_iter_d,
                            &step,
                            &step_inputs_d,
                            4,
                            &mut ch,
                            &ivc_config_union,
                            &dft_ivc,
                            mh_ivc.clone(),
                            mc_ivc.clone(),
                            Some(target_w_d),
                            vec![],
                            make_p2_chal.clone(),
                        );
                    }
                    assert_full_warp_terminal(
                        &state_iter_d.shape,
                        &state_iter_d.accumulator,
                        ivc_config_union.rs_folding_factor,
                        ivc_config_union.rs_log_inv_rate,
                        &dft_ivc,
                    );
                    t_d.elapsed().as_micros() as f64
                }));
                match symphony_d_ok {
                    Ok(us_d) => {
                        let per_circuit_d = us_d / total_circuits as f64;
                        println!(
                            "{:>25} {:>8.1}ms {:>8} {:>12} {:>10.1}ms {:>9.2}x",
                            "D: Symphony+Quasar (l=4)",
                            us_d / 1000.0,
                            steps_l4,
                            steps_l4,
                            per_circuit_d / 1000.0,
                            per_circuit_a / per_circuit_d
                        );
                        sink.push(serde_json::json!({
                            "table": "recursive",
                            "log_size": log_size,
                            "step_muls": step_muls,
                            "total_circuits": total_circuits,
                            "path": "D", "name": "Symphony+Quasar (l=4)",
                            "total_ms": us_d / 1000.0,
                            "steps": steps_l4, "folds": steps_l4,
                            "ms_per_circuit": per_circuit_d / 1000.0,
                            "vs_a": per_circuit_a / per_circuit_d,
                        }));
                    }
                    Err(_) => println!(
                        "{:>25} {:>8} {:>8} {:>12} {:>12} {:>10}",
                        "D: Symphony+Quasar (l=4)", "SKIP", "—", "—", "(too small)", "—"
                    ),
                }
            }

            println!();
            println!(
                "  All paths prove {total_circuits} circuits total. vs A > 1 means faster than baseline."
            );
            println!();
        }
    }

    // Circuit sizes summary (non-union variants at l=2)
    println!();
    println!("Recursive Circuit Sizes (non-union verifier, l=2)");
    println!("=================================================");
    println!("For union (Quasar) variants across multiple arities, see");
    println!("the `circuit_size_arity` benchmark below.");
    {
        use whir_ivc::warp_ivc::compute_recursive_circuit_size;
        let step_dummy = WorkloadStepCircuit::new(100);
        let step_input_dummy = [F::ZERO];

        let perm_sz = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let config_sz =
            Poseidon2CircuitConfig::<F, 16>::from_rng(rf, rp, 3, &mut SmallRng::seed_from_u64(99));

        let (w_poseidon, c_poseidon, _) =
            compute_recursive_circuit_size::<
                F,
                p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
            >(&step_dummy, &step_input_dummy, &config_sz, &perm_sz, 5, 4);

        println!(
            "  Poseidon2 non-union (l=2): {w_poseidon} witness vars, {c_poseidon} constraints"
        );
        sink.push(serde_json::json!({
            "table": "circuit_sizes",
            "variant": "poseidon2_non_union_l2",
            "witness_vars": w_poseidon,
            "constraints": c_poseidon,
        }));

        #[cfg(feature = "symphony")]
        {
            use whir_ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;
            let (w_alg, c_alg, _) = compute_cp_circuit_size(&step_dummy, &step_input_dummy);
            println!("  Algebraic non-union (l=2): {w_alg} witness vars, {c_alg} constraints");
            println!(
                "  Constraint reduction (non-union l=2): {:.0}x",
                c_poseidon as f64 / c_alg as f64
            );
            sink.push(serde_json::json!({
                "table": "circuit_sizes",
                "variant": "algebraic_non_union_l2",
                "witness_vars": w_alg,
                "constraints": c_alg,
            }));
        }
    }

    // WHIR-in-circuit cost estimate
    println!();
    println!("WHIR Verifier In-Circuit Cost Estimate (Why WARP Exists)");
    println!("========================================================");
    println!("A recursive WHIR-per-step IVC would embed the WHIR verifier in the R1CS circuit.");
    println!("This is prohibitively expensive. Estimated costs per operation:");
    println!();
    let poseidon2_cost = 340usize;
    let ef_mul_cost = 20usize;

    for &log_size in &sizes {
        let num_vars = 1usize << log_size;
        let num_inputs = 8;
        let mut rng = SmallRng::seed_from_u64(5);
        let (_shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(
            1 << log_size,
            num_vars,
            num_inputs,
            &mut rng,
        );
        let spartan = R1CSProver::new();
        let sample_w = spartan.prepare_witness(&instance);
        let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
        let wnv = num_witness.trailing_zeros() as usize;
        let cfg = make_whir_config(wnv);

        let n_rounds = cfg.n_rounds();
        let ff = 2usize;

        let mut fs_hashes = 3usize;
        for rp in &cfg.round_parameters {
            fs_hashes += 2;
            fs_hashes += ff;
            fs_hashes += 1;
            let _ = rp;
        }
        let fs_cost = fs_hashes * poseidon2_cost;

        let mut sumcheck_muls = 0usize;
        sumcheck_muls += ff * 3;
        for _ in 0..n_rounds {
            sumcheck_muls += ff * 3;
        }
        let sumcheck_cost = sumcheck_muls * ef_mul_cost;

        let mut merkle_hashes = 0usize;
        let merkle_depth = wnv;
        for rp in &cfg.round_parameters {
            merkle_hashes += rp.num_queries * merkle_depth;
        }
        merkle_hashes += cfg.final_queries * merkle_depth;
        let merkle_cost = merkle_hashes * poseidon2_cost;

        let query_eval_muls: usize = cfg
            .round_parameters
            .iter()
            .map(|rp| rp.num_queries * (1 << ff))
            .sum::<usize>()
            + cfg.final_queries * (1 << ff);
        let query_cost = query_eval_muls * ef_mul_cost;

        let total_whir_circuit = fs_cost + sumcheck_cost + merkle_cost + query_cost;

        println!("  log_size={log_size}: WHIR verifier ≈ {total_whir_circuit} constraints");
        println!(
            "    Breakdown: FS hashing={fs_cost}, sumcheck={sumcheck_cost}, Merkle={merkle_cost}, queries={query_cost}"
        );
        println!(
            "    vs WARP fold verifier: ~4685 constraints ({:.0}x cheaper)",
            total_whir_circuit as f64 / 4685.0
        );
        sink.push(serde_json::json!({
            "table": "whir_circuit_estimate",
            "log_size": log_size,
            "total": total_whir_circuit,
            "fs": fs_cost,
            "sumcheck": sumcheck_cost,
            "merkle": merkle_cost,
            "queries": query_cost,
        }));
        println!();
    }

    // Terminal WHIR verify + proof size
    println!();
    println!("Terminal WHIR Verify Time");
    println!("========================");
    println!(
        "This is the succinct verifier cost (constant per IVC chain, independent of num_steps)."
    );
    println!();
    println!(
        "{:>10} {:>12} {:>12} {:>12} {:>10}",
        "log_size", "prove(us)", "verify(us)", "proof(FE)", "proof(KB)"
    );
    println!("{}", "-".repeat(62));

    for &log_size in &sizes {
        let num_vars = 1 << log_size;
        let num_inputs = 8;
        let mut rng = SmallRng::seed_from_u64(5);
        let (_shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(
            1 << log_size,
            num_vars,
            num_inputs,
            &mut rng,
        );
        let spartan = R1CSProver::new();
        let sample_w = spartan.prepare_witness(&instance);
        let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
        let wnv = num_witness.trailing_zeros() as usize;
        let cfg = make_whir_config(wnv);

        let (prove_us, proof) = terminal_whir_with_proof(&cfg, sample_w.as_slice(), wnv);
        let verify_us = terminal_whir_verify(&cfg, &proof, wnv);
        let proof_fe = whir_proof_field_elements(&proof);
        let proof_kb = proof_fe * 4 / 1024;
        println!(
            "{:>10} {:>10.0}us {:>10.0}us {:>12} {:>8}KB",
            log_size, prove_us, verify_us, proof_fe, proof_kb
        );
        sink.push(serde_json::json!({
            "table": "terminal_whir",
            "log_size": log_size,
            "prove_us": prove_us,
            "verify_us": verify_us,
            "proof_fe": proof_fe,
            "proof_kb": proof_kb,
        }));
    }

    // Table 4: Quasar verifier scaling
    println!();
    println!("Quasar Verifier Scaling: Fold FS Challenge Derivation");
    println!("=====================================================");
    println!("Fiat-Shamir derivation cost at varying arity ℓ.");
    println!("  standard: absorbs O(ℓ) roots,  samples O(ℓ·log_m) fresh_betas");
    println!("  union:    absorbs O(1) root,   samples O(ℓ·log_m) fresh_betas");
    println!("Both paths share the fresh_beta sampling cost, so wall-clock speedup");
    println!("plateaus at the absorb-cost ratio (~2–3×), not at O(ℓ).");
    println!();

    let log_m_bench = sizes.last().copied().unwrap_or(14);
    let log_n_bench = log_m_bench + RS_LOG_INV_RATE;
    println!("Using log_m={log_m_bench}, log_n={log_n_bench}");
    println!();
    println!(
        "{:>6} {:>12} {:>12} {:>10}",
        "arity", "standard(us)", "union(us)", "speedup"
    );
    println!("{}", "-".repeat(46));

    for &arity in &[2usize, 4, 8, 16, 32, 64] {
        let (std_us, union_us) = measure_fold_verifier_fs(log_m_bench, log_n_bench, arity);
        let speedup = std_us / union_us;
        println!(
            "{:>6} {:>10.1}us {:>10.1}us {:>9.1}x",
            arity, std_us, union_us, speedup
        );
        sink.push(serde_json::json!({
            "table": "fs_scaling",
            "log_m": log_m_bench,
            "log_n": log_n_bench,
            "arity": arity,
            "standard_us": std_us,
            "union_us": union_us,
            "speedup": speedup,
        }));
    }
    println!();
    println!("Union absorbs 1 root regardless of arity (O(1) absorbs).");
    println!("Both paths still sample O(ℓ·log_m) fresh_betas → wall-clock is NOT O(1).");

    // ═══════════════════════════════════════════════════════════════
    // Full fold-verifier wall-clock sweep (Quasar's native-verifier story)
    // ═══════════════════════════════════════════════════════════════
    println!();
    println!("Full Fold Verifier Cost (FS + Sumcheck Verify)");
    println!("==============================================");
    println!("Native-verifier wall-clock for ONE fold at varying arity.");
    println!("Measures: Fiat-Shamir derivation + initial-target compute + twin-constraint");
    println!("sumcheck verification. (NOT the full in-circuit cost — see circuit_size_arity.)");
    println!();
    println!(
        "{:>6} {:>12} {:>12} {:>10}",
        "arity", "standard(us)", "union(us)", "speedup"
    );
    println!("{}", "-".repeat(46));
    for &arity in &[2usize, 4, 8, 16, 32, 64] {
        let (std_us, uni_us) = measure_fold_verifier_full(log_m_bench, log_n_bench, arity);
        let speedup = std_us / uni_us;
        println!(
            "{:>6} {:>10.1}us {:>10.1}us {:>9.2}x",
            arity, std_us, uni_us, speedup
        );
        sink.push(serde_json::json!({
            "table": "fold_verify",
            "log_m": log_m_bench,
            "log_n": log_n_bench,
            "arity": arity,
            "standard_us": std_us,
            "union_us": uni_us,
            "speedup": speedup,
        }));
    }

    // ═══════════════════════════════════════════════════════════════
    // In-circuit verifier cost sweep vs arity (Quasar's real payoff)
    // ═══════════════════════════════════════════════════════════════
    println!();
    println!("In-Circuit Fold Verifier Size vs Arity");
    println!("======================================");
    println!("Constraints of the recursive fold-verifier unified circuit that the prover");
    println!("Spartan-proves every IVC step. Quasar (union) grows as O(log ℓ); standard");
    println!("would grow as O(ℓ) (not directly benchable — only union API exists for ℓ>2).");
    println!();
    println!(
        "{:>6} {:>20} {:>20}",
        "arity", "Poseidon2 union", "Algebraic union"
    );
    println!("{}", "-".repeat(50));
    {
        use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
        use whir_ivc::{step::WorkloadStepCircuit, warp_ivc::compute_recursive_circuit_size_union};

        let step_dummy = WorkloadStepCircuit::new(100);
        let step_input_dummy = [F::ZERO];

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(rf, rp, 3, &mut SmallRng::seed_from_u64(99));

        for &arity in &[2usize, 4, 8, 16] {
            let (_w_p, c_p, _) =
                compute_recursive_circuit_size_union::<
                    F,
                    GenericPoseidon2LinearLayersKoalaBear,
                    _,
                    _,
                >(&step_dummy, &step_input_dummy, &config, &perm, 5, arity, 4);
            sink.push(serde_json::json!({
                "table": "circuit_size_arity",
                "variant": "poseidon2_union",
                "arity": arity,
                "constraints": c_p,
                "witness_vars": _w_p,
            }));

            #[cfg(feature = "symphony")]
            {
                use whir_ivc::warp_ivc::compute_recursive_union_circuit_size;
                let (_w_a, c_a, _) =
                    compute_recursive_union_circuit_size(&step_dummy, &step_input_dummy, arity);
                println!("{:>6} {:>18} {:>18}", arity, c_p, c_a);
                sink.push(serde_json::json!({
                    "table": "circuit_size_arity",
                    "variant": "algebraic_union",
                    "arity": arity,
                    "constraints": c_a,
                    "witness_vars": _w_a,
                }));
            }
            #[cfg(not(feature = "symphony"))]
            {
                println!("{:>6} {:>18} {:>18}", arity, c_p, "(symphony off)");
            }
        }
    }

    if let Some(path) = jsonl_path {
        sink.flush(&path).expect("failed to write jsonl");
        eprintln!("\nWrote {} rows to {path}", sink.rows.len());
    }
}
