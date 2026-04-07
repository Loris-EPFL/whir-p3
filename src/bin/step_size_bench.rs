//! Per-phase IVC cost breakdown as a function of step circuit size.
//!
//! Sweeps step circuit sizes from trivial to large and reports where time is
//! spent: circuit build, Spartan prove, RS encode, Merkle commit, WARP fold,
//! etc. This reveals which optimization (packed sumcheck, BOIL, split-eq,
//! linear-time codes) would give the best return at each scale.
//!
//! Usage:
//!   cargo run --release --bin step_size_bench
//!   cargo run --release --bin step_size_bench -- <num_ivc_steps> <repeats>
//!
//! Default: 4 IVC steps, 3 repeats.

use std::{env, time::Instant};

use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
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
        fold::{evaluate_mle_lsb, warp_fold_prove_rs_committed, RSEncodingConfig, WarpFoldResult},
    },
    circuit::builder::CircuitBuilder,
    ivc::step::{StepCircuit, WorkloadStepCircuit},
    poly::evals::EvaluationsList,
    spartan::r1cs_prover::R1CSProver,
};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2KoalaBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;
const DIGEST: usize = 8;

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_hc() -> (MyHash, MyCompress) {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    (MyHash::new(p.clone()), MyCompress::new(p))
}

fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}

fn make_fold_chal() -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(77));
    MyChallenger::new(p)
}

fn rebuild_acc(r: &WarpFoldResult<F>) -> WarpAccumulator<F, F, F, DIGEST> {
    let ec = evaluate_mle_lsb(&r.witness.codeword, &r.instance.eval_point);
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

fn derive_fold_challenges(
    acc: &WarpAccumulator<F, F, F, DIGEST>,
    fresh_root: &[F; DIGEST],
    log_m: usize,
    mut chal: MyChallenger,
) -> (F, Vec<F>, Vec<Vec<F>>, MyChallenger) {
    let log_code = acc.witness.codeword.num_variables();
    for &val in &acc.instance.commitment_root { chal.observe(val); }
    chal.observe(acc.instance.eval_claim);
    for &val in &acc.instance.eval_point { chal.observe(val); }
    chal.observe(acc.instance.pesat_target);
    for &val in fresh_root { chal.observe(val); }
    chal.observe(F::ZERO);
    for _ in 0..log_code { chal.observe(F::ZERO); }
    chal.observe(F::ZERO);
    let omega: F = chal.sample();
    let tau: Vec<F> = (0..1).map(|_| chal.sample()).collect();
    let fresh_betas: Vec<Vec<F>> = (0..1)
        .map(|_| (0..log_m).map(|_| chal.sample()).collect())
        .collect();
    (omega, tau, fresh_betas, chal)
}

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
        &cw, rs_config.folding_factor, mh.clone(), mc.clone(),
    );
    root
}

/// Timing breakdown for one IVC step.
#[derive(Default, Clone)]
struct StepTimings {
    circuit_build_us: f64,
    spartan_prove_us: f64,
    rs_encode_us: f64,
    merkle_commit_us: f64,
    fold_us: f64,
    total_us: f64,
}

/// Run one IVC step and return per-phase timings.
fn timed_ivc_step(
    shape: &whir_p3::spartan::r1cs::R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, DIGEST>,
    step_circuit: &WorkloadStepCircuit,
    step_input: F,
    step_idx: usize,
    rs_config: &RSEncodingConfig,
    dft: &Radix2DFTSmallBatch<F>,
    mh: &MyHash,
    mc: &MyCompress,
) -> (WarpAccumulator<F, F, F, DIGEST>, StepTimings, WarpFoldResult<F>) {
    let mut timings = StepTimings::default();
    let total_start = Instant::now();

    // 1. Build circuit (step only, no recursive verifier — measures raw step cost)
    let t = Instant::now();
    let mut builder = CircuitBuilder::<F>::new();
    let input_var = builder.alloc_witness(step_input);
    let _output = step_circuit.synthesize(&mut builder, &[input_var]);
    let (_circuit_shape, circuit_instance) = builder.build();
    timings.circuit_build_us = t.elapsed().as_micros() as f64;

    // 2. Spartan prove
    let t = Instant::now();
    let spartan = R1CSProver::new();
    let mut chal = make_challenger(step_idx as u64 + 100);
    let _proof = spartan.prove::<EF, _>(&circuit_instance, &mut chal);
    let witness_poly = spartan.prepare_witness(&circuit_instance);
    timings.spartan_prove_us = t.elapsed().as_micros() as f64;

    // 3. Create fresh instance
    let num_inputs = circuit_instance.input().len();
    let z = witness_poly.as_slice();
    let num_witness = (z.len() - num_inputs).next_power_of_two();
    let mut witness_part = z[num_inputs..].to_vec();
    witness_part.resize(num_witness, F::ZERO);

    let fresh = FreshInstance {
        public_input: z[..num_inputs].to_vec(),
        witness: witness_part,
    };

    // 4. RS encode
    let t = Instant::now();
    let fresh_witness_poly = EvaluationsList::new(fresh.witness.clone());
    let fresh_cw = rs_encode(
        &fresh_witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft,
    );
    timings.rs_encode_us = t.elapsed().as_micros() as f64;

    // 5. Merkle commit
    let t = Instant::now();
    let (fresh_root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
        &fresh_cw, rs_config.folding_factor, mh.clone(), mc.clone(),
    );
    timings.merkle_commit_us = t.elapsed().as_micros() as f64;

    // 6. Derive FS challenges + WARP fold
    let t = Instant::now();
    let log_m = shape.num_cons().next_power_of_two().trailing_zeros() as usize;
    let (omega, tau, fresh_betas, mut fold_chal) =
        derive_fold_challenges(acc, &fresh_root, log_m, make_fold_chal());

    let mhc = mh.clone();
    let mcc = mc.clone();
    let result = warp_fold_prove_rs_committed(
        shape, &[fresh], acc, omega, &tau, &fresh_betas,
        rs_config, dft,
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
    );
    timings.fold_us = t.elapsed().as_micros() as f64;
    timings.total_us = total_start.elapsed().as_micros() as f64;

    let new_acc = rebuild_acc(&result);
    (new_acc, timings, result)
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn fmt_us(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.1}s", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("{:.1}ms", v / 1_000.0)
    } else {
        format!("{:.0}us", v)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let num_steps: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let repeats: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    let step_sizes = [10, 50, 100, 500, 1000, 5000, 10_000, 50_000];

    println!("IVC Per-Phase Cost Breakdown by Step Circuit Size");
    println!("=================================================");
    println!("Field: KoalaBear | WARP fold: factor=2, rate=1/2 | Poseidon2 Merkle");
    println!("IVC steps: {num_steps} | Repeats: {repeats} (+ 1 warmup) | Median timing");
    println!();
    println!(
        "{:>8} | {:>8} {:>8} | {:>10} {:>10} {:>10} {:>10} {:>10} | {:>6} {:>6} {:>6} {:>6} {:>6}",
        "muls", "witness", "codeword",
        "circuit", "spartan", "rs_enc", "merkle", "fold",
        "ckt%", "spt%", "rs%", "mk%", "fld%",
    );
    println!("{}", "-".repeat(130));

    let dft = Radix2DFTSmallBatch::<F>::default();
    let (mh, mc) = make_hc();
    let rs_config = RSEncodingConfig::new(2, 1);

    for &num_muls in &step_sizes {
        let step_circuit = WorkloadStepCircuit::new(num_muls);

        // Probe circuit to get shape and sizes
        let mut probe_builder = CircuitBuilder::<F>::new();
        let probe_input = probe_builder.alloc_witness(F::from_u64(3));
        let _ = step_circuit.synthesize(&mut probe_builder, &[probe_input]);
        let (probe_shape, probe_instance) = probe_builder.build();

        let spartan = R1CSProver::new();
        let probe_w = spartan.prepare_witness(&probe_instance);
        let num_inputs = probe_instance.input().len();
        let num_witness = (probe_w.num_evals() - num_inputs).next_power_of_two();
        let log_code = num_witness.trailing_zeros() as usize + rs_config.log_inv_rate;
        let log_m = probe_shape.num_cons().next_power_of_two().trailing_zeros() as usize;

        // Init accumulator
        let zero_acc = make_zero_acc(num_witness, log_code, log_m, num_inputs);

        // Do init fold to get a proper running accumulator
        let z0 = probe_w.as_slice();
        let mut wit0 = z0[num_inputs..].to_vec();
        wit0.resize(num_witness, F::ZERO);
        let fresh0 = FreshInstance {
            public_input: z0[..num_inputs].to_vec(),
            witness: wit0,
        };
        let fresh_root0 = precompute_fresh_root(
            &fresh0.witness, &rs_config, &dft, &mh, &mc,
        );
        let (omega0, tau0, betas0, mut fc0) =
            derive_fold_challenges(&zero_acc, &fresh_root0, log_m, make_fold_chal());
        let mhc = mh.clone();
        let mcc = mc.clone();
        let r0 = warp_fold_prove_rs_committed(
            &probe_shape, &[fresh0], &zero_acc, omega0, &tau0, &betas0,
            &rs_config, &dft,
            |re| { for &e in re { fc0.observe(e); } fc0.sample() },
            |cw, ff| {
                let (root, _) = merkle_commit_codeword::<F, F, _, _, MyHash, MyCompress, DIGEST>(
                    cw, ff, mhc.clone(), mcc.clone(),
                );
                root
            },
        );
        let init_acc = rebuild_acc(&r0);

        // Run timed IVC steps (warmup + repeats)
        let mut all_timings: Vec<StepTimings> = Vec::new();

        for rep in 0..(repeats + 1) {
            let mut acc = init_acc.clone();
            let mut step_timings_sum = StepTimings::default();

            for s in 0..num_steps {
                let (new_acc, timings, _result) = timed_ivc_step(
                    &probe_shape, &acc, &step_circuit, F::from_u64(3),
                    s + rep * num_steps,
                    &rs_config, &dft, &mh, &mc,
                );
                acc = new_acc;
                step_timings_sum.circuit_build_us += timings.circuit_build_us;
                step_timings_sum.spartan_prove_us += timings.spartan_prove_us;
                step_timings_sum.rs_encode_us += timings.rs_encode_us;
                step_timings_sum.merkle_commit_us += timings.merkle_commit_us;
                step_timings_sum.fold_us += timings.fold_us;
                step_timings_sum.total_us += timings.total_us;
            }

            // Average per step
            let n = num_steps as f64;
            step_timings_sum.circuit_build_us /= n;
            step_timings_sum.spartan_prove_us /= n;
            step_timings_sum.rs_encode_us /= n;
            step_timings_sum.merkle_commit_us /= n;
            step_timings_sum.fold_us /= n;
            step_timings_sum.total_us /= n;

            if rep > 0 {
                all_timings.push(step_timings_sum);
            }
        }

        // Take medians
        let mut ckt: Vec<f64> = all_timings.iter().map(|t| t.circuit_build_us).collect();
        let mut spt: Vec<f64> = all_timings.iter().map(|t| t.spartan_prove_us).collect();
        let mut rs: Vec<f64> = all_timings.iter().map(|t| t.rs_encode_us).collect();
        let mut mk: Vec<f64> = all_timings.iter().map(|t| t.merkle_commit_us).collect();
        let mut fld: Vec<f64> = all_timings.iter().map(|t| t.fold_us).collect();
        let mut tot: Vec<f64> = all_timings.iter().map(|t| t.total_us).collect();

        let ckt_m = median(&mut ckt);
        let spt_m = median(&mut spt);
        let rs_m = median(&mut rs);
        let mk_m = median(&mut mk);
        let fld_m = median(&mut fld);
        let tot_m = median(&mut tot);

        let pct = |v: f64| -> String {
            if tot_m > 0.0 { format!("{:.0}%", 100.0 * v / tot_m) }
            else { "0%".to_string() }
        };

        println!(
            "{:>8} | {:>8} {:>8} | {:>10} {:>10} {:>10} {:>10} {:>10} | {:>6} {:>6} {:>6} {:>6} {:>6}",
            num_muls,
            format!("2^{}", num_witness.trailing_zeros()),
            format!("2^{}", (num_witness << rs_config.log_inv_rate).trailing_zeros()),
            fmt_us(ckt_m), fmt_us(spt_m), fmt_us(rs_m), fmt_us(mk_m), fmt_us(fld_m),
            pct(ckt_m), pct(spt_m), pct(rs_m), pct(mk_m), pct(fld_m),
        );
    }

    println!();
    println!("Legend:");
    println!("  muls     = number of multiplication constraints in step circuit");
    println!("  witness  = witness polynomial size (power of 2)");
    println!("  codeword = RS codeword size (witness * 2 for rate 1/2)");
    println!("  circuit  = build R1CS from step circuit");
    println!("  spartan  = Spartan two-phase sumcheck prove");
    println!("  rs_enc   = Reed-Solomon encoding (DFT)");
    println!("  merkle   = Merkle tree commitment (Poseidon2)");
    println!("  fold     = WARP fold (FS challenges + twin-constraint + shift + OOD + eval batch)");
    println!("  %%       = percentage of total per-step time");
}
