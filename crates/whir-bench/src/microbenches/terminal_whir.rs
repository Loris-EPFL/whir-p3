//! Terminal WHIR prove/verify cost + proof size. Axis: `log_size`.
//!
//! Uses `MicrobenchAxes::terminal_repeats` to run each log_size multiple
//! times and report medians — fixes the single-run noise the old
//! compare_bench suffered at this measurement.

use rand::{SeedableRng, rngs::SmallRng};
use whir_spartan::{r1cs::R1CSInstance, r1cs_prover::R1CSProver};

use crate::{
    fixtures::{
        F, make_whir_config, terminal_whir_prove, terminal_whir_verify, whir_proof_field_elements,
    },
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct TerminalWhir;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

impl Microbench for TerminalWhir {
    const NAME: &'static str = "terminal_whir";

    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        let repeats = axes.terminal_repeats.max(1) as usize;

        axes.log_size
            .iter()
            .map(|&log_size| {
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

                let mut prove_times = Vec::with_capacity(repeats);
                let mut verify_times = Vec::with_capacity(repeats);
                let mut proof_fe: u64 = 0;

                for _ in 0..repeats {
                    let t_p = std::time::Instant::now();
                    let proof = terminal_whir_prove(&cfg, sample_w.as_slice(), wnv);
                    prove_times.push(t_p.elapsed().as_micros() as f64);

                    let t_v = std::time::Instant::now();
                    terminal_whir_verify(&cfg, &proof, wnv).expect("terminal WHIR verify failed");
                    verify_times.push(t_v.elapsed().as_micros() as f64);

                    proof_fe = whir_proof_field_elements(&proof);
                }

                let prove_us = median(prove_times);
                let verify_us = median(verify_times);
                let proof_kb = proof_fe * 4 / 1024;

                MicrobenchRow::new(Self::NAME)
                    .with_axis("log_size", log_size)
                    .with_value("prove_us", prove_us)
                    .with_value("verify_us", verify_us)
                    .with_value("proof_fe", proof_fe)
                    .with_value("proof_kb", proof_kb)
                    .with_value("repeats", repeats as u64)
            })
            .collect()
    }
}
