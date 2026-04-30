//! WHIR verifier in-circuit cost estimate — formula-based (not measured).
//! Demonstrates why a recursive-WHIR-per-step IVC would be prohibitively
//! expensive vs the WARP fold verifier.
//!
//! Costs are derived from known constraint counts per operation:
//!   - Poseidon2 permutation (width 16, x^3 sbox) ≈ 340 R1CS constraints
//!   - Extension-field (D=4) multiplication ≈ 20 R1CS constraints
//!   - Merkle path verification per level = 1 Poseidon2 compression

use rand::{SeedableRng, rngs::SmallRng};
use whir_spartan::{r1cs::R1CSInstance, r1cs_prover::R1CSProver};

use crate::{
    fixtures::{F, make_whir_config},
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct WhirInCircuitEstimate;

const POSEIDON2_COST: usize = 340;
const EF_MUL_COST: usize = 20;

impl Microbench for WhirInCircuitEstimate {
    const NAME: &'static str = "whir_in_circuit_estimate";

    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        axes.log_size
            .iter()
            .map(|&log_size| {
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
                for _rp in &cfg.round_parameters {
                    fs_hashes += 2 + ff + 1;
                }
                let fs_cost = fs_hashes * POSEIDON2_COST;

                let mut sumcheck_muls = ff * 3;
                for _ in 0..n_rounds {
                    sumcheck_muls += ff * 3;
                }
                let sumcheck_cost = sumcheck_muls * EF_MUL_COST;

                let mut merkle_hashes = 0usize;
                let merkle_depth = wnv;
                for rp in &cfg.round_parameters {
                    merkle_hashes += rp.num_queries * merkle_depth;
                }
                merkle_hashes += cfg.final_queries * merkle_depth;
                let merkle_cost = merkle_hashes * POSEIDON2_COST;

                let query_eval_muls: usize = cfg
                    .round_parameters
                    .iter()
                    .map(|rp| rp.num_queries * (1 << ff))
                    .sum::<usize>()
                    + cfg.final_queries * (1 << ff);
                let query_cost = query_eval_muls * EF_MUL_COST;

                let total = fs_cost + sumcheck_cost + merkle_cost + query_cost;

                MicrobenchRow::new(Self::NAME)
                    .with_axis("log_size", log_size)
                    .with_value("fs", fs_cost)
                    .with_value("sumcheck", sumcheck_cost)
                    .with_value("merkle", merkle_cost)
                    .with_value("queries", query_cost)
                    .with_value("total", total)
            })
            .collect()
    }
}
