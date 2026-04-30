//! Aggregated WARP vs N independent WHIR proofs — the headline comparison.
//!
//! For each `n` in `axes.n_instances`, we measure end-to-end **prover and
//! verifier wall-time** for two paths that both produce a succinct proof
//! of the same N R1CS instances:
//!
//!   * `whir`         — N independent WHIR proofs. Prover does N proves;
//!     verifier checks N proofs. No accumulation.
//!   * `warp_direct`  — WARP fold (batch=1): 1 init + (N-1) sequential fold
//!     steps + terminal WHIR. Verifier = WARP decider + terminal WHIR.
//!
//! Spartan linearization runs OUTSIDE the timer for all paths so the
//! comparison measures fold/proof work only — apples-to-apples with the
//! Family-A scheme rows in the dashboard.
//!
//! Story:
//!   - **Verifier**: WARP wins for any N>1 — its verifier is constant
//!     time (one terminal WHIR + decider), while WHIR is O(N).
//!   - **Prover, batch=1 (`warp_direct`)**: WARP loses to WHIR — fold
//!     overhead per instance is heavier than a single WHIR commit.

use std::time::Instant;

use p3_field::{Field, PrimeCharacteristicRing};
use warp::accumulator::FreshInstance;
use whir_core::poly::evals::EvaluationsList;
use whir_ivc::warp_ivc::{WarpIVCConfig, warp_ivc_init_fold, warp_ivc_step_fold};
use whir_pcs::whir::{
    committer::{reader::CommitmentReader, writer::CommitmentWriter},
    constraints::statement::{EqStatement, InitialClaim},
    proof::WhirProof,
    prover::Prover as WhirProver,
    verifier::Verifier as WhirVerifier,
};

use crate::{
    fixtures::{
        DIGEST, EF, F, make_challenger, make_dft, make_ds, make_hc, make_whir_config,
        produce_synthetic_r1cs, seed_ch, spartan_linearize_all, terminal_whir_prove,
        terminal_whir_verify_bound, verify_full_warp_terminal,
    },
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct WarpVsWhir;

impl Microbench for WarpVsWhir {
    const NAME: &'static str = "warp_vs_whir";

    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        let mut rows = Vec::new();
        let dft = make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);
        let ivc_config = WarpIVCConfig::default();

        for &log_n in &axes.aggregate_log_n {
            let (shape, instance, num_witness, _, _, _) = produce_synthetic_r1cs(log_n);
            let witness_num_vars = num_witness.trailing_zeros() as usize;
            let cfg = make_whir_config(witness_num_vars);

            for &n in &axes.n_instances {
                if n == 0 {
                    continue;
                }

                // Spartan-linearize n fresh instances OUTSIDE the timer.
                let (linearized, _spartan_us) = spartan_linearize_all(&shape, &instance, n);

                let to_fresh = |idx: usize| -> FreshInstance<F> {
                    let z = linearized[idx].witness.as_slice();
                    let public_input = Vec::new();
                    let mut witness = z.to_vec();
                    witness.resize(num_witness, F::ZERO);
                    FreshInstance {
                        public_input,
                        witness,
                    }
                };

                // ── Path A: N independent WHIR proofs ────────────────────────
                let t = Instant::now();
                let mut whir_proofs: Vec<WhirProof<F, EF, F, DIGEST>> = Vec::with_capacity(n);
                for (i, lin) in linearized.iter().enumerate() {
                    let mut wvec = lin.witness.as_slice().to_vec();
                    wvec.resize(wvec.len().next_power_of_two(), F::ZERO);
                    let wpoly = EvaluationsList::new(wvec);
                    let mut stmt = cfg.initial_statement_with_linear(wpoly, lin.linear.clone());
                    let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(&cfg);
                    let ds = make_ds(&cfg);
                    let mut ch = seed_ch(100 + i as u64, &ds);
                    let comm = CommitmentWriter::new(&cfg)
                        .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                            &dft, &mut proof, &mut ch, &mut stmt,
                        )
                        .expect("commit");
                    WhirProver(&cfg)
                        .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                            &dft, &mut proof, &mut ch, &stmt, comm,
                        )
                        .expect("prove");
                    whir_proofs.push(proof);
                }
                let whir_prove_us = t.elapsed().as_micros() as f64;

                let t = Instant::now();
                for (i, (proof, lin)) in whir_proofs.iter().zip(linearized.iter()).enumerate() {
                    let initial_claim = InitialClaim {
                        eq_statement: EqStatement::initialize(witness_num_vars),
                        linear_statement: lin.linear.clone(),
                    };
                    let ds = make_ds(&cfg);
                    let mut ch = seed_ch(100 + i as u64, &ds);
                    let parsed =
                        CommitmentReader::new(&cfg).parse_commitment::<F, DIGEST>(proof, &mut ch);
                    WhirVerifier::new(&cfg)
                    .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                        proof, &mut ch, &parsed, initial_claim,
                    )
                    .expect("verify");
                }
                let whir_verify_us = t.elapsed().as_micros() as f64;

                // ── Path B: WARP direct fold (batch=1) → terminal WHIR ──────
                // Prover = init + (n-1) sequential step folds + terminal WHIR prove.
                let t = Instant::now();
                let mut state = warp_ivc_init_fold::<F, _, _, _, _>(
                    &shape,
                    to_fresh(0),
                    &ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    vec![],
                    make_fold_chal,
                );
                for step in 1..n {
                    state = warp_ivc_step_fold::<F, _, _, _, _>(
                        &state,
                        to_fresh(step),
                        &ivc_config,
                        &dft,
                        mh.clone(),
                        mc.clone(),
                        vec![],
                        make_fold_chal,
                    );
                }
                let term_proof =
                    terminal_whir_prove(&cfg, &state.accumulator.witness.witness, witness_num_vars);
                let warp_direct_prove_us = t.elapsed().as_micros() as f64;

                let t = Instant::now();
                verify_full_warp_terminal(
                    &state.shape,
                    &state.accumulator,
                    ivc_config.rs_folding_factor,
                    ivc_config.rs_log_inv_rate,
                )
                .expect("full WARP terminal check");
                terminal_whir_verify_bound(
                    &cfg,
                    &term_proof,
                    witness_num_vars,
                    state.accumulator.instance.commitment_root,
                )
                .expect("terminal verify");
                let warp_direct_verify_us = t.elapsed().as_micros() as f64;

                rows.push(
                    MicrobenchRow::new(Self::NAME)
                        .with_axis("n_instances", n)
                        .with_axis("log_n", log_n)
                        .with_value("whir_prove_us", whir_prove_us)
                        .with_value("whir_verify_us", whir_verify_us)
                        .with_value("warp_direct_prove_us", warp_direct_prove_us)
                        .with_value("warp_direct_verify_us", warp_direct_verify_us)
                        .with_value(
                            "prove_speedup_warp_direct",
                            whir_prove_us / warp_direct_prove_us,
                        )
                        .with_value(
                            "verify_speedup_warp_direct",
                            whir_verify_us / warp_direct_verify_us,
                        ),
                );
            }
        }

        rows
    }
}
