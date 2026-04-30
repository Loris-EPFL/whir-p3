//! Path C from compare_bench: Symphony (l=2), recursive algebraic verifier + CP-SNARK.
//!
//! Each IVC step builds an algebraic recursive circuit (step computation +
//! algebraic fold verifier), Spartan-proves it, then WARP-folds at l=2
//! with CP-SNARK committed transcripts.
//!
//! # Benchmark methodology note
//!
//! For a FAIR apples-to-apples comparison with `quasar_warp` and
//! `quasar_symphony`, this scheme now accumulates at the **recursive
//! circuit's** witness size — not the user R1CS's 2^log_n size.  The
//! init builds the step circuit + algebraic fold verifier into an R1CS,
//! Spartan-proves it, and uses THAT as the first accumulator.  Subsequent
//! steps fold tiny recursive-circuit witnesses into the same-size
//! accumulator.  As a result, the per-step prover time is independent of
//! `log_n` (matching the other Family-B schemes).
//!
//! Before this fix, `symphony` was (incorrectly) folding at user-R1CS
//! size, which made its per-step time scale with `log_n` while its
//! siblings stayed flat.  That produced a visually "exponential"
//! Symphony curve in the dashboard — a methodology artifact, not a
//! soundness issue.

use std::time::Instant;

use p3_field::PrimeCharacteristicRing;
use whir_circuit::builder::CircuitBuilder;
use whir_cp_snark::cp_snark_terminal_verify_with_merkle;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_fold_verifier_algebraic::{compute_cp_circuit_size, synthesize_warp_ivc_circuit_cp},
    warp_ivc::{WarpIVCConfig, WarpIVCStateCp, warp_ivc_init_cp, warp_ivc_step_recursive_cp},
};
use whir_spartan::r1cs::R1CSShape;

use crate::{
    axes::Axes,
    fixtures::{
        EF, F, make_challenger, make_hc, produce_synthetic_r1cs, verify_full_warp_terminal,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct Symphony {
    /// Kept only so the total-prover metric includes a "Spartan over user
    /// R1CS" analogue comparable with `independent_whir`; the IVC chain
    /// itself does NOT fold into this shape.
    _user_shape: R1CSShape<F>,
    ivc_config: WarpIVCConfig,
    total_step_circuits: usize,
    step_muls: usize,
}

impl FoldingScheme for Symphony {
    const NAME: &'static str = "symphony";
    type Proof = WarpIVCStateCp<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, _instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let ivc_config = WarpIVCConfig::default();
        Self {
            _user_shape: shape,
            ivc_config,
            total_step_circuits: axes.total_step_circuits.unwrap_or(axes.ivc_steps).max(1),
            step_muls: axes.step_muls,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        let step = WorkloadStepCircuit::new(self.step_muls);
        let step_input = [F::ZERO];
        let (target_w, _, _) = compute_cp_circuit_size(&step, &step_input);

        // Build the init circuit: step + algebraic-verifier R1CS.  Spartan
        // on THIS small R1CS drives the recursive-circuit-sized
        // accumulator — the same shape the step function folds into later.
        let mut init_builder = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut init_builder,
            &step,
            &step_input,
            None,
            Some(target_w),
        );
        let (init_shape, init_instance) = init_builder.build();

        let state = m.time("prove_total", || {
            let mut spartan_ch = make_challenger(300);
            let mut state = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
                &init_shape,
                &init_instance,
                &mut spartan_ch,
                &self.ivc_config,
                &dft,
                mh.clone(),
                mc.clone(),
                vec![],
                make_fold_chal,
            );

            for s in 0..self.total_step_circuits {
                let mut ch = make_challenger(s as u64 + 310);
                // Consume the previous state (moves out the cached acc tree
                // so the step can reuse it without rebuilding).
                state = warp_ivc_step_recursive_cp::<F, EF, _, _, _, _, _, _>(
                    state,
                    &step,
                    &step_input,
                    &mut ch,
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    Some(target_w),
                    vec![],
                    make_fold_chal,
                );
            }
            state
        });
        m.count("total_instances", self.total_step_circuits as u64);
        m.count("total_step_circuits", self.total_step_circuits as u64);
        m.count(
            "target_total_step_circuits",
            self.total_step_circuits as u64,
        );
        m.count("folds", self.total_step_circuits as u64);
        m.count("family_b", 1);
        state
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        let total_start = Instant::now();

        let (mh, mc) = make_hc();
        let cp_start = Instant::now();
        let cp_result = cp_snark_terminal_verify_with_merkle(
            &proof.shape,
            &proof.accumulator,
            &proof.committed_transcripts,
            || make_challenger(77),
            self.ivc_config.rs_folding_factor,
            &mh,
            &mc,
        )
        .map_err(|e| anyhow::anyhow!("CP terminal failed: {e:?}"));
        m.record("cp_replay", cp_start.elapsed().as_nanos());
        cp_result?;

        let decider_start = Instant::now();
        let decider_result = verify_full_warp_terminal(
            &proof.shape,
            &proof.accumulator,
            self.ivc_config.rs_folding_factor,
            self.ivc_config.rs_log_inv_rate,
        );
        m.record("terminal_decider", decider_start.elapsed().as_nanos());
        decider_result?;

        m.record("verify_total", total_start.elapsed().as_nanos());
        Ok(())
    }

    fn static_metrics(&self, _proof: &Self::Proof) -> StaticMetrics {
        let step = WorkloadStepCircuit::new(self.step_muls);
        let step_input = [F::ZERO];
        let (_, c, _) = compute_cp_circuit_size(&step, &step_input);
        StaticMetrics {
            proof_field_elems: 0,
            circuit_constraints: Some(c as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symphony_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
            total_instances: None,
            total_step_circuits: None,
        };
        let s = Symphony::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
