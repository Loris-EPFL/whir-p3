//! Recursive Family B same-arity baseline: Symphony/CP verifier, standard WARP.
//!
//! This is the non-Quasar counterpart of `quasar_symphony`: both fold
//! `arity - 1` recursive step-circuit proofs per step and both defer hash
//! verification through Symphony, but this scheme commits/verifies individual
//! input roots instead of a Quasar union root.

use std::time::Instant;

use p3_field::PrimeCharacteristicRing;
use whir_cp_snark::cp_snark_terminal_verify_with_merkle;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::{
        WarpIVCConfig, WarpIVCStateCp, compute_recursive_standard_cp_circuit_size,
        warp_ivc_init_recursive_standard_cp, warp_ivc_step_recursive_standard_cp,
    },
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{
        EF, F, make_challenger, make_hc, produce_synthetic_r1cs, verify_full_warp_terminal,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct SymphonyStandardArity {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    total_step_circuits: usize,
    arity: usize,
    step_muls: usize,
}

impl FoldingScheme for SymphonyStandardArity {
    const NAME: &'static str = "symphony_standard_arity";
    type Proof = WarpIVCStateCp<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let arity = axes.arity.max(2);
        let ivc_config = WarpIVCConfig {
            fold_arity: arity,
            use_union: false,
            ..Default::default()
        };
        Self {
            shape,
            instance,
            ivc_config,
            total_step_circuits: axes.total_step_circuits.unwrap_or(axes.ivc_steps).max(1),
            arity,
            step_muls: axes.step_muls,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let _ = (&self.shape, &self.instance);
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        let step = WorkloadStepCircuit::new(self.step_muls);
        let step_input = [F::ZERO];
        let (target_w, circuit_constraints, _) =
            compute_recursive_standard_cp_circuit_size(&step, &step_input, self.arity);
        m.count("circuit_constraints", circuit_constraints as u64);

        let state = m.time("prove_total", || {
            let mut state = warp_ivc_init_recursive_standard_cp::<F, _>(
                &step,
                &step_input,
                self.arity,
                &self.ivc_config,
                target_w,
                vec![],
            );

            let circuits_per_step = self.arity - 1;
            let num_ivc_steps = self.total_step_circuits.div_ceil(circuits_per_step);
            for s in 0..num_ivc_steps {
                let step_inputs: Vec<Vec<F>> = (0..circuits_per_step)
                    .map(|i| {
                        let global = s * circuits_per_step + i;
                        if global < self.total_step_circuits {
                            vec![F::from_u64(global as u64)]
                        } else {
                            vec![F::ZERO]
                        }
                    })
                    .collect();
                let mut ch = make_challenger(s as u64 + 410);
                state = warp_ivc_step_recursive_standard_cp::<F, EF, _, _, _, _, _, _>(
                    state,
                    &step,
                    &step_inputs,
                    self.arity,
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

        let circuits_per_step = self.arity - 1;
        let folds = self.total_step_circuits.div_ceil(circuits_per_step);
        let padded = folds * circuits_per_step - self.total_step_circuits;
        m.count("total_instances", self.total_step_circuits as u64);
        m.count("total_step_circuits", self.total_step_circuits as u64);
        m.count(
            "target_total_step_circuits",
            self.total_step_circuits as u64,
        );
        m.count("padding_step_circuits", padded as u64);
        m.count("folds", folds as u64);
        m.count("fresh_per_full_fold", circuits_per_step as u64);
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
        let (_, c, _) = compute_recursive_standard_cp_circuit_size(&step, &step_input, self.arity);
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
    fn symphony_standard_arity_prove_verify() {
        let axes = Axes {
            log_n: 8,
            arity: 4,
            batch: 1,
            ivc_steps: 1,
            step_muls: 8,
            seed: 42,
            total_instances: None,
            total_step_circuits: Some(3),
        };
        let s = SymphonyStandardArity::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
