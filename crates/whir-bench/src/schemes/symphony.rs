//! Path C from compare_bench: Symphony (l=2), recursive algebraic verifier + CP-SNARK.
//!
//! Each IVC step builds an algebraic recursive circuit (step computation +
//! algebraic fold verifier), Spartan-proves it, then WARP-folds at l=2
//! with CP-SNARK committed transcripts.

use p3_field::PrimeCharacteristicRing;
use warp::decider::warp_decide_algebraic_rs;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_fold_verifier_algebraic::compute_cp_circuit_size,
    warp_ivc::{warp_ivc_init_cp, warp_ivc_step_recursive_cp, WarpIVCConfig, WarpIVCStateCp},
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{make_challenger, make_hc, produce_synthetic_r1cs, EF, F},
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct Symphony {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
    step_muls: usize,
}

impl FoldingScheme for Symphony {
    const NAME: &'static str = "symphony";
    type Proof = WarpIVCStateCp<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let ivc_config = WarpIVCConfig::default();
        Self {
            shape,
            instance,
            ivc_config,
            ivc_steps: axes.ivc_steps,
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

        let state = m.time("prove_total", || {
            let mut spartan_ch = make_challenger(300);
            let mut state = warp_ivc_init_cp::<F, EF, _, _, _, _, _>(
                &self.shape,
                &self.instance,
                &mut spartan_ch,
                &self.ivc_config,
                &dft,
                mh.clone(),
                mc.clone(),
                vec![],
                make_fold_chal,
            );

            for s in 0..self.ivc_steps {
                let mut ch = make_challenger(s as u64 + 310);
                state = warp_ivc_step_recursive_cp::<F, EF, _, _, _, _, _, _>(
                    &state,
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
        m.count("total_instances", self.ivc_steps as u64);
        m.count("family_b", 1);
        state
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        m.time("verify_total", || {
            warp_decide_algebraic_rs(&proof.shape, &proof.accumulator)
                .map_err(|e| anyhow::anyhow!("decider failed: {e:?}"))
        })
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
        };
        let s = Symphony::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
