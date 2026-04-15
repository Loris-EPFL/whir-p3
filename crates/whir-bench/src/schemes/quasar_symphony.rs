//! Path D from compare_bench: Symphony + Quasar union (l=arity), recursive
//! algebraic verifier + CP-SNARK committed transcripts.
//!
//! Each IVC step builds a recursive circuit (step computation + algebraic union
//! fold verifier), Spartan-proves it, then union-folds at the configured arity
//! with CP-SNARK committed transcripts.

use p3_field::PrimeCharacteristicRing;
use warp::decider::warp_decide_algebraic_rs;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::{
        compute_recursive_union_circuit_size, warp_ivc_init_recursive_union_cp,
        warp_ivc_step_recursive_union_cp, WarpIVCConfig, WarpIVCStateCp,
    },
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{make_challenger, make_hc, produce_synthetic_r1cs, EF, F},
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct QuasarSymphony {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
    arity: usize,
    step_muls: usize,
}

impl FoldingScheme for QuasarSymphony {
    const NAME: &'static str = "quasar_symphony";
    type Proof = WarpIVCStateCp<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let ivc_config = WarpIVCConfig {
            fold_arity: axes.arity,
            use_union: true,
            ..Default::default()
        };
        Self {
            shape,
            instance,
            ivc_config,
            ivc_steps: axes.ivc_steps,
            arity: axes.arity,
            step_muls: axes.step_muls,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        let step = WorkloadStepCircuit::new(self.step_muls);
        let step_input = [F::ZERO];
        let (target_w, _, _) =
            compute_recursive_union_circuit_size(&step, &step_input, self.arity);

        m.time("prove_total", || {
            let state = warp_ivc_init_recursive_union_cp::<F, _>(
                &step,
                &step_input,
                self.arity,
                &self.ivc_config,
                target_w,
                vec![],
            );
            let mut state = state;

            let circuits_per_step = self.arity - 1;
            let num_ivc_steps = self.ivc_steps / circuits_per_step;

            for s in 0..num_ivc_steps {
                let step_inputs: Vec<Vec<F>> = (0..circuits_per_step)
                    .map(|i| vec![F::from_u64(s as u64 * 10 + i as u64)])
                    .collect();
                let mut ch = make_challenger(s as u64 + 410);
                state = warp_ivc_step_recursive_union_cp::<F, EF, _, _, _, _, _, _>(
                    &state,
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
        })
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        m.time("verify_total", || {
            warp_decide_algebraic_rs(&proof.shape, &proof.accumulator)
                .map_err(|e| anyhow::anyhow!("decider failed: {e:?}"))
        })
    }

    fn static_metrics(&self, _proof: &Self::Proof) -> StaticMetrics {
        StaticMetrics {
            proof_field_elems: 0,
            circuit_constraints: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quasar_symphony_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 4,
            batch: 1,
            ivc_steps: 6,
            step_muls: 100,
            seed: 42,
        };
        let s = QuasarSymphony::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
