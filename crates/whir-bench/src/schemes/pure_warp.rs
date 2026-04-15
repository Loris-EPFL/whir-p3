use warp::decider::warp_decide_algebraic_rs;
use whir_ivc::warp_ivc::{warp_ivc_init, warp_ivc_step, WarpIVCConfig};

use crate::{
    axes::Axes,
    fixtures::{
        make_challenger, make_hc, produce_synthetic_r1cs,
        EF, F,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

#[derive(Debug)]
pub struct PureWarp {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
}

impl FoldingScheme for PureWarp {
    const NAME: &'static str = "pure_warp";
    type Proof = whir_ivc::warp_ivc::WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let ivc_config = WarpIVCConfig::default();
        Self {
            shape,
            instance,
            ivc_config,
            ivc_steps: axes.ivc_steps,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        m.time("prove_total", || {
            let mut spartan_ch = make_challenger(1);
            let mut state = warp_ivc_init::<F, EF, _, _, _, _, _>(
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
            for step in 0..self.ivc_steps {
                let mut ch = make_challenger(step as u64 + 10);
                state = warp_ivc_step::<F, EF, _, _, _, _, _>(
                    &state,
                    &self.instance,
                    &mut ch,
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
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
    fn pure_warp_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
        };
        let s = PureWarp::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
