//! Family A (no step circuit): batch-reduce + WARP fold.
//!
//! Each IVC iteration absorbs `batch` fresh R1CS instances. The batch is
//! reduced to a single witness (constraint_batch sumcheck + random LC), then
//! folded at l=2 into the running accumulator. Mirrors compare_bench's
//! `batch_then_fold` path.
//!
//! Total instances processed = `ivc_steps * batch`.

use p3_field::PrimeCharacteristicRing;
use warp::decider::warp_decide_algebraic_rs;
use whir_ivc::warp_ivc::{warp_ivc_init, warp_ivc_step_batch, WarpIVCConfig, WarpIVCState};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{make_challenger, make_hc, produce_synthetic_r1cs, EF, F},
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct WarpBatch {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
    batch: usize,
}

impl FoldingScheme for WarpBatch {
    const NAME: &'static str = "warp_batch";
    type Proof = WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        Self {
            shape,
            instance,
            ivc_config: WarpIVCConfig::default(),
            ivc_steps: axes.ivc_steps,
            batch: axes.batch.max(1),
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);
        let batch = self.batch;

        let state = m.time("prove_total", || {
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
                let batch_instances: Vec<R1CSInstance<F>> =
                    (0..batch).map(|_| self.instance.clone()).collect();
                let mut spartan_chals: Vec<_> =
                    (0..batch).map(|i| make_challenger(step as u64 * 1000 + i as u64 + 1)).collect();
                let mut cb_chal = make_challenger(step as u64 + 77);
                state = warp_ivc_step_batch::<F, EF, _, _, _, _, _>(
                    &state,
                    &batch_instances,
                    &mut spartan_chals,
                    <EF as PrimeCharacteristicRing>::from_u64(3),
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    &mut cb_chal,
                    vec![],
                    make_fold_chal,
                );
            }
            state
        });

        m.count("total_instances", (self.ivc_steps * batch) as u64);
        m.count("family_a", 1);
        state
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
    fn warp_batch_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 2,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
        };
        let s = WarpBatch::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
