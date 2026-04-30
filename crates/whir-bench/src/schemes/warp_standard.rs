//! Family A: standard multi-arity WARP fold.
//!
//! This is the non-union baseline for Quasar. It absorbs the same number of
//! fresh instances per fold as `warp_union`, but commits each fresh codeword
//! separately and derives Fiat-Shamir challenges from all individual roots.

use p3_field::PrimeCharacteristicRing;
use warp::accumulator::FreshInstance;
use whir_ivc::warp_ivc::{WarpIVCConfig, WarpIVCState, warp_ivc_init_fold, warp_ivc_step_standard};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{
        F, make_challenger, make_hc, produce_synthetic_r1cs, spartan_linearize_all,
        verify_full_warp_terminal_measured,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct WarpStandard {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    arity: usize,
    num_witness: usize,
    total_instances: usize,
}

impl FoldingScheme for WarpStandard {
    const NAME: &'static str = "warp_standard";
    type Proof = WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let total_instances = axes
            .total_instances
            .unwrap_or_else(|| 1 + axes.ivc_steps * axes.arity.saturating_sub(1))
            .max(1);
        let ivc_config = WarpIVCConfig {
            fold_arity: axes.arity,
            use_union: false,
            ..Default::default()
        };
        Self {
            shape,
            instance,
            ivc_config,
            arity: axes.arity.max(2),
            num_witness,
            total_instances,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        let (linearized, spartan_us) =
            spartan_linearize_all(&self.shape, &self.instance, self.total_instances);
        m.record("spartan", (spartan_us * 1000.0) as u128);

        let to_fresh = |idx: usize| -> FreshInstance<F> {
            let z = linearized[idx].witness.as_slice();
            let public_input = Vec::new();
            let mut witness = z.to_vec();
            witness.resize(self.num_witness, F::ZERO);
            FreshInstance {
                public_input,
                witness,
            }
        };

        let per_fold = self.arity.saturating_sub(1).max(1);
        let state = m.time("prove_total", || {
            let mut state = warp_ivc_init_fold::<F, _, _, _, _>(
                &self.shape,
                to_fresh(0),
                &self.ivc_config,
                &dft,
                mh.clone(),
                mc.clone(),
                vec![],
                make_fold_chal,
            );

            let mut next = 1;
            while next < self.total_instances {
                let end = (next + per_fold).min(self.total_instances);
                let fresh: Vec<FreshInstance<F>> = (next..end).map(&to_fresh).collect();
                state = warp_ivc_step_standard::<F, _, _, _, _>(
                    &state,
                    &fresh,
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    vec![],
                    make_fold_chal,
                );
                next = end;
            }
            state
        });

        m.count("total_instances", self.total_instances as u64);
        m.count(
            "folds",
            self.total_instances.saturating_sub(1).div_ceil(per_fold) as u64,
        );
        m.count("fresh_per_full_fold", per_fold as u64);
        m.count("family_a", 1);
        state
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        verify_full_warp_terminal_measured(
            m,
            &proof.shape,
            &proof.accumulator,
            self.ivc_config.rs_folding_factor,
            self.ivc_config.rs_log_inv_rate,
        )
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
    fn warp_standard_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 4,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
            total_instances: Some(7),
            total_step_circuits: None,
        };
        let s = WarpStandard::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
