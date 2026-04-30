//! Family A (no step circuit): non-recursive WARP + Quasar union fold.
//!
//! Each IVC iteration absorbs `arity - 1` fresh R1CS instances, built into a
//! union codeword, folded at arity=`axes.arity`. No in-circuit Poseidon2
//! verifier (that's what separates this from `quasar_warp`).
//!
//! Total instances processed = `ivc_steps * (arity - 1)`.

use p3_field::PrimeCharacteristicRing;
use warp::accumulator::FreshInstance;
use whir_ivc::warp_ivc::{WarpIVCConfig, WarpIVCState, warp_ivc_init_fold, warp_ivc_step_union};
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
pub struct WarpUnion {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    arity: usize,
    num_inputs: usize,
    num_witness: usize,
    total_instances: usize,
}

impl FoldingScheme for WarpUnion {
    const NAME: &'static str = "warp_union";
    type Proof = WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, num_inputs, _, _) = produce_synthetic_r1cs(axes.log_n);
        let arity = axes.arity.max(2);
        let ivc_config = WarpIVCConfig {
            fold_arity: arity,
            use_union: true,
            ..Default::default()
        };
        let per_step = arity - 1;
        let total_instances = axes
            .total_instances
            .unwrap_or_else(|| 1 + axes.ivc_steps * per_step)
            .max(1);
        Self {
            shape,
            instance,
            ivc_config,
            arity,
            num_inputs,
            num_witness,
            total_instances,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        let per_step = self.arity - 1;
        let total = self.total_instances.saturating_sub(1);

        // ── Spartan phase: linearize (init + ivc_steps * per_step) instances
        //    externally so `prove_total` measures ONLY fold work.
        let total_fresh = self.total_instances;
        let (linearized, spartan_us) =
            spartan_linearize_all(&self.shape, &self.instance, total_fresh);
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

        // ── Fold-only phase: post-Spartan.
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

            let mut idx = 1;
            while idx < self.total_instances {
                let end = (idx + per_step).min(self.total_instances);
                let fresh: Vec<FreshInstance<F>> = (idx..end).map(&to_fresh).collect();

                state = warp_ivc_step_union::<F, _, _, _, _>(
                    &state,
                    &fresh,
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    vec![],
                    make_fold_chal,
                );
                idx = end;
            }
            state
        });

        m.count("total_instances", self.total_instances as u64);
        m.count("target_total_instances", self.total_instances as u64);
        m.count("folds", total.div_ceil(per_step) as u64);
        m.count("fresh_per_full_fold", per_step as u64);
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
    fn warp_union_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 4,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
            total_instances: None,
            total_step_circuits: None,
        };
        let s = WarpUnion::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
