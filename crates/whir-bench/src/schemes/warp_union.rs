//! Family A (no step circuit): non-recursive WARP + Quasar union fold.
//!
//! Each IVC iteration absorbs `arity - 1` fresh R1CS instances, built into a
//! union codeword, folded at arity=`axes.arity`. No in-circuit Poseidon2
//! verifier (that's what separates this from `quasar_warp`).
//!
//! Total instances processed = `ivc_steps * (arity - 1)`.

use p3_field::PrimeCharacteristicRing;
use warp::{
    accumulator::FreshInstance,
    decider::warp_decide_algebraic_rs,
};
use whir_ivc::warp_ivc::{warp_ivc_init, warp_ivc_step_union, WarpIVCConfig, WarpIVCState};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{
        make_challenger, make_hc, produce_synthetic_r1cs, spartan_linearize_all, EF, F,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct WarpUnion {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
    arity: usize,
    num_inputs: usize,
    num_witness: usize,
}

impl FoldingScheme for WarpUnion {
    const NAME: &'static str = "warp_union";
    type Proof = WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, num_inputs, _, _) = produce_synthetic_r1cs(axes.log_n);
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
            num_inputs,
            num_witness,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        let per_step = self.arity - 1;
        let total = self.ivc_steps * per_step;

        // Spartan-linearize all fresh instances up front (fair post-Spartan
        // comparison: the `prove_total` timer excludes this, matching the
        // compare_bench convention).
        let (linearized, spartan_us) =
            spartan_linearize_all(&self.shape, &self.instance, total);
        m.record("spartan", (spartan_us * 1000.0) as u128);

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
                let idx = step * per_step;
                let fresh: Vec<FreshInstance<F>> = linearized[idx..idx + per_step]
                    .iter()
                    .map(|li| {
                        let z = li.witness.as_slice();
                        let public_input = z[..self.num_inputs].to_vec();
                        let mut witness = z[self.num_inputs..].to_vec();
                        witness.resize(self.num_witness, F::ZERO);
                        FreshInstance {
                            public_input,
                            witness,
                        }
                    })
                    .collect();

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
            }
            state
        });

        m.count("total_instances", total as u64);
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
    fn warp_union_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 4,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
        };
        let s = WarpUnion::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
