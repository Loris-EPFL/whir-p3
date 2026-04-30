use warp::accumulator::FreshInstance;
use whir_ivc::warp_ivc::{WarpIVCConfig, warp_ivc_init_fold, warp_ivc_step_fold};

use crate::{
    axes::Axes,
    fixtures::{
        F, make_hc, produce_synthetic_r1cs, spartan_linearize_all,
        verify_full_warp_terminal_measured,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};
use p3_challenger::DuplexChallenger;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::Poseidon2KoalaBear;
use rand::{SeedableRng, rngs::SmallRng};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

type Perm = Poseidon2KoalaBear<16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}

#[derive(Debug)]
pub struct PureWarp {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    num_inputs: usize,
    num_witness: usize,
    total_instances: usize,
}

impl FoldingScheme for PureWarp {
    const NAME: &'static str = "pure_warp";
    type Proof = whir_ivc::warp_ivc::WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, num_inputs, _, _) = produce_synthetic_r1cs(axes.log_n);
        let ivc_config = WarpIVCConfig::default();
        let total_instances = axes
            .total_instances
            .unwrap_or_else(|| axes.ivc_steps + 1)
            .max(1);
        Self {
            shape,
            instance,
            ivc_config,
            num_inputs,
            num_witness,
            total_instances,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);

        // ── Spartan phase: linearize ALL (init + ivc_steps) fresh instances
        //     externally so that `prove_total` measures ONLY fold work.
        let total_fresh = self.total_instances;
        let (linearized, spartan_us) =
            spartan_linearize_all(&self.shape, &self.instance, total_fresh);
        m.record("spartan", (spartan_us * 1000.0) as u128);

        // Convert LinearizedInstance → FreshInstance (public_input + padded witness).
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

        // ── Fold-only phase: every call below is post-Spartan.
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
            for step in 1..self.total_instances {
                state = warp_ivc_step_fold::<F, _, _, _, _>(
                    &state,
                    to_fresh(step),
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
        m.count("total_instances", self.total_instances as u64);
        m.count("target_total_instances", self.total_instances as u64);
        m.count("folds", self.total_instances.saturating_sub(1) as u64);
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
    fn pure_warp_prove_verify() {
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
        let s = PureWarp::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());

        let mut bad_root = p.clone();
        bad_root.accumulator.instance.commitment_root[0] += F::ONE;
        assert!(
            s.verify(&bad_root, &mut m).is_err(),
            "verify must reject a final accumulator root not bound to its codeword"
        );

        let mut bad_codeword = p.clone();
        bad_codeword.accumulator.witness.codeword.as_mut_slice()[0] += F::ONE;
        assert!(
            s.verify(&bad_codeword, &mut m).is_err(),
            "verify must reject a final accumulator whose codeword is not RS(witness)"
        );
    }
}
