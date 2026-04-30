//! Family A (no step circuit): batch-reduce + WARP fold.
//!
//! Each IVC iteration absorbs `batch` fresh R1CS instances. The batch is
//! reduced to a single witness (constraint_batch sumcheck + random LC), then
//! folded at l=2 into the running accumulator.
//!
//! Total instances processed = `ivc_steps * batch`.
//!
//! Spartan runs OUTSIDE `prove_total` (see `spartan_linearize_all` below) so
//! the timer measures fold-only work. This makes prover comparisons
//! apples-to-apples post-Spartan against other Family A schemes.

use warp::accumulator::FreshInstance;
use whir_ivc::warp_ivc::{
    WarpIVCConfig, WarpIVCState, warp_ivc_init_fold, warp_ivc_step_batch_fold,
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

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

type Perm = Poseidon2KoalaBear<16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}

#[derive(Debug)]
pub struct WarpBatch {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    batch: usize,
    num_inputs: usize,
    num_witness: usize,
    total_instances: usize,
}

impl FoldingScheme for WarpBatch {
    const NAME: &'static str = "warp_batch";
    type Proof = WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, num_inputs, _, _) = produce_synthetic_r1cs(axes.log_n);
        let batch = axes.batch.max(1);
        let total_instances = axes
            .total_instances
            .unwrap_or_else(|| 1 + axes.ivc_steps * batch)
            .max(1);
        Self {
            shape,
            instance,
            ivc_config: WarpIVCConfig::default(),
            batch,
            num_inputs,
            num_witness,
            total_instances,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let make_fold_chal = || make_challenger(77);
        let batch = self.batch;

        // ── Spartan phase: linearize (init + ivc_steps * batch) instances
        //    externally so that `prove_total` measures ONLY fold work.
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

            let mut next = 1;
            let mut step = 0usize;
            while next < self.total_instances {
                let end = (next + batch).min(self.total_instances);
                let witnesses: Vec<_> = linearized[next..end]
                    .iter()
                    .map(|li| li.witness.clone())
                    .collect();
                let linears: Vec<_> = linearized[next..end]
                    .iter()
                    .map(|li| li.linear.clone())
                    .collect();
                let mut cb_chal = make_challenger(step as u64 + 77);
                state = warp_ivc_step_batch_fold::<F, crate::fixtures::EF, _, _, _, _, _>(
                    &state,
                    &witnesses,
                    &linears,
                    0,
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    &mut cb_chal,
                    vec![],
                    make_fold_chal,
                );
                next = end;
                step += 1;
            }
            state
        });

        m.count("total_instances", self.total_instances as u64);
        m.count("target_total_instances", self.total_instances as u64);
        m.count(
            "folds",
            self.total_instances.saturating_sub(1).div_ceil(batch) as u64,
        );
        m.count("fresh_per_full_fold", batch as u64);
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
    fn warp_batch_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 2,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
            total_instances: None,
            total_step_circuits: None,
        };
        let s = WarpBatch::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
