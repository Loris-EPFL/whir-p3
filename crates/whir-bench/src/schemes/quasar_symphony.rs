use p3_challenger::CanSample;
use p3_field::PrimeCharacteristicRing;
use accumulation::{
    constraint_batch::constraint_batch_prove,
    linearized::linearized_statement_from_spartan_proof,
    random_lc::random_linear_combination,
};
use warp::accumulator::FreshInstance;
use whir_core::poly::evals::EvaluationsList;
use whir_ivc::warp_ivc::{warp_ivc_init_cp, warp_ivc_step_union_cp, WarpIVCConfig, WarpIVCStateCp};
use whir_spartan::{
    r1cs::{R1CSInstance, R1CSShape},
    r1cs_prover::R1CSProver,
};

use crate::{
    axes::Axes,
    fixtures::{
        make_challenger, make_hc, produce_synthetic_r1cs,
        EF, F,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct QuasarSymphony {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
    batch: usize,
}

impl FoldingScheme for QuasarSymphony {
    const NAME: &'static str = "quasar_symphony";
    type Proof = WarpIVCStateCp<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let ivc_config = WarpIVCConfig {
            fold_arity: 2,
            use_union: true,
            ..Default::default()
        };
        Self {
            shape,
            instance,
            ivc_config,
            ivc_steps: axes.ivc_steps,
            batch: axes.batch,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let (mh, mc) = make_hc();
        let spartan = R1CSProver::new();
        let make_fold_chal = || make_challenger(77);

        m.time("prove_total", || {
            let mut spartan_ch = make_challenger(1);
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

            let num_inputs = self.instance.input().len();
            let sample_w = spartan.prepare_witness(&self.instance);
            let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();

            for step in 0..self.ivc_steps {
                // 1. Spartan-prove + linearize all batch instances
                let mut witnesses = Vec::with_capacity(self.batch);
                let mut linears = Vec::with_capacity(self.batch);
                for j in 0..self.batch {
                    let mut ch = make_challenger(step as u64 * 100 + j as u64 + 200);
                    let proof = spartan.prove::<EF, _>(&self.instance, &mut ch);
                    let w = spartan.prepare_witness(&self.instance);
                    let l = linearized_statement_from_spartan_proof(
                        &self.shape,
                        &proof,
                        EF::from_u64(3),
                    );
                    witnesses.push(w);
                    linears.push(l);
                }

                // 2. Batch reduction: constraint_batch + random_lc
                let mut batch_chal = make_fold_chal();
                let gamma: F = batch_chal.sample();
                let eta: F = batch_chal.sample();

                let mut weights = Vec::with_capacity(self.batch);
                let mut targets = Vec::with_capacity(self.batch);
                for linear in &linears {
                    let (w, &t) = linear.iter().next().unwrap();
                    weights.push(w.clone());
                    targets.push(t);
                }

                let _ = constraint_batch_prove(
                    gamma,
                    &weights,
                    &targets,
                    &witnesses,
                    &mut make_challenger(step as u64 + 400),
                );

                let refs: Vec<&EvaluationsList<F>> = witnesses.iter().collect();
                let combined = random_linear_combination(&refs, eta);

                // 3. Build FreshInstance from reduced witness
                let cs = combined.as_slice();
                let pi = cs[..num_inputs].to_vec();
                let mut w = cs[num_inputs..].to_vec();
                w.resize(num_witness, F::ZERO);
                let fresh = vec![FreshInstance {
                    public_input: pi,
                    witness: w,
                }];

                // 4. Fold with CP-SNARK committed transcripts
                state = warp_ivc_step_union_cp::<F, _, _, _, _>(
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
        })
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        m.time("verify_total", || {
            whir_cp_snark::cp_snark_terminal_verify_with_merkle(
                &proof.shape,
                &proof.accumulator,
                &proof.committed_transcripts,
                || make_challenger(77),
                self.ivc_config.rs_folding_factor,
                &make_hc().0,
                &make_hc().1,
            )
            .map_err(|e| anyhow::anyhow!("CP-SNARK terminal verify failed: {e:?}"))
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
            arity: 2,
            batch: 4,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
        };
        let s = QuasarSymphony::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
