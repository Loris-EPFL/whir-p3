//! Path B from compare_bench: Poseidon2 recursive union fold (l=arity).
//!
//! Each IVC step builds a recursive circuit (step computation + Poseidon2
//! fold verifier), Spartan-proves it, then union-folds at the configured arity.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use warp::decider::warp_decide_algebraic_rs;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::{
        compute_recursive_circuit_size_union, warp_ivc_init_recursive_union,
        warp_ivc_step_recursive_union, WarpIVCConfig, WarpIVCState,
    },
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{
        make_challenger, make_hc, make_poseidon2_circuit_config, produce_synthetic_r1cs, EF, F,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct QuasarWarp {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    ivc_steps: usize,
    arity: usize,
    step_muls: usize,
}

impl FoldingScheme for QuasarWarp {
    const NAME: &'static str = "quasar_warp";
    type Proof = WarpIVCState<F>;

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
        let (poseidon_perm, poseidon_config) = make_poseidon2_circuit_config();
        let make_fold_chal = {
            let p = poseidon_perm.clone();
            move || crate::fixtures::MyChallenger::new(p.clone())
        };

        let step = WorkloadStepCircuit::new(self.step_muls);
        let step_input = [F::ZERO];

        let log_m = self
            .shape
            .num_cons()
            .next_power_of_two()
            .trailing_zeros() as usize;
        let (target_w, _, _) = compute_recursive_circuit_size_union::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            _,
        >(
            &step,
            &step_input,
            &poseidon_config,
            &poseidon_perm,
            self.shape.num_poly_vars_y(),
            self.arity,
            log_m,
        );

        let circuit_constraints_cell = {
            let (_, c, _) = compute_recursive_circuit_size_union::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
            >(
                &step,
                &step_input,
                &poseidon_config,
                &poseidon_perm,
                self.shape.num_poly_vars_y(),
                self.arity,
                log_m,
            );
            c as u64
        };
        m.count("circuit_constraints", circuit_constraints_cell);

        let state = m.time("prove_total", || {
            let mut spartan_ch = make_challenger(100);
            let mut state = warp_ivc_init_recursive_union::<
                F,
                EF,
                _,
                _,
                _,
                _,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
                _,
            >(
                &self.shape,
                &self.instance,
                &mut spartan_ch,
                &self.ivc_config,
                &dft,
                mh.clone(),
                mc.clone(),
                &poseidon_config,
                &poseidon_perm,
                &step,
                &step_input,
                self.arity,
                vec![],
                make_fold_chal.clone(),
            );

            let circuits_per_step = self.arity - 1;
            let num_ivc_steps = self.ivc_steps / circuits_per_step;

            for s in 0..num_ivc_steps {
                let step_inputs: Vec<Vec<F>> = (0..circuits_per_step)
                    .map(|i| vec![F::from_u64(s as u64 * 10 + i as u64)])
                    .collect();
                let mut ch = make_challenger(s as u64 + 200);
                state = warp_ivc_step_recursive_union::<
                    F,
                    EF,
                    _,
                    _,
                    _,
                    _,
                    GenericPoseidon2LinearLayersKoalaBear,
                    _,
                    _,
                    _,
                >(
                    &state,
                    &step,
                    &step_inputs,
                    self.arity,
                    &mut ch,
                    &self.ivc_config,
                    &dft,
                    mh.clone(),
                    mc.clone(),
                    &poseidon_config,
                    &poseidon_perm,
                    Some(target_w),
                    vec![],
                    make_fold_chal.clone(),
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
        let (_, c, _) = {
            let (perm, cfg) = crate::fixtures::make_poseidon2_circuit_config();
            let step = WorkloadStepCircuit::new(self.step_muls);
            let step_input = [F::ZERO];
            let log_m = self.shape.num_cons().next_power_of_two().trailing_zeros() as usize;
            compute_recursive_circuit_size_union::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
            >(
                &step,
                &step_input,
                &cfg,
                &perm,
                self.shape.num_poly_vars_y(),
                self.arity,
                log_m,
            )
        };
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
    fn quasar_warp_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 4,
            batch: 1,
            ivc_steps: 6,
            step_muls: 100,
            seed: 42,
        };
        let s = QuasarWarp::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
