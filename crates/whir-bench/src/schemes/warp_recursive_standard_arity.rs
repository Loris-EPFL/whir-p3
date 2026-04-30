//! Recursive Family B same-arity baseline: Poseidon2 verifier, standard WARP.
//!
//! This is the non-Quasar counterpart of `quasar_warp`: each fold absorbs
//! `arity - 1` recursive step-circuit proofs, but the verifier sees every
//! fresh commitment root individually instead of a single union root.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::{
        WarpIVCConfig, WarpIVCState, compute_recursive_circuit_size_standard,
        warp_ivc_init_recursive_standard_arity, warp_ivc_step_recursive_standard_arity,
    },
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{
        EF, F, make_challenger, make_hc, make_poseidon2_circuit_config, produce_synthetic_r1cs,
        verify_full_warp_terminal_measured,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct WarpRecursiveStandardArity {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    ivc_config: WarpIVCConfig,
    total_step_circuits: usize,
    arity: usize,
    step_muls: usize,
}

impl FoldingScheme for WarpRecursiveStandardArity {
    const NAME: &'static str = "warp_recursive_standard_arity";
    type Proof = WarpIVCState<F>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let arity = axes.arity.max(2);
        let ivc_config = WarpIVCConfig {
            fold_arity: arity,
            use_union: false,
            ..Default::default()
        };
        Self {
            shape,
            instance,
            ivc_config,
            total_step_circuits: axes.total_step_circuits.unwrap_or(axes.ivc_steps).max(1),
            arity,
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
        let log_m = self.shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        let (target_w, circuit_constraints, _) = compute_recursive_circuit_size_standard::<
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
        m.count("circuit_constraints", circuit_constraints as u64);

        let state = m.time("prove_total", || {
            let mut spartan_ch = make_challenger(100);
            let mut state = warp_ivc_init_recursive_standard_arity::<
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
            let num_ivc_steps = self.total_step_circuits.div_ceil(circuits_per_step);
            for s in 0..num_ivc_steps {
                let step_inputs: Vec<Vec<F>> = (0..circuits_per_step)
                    .map(|i| {
                        let global = s * circuits_per_step + i;
                        if global < self.total_step_circuits {
                            vec![F::from_u64(global as u64)]
                        } else {
                            vec![F::ZERO]
                        }
                    })
                    .collect();
                let mut ch = make_challenger(s as u64 + 200);
                state = warp_ivc_step_recursive_standard_arity::<
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

        let circuits_per_step = self.arity - 1;
        let folds = self.total_step_circuits.div_ceil(circuits_per_step);
        let padded = folds * circuits_per_step - self.total_step_circuits;
        m.count("total_instances", self.total_step_circuits as u64);
        m.count("total_step_circuits", self.total_step_circuits as u64);
        m.count(
            "target_total_step_circuits",
            self.total_step_circuits as u64,
        );
        m.count("padding_step_circuits", padded as u64);
        m.count("folds", folds as u64);
        m.count("fresh_per_full_fold", circuits_per_step as u64);
        m.count("family_b", 1);
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
        let (perm, cfg) = crate::fixtures::make_poseidon2_circuit_config();
        let step = WorkloadStepCircuit::new(self.step_muls);
        let step_input = [F::ZERO];
        let log_m = self.shape.num_cons().next_power_of_two().trailing_zeros() as usize;
        let (_, c, _) = compute_recursive_circuit_size_standard::<
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
        );
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
    fn warp_recursive_standard_arity_prove_verify() {
        let axes = Axes {
            log_n: 8,
            arity: 4,
            batch: 1,
            ivc_steps: 1,
            step_muls: 8,
            seed: 42,
            total_instances: None,
            total_step_circuits: Some(3),
        };
        let s = WarpRecursiveStandardArity::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
