//! Non-union recursive fold-verifier circuit size at l=2 (Poseidon2 +
//! algebraic). The `_union` counterparts at l=2 save a fold-verifier
//! Poseidon2 absorb (see `circuit_size_arity`); this microbench measures
//! the non-union baseline for comparison.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use p3_poseidon2::poseidon2_round_numbers_128;
use rand::{SeedableRng, rngs::SmallRng};
use whir_circuit::poseidon2::Poseidon2CircuitConfig;
use whir_ivc::{step::WorkloadStepCircuit, warp_ivc::compute_recursive_circuit_size};

use crate::{
    fixtures::{F, Perm},
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct CircuitSizesL2;

impl Microbench for CircuitSizesL2 {
    const NAME: &'static str = "circuit_sizes_l2";

    fn run(_axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        let step_dummy = WorkloadStepCircuit::new(100);
        let step_input_dummy = [F::ZERO];

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) =
            poseidon2_round_numbers_128::<F>(16, 3).expect("unsupported Poseidon2 parameters");
        let config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(rf, rp, 3, &mut SmallRng::seed_from_u64(99));

        let (w_p, c_p, _) = compute_recursive_circuit_size::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            _,
        >(&step_dummy, &step_input_dummy, &config, &perm, 5, 4);

        let mut rows = vec![
            MicrobenchRow::new(Self::NAME)
                .with_axis("variant", "poseidon2_non_union_l2")
                .with_value("constraints", c_p)
                .with_value("witness_vars", w_p),
        ];

        #[cfg(feature = "symphony")]
        {
            use whir_ivc::warp_fold_verifier_algebraic::compute_cp_circuit_size;
            let (w_a, c_a, _) = compute_cp_circuit_size(&step_dummy, &step_input_dummy);
            rows.push(
                MicrobenchRow::new(Self::NAME)
                    .with_axis("variant", "algebraic_non_union_l2")
                    .with_value("constraints", c_a)
                    .with_value("witness_vars", w_a),
            );
        }
        rows
    }
}
