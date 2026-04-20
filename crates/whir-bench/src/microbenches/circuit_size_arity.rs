//! In-circuit verifier size sweep vs arity — Quasar's asymptotic payoff.
//!
//! For each `arity`, compute constraint count for the unified circuit the
//! prover must Spartan-prove at every IVC step:
//!   - `poseidon2_union` — always present (default feature)
//!   - `algebraic_union` — only with `symphony` feature
//!
//! Algebraic union grows +8 constraints per arity doubling (pure O(log ℓ)).
//! Poseidon2 union grows ~1.5× per doubling (sub-linear but not log).

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use p3_poseidon2::poseidon2_round_numbers_128;
use rand::{rngs::SmallRng, SeedableRng};
use whir_circuit::poseidon2::Poseidon2CircuitConfig;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::compute_recursive_circuit_size_union,
};

use crate::{
    fixtures::{F, Perm},
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct CircuitSizeArity;

impl Microbench for CircuitSizeArity {
    const NAME: &'static str = "circuit_size_arity";

    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        let step_dummy = WorkloadStepCircuit::new(100);
        let step_input_dummy = [F::ZERO];

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            rf,
            rp,
            3,
            &mut SmallRng::seed_from_u64(99),
        );

        let mut rows = Vec::new();
        for &arity in &axes.arity {
            let (w_p, c_p, _) = compute_recursive_circuit_size_union::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
            >(&step_dummy, &step_input_dummy, &config, &perm, 5, arity, 4);
            rows.push(
                MicrobenchRow::new(Self::NAME)
                    .with_axis("arity", arity)
                    .with_axis("variant", "poseidon2_union")
                    .with_value("constraints", c_p)
                    .with_value("witness_vars", w_p),
            );

            #[cfg(feature = "symphony")]
            {
                use whir_ivc::warp_ivc::compute_recursive_union_circuit_size;
                let (w_a, c_a, _) =
                    compute_recursive_union_circuit_size(&step_dummy, &step_input_dummy, arity);
                rows.push(
                    MicrobenchRow::new(Self::NAME)
                        .with_axis("arity", arity)
                        .with_axis("variant", "algebraic_union")
                        .with_value("constraints", c_a)
                        .with_value("witness_vars", w_a),
                );
            }
        }
        rows
    }
}
