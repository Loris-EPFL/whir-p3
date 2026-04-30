//! In-circuit verifier size sweep vs arity — Quasar's asymptotic payoff.
//!
//! For each `arity`, compute the unified-circuit constraint count the prover
//! must Spartan-prove at every IVC step, under four variants:
//!   - `poseidon2_standard` — non-union, absorbs ℓ Merkle roots in-circuit.
//!     Grows **linearly** in ℓ (dominated by ℓ Poseidon2 compressions).
//!   - `poseidon2_union`    — Quasar union, absorbs 1 union root in-circuit.
//!     Grows **sub-linearly** (~ℓ^0.67): the ℓ→1 saving appears here.
//!   - `algebraic_standard` — non-union algebraic (CP-SNARK) verifier.
//!     Only with `symphony` feature. Hash absorption is deferred to terminal,
//!     so the in-circuit cost is essentially identical to the union variant —
//!     Quasar's algebraic win lives at terminal, not in the recursive circuit.
//!   - `algebraic_union`    — Quasar algebraic variant (symphony feature).
//!     Grows **+8 constraints per arity doubling** (pure O(log ℓ)).
//!
//! The apples-to-apples Quasar-vs-non-Quasar comparison lives in the
//! `poseidon2_standard` vs `poseidon2_union` pair: at ℓ=64 standard absorbs
//! ~64× more roots than union, so the slopes diverge sharply.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use p3_poseidon2::poseidon2_round_numbers_128;
use rand::{SeedableRng, rngs::SmallRng};
use whir_circuit::poseidon2::Poseidon2CircuitConfig;
use whir_ivc::{
    step::WorkloadStepCircuit,
    warp_ivc::{compute_recursive_circuit_size_standard, compute_recursive_circuit_size_union},
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
        let (rf, rp) =
            poseidon2_round_numbers_128::<F>(16, 3).expect("unsupported Poseidon2 parameters");
        let config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(rf, rp, 3, &mut SmallRng::seed_from_u64(99));

        let mut rows = Vec::new();
        for &arity in &axes.arity {
            // Non-union Poseidon2 — absorbs ℓ roots in-circuit (linear in ℓ).
            let (w_ps, c_ps, _) =
                compute_recursive_circuit_size_standard::<
                    F,
                    GenericPoseidon2LinearLayersKoalaBear,
                    _,
                    _,
                >(&step_dummy, &step_input_dummy, &config, &perm, 5, arity, 4);
            rows.push(
                MicrobenchRow::new(Self::NAME)
                    .with_axis("arity", arity)
                    .with_axis("variant", "poseidon2_standard")
                    .with_value("constraints", c_ps)
                    .with_value("witness_vars", w_ps),
            );

            // Union Poseidon2 — absorbs 1 union root (sub-linear in ℓ).
            let (w_p, c_p, _) =
                compute_recursive_circuit_size_union::<
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
                // Union algebraic (defers hashes to terminal) — O(log ℓ).
                let (w_a, c_a, _) =
                    compute_recursive_union_circuit_size(&step_dummy, &step_input_dummy, arity);
                rows.push(
                    MicrobenchRow::new(Self::NAME)
                        .with_axis("arity", arity)
                        .with_axis("variant", "algebraic_union")
                        .with_value("constraints", c_a)
                        .with_value("witness_vars", w_a),
                );

                // Non-union algebraic — modelled as ℓ-1 pairwise l=2 algebraic
                // folds chained together. In the `symphony` (no-union)
                // pipeline, folding ℓ instances into one accumulator without
                // the multicast structure requires ℓ-1 sequential fold steps,
                // each of which runs one round of the algebraic twin-constraint
                // sumcheck. Approximate the in-circuit cost by (ℓ-1) × the
                // l=2 algebraic verifier. This yields linear scaling vs. the
                // log-scaling union variant.
                let pairs = arity.saturating_sub(1).max(1);
                let (w_a1, c_a1, _) =
                    compute_recursive_union_circuit_size(&step_dummy, &step_input_dummy, 2);
                rows.push(
                    MicrobenchRow::new(Self::NAME)
                        .with_axis("arity", arity)
                        .with_axis("variant", "algebraic_standard")
                        .with_value("constraints", c_a1 * pairs)
                        .with_value("witness_vars", w_a1 * pairs),
                );
            }
        }
        rows
    }
}
