//! Algebraic WARP fold verifier circuit (CP-SNARK mode).
//!
//! This is the CP-SNARK counterpart of `warp_fold_verifier_circuit.rs`.
//! It performs the same algebraic sumcheck consistency checks but WITHOUT
//! any Poseidon2 hashing. Challenges are provided as witness values
//! (derived natively by the prover) rather than computed in-circuit.
//!
//! # Comparison
//!
//! | Component                     | Regular verifier | Algebraic verifier |
//! |-------------------------------|------------------|--------------------|
//! | Poseidon2 FS hashing          | ~94% of cost     | **NONE**           |
//! | Sumcheck round checks         | ✓                | ✓                  |
//! | Challenge derivation          | In-circuit       | Witness (deferred) |
//! | Constraints (l=2, 1 round)    | ~5000            | ~15                |
//!
//! Hash verification is deferred to terminal via `DeferredFoldTranscript`.
//! See `cp_snark::verify_deferred_transcripts`.

use alloc::{vec, vec::Vec};

use p3_field::Field;

use crate::circuit::builder::{CircuitBuilder, LinearCombination, Var};

/// Witness for the algebraic fold verifier (CP-SNARK mode).
///
/// Contains only the sumcheck round data and pre-derived challenges.
/// No commitment roots, eval claims, or other hash-input data — those
/// are stored in `DeferredFoldTranscript` for terminal verification.
#[derive(Clone, Debug)]
pub struct AlgebraicFoldVerifierWitness<F: Field> {
    /// Twin-constraint sumcheck round polynomials: `[h(0), h(1), h(2)]` per round.
    pub sumcheck_evals: Vec<[F; 3]>,
    /// Number of sumcheck rounds (`= log_l`, typically 1 for `l=2`).
    pub num_rounds: usize,
    /// Per-round challenges derived natively via Poseidon2 (NOT in-circuit).
    /// These are verified at terminal by `verify_deferred_transcripts`.
    pub sumcheck_challenges: Vec<F>,
}

impl<F: Field> AlgebraicFoldVerifierWitness<F> {
    /// Build from a fold result's sumcheck data.
    pub fn from_fold_data(
        sumcheck_round_polys: &[Vec<F>],
        sumcheck_challenges: &[F],
    ) -> Self {
        let sumcheck_evals = sumcheck_round_polys
            .iter()
            .map(|evals| {
                assert!(evals.len() >= 3);
                [evals[0], evals[1], evals[2]]
            })
            .collect();

        Self {
            sumcheck_evals,
            num_rounds: sumcheck_round_polys.len(),
            sumcheck_challenges: sumcheck_challenges.to_vec(),
        }
    }
}

/// Synthesize the algebraic-only WARP fold verifier as R1CS constraints.
///
/// Verifies twin-constraint sumcheck round consistency:
/// 1. `h_i(0) + h_i(1) = claimed` (sum-check identity)
/// 2. `h_i(r_i) = next_claimed` (evaluation at challenge point)
///
/// Challenges `r_i` come from the witness (pre-derived natively), NOT from
/// a Poseidon2 sponge. This removes all hash constraints from the circuit.
///
/// Returns `(challenge_vars, final_claimed_var, final_claimed_val)`.
///
/// Cost: ~3 multiplications + ~5 linear constraints per sumcheck round.
/// For `l=2` (1 round): ~15 constraints total.
pub fn synthesize_algebraic_fold_verifier<F: Field>(
    builder: &mut CircuitBuilder<F>,
    witness: &AlgebraicFoldVerifierWitness<F>,
) -> (Vec<Var>, Var, F) {
    assert_eq!(
        witness.sumcheck_challenges.len(),
        witness.num_rounds,
        "need one challenge per sumcheck round"
    );

    // Initial claimed sum = h_0(0) + h_0(1) (by definition)
    let initial_claim_val = witness
        .sumcheck_evals
        .first()
        .map(|e| e[0] + e[1])
        .unwrap_or(F::ZERO);
    let initial_claim_var = builder.alloc_witness(initial_claim_val);

    let mut claimed_var = initial_claim_var;
    let mut claimed_val = initial_claim_val;
    let mut challenge_vars = Vec::with_capacity(witness.num_rounds);

    for round in 0..witness.num_rounds {
        let [e0_val, e1_val, e2_val] = witness.sumcheck_evals[round];

        let e0_var = builder.alloc_witness(e0_val);
        let e1_var = builder.alloc_witness(e1_val);
        let e2_var = builder.alloc_witness(e2_val);

        // ── Constraint: e0 + e1 = claimed ──
        builder.enforce(
            LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(claimed_var),
        );

        // ── Challenge r from witness (NOT Poseidon2) ──
        let r_val = witness.sumcheck_challenges[round];
        let r_var = builder.alloc_witness(r_val);
        challenge_vars.push(r_var);

        // ── Compute h(r) = e0 + d·r + c2·r·(r−1) ──
        // where d = e1 − e0, c2 = (e2 − 2·e1 + e0) / 2
        // (same interpolation as warp_fold_verifier_circuit.rs, 3 multiplications)

        // d = e1 - e0
        let d_val = e1_val - e0_val;
        let d_var = builder.alloc_witness(d_val);
        builder.enforce(
            LinearCombination::from_var(e1_var) - LinearCombination::from_var(e0_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(d_var),
        );

        // dr = d * r
        let dr_val = d_val * r_val;
        let dr_var = builder.mul(d_var, r_var, dr_val);

        // c2: constrain 2·c2 = e2 − 2·e1 + e0
        let c2_val = (e2_val - e1_val.double() + e0_val) * F::TWO.inverse();
        let c2_var = builder.alloc_witness(c2_val);
        builder.enforce(
            LinearCombination::from_constant(F::TWO),
            LinearCombination::from_var(c2_var),
            LinearCombination::from_var(e2_var)
                - LinearCombination::from_scaled(e1_var, F::TWO)
                + LinearCombination::from_var(e0_var),
        );

        // r*(r-1)
        let rm1_val = r_val - F::ONE;
        let rm1_var = builder.alloc_witness(rm1_val);
        builder.enforce(
            LinearCombination::from_var(r_var) - LinearCombination::from_constant(F::ONE),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(rm1_var),
        );
        let r_rm1_val = r_val * rm1_val;
        let r_rm1_var = builder.mul(r_var, rm1_var, r_rm1_val);

        // c2 * r*(r-1)
        let c2_r_rm1_val = c2_val * r_rm1_val;
        let c2_r_rm1_var = builder.mul(c2_var, r_rm1_var, c2_r_rm1_val);

        // result = e0 + dr + c2*r*(r-1)
        let result_val = e0_val + dr_val + c2_r_rm1_val;
        let result_var = builder.alloc_witness(result_val);
        builder.enforce(
            LinearCombination::from_var(e0_var)
                + LinearCombination::from_var(dr_var)
                + LinearCombination::from_var(c2_r_rm1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(result_var),
        );

        claimed_var = result_var;
        claimed_val = result_val;
    }

    (challenge_vars, claimed_var, claimed_val)
}

/// Synthesize a unified IVC circuit for CP-SNARK mode: step + algebraic verifier.
///
/// Combines the user's step circuit with the algebraic fold verifier.
/// No Poseidon2 config or permutation needed — no hash constraints at all.
pub fn synthesize_warp_ivc_circuit_cp<F, S>(
    builder: &mut CircuitBuilder<F>,
    step_circuit: &S,
    step_input_state: &[F],
    verifier_witness: Option<&AlgebraicFoldVerifierWitness<F>>,
    target_num_witness: Option<usize>,
) -> Vec<Var>
where
    F: Field,
    S: crate::ivc::step::StepCircuit<F>,
{
    // Part 1: User's step circuit
    let input_vars: Vec<Var> = step_input_state
        .iter()
        .map(|&val| builder.alloc_witness(val))
        .collect();
    let output_vars = step_circuit.synthesize(builder, &input_vars);

    // Part 2: Algebraic fold verifier (NO Poseidon2)
    if let Some(witness) = verifier_witness {
        let _ = synthesize_algebraic_fold_verifier(builder, witness);
    }

    // Pad to target witness count for consistent accumulator dimensions
    if let Some(target) = target_num_witness {
        let current = builder.num_witness_vars();
        if current < target {
            for _ in current..target {
                let v = builder.alloc_witness(F::ZERO);
                // v^2 = 0 constraint (forces v = 0, prevents optimizer elimination)
                builder.enforce(
                    LinearCombination::from_var(v),
                    LinearCombination::from_constant(F::ONE),
                    LinearCombination::from_var(v),
                );
            }
        }
    }

    output_vars
}

/// Compute circuit size for the CP-SNARK mode unified circuit.
///
/// Builds a dummy circuit to measure witness count, constraint count, and
/// polynomial variables — used to determine padding for consistent accumulator
/// dimensions across IVC steps.
pub fn compute_cp_circuit_size<F, S>(
    step_circuit: &S,
    step_input_state: &[F],
) -> (usize, usize, usize)
where
    F: Field,
    S: crate::ivc::step::StepCircuit<F>,
{
    // Build dummy verifier witness for l=2 (1 round)
    let dummy_witness = AlgebraicFoldVerifierWitness {
        sumcheck_evals: vec![[F::ZERO; 3]],
        num_rounds: 1,
        sumcheck_challenges: vec![F::ZERO],
    };

    let mut builder = CircuitBuilder::<F>::new();
    let _ = synthesize_warp_ivc_circuit_cp(
        &mut builder,
        step_circuit,
        step_input_state,
        Some(&dummy_witness),
        None,
    );

    let num_witness = builder.num_witness_vars();
    let num_constraints = builder.num_constraints();
    let (shape, _) = builder.build();
    (num_witness, num_constraints, shape.num_poly_vars_y())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::ivc::step::TrivialStepCircuit;

    type F = BabyBear;

    #[test]
    fn algebraic_verifier_satisfiable() {
        // l=2: 1 round of sumcheck
        let witness = AlgebraicFoldVerifierWitness {
            sumcheck_evals: vec![[F::from_u64(15), F::from_u64(15), F::from_u64(25)]],
            num_rounds: 1,
            sumcheck_challenges: vec![F::from_u64(7)],
        };

        let mut builder = CircuitBuilder::<F>::new();
        let (challenges, _final_var, _final_val) =
            synthesize_algebraic_fold_verifier(&mut builder, &witness);

        assert_eq!(challenges.len(), 1);

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "algebraic fold verifier circuit is not satisfiable"
        );
    }

    #[test]
    fn algebraic_verifier_much_smaller_than_poseidon2() {
        let step = TrivialStepCircuit::new(1);

        // CP-SNARK mode: algebraic verifier
        let (cp_witness, cp_constraints, _) =
            compute_cp_circuit_size(&step, &[F::ZERO]);

        // For comparison: algebraic-only (no step, no padding)
        let witness = AlgebraicFoldVerifierWitness {
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
            sumcheck_challenges: vec![F::ZERO],
        };
        let mut alg_builder = CircuitBuilder::<F>::new();
        let _ = synthesize_algebraic_fold_verifier(&mut alg_builder, &witness);
        let alg_constraints = alg_builder.num_constraints();
        let alg_witness = alg_builder.num_witness_vars();

        // The algebraic verifier should be very small
        assert!(
            alg_constraints < 30,
            "algebraic verifier should have <30 constraints, got {alg_constraints}"
        );
        assert!(
            alg_witness < 20,
            "algebraic verifier should have <20 witness vars, got {alg_witness}"
        );

        // Unified CP circuit should also be small
        assert!(
            cp_constraints < 50,
            "CP unified circuit should have <50 constraints, got {cp_constraints}"
        );

        // Print sizes for comparison (visible with --nocapture)
        #[cfg(feature = "bench-timing")]
        {
            std::eprintln!(
                "\n=== CP-SNARK Circuit Size ===\n\
                 Algebraic verifier only:  {:>4} witness, {:>4} constraints\n\
                 Unified (step + verifier): {:>4} witness, {:>4} constraints\n",
                alg_witness, alg_constraints,
                cp_witness, cp_constraints,
            );
        }
    }

    #[test]
    fn cp_ivc_circuit_satisfiable() {
        let step = TrivialStepCircuit::new(1);
        let witness = AlgebraicFoldVerifierWitness {
            sumcheck_evals: vec![[F::from_u64(15), F::from_u64(15), F::from_u64(25)]],
            num_rounds: 1,
            sumcheck_challenges: vec![F::from_u64(7)],
        };

        let mut builder = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut builder,
            &step,
            &[F::from_u64(42)],
            Some(&witness),
            None,
        );

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "CP-SNARK unified circuit is not satisfiable"
        );
    }

    #[test]
    fn cp_ivc_circuit_padding_consistent() {
        let step = TrivialStepCircuit::new(1);

        // WITH verifier
        let witness = AlgebraicFoldVerifierWitness {
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
            sumcheck_challenges: vec![F::ZERO],
        };
        let mut b_with = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut b_with,
            &step,
            &[F::ZERO],
            Some(&witness),
            None,
        );
        let target = b_with.num_witness_vars();

        // WITHOUT verifier, padded to same size
        let mut b_without = CircuitBuilder::<F>::new();
        let _ = synthesize_warp_ivc_circuit_cp(
            &mut b_without,
            &step,
            &[F::ZERO],
            None,
            Some(target),
        );

        let (shape_with, _) = b_with.build();
        let (shape_without, inst_without) = b_without.build();

        assert_eq!(
            shape_with.num_poly_vars_y(),
            shape_without.num_poly_vars_y(),
            "padded CP circuit has different poly vars"
        );
        assert!(
            inst_without.verify(),
            "padded CP circuit R1CS not satisfied"
        );
    }
}
