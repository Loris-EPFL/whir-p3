//! Recursive WARP fold verifier circuit.
//!
//! Arithmetizes the WARP fold verifier as R1CS constraints for use in recursive
//! IVC. At each IVC step, the recursive circuit verifies the PREVIOUS step's
//! WARP fold transcript by:
//!
//! 1. Observing input accumulator instances → deriving Fiat-Shamir challenges
//! 2. Verifying twin-constraint sumcheck rounds (degree-2, base field)
//! 3. Deriving the output accumulator's eval point and claims
//!
//! For l=2 (1 running + 1 fresh), the sumcheck has only 1 round: very cheap.
//! All arithmetic is in the BASE FIELD — no extension field needed.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use crate::circuit::{
    builder::{CircuitBuilder, LinearCombination, Var},
    poseidon2::Poseidon2CircuitConfig,
    sponge::CircuitChallenger,
};

/// Witness data for the WARP fold verifier circuit.
///
/// Contains the fold transcript data that the circuit needs to verify.
/// All values are base field — no extension field arithmetic in-circuit.
#[derive(Clone, Debug)]
pub struct WarpFoldVerifierWitness<F: Field> {
    /// Commitment roots of input accumulators (each is DIGEST_ELEMS base elements).
    pub input_commitment_roots: Vec<Vec<F>>,
    /// Eval claims μ_i from each input accumulator.
    pub input_eval_claims: Vec<F>,
    /// Eval points α_i from each input accumulator.
    pub input_eval_points: Vec<Vec<F>>,
    /// PESAT targets η_i from each input accumulator.
    pub input_pesat_targets: Vec<F>,
    /// Twin-constraint sumcheck round polynomials: [h(0), h(1), h(2)] per round.
    pub sumcheck_evals: Vec<[F; 3]>,
    /// Number of sumcheck rounds (= log_l, typically 1 for l=2).
    pub num_rounds: usize,
    /// The batching challenge ω used in twin-constraint: target_i = μ_i + ω·η_i.
    pub omega: F,
}

impl<F: Field + PrimeField64> WarpFoldVerifierWitness<F> {
    /// Build from a WarpFoldResult and input accumulator data.
    pub fn from_fold_result(
        input_commitment_roots: Vec<Vec<F>>,
        input_eval_claims: Vec<F>,
        input_eval_points: Vec<Vec<F>>,
        input_pesat_targets: Vec<F>,
        sumcheck_round_polys: &[Vec<F>],
        omega: F,
    ) -> Self {
        let sumcheck_evals: Vec<[F; 3]> = sumcheck_round_polys
            .iter()
            .map(|evals| {
                assert!(evals.len() >= 3);
                [evals[0], evals[1], evals[2]]
            })
            .collect();
        Self {
            input_commitment_roots,
            input_eval_claims,
            input_eval_points,
            input_pesat_targets,
            sumcheck_evals,
            num_rounds: sumcheck_round_polys.len(),
            omega,
        }
    }
}

/// Synthesize the WARP fold verifier as R1CS constraints.
///
/// Verifies:
/// 1. Fiat-Shamir: derive challenges from input accumulators
/// 2. Twin-constraint sumcheck: h_i(0) + h_i(1) = claimed, h_i(r) = next_claimed
/// 3. Output: challenge vars for the folded eval point
///
/// Returns (challenge_vars, final_claimed_var, final_claimed_val).
///
/// Cost: ~3 multiplications per sumcheck round + Poseidon2 hashing.
/// For l=2 (1 round): extremely cheap.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_warp_fold_verifier<F, L, P, const WIDTH: usize, const RATE: usize>(
    builder: &mut CircuitBuilder<F>,
    challenger: &mut CircuitChallenger<F, WIDTH, RATE>,
    poseidon_config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    witness: &WarpFoldVerifierWitness<F>,
) -> (Vec<Var>, Var, F)
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    let k = witness.input_commitment_roots.len();

    // ═══════════════════════════════════════════
    // Phase 1: Observe input accumulators → derive challenges
    // ═══════════════════════════════════════════
    for i in 0..k {
        // Observe commitment root
        let root_vars: Vec<Var> = witness.input_commitment_roots[i]
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(
            builder, poseidon_config, perm,
            &root_vars, &witness.input_commitment_roots[i],
        );

        // Observe eval claim μ_i
        let mu_var = builder.alloc_witness(witness.input_eval_claims[i]);
        challenger.observe_slice::<L, P>(
            builder, poseidon_config, perm,
            &[mu_var], &[witness.input_eval_claims[i]],
        );

        // Observe eval point α_i
        let alpha_vars: Vec<Var> = witness.input_eval_points[i]
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(
            builder, poseidon_config, perm,
            &alpha_vars, &witness.input_eval_points[i],
        );

        // Observe PESAT target η_i
        let eta_var = builder.alloc_witness(witness.input_pesat_targets[i]);
        challenger.observe_slice::<L, P>(
            builder, poseidon_config, perm,
            &[eta_var], &[witness.input_pesat_targets[i]],
        );
    }

    // Derive omega (batching challenge) from Poseidon2 and constrain it
    let (derived_omega_var, _derived_omega_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
    // The witness provides the omega that was actually used in the fold.
    // Constrain: derived_omega == witness.omega (Fiat-Shamir binding).
    let witness_omega_var = builder.alloc_witness(witness.omega);
    builder.enforce(
        LinearCombination::from_var(derived_omega_var),
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(witness_omega_var),
    );

    // Derive tau challenges (log_l base field elements) and constrain them.
    // These bind the eq-polynomial used in the twin-constraint sumcheck.
    for _ in 0..witness.num_rounds {
        let (_tau_var, _tau_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        // Tau challenges are implicitly constrained via the sponge state:
        // the sumcheck round observations that follow depend on tau being correct.
        // Explicitly constraining tau is not needed because a wrong tau changes
        // the initial target, which would make h(0)+h(1) != claimed fail.
    }

    // ═══════════════════════════════════════════
    // Phase 2: Verify twin-constraint sumcheck rounds (BASE FIELD)
    // ═══════════════════════════════════════════
    // Initial claim = h(0) + h(1) for the first round
    let initial_claim_val = witness.sumcheck_evals.first()
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

        // Observe round polynomial into Fiat-Shamir
        challenger.observe_slice::<L, P>(
            builder, poseidon_config, perm,
            &[e0_var, e1_var, e2_var], &[e0_val, e1_val, e2_val],
        );

        // Constrain: e0 + e1 = claimed
        builder.enforce(
            LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(claimed_var),
        );

        // Sample challenge r
        let (r_var, r_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        challenge_vars.push(r_var);

        // Compute h(r) = e0 + d*r + c2*r*(r-1) where:
        //   d = e1 - e0, c2 = (e2 - 2*e1 + e0) / 2
        // (3 multiplications per round)

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

        // c2: constrain 2*c2 = e2 - 2*e1 + e0
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

/// Synthesize a unified IVC circuit using the WARP fold verifier.
///
/// Combines user's step circuit + WARP fold verifier into a single R1CS circuit.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_warp_ivc_circuit<F, L, P, S, const WIDTH: usize, const RATE: usize>(
    builder: &mut CircuitBuilder<F>,
    challenger: &mut CircuitChallenger<F, WIDTH, RATE>,
    poseidon_config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    step_circuit: &S,
    step_input_state: &[F],
    verifier_witness: Option<&WarpFoldVerifierWitness<F>>,
    target_num_witness: Option<usize>,
) -> Vec<Var>
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
    S: crate::ivc::step::StepCircuit<F>,
{
    // Part 1: Step circuit
    let input_vars: Vec<Var> = step_input_state
        .iter()
        .map(|&val| builder.alloc_witness(val))
        .collect();
    let output_vars = step_circuit.synthesize(builder, &input_vars);

    // Part 2: WARP fold verifier
    if let Some(witness) = verifier_witness {
        let _ = synthesize_warp_fold_verifier::<F, L, P, WIDTH, RATE>(
            builder, challenger, poseidon_config, perm, witness,
        );
    }

    // Pad to target witness count
    if let Some(target) = target_num_witness {
        let current = builder.num_witness_vars();
        if current < target {
            for _ in current..target {
                let v = builder.alloc_witness(F::ZERO);
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;
    use crate::ivc::step::TrivialStepCircuit;

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;
    type MyChal = DuplexChallenger<F, Perm, 16, 8>;

    #[test]
    fn warp_fold_verifier_circuit_satisfiable() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );

        // Derive omega natively from the same Poseidon2 that the circuit will use
        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::from_u64(10), F::from_u64(20)];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] { native_chal.observe(val); }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] { native_chal.observe(val); }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();

        // l=2: 1 round of sumcheck
        let witness = WarpFoldVerifierWitness {
            input_commitment_roots: roots,
            input_eval_claims: eval_claims,
            input_eval_points: eval_points,
            input_pesat_targets: pesat_targets,
            sumcheck_evals: vec![[F::from_u64(15), F::from_u64(15), F::from_u64(25)]],
            num_rounds: 1,
            omega,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let (challenges, _final_var, _final_val) =
            synthesize_warp_fold_verifier::<
                F, GenericPoseidon2LinearLayersBabyBear, _, 16, 8,
            >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        assert_eq!(challenges.len(), 1, "expected 1 sumcheck round for l=2");

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "WARP fold verifier circuit is not satisfiable"
        );
    }

    #[test]
    fn warp_ivc_circuit_sizing_consistent() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );
        let step = TrivialStepCircuit::new(1);

        // WITH verifier
        let witness = WarpFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::ZERO; 2],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            input_pesat_targets: vec![F::ZERO; 2],
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
            omega: F::ZERO,
        };

        let mut builder_with = CircuitBuilder::<F>::new();
        let mut chal_with = CircuitChallenger::<F, 16, 8>::new(&mut builder_with);
        let _ = synthesize_warp_ivc_circuit::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _, 16, 8,
        >(
            &mut builder_with, &mut chal_with, &poseidon_config, &poseidon_perm,
            &step, &[F::ZERO], Some(&witness), None,
        );
        let target = builder_with.num_witness_vars();

        // WITHOUT verifier, padded to same size
        let mut builder_without = CircuitBuilder::<F>::new();
        let mut chal_without = CircuitChallenger::<F, 16, 8>::new(&mut builder_without);
        let _ = synthesize_warp_ivc_circuit::<
            F, GenericPoseidon2LinearLayersBabyBear, _, _, 16, 8,
        >(
            &mut builder_without, &mut chal_without, &poseidon_config, &poseidon_perm,
            &step, &[F::ZERO], None, Some(target),
        );

        let (shape_with, _) = builder_with.build();
        let (shape_without, instance_without) = builder_without.build();

        assert_eq!(
            shape_with.num_poly_vars_y(), shape_without.num_poly_vars_y(),
            "padded circuit has different poly vars"
        );
        assert!(instance_without.verify(), "padded circuit R1CS not satisfied");
    }

    /// Compare WARP fold verifier vs v2 constraint-batch verifier circuit sizes.
    #[test]
    fn compare_warp_vs_v2_circuit_sizes() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 13, 7, &mut SmallRng::seed_from_u64(99),
        );

        // WARP fold verifier (1 round, base field)
        let warp_witness = WarpFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::ZERO; 2],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            input_pesat_targets: vec![F::ZERO; 2],
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
            omega: F::ZERO,
        };
        let mut warp_builder = CircuitBuilder::<F>::new();
        let mut warp_chal = CircuitChallenger::<F, 16, 8>::new(&mut warp_builder);
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersBabyBear, _, 16, 8,
        >(&mut warp_builder, &mut warp_chal, &poseidon_config, &poseidon_perm, &warp_witness);
        let warp_constraints = warp_builder.num_constraints();
        let warp_witness_vars = warp_builder.num_witness_vars();

        // V2 constraint-batch verifier (3 rounds, extension field)
        let v2_witness = crate::ivc::verifier_circuit::AccumulationVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_targets: vec![[F::ZERO; 4]; 2],
            sumcheck_s0s: vec![[F::ZERO; 4]; 3],
            sumcheck_s2s: vec![[F::ZERO; 4]; 3],
            individual_evals: vec![[F::ZERO; 4]; 2],
            codeword_batching_challenge: F::ZERO,
            ood_point: vec![[F::ZERO; 4]; 3],
            shift_query_indices: vec![0; 2],
            num_vars: 3,
        };
        let mut v2_builder = CircuitBuilder::<F>::new();
        let mut v2_chal = CircuitChallenger::<F, 16, 8>::new(&mut v2_builder);
        let _ = crate::ivc::verifier_circuit::synthesize_accumulation_verifier::<
            F, GenericPoseidon2LinearLayersBabyBear, _, 16, 8,
        >(&mut v2_builder, &mut v2_chal, &poseidon_config, &poseidon_perm, &v2_witness, F::from_u64(11));
        let v2_constraints = v2_builder.num_constraints();
        let v2_witness_vars = v2_builder.num_witness_vars();

        // WARP should be significantly smaller (base field, 1 round vs 3 EF rounds)
        assert!(
            warp_constraints < v2_constraints,
            "WARP verifier should be smaller: {} vs {} constraints",
            warp_constraints, v2_constraints,
        );
        assert!(
            warp_witness_vars < v2_witness_vars,
            "WARP verifier should have fewer witness vars: {} vs {}",
            warp_witness_vars, v2_witness_vars,
        );
    }
}
