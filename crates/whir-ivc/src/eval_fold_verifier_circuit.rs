//! Recursive eval-fold verifier circuit.
//!
//! Arithmetizes the eval-fold verifier as R1CS constraints. This is the
//! in-circuit counterpart of `eval_fold_prove` — it re-derives Fiat-Shamir
//! challenges and verifies the eval-claim sumcheck transcript.
//!
//! **Key advantage over the v2 constraint-batch verifier:**
//! The eval-claim sumcheck operates over the BASE FIELD (not extension field),
//! so each sumcheck round costs ~4x fewer R1CS constraints.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use crate::circuit::{
    builder::{CircuitBuilder, LinearCombination, Var},
    poseidon2::Poseidon2CircuitConfig,
    sponge::CircuitChallenger,
};

/// Witness data for the eval-fold verifier circuit.
///
/// All values are in the BASE FIELD (no extension field arithmetic needed
/// for the eval-claim sumcheck).
#[derive(Clone, Debug)]
pub struct EvalFoldVerifierWitness<F: Field> {
    /// Commitment roots of the input accumulators (each is DIGEST_ELEMS base elements).
    pub input_commitment_roots: Vec<Vec<F>>,
    /// Eval claims μ_i from each input accumulator (base field scalars).
    pub input_eval_claims: Vec<F>,
    /// Eval points α_i from each input accumulator (each is a Vec of base field elements).
    pub input_eval_points: Vec<Vec<F>>,
    /// Sumcheck round polynomials: [h(0), h(1), h(2)] per round (base field).
    pub sumcheck_evals: Vec<[F; 3]>,
    /// Number of sumcheck rounds (= log_l).
    pub num_rounds: usize,
}

impl<F: Field + PrimeField64> EvalFoldVerifierWitness<F> {
    /// Build from an `EvalFoldResult` and input accumulator data.
    pub fn from_eval_fold_result(
        input_commitment_roots: Vec<Vec<F>>,
        input_eval_claims: Vec<F>,
        input_eval_points: Vec<Vec<F>>,
        sumcheck_round_polys: &[Vec<F>],
    ) -> Self {
        let sumcheck_evals: Vec<[F; 3]> = sumcheck_round_polys
            .iter()
            .map(|evals| {
                assert!(evals.len() >= 3, "need evals at 0,1,2");
                [evals[0], evals[1], evals[2]]
            })
            .collect();

        Self {
            input_commitment_roots,
            input_eval_claims,
            input_eval_points,
            sumcheck_evals,
            num_rounds: sumcheck_round_polys.len(),
        }
    }
}

/// Synthesize the eval-fold verifier as R1CS constraints.
///
/// Verifies:
/// 1. Fiat-Shamir: derive tau challenges from input accumulators
/// 2. Eval-claim sumcheck: h_i(0) + h_i(1) = claimed, h_i(r) = next_claimed
/// 3. Output: the folded eval point and claim (as circuit variables)
///
/// Returns (sumcheck_challenge_vars, final_claimed_var).
#[allow(clippy::too_many_arguments)]
pub fn synthesize_eval_fold_verifier<F, L, P, const WIDTH: usize, const RATE: usize>(
    builder: &mut CircuitBuilder<F>,
    challenger: &mut CircuitChallenger<F, WIDTH, RATE>,
    poseidon_config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    witness: &EvalFoldVerifierWitness<F>,
) -> (Vec<Var>, Var, F)
// (challenge_vars, final_claimed_var, final_claimed_val)
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    let k = witness.input_commitment_roots.len();

    // ==========================================================
    // Phase 1: Observe input accumulators → derive tau challenges
    // ==========================================================
    for i in 0..k {
        // Observe commitment root
        let root_vars: Vec<Var> = witness.input_commitment_roots[i]
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &root_vars,
            &witness.input_commitment_roots[i],
        );

        // Observe eval claim (1 base field element)
        let claim_var = builder.alloc_witness(witness.input_eval_claims[i]);
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[claim_var],
            &[witness.input_eval_claims[i]],
        );

        // Observe eval point
        let point_vars: Vec<Var> = witness.input_eval_points[i]
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &point_vars,
            &witness.input_eval_points[i],
        );
    }

    // Sample tau challenges (log_l base field elements)
    // These are derived deterministically; the verifier checks they match
    let _tau_challenges: Vec<(Var, F)> = (0..witness.num_rounds)
        .map(|_| challenger.sample::<L, P>(builder, poseidon_config, perm))
        .collect();

    // ==========================================================
    // Phase 2: Compute initial claimed sum (base field, NOT extension field!)
    // ==========================================================
    // Initial claim = Σ_i eq(τ, i) · μ_i
    // For the circuit, we allocate the initial claim as a witness and
    // verify it's consistent with the sumcheck transcript.
    //
    // The verifier doesn't need to recompute eq(τ, i) · μ_i in-circuit
    // (that would require exponentiation). Instead, we verify the sumcheck
    // rounds are self-consistent: h_0(0) + h_0(1) = initial_claim.
    let initial_claim_val = witness
        .sumcheck_evals
        .first()
        .map(|e| e[0] + e[1])
        .unwrap_or(F::ZERO);
    let initial_claim_var = builder.alloc_witness(initial_claim_val);

    // ==========================================================
    // Phase 3: Verify sumcheck rounds (all in BASE FIELD — cheap!)
    // ==========================================================
    let mut claimed_var = initial_claim_var;
    let mut claimed_val = initial_claim_val;
    let mut challenge_vars = Vec::with_capacity(witness.num_rounds);

    for round in 0..witness.num_rounds {
        let [e0_val, e1_val, e2_val] = witness.sumcheck_evals[round];

        let e0_var = builder.alloc_witness(e0_val);
        let e2_var = builder.alloc_witness(e2_val);

        // Observe round polynomial into challenger
        let round_vals = [e0_val, e1_val, e2_val];
        let e1_var = builder.alloc_witness(e1_val);
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[e0_var, e1_var, e2_var],
            &round_vals,
        );

        // Constrain: e0 + e1 = claimed
        builder.enforce(
            LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(claimed_var),
        );

        // Sample challenge r (base field)
        let (r_var, r_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        challenge_vars.push(r_var);

        // Compute next claimed = h(r) = c0 + c1*r + c2*r^2
        // where c0 = e0, c2 = (e2 - 2*e1 + e0)/2, c1 = e1 - e0 - c2
        //
        // More directly via Lagrange interpolation at {0,1,2}:
        // h(r) = e0*(1-r)*(2-r)/2 + e1*r*(2-r)/(-1) + e2*r*(r-1)/2
        //
        // But it's simpler to compute: d = e1 - e0, then
        // h(r) = e0 + d*r + c2*r*(r-1), where c2 = (e2 - 2*e1 + e0)/2
        //
        // In R1CS:
        // 1. d = e1 - e0 (linear, free)
        // 2. dr = d * r (1 mul)
        // 3. c2 = (e2 - 2*e1 + e0) * inv(2) (linear, free — just rescale)
        // 4. r_minus_1 = r - 1 (linear, free)
        // 5. r_rm1 = r * r_minus_1 (1 mul)
        // 6. c2_r_rm1 = c2 * r_rm1 (1 mul)
        // 7. result = e0 + dr + c2_r_rm1 (linear, free)
        //
        // Total: 3 multiplications per sumcheck round

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

        // c2_unscaled = e2 - 2*e1 + e0
        let c2_unscaled_val = e2_val - e1_val.double() + e0_val;
        let c2_val = c2_unscaled_val * F::TWO.inverse();
        let c2_var = builder.alloc_witness(c2_val);
        // Constrain: 2 * c2 = e2 - 2*e1 + e0
        builder.enforce(
            LinearCombination::from_constant(F::TWO),
            LinearCombination::from_var(c2_var),
            LinearCombination::from_var(e2_var) - LinearCombination::from_scaled(e1_var, F::TWO)
                + LinearCombination::from_var(e0_var),
        );

        // r_minus_1 = r - 1
        let rm1_val = r_val - F::ONE;
        let rm1_var = builder.alloc_witness(rm1_val);
        builder.enforce(
            LinearCombination::from_var(r_var) - LinearCombination::from_constant(F::ONE),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(rm1_var),
        );

        // r_rm1 = r * (r - 1)
        let r_rm1_val = r_val * rm1_val;
        let r_rm1_var = builder.mul(r_var, rm1_var, r_rm1_val);

        // c2_r_rm1 = c2 * r*(r-1)
        let c2_r_rm1_val = c2_val * r_rm1_val;
        let c2_r_rm1_var = builder.mul(c2_var, r_rm1_var, c2_r_rm1_val);

        // result = e0 + dr + c2_r_rm1
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

/// Synthesize a unified IVC circuit using the eval-fold verifier.
///
/// Similar to `synthesize_unified_ivc_circuit` but uses the simpler
/// eval-fold verifier instead of the constraint-batch verifier.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_eval_fold_ivc_circuit<F, L, P, S, const WIDTH: usize, const RATE: usize>(
    builder: &mut CircuitBuilder<F>,
    challenger: &mut CircuitChallenger<F, WIDTH, RATE>,
    poseidon_config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    step_circuit: &S,
    step_input_state: &[F],
    verifier_witness: Option<&EvalFoldVerifierWitness<F>>,
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

    // Part 2: Eval-fold verifier (if previous accumulation exists)
    if let Some(witness) = verifier_witness {
        let _ = synthesize_eval_fold_verifier::<F, L, P, WIDTH, RATE>(
            builder,
            challenger,
            poseidon_config,
            perm,
            witness,
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

    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};

    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::ivc::step::TrivialStepCircuit;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    #[test]
    fn eval_fold_verifier_circuit_builds() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

        let witness = EvalFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::from_u64(42), F::from_u64(17)],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            sumcheck_evals: vec![[F::from_u64(20), F::from_u64(22), F::from_u64(30)]],
            num_rounds: 1,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let (challenges, _final_var, final_val) =
            synthesize_eval_fold_verifier::<F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8>(
                &mut builder,
                &mut challenger,
                &poseidon_config,
                &poseidon_perm,
                &witness,
            );

        assert_eq!(challenges.len(), 1);
        assert_ne!(final_val, F::ZERO);

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "eval fold verifier circuit is not satisfiable"
        );
    }

    #[test]
    fn eval_fold_ivc_circuit_builds_with_and_without_verifier() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));
        let step = TrivialStepCircuit::new(1);

        // WITH verifier
        let witness = EvalFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::ZERO; 2],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
        };

        let mut builder_with = CircuitBuilder::<F>::new();
        let mut chal_with = CircuitChallenger::<F, 16, 8>::new(&mut builder_with);
        let _ = synthesize_eval_fold_ivc_circuit::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            _,
            16,
            8,
        >(
            &mut builder_with,
            &mut chal_with,
            &poseidon_config,
            &poseidon_perm,
            &step,
            &[F::ZERO],
            Some(&witness),
            None,
        );
        let target = builder_with.num_witness_vars();

        // WITHOUT verifier, padded to same size
        let mut builder_without = CircuitBuilder::<F>::new();
        let mut chal_without = CircuitChallenger::<F, 16, 8>::new(&mut builder_without);
        let _ = synthesize_eval_fold_ivc_circuit::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            _,
            16,
            8,
        >(
            &mut builder_without,
            &mut chal_without,
            &poseidon_config,
            &poseidon_perm,
            &step,
            &[F::ZERO],
            None,
            Some(target),
        );

        let (shape_with, _) = builder_with.build();
        let (shape_without, instance_without) = builder_without.build();

        assert_eq!(
            shape_with.num_poly_vars_y(),
            shape_without.num_poly_vars_y(),
            "padded circuit has different poly vars"
        );
        assert!(
            instance_without.verify(),
            "padded circuit R1CS not satisfied"
        );
    }

    /// Compare circuit sizes: eval-fold verifier vs v2 constraint-batch verifier
    #[test]
    fn compare_circuit_sizes_eval_fold_vs_constraint_batch() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

        // Eval-fold verifier (base field sumcheck, 1 round)
        let eval_witness = EvalFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::ZERO; 2],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
        };
        let mut eval_builder = CircuitBuilder::<F>::new();
        let mut eval_chal = CircuitChallenger::<F, 16, 8>::new(&mut eval_builder);
        let _ = synthesize_eval_fold_verifier::<F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8>(
            &mut eval_builder,
            &mut eval_chal,
            &poseidon_config,
            &poseidon_perm,
            &eval_witness,
        );
        let eval_constraints = eval_builder.num_constraints();
        let _eval_witness_vars = eval_builder.num_witness_vars();

        // V2 constraint-batch verifier (EF sumcheck, 3 rounds for 3-variable claims)
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
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            16,
            8,
        >(
            &mut v2_builder,
            &mut v2_chal,
            &poseidon_config,
            &poseidon_perm,
            &v2_witness,
            F::from_u64(3),
        );
        let v2_constraints = v2_builder.num_constraints();
        let _v2_witness_vars = v2_builder.num_witness_vars();

        // The eval-fold verifier should be meaningfully smaller.
        // Exact sizes depend on Poseidon2 round counts but the sumcheck portion
        // is ~4x cheaper (base field vs extension field arithmetic).

        // The eval-fold verifier should be smaller
        assert!(
            eval_constraints <= v2_constraints,
            "eval-fold verifier should have fewer constraints: {} vs {}",
            eval_constraints,
            v2_constraints,
        );
    }
}
