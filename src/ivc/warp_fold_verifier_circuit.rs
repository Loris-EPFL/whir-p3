//! Recursive WARP fold verifier circuit.
//!
//! Arithmetizes the WARP fold verifier as R1CS constraints for use in recursive
//! IVC. At each IVC step, the recursive circuit verifies the PREVIOUS step's
//! WARP fold transcript by:
//!
//! 1. Observing input accumulator instances -> deriving Fiat-Shamir challenges
//! 2. Computing sigma_0 from input data and constraining it
//! 3. Verifying twin-constraint sumcheck rounds (degree-2, base field)
//! 4. Computing folded output accumulator values
//!
//! For l=2 (1 running + 1 fresh), the sumcheck has only 1 round: very cheap.
//! All arithmetic is in the BASE FIELD -- no extension field needed.

use alloc::{vec, vec::Vec};

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use crate::circuit::{
    builder::{CircuitBuilder, LinearCombination, Var},
    poseidon2::Poseidon2CircuitConfig,
    sponge::CircuitChallenger,
};

/// Output of the WARP fold verifier circuit.
///
/// Contains circuit variables for the folded output accumulator, allowing
/// the caller to bind them to the next IVC step's input.
#[derive(Clone, Debug)]
pub struct WarpFoldVerifierOutput<F: Field> {
    /// Sumcheck challenge variables (gamma_0, gamma_1, ..., gamma_{log_l-1}).
    pub challenge_vars: Vec<Var>,
    /// Folded eval point: alpha'[j] = sum_i eq(gamma, i) * alpha_i[j].
    pub folded_alpha_vars: Vec<Var>,
    /// Folded eval claim: mu' = sum_i eq(gamma, i) * mu_i.
    pub folded_mu_var: Var,
    /// Folded PESAT target: eta' = sum_i eq(gamma, i) * eta_i.
    pub folded_eta_var: Var,
    /// Final claimed value variable from the last sumcheck round.
    pub final_claimed_var: Var,
    /// Final claimed value (native) from the last sumcheck round.
    pub final_claimed_val: F,
}

/// Witness data for the WARP fold verifier circuit.
///
/// Contains the fold transcript data that the circuit needs to verify.
/// All values are base field -- no extension field arithmetic in-circuit.
#[derive(Clone, Debug)]
pub struct WarpFoldVerifierWitness<F: Field> {
    /// Commitment roots of input accumulators (each is DIGEST_ELEMS base elements).
    pub input_commitment_roots: Vec<Vec<F>>,
    /// Eval claims mu_i from each input accumulator.
    pub input_eval_claims: Vec<F>,
    /// Eval points alpha_i from each input accumulator.
    pub input_eval_points: Vec<Vec<F>>,
    /// PESAT targets eta_i from each input accumulator.
    pub input_pesat_targets: Vec<F>,
    /// Twin-constraint sumcheck round polynomials: [h(0), h(1), h(2)] per round.
    pub sumcheck_evals: Vec<[F; 3]>,
    /// Number of sumcheck rounds (= log_l, typically 1 for l=2).
    pub num_rounds: usize,
    /// The batching challenge omega used in twin-constraint: target_i = mu_i + omega*eta_i.
    pub omega: F,
    /// Number of fresh instances (l-1). Used to sample fresh_betas from the
    /// Poseidon2 sponge, keeping the in-circuit FS state in sync with the
    /// native `derive_fold_challenges{,_union}` which samples
    /// `num_fresh * log_m` challenges between tau and sumcheck rounds.
    pub num_fresh: usize,
    /// Log2 of constraint count. Together with `num_fresh`, determines how many
    /// fresh_betas the sponge must sample to stay in sync with the native prover.
    pub log_m: usize,
    /// Quasar union commitment root. When `Some`, replaces individual fresh roots
    /// in Phase 1 FS absorption: the circuit absorbs running acc (index 0) + this
    /// single union root instead of l individual roots. This is O(1) in l.
    pub union_commitment_root: Option<Vec<F>>,
    /// All eval claims for ALL l instances (including fresh ones not absorbed individually).
    /// In union mode, `input_eval_claims` only has the running acc's claim, but
    /// `all_eval_claims` has all l claims needed for sigma_0 computation.
    /// If `None`, falls back to `input_eval_claims`.
    pub all_eval_claims: Option<Vec<F>>,
    /// All PESAT targets for ALL l instances. Same semantics as `all_eval_claims`.
    pub all_pesat_targets: Option<Vec<F>>,
    /// All eval points for ALL l instances. Same semantics as `all_eval_claims`.
    pub all_eval_points: Option<Vec<Vec<F>>>,
}

impl<F: Field + PrimeField64> WarpFoldVerifierWitness<F> {
    /// Build from a `WarpFoldResult` and input accumulator data.
    pub fn from_fold_result(
        input_commitment_roots: Vec<Vec<F>>,
        input_eval_claims: Vec<F>,
        input_eval_points: Vec<Vec<F>>,
        input_pesat_targets: Vec<F>,
        sumcheck_round_polys: &[Vec<F>],
        omega: F,
        num_fresh: usize,
        log_m: usize,
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
            input_eval_claims: input_eval_claims.clone(),
            input_eval_points: input_eval_points.clone(),
            input_pesat_targets: input_pesat_targets.clone(),
            sumcheck_evals,
            num_rounds: sumcheck_round_polys.len(),
            omega,
            num_fresh,
            log_m,
            union_commitment_root: None,
            all_eval_claims: Some(input_eval_claims),
            all_pesat_targets: Some(input_pesat_targets),
            all_eval_points: Some(input_eval_points),
        }
    }

    /// Build a union-mode witness from fold result data.
    ///
    /// Only the running accumulator's instance data (index 0) is stored
    /// individually. The l-1 fresh roots are replaced by a single union root.
    /// The in-circuit Phase 1 absorbs: running acc + union root -> O(1) in l.
    ///
    /// `all_eval_claims`, `all_pesat_targets`, `all_eval_points` provide the
    /// full set of l values needed for sigma_0 computation and output folding.
    #[allow(clippy::too_many_arguments)]
    pub fn from_fold_result_union(
        running_root: Vec<F>,
        running_eval_claim: F,
        running_eval_point: Vec<F>,
        running_pesat_target: F,
        union_root: Vec<F>,
        sumcheck_round_polys: &[Vec<F>],
        omega: F,
        num_fresh: usize,
        log_m: usize,
        all_eval_claims: Vec<F>,
        all_pesat_targets: Vec<F>,
        all_eval_points: Vec<Vec<F>>,
    ) -> Self {
        let sumcheck_evals: Vec<[F; 3]> = sumcheck_round_polys
            .iter()
            .map(|evals| {
                assert!(evals.len() >= 3);
                [evals[0], evals[1], evals[2]]
            })
            .collect();
        Self {
            input_commitment_roots: vec![running_root],
            input_eval_claims: vec![running_eval_claim],
            input_eval_points: vec![running_eval_point],
            input_pesat_targets: vec![running_pesat_target],
            sumcheck_evals,
            num_rounds: sumcheck_round_polys.len(),
            omega,
            num_fresh,
            log_m,
            union_commitment_root: Some(union_root),
            all_eval_claims: Some(all_eval_claims),
            all_pesat_targets: Some(all_pesat_targets),
            all_eval_points: Some(all_eval_points),
        }
    }
}

/// Perform binary tree folding of a table of circuit variables using challenges.
///
/// Given a table of `l` values and `log_l` challenge variables, computes:
/// `result = sum_i eq(challenges, i) * table[i]`
///
/// This is done iteratively: for each round j with challenge tau_j,
/// `table[k] = table[2k] + tau_j * (table[2k+1] - table[2k])`.
/// After `log_l` rounds, `table[0]` holds the result.
fn binary_tree_fold<F: Field>(
    builder: &mut CircuitBuilder<F>,
    table_vars: &[Var],
    table_vals: &[F],
    challenge_vars: &[Var],
    challenge_vals: &[F],
) -> (Var, F) {
    assert_eq!(table_vars.len(), table_vals.len());
    assert_eq!(challenge_vars.len(), challenge_vals.len());
    assert_eq!(table_vars.len(), 1 << challenge_vars.len());

    let mut cur_vars: Vec<Var> = table_vars.to_vec();
    let mut cur_vals: Vec<F> = table_vals.to_vec();

    for round in 0..challenge_vars.len() {
        let tau_var = challenge_vars[round];
        let tau_val = challenge_vals[round];
        let half = cur_vars.len() / 2;
        let mut new_vars = Vec::with_capacity(half);
        let mut new_vals = Vec::with_capacity(half);
        for k in 0..half {
            let lo_var = cur_vars[2 * k];
            let hi_var = cur_vars[2 * k + 1];
            let lo_val = cur_vals[2 * k];
            let hi_val = cur_vals[2 * k + 1];
            // result = lo + tau * (hi - lo)
            let diff_val = hi_val - lo_val;
            let diff_var = builder.alloc_witness(diff_val);
            builder.enforce(
                LinearCombination::from_var(hi_var) - LinearCombination::from_var(lo_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(diff_var),
            );
            let tau_diff_val = tau_val * diff_val;
            let tau_diff_var = builder.mul(tau_var, diff_var, tau_diff_val);
            let result_val = lo_val + tau_diff_val;
            let result_var = builder.alloc_witness(result_val);
            builder.enforce(
                LinearCombination::from_var(lo_var) + LinearCombination::from_var(tau_diff_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(result_var),
            );
            new_vars.push(result_var);
            new_vals.push(result_val);
        }
        cur_vars = new_vars;
        cur_vals = new_vals;
    }
    (cur_vars[0], cur_vals[0])
}

/// Synthesize the WARP fold verifier as R1CS constraints.
///
/// Verifies:
/// 1. Fiat-Shamir: derive challenges from input accumulators
/// 2. Compute sigma_0 from input mu_i, eta_i, omega, tau and constrain it
/// 3. Twin-constraint sumcheck: h_i(0) + h_i(1) = claimed, h_i(r) = next_claimed
/// 4. Fold output accumulator values using sumcheck challenges (gamma)
///
/// Returns `WarpFoldVerifierOutput` with all folded output variables.
///
/// Cost: ~3 multiplications per sumcheck round + sigma_0 folding + output folding
/// + Poseidon2 hashing. For l=2 (1 round): extremely cheap.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_warp_fold_verifier<F, L, P, const WIDTH: usize, const RATE: usize>(
    builder: &mut CircuitBuilder<F>,
    challenger: &mut CircuitChallenger<F, WIDTH, RATE>,
    poseidon_config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    witness: &WarpFoldVerifierWitness<F>,
) -> WarpFoldVerifierOutput<F>
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    // Resolve the full set of l eval claims, pesat targets, and eval points.
    // In non-union mode these come from input_*; in union mode from all_*.
    let all_mu: Vec<F> = witness
        .all_eval_claims
        .clone()
        .unwrap_or_else(|| witness.input_eval_claims.clone());
    let all_eta: Vec<F> = witness
        .all_pesat_targets
        .clone()
        .unwrap_or_else(|| witness.input_pesat_targets.clone());
    let all_alpha: Vec<Vec<F>> = witness
        .all_eval_points
        .clone()
        .unwrap_or_else(|| witness.input_eval_points.clone());
    let l = all_mu.len();
    assert_eq!(all_eta.len(), l);
    assert_eq!(all_alpha.len(), l);
    let alpha_dim = all_alpha[0].len();

    // =============================================
    // Phase 1: Observe input accumulators -> derive challenges
    // =============================================
    // We track mu/eta/alpha vars for ALL l instances (for sigma_0 and output folding).
    let mut all_mu_vars: Vec<Var> = Vec::with_capacity(l);
    let mut all_eta_vars: Vec<Var> = Vec::with_capacity(l);
    let mut all_alpha_vars: Vec<Vec<Var>> = Vec::with_capacity(l);

    if let Some(ref union_root) = witness.union_commitment_root {
        // UNION PATH (Quasar multicast): absorb running acc (index 0) + union root.
        // Cost is O(1) in l -- only 2 absorptions regardless of how many fresh instances.
        // Matches the native `derive_fold_challenges_union` in fold.rs.

        // Running accumulator: root + mu + alpha + eta
        let root_vars: Vec<Var> = witness.input_commitment_roots[0]
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &root_vars,
            &witness.input_commitment_roots[0],
        );
        let mu0_var = builder.alloc_witness(witness.input_eval_claims[0]);
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[mu0_var],
            &[witness.input_eval_claims[0]],
        );
        let alpha0_vars: Vec<Var> = witness.input_eval_points[0]
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &alpha0_vars,
            &witness.input_eval_points[0],
        );
        let eta0_var = builder.alloc_witness(witness.input_pesat_targets[0]);
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[eta0_var],
            &[witness.input_pesat_targets[0]],
        );

        // Track running acc vars (index 0)
        all_mu_vars.push(mu0_var);
        all_eta_vars.push(eta0_var);
        all_alpha_vars.push(alpha0_vars);

        // Union root: 8 elements -- replaces all l-1 fresh roots+claims+points+targets
        let union_vars: Vec<Var> = union_root
            .iter()
            .map(|&val| builder.alloc_witness(val))
            .collect();
        challenger.observe_slice::<L, P>(builder, poseidon_config, perm, &union_vars, union_root);

        // Allocate witness vars for fresh instances' mu/eta/alpha (not absorbed, but
        // needed for sigma_0 computation and output folding).
        for i in 1..l {
            let mu_var = builder.alloc_witness(all_mu[i]);
            all_mu_vars.push(mu_var);
            let eta_var = builder.alloc_witness(all_eta[i]);
            all_eta_vars.push(eta_var);
            let a_vars: Vec<Var> = all_alpha[i]
                .iter()
                .map(|&val| builder.alloc_witness(val))
                .collect();
            all_alpha_vars.push(a_vars);
        }
    } else {
        // NON-UNION PATH: absorb all k accumulators individually -- O(l).
        // FS absorption uses `input_eval_claims` / `input_pesat_targets` (may be
        // zeros for fresh instances, matching derive_fold_challenges). The sigma_0
        // computation uses `all_mu` / `all_eta` (actual values from the fold).
        // These may differ, so we allocate SEPARATE vars for sigma_0.
        let k = witness.input_commitment_roots.len();
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

            // Observe eval claim mu_i (FS value, may be zero for fresh instances)
            let fs_mu_var = builder.alloc_witness(witness.input_eval_claims[i]);
            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &[fs_mu_var],
                &[witness.input_eval_claims[i]],
            );

            // Observe eval point alpha_i
            let alpha_vars: Vec<Var> = witness.input_eval_points[i]
                .iter()
                .map(|&val| builder.alloc_witness(val))
                .collect();
            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &alpha_vars,
                &witness.input_eval_points[i],
            );

            // Observe PESAT target eta_i (FS value, may be zero for fresh instances)
            let fs_eta_var = builder.alloc_witness(witness.input_pesat_targets[i]);
            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &[fs_eta_var],
                &[witness.input_pesat_targets[i]],
            );

            // For sigma_0: use ACTUAL values (from all_mu/all_eta, which may differ from FS values)
            let sigma_mu_var = builder.alloc_witness(all_mu[i]);
            all_mu_vars.push(sigma_mu_var);
            let sigma_eta_var = builder.alloc_witness(all_eta[i]);
            all_eta_vars.push(sigma_eta_var);
            all_alpha_vars.push(alpha_vars);
        }
    }

    // Derive omega (batching challenge) from Poseidon2 and constrain it
    let (derived_omega_var, _derived_omega_val) =
        challenger.sample::<L, P>(builder, poseidon_config, perm);
    // The witness provides the omega that was actually used in the fold.
    // Constrain: derived_omega == witness.omega (Fiat-Shamir binding).
    let witness_omega_var = builder.alloc_witness(witness.omega);
    builder.enforce(
        LinearCombination::from_var(derived_omega_var),
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(witness_omega_var),
    );

    // Derive tau challenges (log_l base field elements).
    // Save them for sigma_0 computation.
    let mut tau_vars: Vec<Var> = Vec::with_capacity(witness.num_rounds);
    let mut tau_vals: Vec<F> = Vec::with_capacity(witness.num_rounds);
    for _ in 0..witness.num_rounds {
        let (tau_var, tau_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        tau_vars.push(tau_var);
        tau_vals.push(tau_val);
    }

    // Sample fresh_betas to keep Poseidon2 sponge state synchronized with the
    // native prover's derive_fold_challenges{,_union}. The native FS samples
    // num_fresh * log_m challenges between tau and the sumcheck rounds. Without
    // this, the sponge state diverges and subsequent sumcheck challenges r_i
    // would differ between circuit and prover, breaking Fiat-Shamir binding.
    for _ in 0..witness.num_fresh {
        for _ in 0..witness.log_m {
            let _ = challenger.sample::<L, P>(builder, poseidon_config, perm);
        }
    }

    // =============================================
    // Phase 2a: Compute sigma_0 from input data (FIX C2)
    // =============================================
    // sigma_0 = sum_{i=0}^{l-1} eq(tau, i) * (mu_i + omega * eta_i)
    //
    // Step 1: Build the target table t_i = mu_i + omega * eta_i
    let mut target_vars: Vec<Var> = Vec::with_capacity(l);
    let mut target_vals: Vec<F> = Vec::with_capacity(l);
    for i in 0..l {
        // omega * eta_i
        let omega_eta_val = witness.omega * all_eta[i];
        let omega_eta_var = builder.mul(witness_omega_var, all_eta_vars[i], omega_eta_val);
        // t_i = mu_i + omega * eta_i
        let t_val = all_mu[i] + omega_eta_val;
        let t_var = builder.alloc_witness(t_val);
        builder.enforce(
            LinearCombination::from_var(all_mu_vars[i]) + LinearCombination::from_var(omega_eta_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(t_var),
        );
        target_vars.push(t_var);
        target_vals.push(t_val);
    }

    // Step 2: Fold the target table using tau challenges via binary tree folding.
    // After log_l rounds, table[0] = sigma_0.
    let (sigma0_var, sigma0_val) =
        binary_tree_fold(builder, &target_vars, &target_vals, &tau_vars, &tau_vals);

    // =============================================
    // Phase 2b: Verify twin-constraint sumcheck rounds (BASE FIELD)
    // =============================================
    // Initial claim = sigma_0 (computed from inputs, NOT from round polys).
    // The first round's h(0)+h(1) must equal sigma_0.
    let mut claimed_var = sigma0_var;
    let mut claimed_val = sigma0_val;
    let mut sumcheck_challenge_vars: Vec<Var> = Vec::with_capacity(witness.num_rounds);
    let mut sumcheck_challenge_vals: Vec<F> = Vec::with_capacity(witness.num_rounds);

    for round in 0..witness.num_rounds {
        let [e0_val, e1_val, e2_val] = witness.sumcheck_evals[round];

        let e0_var = builder.alloc_witness(e0_val);
        let e1_var = builder.alloc_witness(e1_val);
        let e2_var = builder.alloc_witness(e2_val);

        // Observe round polynomial into Fiat-Shamir
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[e0_var, e1_var, e2_var],
            &[e0_val, e1_val, e2_val],
        );

        // Constrain: e0 + e1 = claimed
        builder.enforce(
            LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(claimed_var),
        );

        // Sample challenge r
        let (r_var, r_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        sumcheck_challenge_vars.push(r_var);
        sumcheck_challenge_vals.push(r_val);

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

    // =============================================
    // Phase 3: Fold output accumulator values using sumcheck challenges (FIX C1)
    // =============================================
    // gamma = sumcheck_challenge_vars (the challenges from the sumcheck rounds)
    // Compute folded values: sum_i eq(gamma, i) * value_i

    // Folded mu: mu' = sum_i eq(gamma, i) * mu_i
    let (folded_mu_var, _folded_mu_val) = binary_tree_fold(
        builder,
        &all_mu_vars,
        &all_mu,
        &sumcheck_challenge_vars,
        &sumcheck_challenge_vals,
    );

    // Folded eta: eta' = sum_i eq(gamma, i) * eta_i
    let (folded_eta_var, _folded_eta_val) = binary_tree_fold(
        builder,
        &all_eta_vars,
        &all_eta,
        &sumcheck_challenge_vars,
        &sumcheck_challenge_vals,
    );

    // Folded alpha: alpha'[j] = sum_i eq(gamma, i) * alpha_i[j] for each coordinate j
    let mut folded_alpha_vars: Vec<Var> = Vec::with_capacity(alpha_dim);
    for j in 0..alpha_dim {
        let col_vars: Vec<Var> = (0..l).map(|i| all_alpha_vars[i][j]).collect();
        let col_vals: Vec<F> = (0..l).map(|i| all_alpha[i][j]).collect();
        let (folded_j_var, _folded_j_val) = binary_tree_fold(
            builder,
            &col_vars,
            &col_vals,
            &sumcheck_challenge_vars,
            &sumcheck_challenge_vals,
        );
        folded_alpha_vars.push(folded_j_var);
    }

    WarpFoldVerifierOutput {
        challenge_vars: sumcheck_challenge_vars,
        folded_alpha_vars,
        folded_mu_var,
        folded_eta_var,
        final_claimed_var: claimed_var,
        final_claimed_val: claimed_val,
    }
}

/// Synthesize a unified IVC circuit using the WARP fold verifier.
///
/// Combines user's step circuit + WARP fold verifier into a single R1CS circuit.
/// Returns step output vars and optionally the fold verifier output.
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
) -> (Vec<Var>, Option<WarpFoldVerifierOutput<F>>)
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

    // Part 2: WARP fold verifier (FIX C1: keep the output instead of discarding)
    let fold_output = verifier_witness.map(|witness| {
        synthesize_warp_fold_verifier::<F, L, P, WIDTH, RATE>(
            builder, challenger, poseidon_config, perm, witness,
        )
    });

    // Pad to target witness count
    if let Some(target) = target_num_witness {
        let current = builder.num_witness_vars();
        if current < target {
            for _ in current..target {
                let v = builder.alloc_witness(F::ZERO);
                // Constrain v * 1 = 0, i.e., v = 0 (satisfiable since v is allocated as zero).
                builder.enforce(
                    LinearCombination::from_var(v),
                    LinearCombination::from_constant(F::ONE),
                    LinearCombination::from_constant(F::ZERO),
                );
            }
        }
    }

    (output_vars, fold_output)
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

    /// Compute sigma_0 natively: sum_i eq(tau, i) * (mu_i + omega * eta_i).
    fn compute_sigma0_native(
        mu: &[F],
        eta: &[F],
        omega: F,
        tau: &[F],
    ) -> F {
        let l = mu.len();
        assert_eq!(eta.len(), l);
        assert_eq!(1 << tau.len(), l);

        // Build target table
        let mut table: Vec<F> = (0..l).map(|i| mu[i] + omega * eta[i]).collect();

        // Binary tree fold
        for round in 0..tau.len() {
            let half = table.len() / 2;
            let mut new_table = Vec::with_capacity(half);
            for k in 0..half {
                new_table.push(table[2 * k] + tau[round] * (table[2 * k + 1] - table[2 * k]));
            }
            table = new_table;
        }
        table[0]
    }

    /// Construct sumcheck round polynomials consistent with sigma_0 and the FS transcript.
    /// Returns (round_polys, native_challenger_after_sumcheck).
    fn construct_consistent_round_polys(
        sigma0: F,
        num_rounds: usize,
        native_chal: &mut MyChal,
    ) -> Vec<[F; 3]> {
        use p3_challenger::{CanObserve, CanSample};

        let mut round_polys = Vec::with_capacity(num_rounds);
        let mut claimed = sigma0;

        for _ in 0..num_rounds {
            // Split the claim: e0 + e1 = claimed
            // Use e0 = claimed, e1 = 0 for simplicity
            let e0 = claimed;
            let e1 = F::ZERO;
            // e2 can be anything -- use e0 so c2 = 0 (simplifies computation)
            let e2 = e0;

            round_polys.push([e0, e1, e2]);

            // Observe into native challenger
            native_chal.observe(e0);
            native_chal.observe(e1);
            native_chal.observe(e2);
            let r: F = native_chal.sample();

            // Compute h(r) = e0 + d*r + c2*r*(r-1)
            let d = e1 - e0;
            let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
            claimed = e0 + d * r + c2 * r * (r - F::ONE);
        }

        round_polys
    }

    #[test]
    fn warp_fold_verifier_circuit_satisfiable() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut SmallRng::seed_from_u64(99));

        // Derive omega natively from the same Poseidon2 that the circuit will use
        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::from_u64(10), F::from_u64(20)];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] {
                native_chal.observe(val);
            }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                native_chal.observe(val);
            }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();

        // l=2: 1 round of sumcheck, 1 fresh instance, log_m=2
        let num_fresh = 1;
        let log_m = 2;

        // Sample tau from native challenger
        let tau_0: F = native_chal.sample(); // tau (1 challenge for log_l=1)

        // Sample fresh_betas
        for _ in 0..num_fresh * log_m {
            let _: F = native_chal.sample();
        }

        // Compute sigma_0 from input data
        let sigma0 = compute_sigma0_native(&eval_claims, &pesat_targets, omega, &[tau_0]);

        // Construct consistent round polys
        let round_polys =
            construct_consistent_round_polys(sigma0, 1, &mut native_chal);

        let witness = WarpFoldVerifierWitness {
            input_commitment_roots: roots,
            input_eval_claims: eval_claims.clone(),
            input_eval_points: eval_points.clone(),
            input_pesat_targets: pesat_targets.clone(),
            sumcheck_evals: round_polys,
            num_rounds: 1,
            omega,
            num_fresh,
            log_m,
            union_commitment_root: None,
            all_eval_claims: Some(eval_claims),
            all_pesat_targets: Some(pesat_targets),
            all_eval_points: Some(eval_points),
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let output = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            16,
            8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        assert_eq!(
            output.challenge_vars.len(),
            1,
            "expected 1 sumcheck round for l=2"
        );

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "WARP fold verifier circuit is not satisfiable"
        );
    }

    #[test]
    fn warp_ivc_circuit_sizing_consistent() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut SmallRng::seed_from_u64(99));
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
            num_fresh: 1,
            log_m: 2,
            union_commitment_root: None,
            all_eval_claims: None,
            all_pesat_targets: None,
            all_eval_points: None,
        };

        let mut builder_with = CircuitBuilder::<F>::new();
        let mut chal_with = CircuitChallenger::<F, 16, 8>::new(&mut builder_with);
        let (_, fold_out) = synthesize_warp_ivc_circuit::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
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
        assert!(fold_out.is_some(), "fold output should be present");
        let target = builder_with.num_witness_vars();

        // WITHOUT verifier, padded to same size
        let mut builder_without = CircuitBuilder::<F>::new();
        let mut chal_without = CircuitChallenger::<F, 16, 8>::new(&mut builder_without);
        let (_, fold_out_none) = synthesize_warp_ivc_circuit::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
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
        assert!(fold_out_none.is_none(), "fold output should be absent");

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

    /// Compare WARP fold verifier vs v2 constraint-batch verifier circuit sizes.
    #[test]
    fn compare_warp_vs_v2_circuit_sizes() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut SmallRng::seed_from_u64(99));

        // WARP fold verifier (1 round, base field)
        let warp_witness = WarpFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 2],
            input_eval_claims: vec![F::ZERO; 2],
            input_eval_points: vec![vec![F::ZERO; 3]; 2],
            input_pesat_targets: vec![F::ZERO; 2],
            sumcheck_evals: vec![[F::ZERO; 3]],
            num_rounds: 1,
            omega: F::ZERO,
            num_fresh: 1,
            log_m: 2,
            union_commitment_root: None,
            all_eval_claims: None,
            all_pesat_targets: None,
            all_eval_points: None,
        };
        let mut warp_builder = CircuitBuilder::<F>::new();
        let mut warp_chal = CircuitChallenger::<F, 16, 8>::new(&mut warp_builder);
        let _ = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            16,
            8,
        >(
            &mut warp_builder,
            &mut warp_chal,
            &poseidon_config,
            &poseidon_perm,
            &warp_witness,
        );
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
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            16,
            8,
        >(
            &mut v2_builder,
            &mut v2_chal,
            &poseidon_config,
            &poseidon_perm,
            &v2_witness,
            F::from_u64(11),
        );
        let v2_constraints = v2_builder.num_constraints();
        let v2_witness_vars = v2_builder.num_witness_vars();

        // WARP should be significantly smaller (base field, 1 round vs 3 EF rounds)
        assert!(
            warp_constraints < v2_constraints,
            "WARP verifier should be smaller: {} vs {} constraints",
            warp_constraints,
            v2_constraints,
        );
        assert!(
            warp_witness_vars < v2_witness_vars,
            "WARP verifier should have fewer witness vars: {} vs {}",
            warp_witness_vars,
            v2_witness_vars,
        );
    }

    #[test]
    fn warp_fold_verifier_circuit_union_satisfiable() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut SmallRng::seed_from_u64(99));

        // l=4: 1 running acc + 3 fresh -> union root replaces the 3 fresh roots
        let running_root = vec![F::from_u64(1); 8];
        let running_eval_claim = F::from_u64(10);
        let running_eval_point = vec![F::from_u64(2); 3];
        let running_pesat_target = F::from_u64(5);
        let union_root = vec![F::from_u64(42); 8];

        // All l=4 instance data (running + 3 fresh with zeros)
        let all_eval_claims = vec![
            running_eval_claim,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        let all_pesat_targets = vec![
            running_pesat_target,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        let all_eval_points = vec![
            running_eval_point.clone(),
            vec![F::ZERO; 3],
            vec![F::ZERO; 3],
            vec![F::ZERO; 3],
        ];

        // Derive omega natively via the union FS path:
        // absorb running acc, then union root
        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for &val in &running_root {
            native_chal.observe(val);
        }
        native_chal.observe(running_eval_claim);
        for &val in &running_eval_point {
            native_chal.observe(val);
        }
        native_chal.observe(running_pesat_target);
        for &val in &union_root {
            native_chal.observe(val);
        }
        let omega: F = native_chal.sample();

        // Sample tau challenges (2 for l=4)
        let tau_0: F = native_chal.sample();
        let tau_1: F = native_chal.sample();

        // Sample fresh_betas (3 fresh x 2 log_m = 6 samples)
        let num_fresh = 3;
        let log_m = 2;
        for _ in 0..num_fresh * log_m {
            let _: F = native_chal.sample();
        }

        // Compute sigma_0 from input data
        let sigma0 =
            compute_sigma0_native(&all_eval_claims, &all_pesat_targets, omega, &[tau_0, tau_1]);

        // l=4 -> log_l=2 -> 2 sumcheck rounds
        let round_polys =
            construct_consistent_round_polys(sigma0, 2, &mut native_chal);

        let witness = WarpFoldVerifierWitness::from_fold_result_union(
            running_root,
            running_eval_claim,
            running_eval_point,
            running_pesat_target,
            union_root,
            &round_polys
                .iter()
                .map(|rp| vec![rp[0], rp[1], rp[2]])
                .collect::<Vec<_>>(),
            omega,
            num_fresh,
            log_m,
            all_eval_claims,
            all_pesat_targets,
            all_eval_points,
        );

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let output = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            16,
            8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        assert_eq!(
            output.challenge_vars.len(),
            2,
            "expected 2 sumcheck rounds for l=4"
        );

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "union-mode WARP fold verifier circuit is not satisfiable"
        );
    }

    #[test]
    fn union_verifier_fewer_constraints_than_nonunion() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut SmallRng::seed_from_u64(99));

        let log_n = 3; // eval point dimension

        // Non-union l=4: absorbs 4 accumulators individually
        let nonunion_witness = WarpFoldVerifierWitness {
            input_commitment_roots: vec![vec![F::ZERO; 8]; 4],
            input_eval_claims: vec![F::ZERO; 4],
            input_eval_points: vec![vec![F::ZERO; log_n]; 4],
            input_pesat_targets: vec![F::ZERO; 4],
            sumcheck_evals: vec![[F::ZERO; 3]; 2], // log_l=2 rounds
            num_rounds: 2,
            omega: F::ZERO,
            num_fresh: 3,
            log_m: 0, // zero to compare Phase 1 savings only
            union_commitment_root: None,
            all_eval_claims: None,
            all_pesat_targets: None,
            all_eval_points: None,
        };

        let mut nonunion_builder = CircuitBuilder::<F>::new();
        let mut nonunion_chal = CircuitChallenger::<F, 16, 8>::new(&mut nonunion_builder);
        let _ = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            16,
            8,
        >(
            &mut nonunion_builder,
            &mut nonunion_chal,
            &poseidon_config,
            &poseidon_perm,
            &nonunion_witness,
        );
        let nonunion_constraints = nonunion_builder.num_constraints();

        // Union l=4: absorbs 1 running acc + 1 union root
        let union_witness = WarpFoldVerifierWitness::from_fold_result_union(
            vec![F::ZERO; 8],
            F::ZERO,
            vec![F::ZERO; log_n],
            F::ZERO,
            vec![F::ZERO; 8],
            &vec![vec![F::ZERO; 3]; 2],
            F::ZERO,
            3, // num_fresh
            0, // log_m: zero to compare Phase 1 savings only
            vec![F::ZERO; 4],
            vec![F::ZERO; 4],
            vec![vec![F::ZERO; log_n]; 4],
        );

        let mut union_builder = CircuitBuilder::<F>::new();
        let mut union_chal = CircuitChallenger::<F, 16, 8>::new(&mut union_builder);
        let _ = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            _,
            16,
            8,
        >(
            &mut union_builder,
            &mut union_chal,
            &poseidon_config,
            &poseidon_perm,
            &union_witness,
        );
        let union_constraints = union_builder.num_constraints();

        // Union should have significantly fewer constraints (Phase 1 savings)
        assert!(
            union_constraints < nonunion_constraints,
            "union verifier should have fewer constraints: {} vs {} (non-union)",
            union_constraints,
            nonunion_constraints,
        );

        // At l=4, expect significant savings (>20%)
        let savings_pct = 100.0 * (1.0 - union_constraints as f64 / nonunion_constraints as f64);
        assert!(
            savings_pct > 20.0,
            "expected >20% savings at l=4, got {savings_pct:.1}%"
        );
    }

    #[test]
    fn union_verifier_constraint_scaling() {
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut SmallRng::seed_from_u64(99));
        let log_n = 3;

        // Verify constraint scaling across arities

        for &arity in &[2usize, 4, 8, 16] {
            let log_l = arity.trailing_zeros() as usize;

            // Non-union: absorb `arity` accumulators
            let nonunion_witness = WarpFoldVerifierWitness {
                input_commitment_roots: vec![vec![F::ZERO; 8]; arity],
                input_eval_claims: vec![F::ZERO; arity],
                input_eval_points: vec![vec![F::ZERO; log_n]; arity],
                input_pesat_targets: vec![F::ZERO; arity],
                sumcheck_evals: vec![[F::ZERO; 3]; log_l],
                num_rounds: log_l,
                omega: F::ZERO,
                num_fresh: arity - 1,
                log_m: 0, // zero to compare Phase 1 savings only
                union_commitment_root: None,
                all_eval_claims: None,
                all_pesat_targets: None,
                all_eval_points: None,
            };

            let mut b1 = CircuitBuilder::<F>::new();
            let mut c1 = CircuitChallenger::<F, 16, 8>::new(&mut b1);
            let _ = synthesize_warp_fold_verifier::<
                F,
                GenericPoseidon2LinearLayersBabyBear,
                _,
                16,
                8,
            >(&mut b1, &mut c1, &poseidon_config, &poseidon_perm, &nonunion_witness);
            let nc = b1.num_constraints();

            // Union: absorb 1 running + 1 union root
            let union_witness = WarpFoldVerifierWitness::from_fold_result_union(
                vec![F::ZERO; 8],
                F::ZERO,
                vec![F::ZERO; log_n],
                F::ZERO,
                vec![F::ZERO; 8],
                &vec![vec![F::ZERO; 3]; log_l],
                F::ZERO,
                arity - 1, // num_fresh
                0,         // log_m: zero to compare Phase 1 savings only
                vec![F::ZERO; arity],
                vec![F::ZERO; arity],
                vec![vec![F::ZERO; log_n]; arity],
            );

            let mut b2 = CircuitBuilder::<F>::new();
            let mut c2 = CircuitChallenger::<F, 16, 8>::new(&mut b2);
            let _ = synthesize_warp_fold_verifier::<
                F,
                GenericPoseidon2LinearLayersBabyBear,
                _,
                16,
                8,
            >(&mut b2, &mut c2, &poseidon_config, &poseidon_perm, &union_witness);
            let uc = b2.num_constraints();

            // Union should never be more expensive
            assert!(uc <= nc, "union should not add constraints at arity {arity}");
            // At arity >= 4, union should be strictly cheaper
            if arity >= 4 {
                assert!(uc < nc, "union should be cheaper at arity {arity}");
            }
        }
    }
}
