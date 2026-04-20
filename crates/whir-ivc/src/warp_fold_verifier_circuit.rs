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
    /// Shift-query authentication data (Phase 3 / Phase 2.3).
    ///
    /// For every committed codeword the prover opened at a sampled position,
    /// this carries the row values and the Merkle authentication path. When
    /// empty, the circuit emits no Merkle-verify constraints (preserves
    /// backward compatibility for call sites that pre-date Phase 3).
    ///
    /// In the non-union case `shift_auth_paths[q][i]` authenticates the
    /// `i`-th input codeword's row at position `shift_positions[q]` against
    /// `commitment_roots[i]`. In the union case (Quasar multicast) there is
    /// exactly ONE path per query into the union tree, so
    /// `shift_auth_paths[q].len() == 1`.
    #[allow(clippy::struct_field_names)]
    pub shift_positions: Vec<usize>,
    pub shift_input_values: Vec<Vec<Vec<F>>>,
    pub shift_auth_paths: Vec<Vec<Vec<Vec<F>>>>,
    /// RS folding factor used when building the Merkle tree (leaf row width
    /// = 1 << folding_factor). Zero when no shift authentication is in use.
    pub shift_folding_factor: usize,
    /// Per-codeword Merkle roots corresponding to `shift_auth_paths`. In the
    /// non-union case this is `[acc_root, fresh_root_0, …]`; in the union
    /// case it is `[union_root]`. Empty when no shift authentication.
    pub shift_codeword_roots: Vec<Vec<F>>,
    /// Enables union-tree Merkle verification when `true` AND
    /// `shift_auth_paths` is non-empty. In union mode, every shift query's
    /// `auth_paths[q]` has exactly 1 entry (the union-tree proof), and the
    /// leaf row is reconstructed column-by-column from the per-codeword
    /// `input_values[q][i]` as `[v_0[c], v_1[c], …, v_{l-1}[c]]` for each
    /// column `c`. Set by the Quasar-backed callers.
    pub shift_union_mode: bool,
    /// OOD + evaluation-batching-sumcheck data (Phase 3.5).
    ///
    /// When `eval_batch_round_polys` is non-empty, the circuit verifies
    /// the eval batching sumcheck that binds OOD answers + shift-query
    /// values to the codeword MLE. Verifying this sumcheck closes the
    /// OOD-binding gap: a malicious prover who commits a non-proximal
    /// codeword cannot satisfy the sumcheck with arbitrary OOD answers,
    /// because the linear combination Σ ρ^k · v_k must match what the
    /// codeword's MLE implies at the derived challenge point.
    ///
    /// - `alpha_eval`: codeword MLE at `instance.eval_point` (first
    ///   claim in the batched list).
    /// - `ood_answers`: ν_k = codeword_MLE(ζ_k). Length = # OOD samples.
    /// - `ood_points`: the ζ_k points (LSB-first convention matching
    ///   the native prover's call into the batching sumcheck).
    /// - `rho`: batching challenge sampled from FS after the twin
    ///   sumcheck completes.
    /// - `eval_batch_round_polys`: 3-eval vectors, one per round,
    ///   `log_n` rounds total.
    /// - `eval_batch_challenges`: per-round sumcheck challenges.
    /// - `new_eval_claim`: the sumcheck's final eval claim; becomes the
    ///   new accumulator eval_claim.
    ///
    /// All are empty/zero when the caller does not request in-circuit
    /// batching verification.
    pub alpha_eval: F,
    pub ood_answers: Vec<F>,
    pub ood_points: Vec<Vec<F>>,
    pub rho: F,
    pub eval_batch_round_polys: Vec<[F; 3]>,
    pub eval_batch_challenges: Vec<F>,
    pub new_eval_claim: F,
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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        }
    }

    /// Attach shift-query authentication data to an already-constructed
    /// witness. The circuit emits one Merkle-verify sub-circuit per
    /// `(query, codeword)` pair, proving that `shift_input_values[q][i]`
    /// is the row at `shift_positions[q]` in the codeword whose Merkle
    /// root is `shift_codeword_roots[i]`.
    ///
    /// Non-union case: pass per-codeword roots in the same order as the
    /// prover arranged them (`[acc_root, fresh_root_0, …]`).
    /// Union case: pass `[union_root]` and a single path per query.
    ///
    /// `folding_factor` is the RS folding factor used to build the Merkle
    /// tree (leaf row width = 1 << folding_factor).
    #[must_use]
    pub fn with_shift_authentication(
        mut self,
        shift_positions: Vec<usize>,
        shift_input_values: Vec<Vec<Vec<F>>>,
        shift_auth_paths: Vec<Vec<Vec<Vec<F>>>>,
        folding_factor: usize,
        codeword_roots: Vec<Vec<F>>,
    ) -> Self {
        assert_eq!(shift_positions.len(), shift_input_values.len());
        assert_eq!(shift_positions.len(), shift_auth_paths.len());
        self.shift_positions = shift_positions;
        self.shift_input_values = shift_input_values;
        self.shift_auth_paths = shift_auth_paths;
        self.shift_folding_factor = folding_factor;
        self.shift_codeword_roots = codeword_roots;
        self
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
    let (folded_mu_var, folded_mu_val) = binary_tree_fold(
        builder,
        &all_mu_vars,
        &all_mu,
        &sumcheck_challenge_vars,
        &sumcheck_challenge_vals,
    );

    // Folded eta: eta' = sum_i eq(gamma, i) * eta_i
    let (folded_eta_var, folded_eta_val) = binary_tree_fold(
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

    // =============================================
    // Phase 4: Final evaluation check (H1 fix)
    // =============================================
    // Constrain: final_claimed == eq(τ, γ) · (folded_mu + ω · folded_eta)
    //
    // This is the sumcheck "final evaluation check" per WARP Construction 6.3:
    // after the sumcheck reduces P(b) = eq(τ,b)·(μ̃(b) + ω·η̃(b)) over {0,1}^{log l},
    // the final claimed value must equal the polynomial evaluated at the challenge point γ.

    // Step 1: Compute eq(τ, γ) = Π_j (τ_j · γ_j + (1 - τ_j) · (1 - γ_j))
    //        = Π_j (2·τ_j·γ_j - τ_j - γ_j + 1)
    // Cost: log_l multiplications (one τ·γ product + one running product per round)
    let mut eq_tau_gamma_var = builder.alloc_witness(F::ONE);
    builder.enforce_constant(eq_tau_gamma_var, F::ONE);
    let mut eq_tau_gamma_val = F::ONE;

    for j in 0..witness.num_rounds {
        // term_j = 2·τ_j·γ_j - τ_j - γ_j + 1
        let tau_gamma_val = tau_vals[j] * sumcheck_challenge_vals[j];
        let tau_gamma_var = builder.mul(tau_vars[j], sumcheck_challenge_vars[j], tau_gamma_val);

        let term_val = tau_gamma_val.double() - tau_vals[j] - sumcheck_challenge_vals[j] + F::ONE;
        let term_var = builder.alloc_witness(term_val);
        builder.enforce(
            LinearCombination::from_scaled(tau_gamma_var, F::TWO)
                - LinearCombination::from_var(tau_vars[j])
                - LinearCombination::from_var(sumcheck_challenge_vars[j])
                + LinearCombination::from_constant(F::ONE),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(term_var),
        );

        // Running product: eq_tau_gamma *= term_j
        eq_tau_gamma_val *= term_val;
        let new_eq_var = builder.mul(eq_tau_gamma_var, term_var, eq_tau_gamma_val);
        eq_tau_gamma_var = new_eq_var;
    }

    // Step 2: Compute folded_mu + ω · folded_eta
    let omega_eta_folded_val = witness.omega * folded_eta_val;
    let omega_eta_folded_var = builder.mul(witness_omega_var, folded_eta_var, omega_eta_folded_val);
    let mu_plus_omega_eta_val = folded_mu_val + omega_eta_folded_val;
    let mu_plus_omega_eta_var = builder.alloc_witness(mu_plus_omega_eta_val);
    builder.enforce(
        LinearCombination::from_var(folded_mu_var) + LinearCombination::from_var(omega_eta_folded_var),
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(mu_plus_omega_eta_var),
    );

    // Step 3: expected = eq(τ, γ) · (folded_mu + ω · folded_eta)
    let expected_final_val = eq_tau_gamma_val * mu_plus_omega_eta_val;
    let expected_final_var = builder.mul(eq_tau_gamma_var, mu_plus_omega_eta_var, expected_final_val);

    // Step 4: Constrain final_claimed == expected_final
    builder.enforce_equal(claimed_var, expected_final_var);

    // =============================================
    // Phase 5 — Shift-query Merkle authentication (bug_014 / Phase 3)
    // =============================================
    // For every committed codeword row the prover opened at a shift
    // position, re-hash the leaf and climb the path in-circuit against
    // the stored Merkle root. This is the WARP paper's Construction 7.2
    // shift-query check — it is what binds the commitment root to the
    // prover-claimed values that feed the eval-batching sumcheck.
    //
    // Two flavours, gated by `witness.shift_union_mode`:
    //   (a) Non-union — one Merkle path per (query, codeword) pair against
    //       the individual codeword root. Per-codeword `input_values[q][i]`
    //       IS the leaf row.
    //   (b) Union (Quasar multicast) — a single Merkle path per query into
    //       the union tree. The leaf row is reconstructed column-major:
    //       for each column `c`, concatenate `[v_0[c], v_1[c], …, v_{l-1}[c]]`.
    //
    // When `witness.shift_auth_paths` is empty (e.g. the caller did not
    // populate paths post-fold), Phase 5 is a no-op and the circuit
    // reverts to the pre-Phase-3 behaviour. This preserves backward
    // compatibility with tests / in-tree consumers that have not yet
    // been upgraded.
    if !witness.shift_auth_paths.is_empty() {
        debug_assert_eq!(
            witness.shift_positions.len(),
            witness.shift_auth_paths.len(),
            "shift_positions and shift_auth_paths must have matching lengths"
        );
        debug_assert_eq!(
            witness.shift_positions.len(),
            witness.shift_input_values.len(),
            "shift_positions and shift_input_values must have matching lengths"
        );

        // Allocate witness-shaped vars for every Merkle root once and reuse
        // across queries (a single commitment root is referenced by every
        // shift-query at that codeword index).
        let root_vars_per_codeword: alloc::vec::Vec<[Var; 8]> = witness
            .shift_codeword_roots
            .iter()
            .map(|root| {
                core::array::from_fn(|i| {
                    debug_assert!(i < root.len(), "commitment root shorter than 8 elements");
                    builder.alloc_witness(root[i])
                })
            })
            .collect();
        let root_vals_per_codeword: alloc::vec::Vec<[F; 8]> = witness
            .shift_codeword_roots
            .iter()
            .map(|root| core::array::from_fn(|i| root[i]))
            .collect();

        if witness.shift_union_mode {
            // ---------- Union-mode branch ----------
            // Single path per query, single root, column-major reconstructed
            // row.  Mirrors `verify_shift_queries_merkle_union` in
            // `warp/src/fold.rs`.
            debug_assert_eq!(
                root_vars_per_codeword.len(),
                1,
                "union mode expects a single Merkle root"
            );
            let union_root_vars = &root_vars_per_codeword[0];
            let union_root_vals = &root_vals_per_codeword[0];

            for q in 0..witness.shift_positions.len() {
                let pos = witness.shift_positions[q];
                let per_codeword_values = &witness.shift_input_values[q];
                let per_codeword_paths = &witness.shift_auth_paths[q];
                debug_assert_eq!(
                    per_codeword_paths.len(),
                    1,
                    "union mode expects exactly 1 auth path per query"
                );
                debug_assert!(
                    !per_codeword_values.is_empty(),
                    "union mode requires ≥ 1 codeword's row values"
                );

                let l_here = per_codeword_values.len();
                let per_codeword_width = per_codeword_values[0].len();
                // Reconstruct the union row: for each column c, push
                // [cw_0[c], cw_1[c], …, cw_{l-1}[c]].
                let mut union_row_vars: alloc::vec::Vec<Var> =
                    alloc::vec::Vec::with_capacity(per_codeword_width * l_here);
                let mut union_row_vals: alloc::vec::Vec<F> =
                    alloc::vec::Vec::with_capacity(per_codeword_width * l_here);
                for col in 0..per_codeword_width {
                    for codeword in per_codeword_values.iter() {
                        debug_assert_eq!(
                            codeword.len(),
                            per_codeword_width,
                            "all codewords must share the same row width",
                        );
                        let val = codeword[col];
                        let var = builder.alloc_witness(val);
                        union_row_vars.push(var);
                        union_row_vals.push(val);
                    }
                }

                // Allocate the single path.
                let auth_path = &per_codeword_paths[0];
                let path_vars: alloc::vec::Vec<[Var; 8]> = auth_path
                    .iter()
                    .map(|sibling| {
                        debug_assert_eq!(
                            sibling.len(),
                            8,
                            "sibling digest must be 8 elements"
                        );
                        core::array::from_fn(|i| builder.alloc_witness(sibling[i]))
                    })
                    .collect();
                let path_vals: alloc::vec::Vec<[F; 8]> = auth_path
                    .iter()
                    .map(|sibling| core::array::from_fn(|i| sibling[i]))
                    .collect();

                whir_circuit::merkle::merkle_verify_path_circuit::<F, L, P, WIDTH>(
                    builder,
                    poseidon_config,
                    perm,
                    &union_row_vars,
                    &union_row_vals,
                    pos,
                    &path_vars,
                    &path_vals,
                    union_root_vars,
                    union_root_vals,
                );
            }
        } else {
            // ---------- Per-codeword branch (non-union) ----------
            for q in 0..witness.shift_positions.len() {
                let pos = witness.shift_positions[q];
                let per_codeword_values = &witness.shift_input_values[q];
                let per_codeword_paths = &witness.shift_auth_paths[q];
                debug_assert_eq!(per_codeword_values.len(), per_codeword_paths.len());

                for (cw_idx, (row_vals, auth_path)) in per_codeword_values
                    .iter()
                    .zip(per_codeword_paths.iter())
                    .enumerate()
                {
                    // Allocate row witnesses.
                    let row_vars: alloc::vec::Vec<Var> =
                        row_vals.iter().map(|&v| builder.alloc_witness(v)).collect();

                    // Allocate path siblings as [Var; 8] per level.
                    let path_vars: alloc::vec::Vec<[Var; 8]> = auth_path
                        .iter()
                        .map(|sibling| {
                            debug_assert_eq!(
                                sibling.len(),
                                8,
                                "sibling digest must be 8 elements"
                            );
                            core::array::from_fn(|i| builder.alloc_witness(sibling[i]))
                        })
                        .collect();
                    let path_vals: alloc::vec::Vec<[F; 8]> = auth_path
                        .iter()
                        .map(|sibling| core::array::from_fn(|i| sibling[i]))
                        .collect();

                    // Pick the Merkle root this codeword was committed against.
                    let root_vars = &root_vars_per_codeword[cw_idx];
                    let root_vals = &root_vals_per_codeword[cw_idx];

                    // Emit the in-circuit Merkle path verification.
                    whir_circuit::merkle::merkle_verify_path_circuit::<F, L, P, WIDTH>(
                        builder,
                        poseidon_config,
                        perm,
                        &row_vars,
                        row_vals,
                        pos,
                        &path_vars,
                        &path_vals,
                        root_vars,
                        root_vals,
                    );
                }
            }
        }
    }

    // =============================================
    // Phase 6 — Evaluation-batching sumcheck + OOD binding (Phase 3.5)
    // =============================================
    // Verifies the sumcheck that reduces (folded-α eval claim, OOD answers,
    // shift-query values) into a single claim against the committed folded
    // codeword.  This closes the OOD-binding gap: a malicious prover who
    // commits a non-proximal codeword cannot satisfy the sumcheck with
    // arbitrary OOD answers, because
    //   initial_claim = Σ_k ρ^k · v_k
    // must equal the sumcheck's first-round sum — and with random ρ this
    // forces each `v_k` to match the codeword MLE at `p_k`.
    //
    // FS replay ordering matches `warp_fold_prove_rs_inner`:
    //   1. Shift-query positions (one observe/sample per query)
    //   2. OOD sampling (one observe/sample for the univariate challenge,
    //      then one observe/sample absorbing the prover's answer)
    //   3. ρ (observe counter, sample)
    //   4. log_n eval-batch rounds (observe 3 round evals, sample r)
    //
    // When `eval_batch_round_polys` is empty (e.g. prover didn't commit the
    // codeword, or tests that pre-date Phase 3.5), this block is a no-op.
    if !witness.eval_batch_round_polys.is_empty() {
        debug_assert_eq!(
            witness.eval_batch_challenges.len(),
            witness.eval_batch_round_polys.len(),
            "eval_batch_challenges must have the same length as eval_batch_round_polys"
        );

        let num_shift = witness.shift_positions.len();
        let num_ood = witness.ood_answers.len();
        let log_n_batch = witness.eval_batch_round_polys.len();

        // ---- Step 6.1: replay FS — shift-query positions ----
        for q in 0..num_shift {
            let counter_val = F::from_usize(q);
            let counter_var = builder.alloc_witness(counter_val);
            builder.enforce_constant(counter_var, counter_val);
            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &[counter_var],
                &[counter_val],
            );
            let _ = challenger.sample::<L, P>(builder, poseidon_config, perm);
        }

        // ---- Step 6.2: replay FS — OOD sampling ----
        for k in 0..num_ood {
            // Univariate challenge counter = `k + num_shift + 1000`.
            let counter_val = F::from_usize(k + num_shift + 1000);
            let counter_var = builder.alloc_witness(counter_val);
            builder.enforce_constant(counter_var, counter_val);
            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &[counter_var],
                &[counter_val],
            );
            let _ = challenger.sample::<L, P>(builder, poseidon_config, perm);

            // Absorb the prover's OOD answer.
            let answer_val = witness.ood_answers[k];
            let answer_var = builder.alloc_witness(answer_val);
            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &[answer_var],
                &[answer_val],
            );
            let _ = challenger.sample::<L, P>(builder, poseidon_config, perm);
        }

        // ---- Step 6.3: derive ρ and bind to `witness.rho` ----
        let rho_counter_val = F::from_usize(2000);
        let rho_counter_var = builder.alloc_witness(rho_counter_val);
        builder.enforce_constant(rho_counter_var, rho_counter_val);
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[rho_counter_var],
            &[rho_counter_val],
        );
        let (derived_rho_var, _derived_rho_val) =
            challenger.sample::<L, P>(builder, poseidon_config, perm);
        let rho_var = builder.alloc_witness(witness.rho);
        builder.enforce_equal(derived_rho_var, rho_var);

        // ---- Step 6.4: reconstruct initial claim  Σ_k ρ^k · v_k ----
        // v_0        = alpha_eval (first claim — codeword MLE at folded α)
        // v_1..=no   = ood_answers   (ν_k)
        // v_no+1..   = folded shift-query col-0 values
        //
        // Layout: initial_claim_val/var tracks running total;
        //         rho_pow_val/var tracks ρ^k.
        let alpha_eval_var = builder.alloc_witness(witness.alpha_eval);

        let mut claim_val = witness.alpha_eval;
        let mut claim_var = alpha_eval_var;

        let mut rho_pow_val = F::ONE;
        let mut rho_pow_var = builder.alloc_witness(F::ONE);
        builder.enforce_constant(rho_pow_var, F::ONE);

        // Helper: bump ρ^k → ρ^{k+1}.
        let bump_rho_pow =
            |builder: &mut CircuitBuilder<F>,
             rho_pow_var: &mut Var,
             rho_pow_val: &mut F,
             rho_var: Var,
             rho_val: F| {
                let new_val = *rho_pow_val * rho_val;
                let new_var = builder.mul(*rho_pow_var, rho_var, new_val);
                *rho_pow_var = new_var;
                *rho_pow_val = new_val;
            };

        let rho_val = witness.rho;

        // OOD contributions  v_1..=num_ood
        for k in 0..num_ood {
            bump_rho_pow(
                builder,
                &mut rho_pow_var,
                &mut rho_pow_val,
                rho_var,
                rho_val,
            );
            let v_val = witness.ood_answers[k];
            let v_var = builder.alloc_witness(v_val);
            let prod_val = rho_pow_val * v_val;
            let prod_var = builder.mul(rho_pow_var, v_var, prod_val);
            let new_claim_val = claim_val + prod_val;
            let new_claim_var = builder.alloc_witness(new_claim_val);
            builder.enforce(
                LinearCombination::from_var(claim_var)
                    + LinearCombination::from_var(prod_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(new_claim_var),
            );
            claim_var = new_claim_var;
            claim_val = new_claim_val;
        }

        // Shift-query contributions — the batched value is the folded
        // codeword's column-0 entry at the query row, which equals
        //     Σ_i eq(γ, i) · v_{i,0}
        // where `v_{i,0}` = first-column value of the i-th input row.
        for q in 0..num_shift {
            let per_codeword_values = &witness.shift_input_values[q];
            debug_assert!(
                !per_codeword_values.is_empty(),
                "shift-query {q} has no per-codeword values"
            );

            // Collect column-0 per-input-codeword values.
            let col0_vals: alloc::vec::Vec<F> =
                per_codeword_values.iter().map(|row| row[0]).collect();
            let col0_vars: alloc::vec::Vec<Var> = col0_vals
                .iter()
                .map(|&v| builder.alloc_witness(v))
                .collect();

            // Fold with the sumcheck challenges γ (= `sumcheck_challenge_*`).
            let (folded_col0_var, folded_col0_val) = binary_tree_fold(
                builder,
                &col0_vars,
                &col0_vals,
                &sumcheck_challenge_vars,
                &sumcheck_challenge_vals,
            );

            bump_rho_pow(
                builder,
                &mut rho_pow_var,
                &mut rho_pow_val,
                rho_var,
                rho_val,
            );
            let prod_val = rho_pow_val * folded_col0_val;
            let prod_var = builder.mul(rho_pow_var, folded_col0_var, prod_val);
            let new_claim_val = claim_val + prod_val;
            let new_claim_var = builder.alloc_witness(new_claim_val);
            builder.enforce(
                LinearCombination::from_var(claim_var)
                    + LinearCombination::from_var(prod_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(new_claim_var),
            );
            claim_var = new_claim_var;
            claim_val = new_claim_val;
        }

        // ---- Step 6.5: verify each sumcheck round ----
        // Per round: observe [e0, e1, e2], sample r; enforce
        //   e0 + e1 == current_claim
        //   current_claim <- h(r), where h is the degree-2 poly through
        //                           (0, e0), (1, e1), (2, e2).
        let mut current_claim_var = claim_var;
        let mut current_claim_val = claim_val;

        for round in 0..log_n_batch {
            let [e0_val, e1_val, e2_val] = witness.eval_batch_round_polys[round];

            let e0_var = builder.alloc_witness(e0_val);
            let e1_var = builder.alloc_witness(e1_val);
            let e2_var = builder.alloc_witness(e2_val);

            challenger.observe_slice::<L, P>(
                builder,
                poseidon_config,
                perm,
                &[e0_var, e1_var, e2_var],
                &[e0_val, e1_val, e2_val],
            );

            // e0 + e1 == current_claim
            builder.enforce(
                LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(current_claim_var),
            );

            let (r_var, r_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
            let expected_r = witness.eval_batch_challenges[round];
            // Bind the witness-provided challenge to the FS-derived one.
            let witness_r_var = builder.alloc_witness(expected_r);
            builder.enforce_equal(r_var, witness_r_var);
            debug_assert_eq!(
                r_val, expected_r,
                "batching sumcheck: round {round} FS-derived challenge != witness"
            );

            // h(r) = e0 + d*r + c2*r*(r-1)
            //        with d  = e1 - e0
            //             c2 = (e2 - 2·e1 + e0) / 2
            let d_val = e1_val - e0_val;
            let d_var = builder.alloc_witness(d_val);
            builder.enforce(
                LinearCombination::from_var(e1_var) - LinearCombination::from_var(e0_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(d_var),
            );

            let dr_val = d_val * r_val;
            let dr_var = builder.mul(d_var, r_var, dr_val);

            let c2_val = (e2_val - e1_val.double() + e0_val) * F::TWO.inverse();
            let c2_var = builder.alloc_witness(c2_val);
            builder.enforce(
                LinearCombination::from_constant(F::TWO),
                LinearCombination::from_var(c2_var),
                LinearCombination::from_var(e2_var)
                    - LinearCombination::from_scaled(e1_var, F::TWO)
                    + LinearCombination::from_var(e0_var),
            );

            let rm1_val = r_val - F::ONE;
            let rm1_var = builder.alloc_witness(rm1_val);
            builder.enforce(
                LinearCombination::from_var(r_var) - LinearCombination::from_constant(F::ONE),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(rm1_var),
            );
            let r_rm1_val = r_val * rm1_val;
            let r_rm1_var = builder.mul(r_var, rm1_var, r_rm1_val);

            let c2_r_rm1_val = c2_val * r_rm1_val;
            let c2_r_rm1_var = builder.mul(c2_var, r_rm1_var, c2_r_rm1_val);

            let result_val = e0_val + dr_val + c2_r_rm1_val;
            let result_var = builder.alloc_witness(result_val);
            builder.enforce(
                LinearCombination::from_var(e0_var)
                    + LinearCombination::from_var(dr_var)
                    + LinearCombination::from_var(c2_r_rm1_var),
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(result_var),
            );

            current_claim_var = result_var;
            current_claim_val = result_val;
        }

        // ---- Step 6.6: final claim must equal witness.new_eval_claim ----
        let new_eval_claim_var = builder.alloc_witness(witness.new_eval_claim);
        builder.enforce_equal(current_claim_var, new_eval_claim_var);
        debug_assert_eq!(
            current_claim_val, witness.new_eval_claim,
            "batching sumcheck: final claim != witness.new_eval_claim",
        );
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

    use p3_koala_bear::{KoalaBear, GenericPoseidon2LinearLayersKoalaBear, Poseidon2KoalaBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;
    use crate::ivc::step::TrivialStepCircuit;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
    type MyChal = DuplexChallenger<F, Perm, 16, 8>;

    /// Construct CORRECT sumcheck round polynomials from the actual twin-constraint
    /// polynomial P(b) = eq(τ,b) · target(b), and advance the FS challenger.
    ///
    /// This mirrors what `twin_constraint_sumcheck` does: at each round, evaluate the
    /// degree-2 univariate at points 0, 1, 2 from the tau and target tables, then fold.
    fn construct_correct_round_polys(
        mu: &[F],
        eta: &[F],
        omega: F,
        tau_challenges: &[F],
        native_chal: &mut MyChal,
    ) -> Vec<[F; 3]> {
        use p3_challenger::{CanObserve, CanSample};
        use crate::spartan::encoding::eq_poly_at_index;

        let l = mu.len();
        let log_l = tau_challenges.len();
        assert_eq!(l, 1 << log_l);

        // Build tau eq-evals and target table (same as twin_constraint_sumcheck)
        let mut tau_evals: Vec<F> = (0..l)
            .map(|idx| eq_poly_at_index::<F, F>(idx, tau_challenges))
            .collect();
        let mut target_table: Vec<F> = (0..l)
            .map(|i| mu[i] + omega * eta[i])
            .collect();

        let mut round_polys = Vec::with_capacity(log_l);

        for _ in 0..log_l {
            let half = tau_evals.len() / 2;

            // Evaluate degree-2 univariate at 0, 1, 2
            let mut evals = [F::ZERO; 3];
            for i in 0..half {
                let t_lo = tau_evals[2 * i];
                let t_hi = tau_evals[2 * i + 1];
                let v_lo = target_table[2 * i];
                let v_hi = target_table[2 * i + 1];
                let t_d = t_hi - t_lo;
                let v_d = v_hi - v_lo;
                evals[0] += t_lo * v_lo;
                evals[1] += t_hi * v_hi;
                evals[2] += (t_lo + t_d.double()) * (v_lo + v_d.double());
            }

            round_polys.push([evals[0], evals[1], evals[2]]);

            // Observe into native challenger and sample challenge
            native_chal.observe(evals[0]);
            native_chal.observe(evals[1]);
            native_chal.observe(evals[2]);
            let r: F = native_chal.sample();

            // Fold tables
            for i in 0..half {
                tau_evals[i] =
                    tau_evals[2 * i] + r * (tau_evals[2 * i + 1] - tau_evals[2 * i]);
                target_table[i] =
                    target_table[2 * i] + r * (target_table[2 * i + 1] - target_table[2 * i]);
            }
            tau_evals.truncate(half);
            target_table.truncate(half);
        }

        round_polys
    }

    #[test]
    fn warp_fold_verifier_circuit_satisfiable() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

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

        // Construct correct round polys from the actual twin-constraint polynomial
        let round_polys =
            construct_correct_round_polys(&eval_claims, &pesat_targets, omega, &[tau_0], &mut native_chal);

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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let output = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
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
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));
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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut builder_with = CircuitBuilder::<F>::new();
        let mut chal_with = CircuitChallenger::<F, 16, 8>::new(&mut builder_with);
        let (_, fold_out) = synthesize_warp_ivc_circuit::<
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
        assert!(fold_out.is_some(), "fold output should be present");
        let target = builder_with.num_witness_vars();

        // WITHOUT verifier, padded to same size
        let mut builder_without = CircuitBuilder::<F>::new();
        let mut chal_without = CircuitChallenger::<F, 16, 8>::new(&mut builder_without);
        let (_, fold_out_none) = synthesize_warp_ivc_circuit::<
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
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };
        let mut warp_builder = CircuitBuilder::<F>::new();
        let mut warp_chal = CircuitChallenger::<F, 16, 8>::new(&mut warp_builder);
        let _ = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
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
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

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

        // l=4 -> log_l=2 -> 2 sumcheck rounds from actual polynomial
        let round_polys =
            construct_correct_round_polys(&all_eval_claims, &all_pesat_targets, omega, &[tau_0, tau_1], &mut native_chal);

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
            GenericPoseidon2LinearLayersKoalaBear,
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
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut nonunion_builder = CircuitBuilder::<F>::new();
        let mut nonunion_chal = CircuitChallenger::<F, 16, 8>::new(&mut nonunion_builder);
        let _ = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
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
            GenericPoseidon2LinearLayersKoalaBear,
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
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));
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
                shift_positions: Vec::new(),
                shift_input_values: Vec::new(),
                shift_auth_paths: Vec::new(),
                shift_folding_factor: 0,
                shift_codeword_roots: Vec::new(),
                shift_union_mode: false,
                alpha_eval: F::ZERO,
                ood_answers: Vec::new(),
                ood_points: Vec::new(),
                rho: F::ZERO,
                eval_batch_round_polys: Vec::new(),
                eval_batch_challenges: Vec::new(),
                new_eval_claim: F::ZERO,
            };

            let mut b1 = CircuitBuilder::<F>::new();
            let mut c1 = CircuitChallenger::<F, 16, 8>::new(&mut b1);
            let _ = synthesize_warp_fold_verifier::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
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
                GenericPoseidon2LinearLayersKoalaBear,
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

    #[test]
    fn warp_fold_verifier_circuit_rejects_wrong_sigma0() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

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
        let _tau_0: F = native_chal.sample();

        // Sample fresh_betas
        for _ in 0..num_fresh * log_m {
            let _: F = native_chal.sample();
        }

        // Use WRONG round polys that do NOT satisfy h(0)+h(1) == sigma_0.
        // This means the C2 constraint (e0 + e1 = claimed) will fail.
        let bad_round_polys = vec![[F::from_u64(99), F::from_u64(99), F::from_u64(99)]];

        let witness = WarpFoldVerifierWitness {
            input_commitment_roots: roots,
            input_eval_claims: eval_claims.clone(),
            input_eval_points: eval_points.clone(),
            input_pesat_targets: pesat_targets.clone(),
            sumcheck_evals: bad_round_polys,
            num_rounds: 1,
            omega,
            num_fresh,
            log_m,
            union_commitment_root: None,
            all_eval_claims: Some(eval_claims),
            all_pesat_targets: Some(pesat_targets),
            all_eval_points: Some(eval_points),
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let _output = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            16,
            8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            !shape.is_sat(instance.witness(), instance.input()),
            "circuit should be unsatisfiable with wrong sigma_0 (h(0)+h(1) != sigma_0)"
        );
    }

    #[test]
    fn warp_fold_verifier_circuit_rejects_wrong_omega() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

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
        let correct_omega: F = native_chal.sample();

        // Use a WRONG omega that does not match Poseidon2 derivation
        let wrong_omega = F::from_u64(12345);
        assert_ne!(correct_omega, wrong_omega, "test sanity: omegas should differ");

        // l=2: 1 round of sumcheck, 1 fresh instance, log_m=2
        let num_fresh = 1;
        let log_m = 2;

        // Sample tau from native challenger (to keep state, but we'll use wrong omega)
        let tau_0: F = native_chal.sample();

        // Sample fresh_betas
        for _ in 0..num_fresh * log_m {
            let _: F = native_chal.sample();
        }

        // Construct round polys using the WRONG omega. The circuit will derive the correct
        // omega and the constraint derived_omega == witness.omega will fail.
        let round_polys =
            construct_correct_round_polys(&eval_claims, &pesat_targets, wrong_omega, &[tau_0], &mut native_chal);

        let witness = WarpFoldVerifierWitness {
            input_commitment_roots: roots,
            input_eval_claims: eval_claims.clone(),
            input_eval_points: eval_points.clone(),
            input_pesat_targets: pesat_targets.clone(),
            sumcheck_evals: round_polys,
            num_rounds: 1,
            omega: wrong_omega, // WRONG omega
            num_fresh,
            log_m,
            union_commitment_root: None,
            all_eval_claims: Some(eval_claims),
            all_pesat_targets: Some(pesat_targets),
            all_eval_points: Some(eval_points),
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        let _output = synthesize_warp_fold_verifier::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            16,
            8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            !shape.is_sat(instance.witness(), instance.input()),
            "circuit should be unsatisfiable with wrong omega (Fiat-Shamir binding violated)"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 3 — in-circuit Merkle-path authentication tests.
    // ══════════════════════════════════════════════════════════════════════

    /// Shared helper: produce one valid Merkle proof (position 2 of a 4-row,
    /// 4-wide matrix) using the same Poseidon2 configuration as the circuit.
    fn build_sample_merkle_opening(
    ) -> (alloc::vec::Vec<F>, alloc::vec::Vec<[F; 8]>, [F; 8], usize, usize) {
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

        type LocalHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        type LocalCompress = TruncatedPermutation<Perm, 2, 8, 16>;

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let hasher = LocalHash::new(perm.clone());
        let compress = LocalCompress::new(perm);

        let rows: alloc::vec::Vec<F> = (0..16).map(|i| F::from_u64(i as u64 + 1)).collect();
        let matrix = RowMajorMatrix::new(rows.clone(), 4);
        let mmcs: MerkleTreeMmcs<_, _, _, _, 8> =
            MerkleTreeMmcs::<F, F, _, _, 8>::new(hasher, compress);
        let (root_hash, tree) = mmcs.commit(alloc::vec![matrix]);
        let root: [F; 8] = root_hash.into();

        let position: usize = 2;
        let row_width = 4;
        let opening = mmcs.open_batch(position, &tree);
        let (opened, proof) = opening.unpack();
        let leaf_row: alloc::vec::Vec<F> = opened.into_iter().next().unwrap();

        (leaf_row, proof, root, position, row_width)
    }

    /// Honest shift-query data must produce a satisfiable in-circuit
    /// verifier. This confirms the Phase-5 wiring matches the native
    /// Merkle verify primitive.
    #[test]
    fn warp_fold_verifier_accepts_honest_shift_paths() {
        use p3_challenger::{CanObserve, CanSample};
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            rf, rp, 3, &mut SmallRng::seed_from_u64(99),
        );

        let (leaf_row, proof, root_arr, position, _row_width) = build_sample_merkle_opening();

        // Minimal valid twin-constraint setup (l=2, 1 round) so the rest
        // of the verifier accepts; we only care about Phase 5 here.
        let roots: alloc::vec::Vec<alloc::vec::Vec<F>> = vec![vec![F::ZERO; 8]; 2];
        let eval_points: alloc::vec::Vec<alloc::vec::Vec<F>> = vec![vec![F::ZERO; 3]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] { native_chal.observe(val); }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] { native_chal.observe(val); }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }

        let round_polys = construct_correct_round_polys(
            &eval_claims, &pesat_targets, omega, &[tau_0], &mut native_chal);

        // Attach a single shift query with honest Merkle data.
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
            shift_positions: vec![position],
            shift_input_values: vec![vec![leaf_row.clone()]],
            shift_auth_paths: vec![vec![proof.iter().map(|s| s.to_vec()).collect()]],
            shift_folding_factor: 2,
            shift_codeword_roots: vec![root_arr.to_vec()],
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "honest Phase-5 Merkle verification must be satisfiable"
        );
    }

    /// Tampering a shift-query **value** must make the circuit unsatisfiable
    /// — the Merkle-verify gadget's root equality constraint fails.
    #[test]
    #[should_panic(expected = "derived root")]
    fn warp_fold_verifier_rejects_tampered_shift_value() {
        use p3_challenger::{CanObserve, CanSample};
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            rf, rp, 3, &mut SmallRng::seed_from_u64(99),
        );

        let (mut leaf_row, proof, root_arr, position, _row_width) = build_sample_merkle_opening();
        // Tamper: flip one row element.
        leaf_row[0] += F::ONE;

        let roots: alloc::vec::Vec<alloc::vec::Vec<F>> = vec![vec![F::ZERO; 8]; 2];
        let eval_points: alloc::vec::Vec<alloc::vec::Vec<F>> = vec![vec![F::ZERO; 3]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] { native_chal.observe(val); }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] { native_chal.observe(val); }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }

        let round_polys = construct_correct_round_polys(
            &eval_claims, &pesat_targets, omega, &[tau_0], &mut native_chal);

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
            shift_positions: vec![position],
            shift_input_values: vec![vec![leaf_row]],
            shift_auth_paths: vec![vec![proof.iter().map(|s| s.to_vec()).collect()]],
            shift_folding_factor: 2,
            shift_codeword_roots: vec![root_arr.to_vec()],
            shift_union_mode: false,
            alpha_eval: F::ZERO,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: F::ZERO,
            eval_batch_round_polys: Vec::new(),
            eval_batch_challenges: Vec::new(),
            new_eval_claim: F::ZERO,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        // The gadget asserts derived_root == expected_root at compile/
        // synthesis time — so this call panics (should_panic covers it).
        // If the assertion were removed, the resulting R1CS would also
        // be unsatisfiable because the enforce_equal constraint fails.
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);
    }

    // =======================================================================
    // Phase 3.5 — eval-batching sumcheck + union-mode Merkle verification
    // =======================================================================

    /// Synthetic helper: build a Merkle commitment of a 2-codeword union
    /// tree and return:
    ///   (per-codeword rows at query position, auth path, union root,
    ///    query position, per-codeword row width, codewords for sanity).
    ///
    /// Layout matches `build_union_codeword` (column-major interleaved) and
    /// `union_folding_factor(base_ff=2, l=2) = 3` (leaf width = 8).
    #[allow(clippy::type_complexity)]
    fn build_sample_union_merkle_opening() -> (
        alloc::vec::Vec<alloc::vec::Vec<F>>,
        alloc::vec::Vec<[F; 8]>,
        [F; 8],
        usize,
        usize,
    ) {
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

        type LocalHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        type LocalCompress = TruncatedPermutation<Perm, 2, 8, 16>;

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let hasher = LocalHash::new(perm.clone());
        let compress = LocalCompress::new(perm);

        // l=2 codewords of length 8 each → union codeword of length 16,
        // committed with row width 8 → tree height 2 (1 level path).
        let n = 8;
        let l = 2;
        let cw_0: alloc::vec::Vec<F> = (0..n).map(|i| F::from_u64(10 + i as u64)).collect();
        let cw_1: alloc::vec::Vec<F> = (0..n).map(|i| F::from_u64(100 + i as u64)).collect();
        let codewords = alloc::vec![cw_0.clone(), cw_1.clone()];
        let union = crate::warp::encoding::build_union_codeword(&codewords);
        debug_assert_eq!(union.len(), n * l);

        let row_width = 8; // = 1 << union_folding_factor (2 + log2(2) = 3)
        let per_codeword_width = row_width / l; // = 4

        let matrix = RowMajorMatrix::new(union.clone(), row_width);
        let mmcs: MerkleTreeMmcs<_, _, _, _, 8> =
            MerkleTreeMmcs::<F, F, _, _, 8>::new(hasher, compress);
        let (root_hash, tree) = mmcs.commit(alloc::vec![matrix]);
        let root: [F; 8] = root_hash.into();

        let position: usize = 1;
        let opening = mmcs.open_batch(position, &tree);
        let (_opened, proof) = opening.unpack();

        // Per-codeword rows at `position`: codeword_i[pos*per_codeword_width + col]
        let per_codeword_rows: alloc::vec::Vec<alloc::vec::Vec<F>> = codewords
            .iter()
            .map(|cw| {
                cw[position * per_codeword_width..(position + 1) * per_codeword_width].to_vec()
            })
            .collect();

        (per_codeword_rows, proof, root, position, per_codeword_width)
    }

    /// Honest Phase-6 (eval-batching sumcheck) data must produce a
    /// satisfiable in-circuit verifier.  No shift / OOD contributions;
    /// we exercise a single synthetic round where
    ///   initial_claim = alpha_eval
    /// and the witness-supplied `new_eval_claim` = h(r) for the sampled r.
    #[test]
    fn warp_fold_verifier_accepts_honest_batching_sumcheck() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

        // Minimal twin-constraint setup (l=2, 1 round, all-zero claims).
        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] { native_chal.observe(val); }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] { native_chal.observe(val); }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }

        let round_polys = construct_correct_round_polys(
            &eval_claims, &pesat_targets, omega, &[tau_0], &mut native_chal);

        // Phase 6 FS replay — no shift, no OOD, sample rho directly.
        native_chal.observe(F::from_usize(2000));
        let rho: F = native_chal.sample();

        // Build one synthetic batching round with e0 + e1 = alpha_eval.
        let alpha_eval = F::from_u64(17);
        let e0 = F::from_u64(5);
        let e1 = alpha_eval - e0;
        let e2 = F::from_u64(7);
        native_chal.observe(e0);
        native_chal.observe(e1);
        native_chal.observe(e2);
        let r: F = native_chal.sample();

        // Compute h(r) matching the circuit's degree-2 evaluation formula.
        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        let new_eval_claim = e0 + c1 * r + c2 * r * r;

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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho,
            eval_batch_round_polys: vec![[e0, e1, e2]],
            eval_batch_challenges: vec![r],
            new_eval_claim,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "honest Phase-6 batching sumcheck verification must be satisfiable"
        );
    }

    /// Tampering `alpha_eval` breaks the Phase-6 initial-claim check —
    /// `e0 + e1 == current_claim` fails because current_claim now differs
    /// from the (tampered) alpha_eval.
    #[test]
    fn warp_fold_verifier_rejects_tampered_alpha_eval() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] { native_chal.observe(val); }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] { native_chal.observe(val); }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }

        let round_polys = construct_correct_round_polys(
            &eval_claims, &pesat_targets, omega, &[tau_0], &mut native_chal);

        native_chal.observe(F::from_usize(2000));
        let rho: F = native_chal.sample();

        let alpha_eval = F::from_u64(17);
        let e0 = F::from_u64(5);
        let e1 = alpha_eval - e0;
        let e2 = F::from_u64(7);
        native_chal.observe(e0);
        native_chal.observe(e1);
        native_chal.observe(e2);
        let r: F = native_chal.sample();

        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        let new_eval_claim = e0 + c1 * r + c2 * r * r;

        // Tamper: claim a different alpha_eval than what (e0, e1) sums to.
        let tampered_alpha = alpha_eval + F::ONE;

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
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval: tampered_alpha,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho,
            eval_batch_round_polys: vec![[e0, e1, e2]],
            eval_batch_challenges: vec![r],
            new_eval_claim,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            !shape.is_sat(instance.witness(), instance.input()),
            "tampered alpha_eval must make Phase-6 R1CS unsatisfiable"
        );
    }

    /// Tampering `rho` breaks the Fiat-Shamir binding: the circuit
    /// re-derives rho from the sponge, so a mismatched witness.rho hits
    /// the `enforce_equal(derived_rho, witness_rho)` constraint.
    #[test]
    fn warp_fold_verifier_rejects_tampered_rho() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config =
            Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut SmallRng::seed_from_u64(99));

        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let pesat_targets = vec![F::ZERO; 2];

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for i in 0..2 {
            for &val in &roots[i] { native_chal.observe(val); }
            native_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] { native_chal.observe(val); }
            native_chal.observe(pesat_targets[i]);
        }
        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }
        let round_polys = construct_correct_round_polys(
            &eval_claims, &pesat_targets, omega, &[tau_0], &mut native_chal);

        native_chal.observe(F::from_usize(2000));
        let rho: F = native_chal.sample();
        let alpha_eval = F::from_u64(17);
        let e0 = F::from_u64(5);
        let e1 = alpha_eval - e0;
        let e2 = F::from_u64(7);
        native_chal.observe(e0);
        native_chal.observe(e1);
        native_chal.observe(e2);
        let r: F = native_chal.sample();
        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        let new_eval_claim = e0 + c1 * r + c2 * r * r;

        let witness = WarpFoldVerifierWitness {
            input_commitment_roots: roots,
            input_eval_claims: eval_claims.clone(),
            input_eval_points: eval_points.clone(),
            input_pesat_targets: pesat_targets.clone(),
            sumcheck_evals: round_polys,
            num_rounds: 1, omega, num_fresh, log_m,
            union_commitment_root: None,
            all_eval_claims: Some(eval_claims),
            all_pesat_targets: Some(pesat_targets),
            all_eval_points: Some(eval_points),
            shift_positions: Vec::new(),
            shift_input_values: Vec::new(),
            shift_auth_paths: Vec::new(),
            shift_folding_factor: 0,
            shift_codeword_roots: Vec::new(),
            shift_union_mode: false,
            alpha_eval,
            ood_answers: Vec::new(),
            ood_points: Vec::new(),
            rho: rho + F::ONE, // TAMPER
            eval_batch_round_polys: vec![[e0, e1, e2]],
            eval_batch_challenges: vec![r],
            new_eval_claim,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            !shape.is_sat(instance.witness(), instance.input()),
            "tampered rho must break the FS binding"
        );
    }

    /// Honest union-mode Merkle authentication must produce a satisfiable
    /// in-circuit verifier (Phase 5 — union branch).
    #[test]
    fn warp_fold_verifier_accepts_honest_union_merkle() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            rf, rp, 3, &mut SmallRng::seed_from_u64(99),
        );

        let (per_codeword_rows, proof, union_root, position, _) =
            build_sample_union_merkle_opening();

        // Minimal twin-constraint setup — we only care that the union-mode
        // Merkle branch of Phase 5 accepts.  l=2, log_l=1, so num_rounds=1.
        let running_root = vec![F::ZERO; 8];
        let running_eval_claim = F::ZERO;
        let running_eval_point = vec![F::ZERO; 3];
        let running_pesat_target = F::ZERO;

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        // Non-union FS absorbs each accumulator; union FS absorbs only the
        // running acc + union root (see Phase 1 union branch).
        for &v in &running_root { native_chal.observe(v); }
        native_chal.observe(running_eval_claim);
        for &v in &running_eval_point { native_chal.observe(v); }
        native_chal.observe(running_pesat_target);
        for &v in &union_root { native_chal.observe(v); }

        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }

        // All-zero mu/eta for l=2 → round polys that sum to zero.
        let all_mu = vec![F::ZERO; 2];
        let all_eta = vec![F::ZERO; 2];
        let round_polys = construct_correct_round_polys(
            &all_mu, &all_eta, omega, &[tau_0], &mut native_chal);

        let witness = WarpFoldVerifierWitness::from_fold_result_union(
            running_root,
            running_eval_claim,
            running_eval_point,
            running_pesat_target,
            union_root.to_vec(),
            &round_polys.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
            omega,
            num_fresh,
            log_m,
            all_mu,
            all_eta,
            vec![vec![F::ZERO; 3]; 2],
        )
        .with_shift_authentication(
            vec![position],
            vec![per_codeword_rows],
            vec![vec![proof.iter().map(|s| s.to_vec()).collect()]],
            2, // base folding factor
            vec![union_root.to_vec()],
        );

        // Flip union mode on (not done by `with_shift_authentication`).
        let mut witness = witness;
        witness.shift_union_mode = true;

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "honest union-mode Phase-5 verification must be satisfiable"
        );
    }

    /// Tampering one per-codeword row value in union mode must invalidate
    /// the Merkle opening against the union root.
    #[test]
    #[should_panic(expected = "derived root")]
    fn warp_fold_verifier_union_rejects_tampered_value() {
        use p3_challenger::{CanObserve, CanSample};

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let poseidon_config = Poseidon2CircuitConfig::<F, 16>::from_rng(
            rf, rp, 3, &mut SmallRng::seed_from_u64(99),
        );

        let (mut per_codeword_rows, proof, union_root, position, _) =
            build_sample_union_merkle_opening();
        // Tamper: flip one column of codeword 0.
        per_codeword_rows[0][0] += F::ONE;

        let running_root = vec![F::ZERO; 8];
        let running_eval_claim = F::ZERO;
        let running_eval_point = vec![F::ZERO; 3];
        let running_pesat_target = F::ZERO;

        let mut native_chal = MyChal::new(poseidon_perm.clone());
        for &v in &running_root { native_chal.observe(v); }
        native_chal.observe(running_eval_claim);
        for &v in &running_eval_point { native_chal.observe(v); }
        native_chal.observe(running_pesat_target);
        for &v in &union_root { native_chal.observe(v); }

        let omega: F = native_chal.sample();
        let tau_0: F = native_chal.sample();
        let num_fresh = 1;
        let log_m = 2;
        for _ in 0..num_fresh * log_m { let _: F = native_chal.sample(); }
        let all_mu = vec![F::ZERO; 2];
        let all_eta = vec![F::ZERO; 2];
        let round_polys = construct_correct_round_polys(
            &all_mu, &all_eta, omega, &[tau_0], &mut native_chal);

        let mut witness = WarpFoldVerifierWitness::from_fold_result_union(
            running_root,
            running_eval_claim,
            running_eval_point,
            running_pesat_target,
            union_root.to_vec(),
            &round_polys.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
            omega,
            num_fresh,
            log_m,
            all_mu,
            all_eta,
            vec![vec![F::ZERO; 3]; 2],
        )
        .with_shift_authentication(
            vec![position],
            vec![per_codeword_rows],
            vec![vec![proof.iter().map(|s| s.to_vec()).collect()]],
            2,
            vec![union_root.to_vec()],
        );
        witness.shift_union_mode = true;

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        // The merkle gadget asserts derived_root == expected_root, so this
        // call panics with "derived root[...] does not match expected".
        let _ = synthesize_warp_fold_verifier::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, 16, 8,
        >(&mut builder, &mut challenger, &poseidon_config, &poseidon_perm, &witness);
    }
}
