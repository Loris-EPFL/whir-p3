//! WARP fold prover: reduces l instances + running accumulator into one accumulator.
//!
//! This implements the WARP accumulation prover (Phase 1-2 from the plan):
//! 1. PESAT reduction: encode fresh witnesses, commit, derive randomness
//! 2. Twin-constraint sumcheck: fold codeword proximity + R1CS satisfaction
//!
//! After the sumcheck, the folded codeword, witness, eval point, and PESAT
//! point are extracted — all at the original fixed size.
//!
//! Phase 3 (codeword batching via OOD + shift queries) is handled by the
//! terminal decider using WHIR, keeping this module focused on the core fold.

use alloc::{vec, vec::Vec};

use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeField64, TwoAdicField};

use crate::spartan::{encoding::eq_poly_at_index, r1cs::R1CSShape};

use super::{
    accumulator::{FreshInstance, WarpAccumulator, WarpAccumulatorWitness},
    encoding::rs_encode,
    twin_constraint::{self, shape_to_sparse_constraints},
};

/// Reed-Solomon encoding configuration for the WARP fold.
/// When provided, the fold will RS-encode fresh witnesses before the sumcheck.
#[derive(Clone, Debug)]
pub struct RSEncodingConfig {
    pub folding_factor: usize,
    pub log_inv_rate: usize,
}

impl RSEncodingConfig {
    pub fn new(folding_factor: usize, log_inv_rate: usize) -> Self {
        Self { folding_factor, log_inv_rate }
    }
}

/// Configuration for the WARP fold.
#[derive(Clone, Debug)]
pub struct WarpFoldConfig {
    /// Number of OOD samples (s) for codeword batching.
    pub num_ood_samples: usize,
    /// Number of shift queries (t) for in-domain spot checks.
    pub num_shift_queries: usize,
}

impl Default for WarpFoldConfig {
    fn default() -> Self {
        Self {
            num_ood_samples: 2,
            num_shift_queries: 4,
        }
    }
}

/// Per-phase timing breakdown for a single WARP fold step (in microseconds).
#[derive(Clone, Debug, Default)]
pub struct WarpFoldTimings {
    /// RS encoding of fresh witnesses.
    pub rs_encode_us: u64,
    /// Merkle commitment of fresh codewords.
    pub merkle_fresh_us: u64,
    /// Twin-constraint sumcheck (log l rounds).
    pub twin_sumcheck_us: u64,
    /// Shift queries (proximity spot checks).
    pub shift_queries_us: u64,
    /// OOD sampling (MLE evaluations at random points).
    pub ood_sampling_us: u64,
    /// Merkle commitment of folded codeword.
    pub merkle_folded_us: u64,
    /// Evaluation batching sumcheck (log n rounds).
    pub eval_batch_us: u64,
    /// Codeword clone for shift query verification.
    pub codeword_clone_us: u64,
}

/// A single shift query opening: position + queried row values + Merkle auth path.
#[derive(Clone, Debug)]
pub struct ShiftQueryOpening<F: Field, const DIGEST_ELEMS: usize = 8> {
    /// The queried position (row index in the codeword matrix).
    pub position: usize,
    /// For each input codeword i: the row values at this position (width = 2^folding_factor).
    pub input_values: Vec<Vec<F>>,
    /// Merkle authentication paths for each input codeword (one per input).
    pub auth_paths: Vec<Vec<[F; DIGEST_ELEMS]>>,
    /// The expected folded value at this position: Σ_i eq(γ, i) * input_i[pos].
    pub expected_folded: Vec<F>,
}

/// Result of a WARP fold step.
#[derive(Clone, Debug)]
pub struct WarpFoldResult<F: Field, const DIGEST_ELEMS: usize = 8> {
    /// Merkle root of the folded codeword (zero if not committed).
    pub commitment_root: [F; DIGEST_ELEMS],
    /// Merkle roots of the fresh input codewords (empty if not committed).
    pub fresh_commitment_roots: Vec<[F; DIGEST_ELEMS]>,
    /// The output accumulator instance (public).
    pub instance: WarpFoldedInstance<F>,
    /// The output accumulator witness (prover only).
    pub witness: WarpAccumulatorWitness<F>,
    /// Twin-constraint sumcheck round polynomials (for the verifier).
    pub sumcheck_round_polys: Vec<Vec<F>>,
    /// Twin-constraint sumcheck challenges (derived from transcript).
    pub sumcheck_challenges: Vec<F>,
    /// Fresh codeword evaluation claims μ_i = f_i[0] (needed by verifier for target).
    pub fresh_eval_claims: Vec<F>,
    /// Fresh PESAT targets η_i (0 for valid instances, needed by verifier).
    pub fresh_pesat_targets: Vec<F>,
    /// Shift query openings (proximity check proof data).
    pub shift_queries: Vec<ShiftQueryOpening<F, DIGEST_ELEMS>>,
    /// OOD (out-of-domain) sample points (for list decoding disambiguation).
    pub ood_points: Vec<Vec<F>>,
    /// OOD evaluations: ν_k = f̃(ζ_k) where f̃ is the folded codeword's MLE.
    pub ood_answers: Vec<F>,
    /// Evaluation batching sumcheck round polynomials.
    pub eval_batch_round_polys: Vec<Vec<F>>,
    /// Evaluation batching sumcheck challenges.
    pub eval_batch_challenges: Vec<F>,
    /// Per-phase timing breakdown.
    pub timings: WarpFoldTimings,
}

/// The folded instance produced by the WARP fold (before commitment).
/// This is the algebraic output — the Merkle commitment happens separately.
#[derive(Clone, Debug)]
pub struct WarpFoldedInstance<F: Field> {
    /// Folded evaluation point α (log_n elements).
    pub eval_point: Vec<F>,
    /// Folded PESAT point — tau component (log_M elements).
    pub pesat_tau: Vec<F>,
    /// Folded PESAT point — public input x.
    pub pesat_x: Vec<F>,
    /// PESAT target η = P*(β, z).
    pub pesat_target: F,
}

/// Evaluate bundled R1CS at a given PESAT point.
///
/// Computes η = Σ_i eq(tau, i) · (Az_i · Bz_i - Cz_i) where the sum is
/// over constraint rows bundled by the eq polynomial at tau.
pub fn evaluate_bundled_r1cs<F: Field>(
    shape: &R1CSShape<F>,
    tau: &[F],
    z: &[F],
) -> F {
    let num_cons = shape.num_cons();
    let num_rows = num_cons.next_power_of_two();

    // Compute Az, Bz, Cz
    let az = shape.a().multiply_vec(num_rows, z.len(), z);
    let bz = shape.b().multiply_vec(num_rows, z.len(), z);
    let cz = shape.c().multiply_vec(num_rows, z.len(), z);

    // Bundle by eq(tau, i)
    let mut eta = F::ZERO;
    for i in 0..num_rows {
        let eq_val = eq_poly_at_index::<F, F>(i, tau);
        eta += eq_val * (az[i] * bz[i] - cz[i]);
    }
    eta
}

/// Build the full z = (x || w) vector from public input and witness.
pub fn build_z_vector<F: Field>(public_input: &[F], witness: &[F]) -> Vec<F> {
    let mut z = Vec::with_capacity(public_input.len() + witness.len());
    z.extend_from_slice(public_input);
    z.extend_from_slice(witness);
    z
}

/// Run the WARP fold prover.
///
/// Takes l fresh instances + a running accumulator and produces a single
/// new accumulator with fixed-size witness.
///
/// # Arguments
/// - `shape`: R1CS constraint shape (shared across all instances)
/// - `fresh_instances`: l fresh computation instances to fold in
/// - `acc`: the running accumulator (from previous fold, or initial)
/// - `omega`: batching challenge (combines codeword + R1CS checks)
/// - `tau_challenges`: log_l challenges for the sumcheck eq polynomial
/// - `transcript_round`: callback to absorb sumcheck coeffs and squeeze challenge
///
/// # Returns
/// The folded result with new accumulator + sumcheck proof data.
pub fn warp_fold_prove<F: Field>(
    shape: &R1CSShape<F>,
    fresh_instances: &[FreshInstance<F>],
    acc: &WarpAccumulator<F, F, F, 8>,
    omega: F,
    tau_challenges: &[F],
    mut transcript_round: impl FnMut(&[F]) -> F,
) -> WarpFoldResult<F> {
    let l1 = fresh_instances.len();
    assert!(l1 > 0, "need at least one fresh instance");

    // l = l2 (accumulated) + l1 (fresh), must be power of 2
    // For simplicity, l2 = 1 (the running accumulator)
    let l2 = 1usize;
    let l = (l2 + l1).next_power_of_two();
    let log_l = l.trailing_zeros() as usize;

    assert_eq!(
        tau_challenges.len(),
        log_l,
        "need log_l = {} tau challenges, got {}",
        log_l,
        tau_challenges.len()
    );

    let num_cons = shape.num_cons().next_power_of_two();
    let log_m = num_cons.trailing_zeros() as usize;
    let num_vars_y = 1 << shape.num_poly_vars_y();

    // For now, codewords = witnesses (identity encoding).
    // Real RS encoding will be added when we integrate with WHIR's commitment.
    let code_len = acc.witness.codeword.as_slice().len();
    let log_n = code_len.trailing_zeros() as usize;

    // Build R1CS constraints in sparse row form
    let constraints = shape_to_sparse_constraints(shape);

    // ========================================
    // Phase 1: Assemble tables for sumcheck
    // ========================================

    // Codeword table: [acc_codeword, fresh_0, fresh_1, ..., padding...]
    let mut codewords: Vec<Vec<F>> = Vec::with_capacity(l);
    codewords.push(acc.witness.codeword.as_slice().to_vec());
    for inst in fresh_instances {
        // Identity encoding for now — the witness IS the codeword
        let mut cw = vec![F::ZERO; code_len];
        let copy_len = inst.witness.len().min(code_len);
        cw[..copy_len].copy_from_slice(&inst.witness[..copy_len]);
        codewords.push(cw);
    }
    // Pad to power of 2 with zero codewords
    while codewords.len() < l {
        codewords.push(vec![F::ZERO; code_len]);
    }

    // Witness (z = x||w) table
    let mut witnesses: Vec<Vec<F>> = Vec::with_capacity(l);
    witnesses.push(build_z_vector(&acc.instance.pesat_x, &acc.witness.witness));
    for inst in fresh_instances {
        witnesses.push(build_z_vector(&inst.public_input, &inst.witness));
    }
    while witnesses.len() < l {
        witnesses.push(vec![F::ZERO; num_vars_y]);
    }

    // Alpha (evaluation point) table
    let mut alphas: Vec<Vec<F>> = Vec::with_capacity(l);
    // Convert accumulated eval_point from possibly-EF to F
    // For now, treat eval_point as F directly
    alphas.push(acc.instance.eval_point.clone());
    // Fresh instances start with zero alpha (no prior eval claim)
    for _ in 0..l1 {
        alphas.push(vec![F::ZERO; log_n]);
    }
    while alphas.len() < l {
        alphas.push(vec![F::ZERO; log_n]);
    }

    // Beta (PESAT point = tau) table
    let mut betas: Vec<Vec<F>> = Vec::with_capacity(l);
    betas.push(acc.instance.pesat_tau.clone());
    // Fresh instances get their own tau from zerocheck randomness
    // For now, use zero (the fold will derive the correct folded tau)
    for _ in 0..l1 {
        betas.push(vec![F::ZERO; log_m]);
    }
    while betas.len() < l {
        betas.push(vec![F::ZERO; log_m]);
    }

    // Tau eq-evals: eq(τ, 0), eq(τ, 1), ..., eq(τ, l-1)
    let mut tau_evals: Vec<F> = (0..l)
        .map(|idx| eq_poly_at_index::<F, F>(idx, tau_challenges))
        .collect();

    // ========================================
    // Phase 2: Twin-constraint sumcheck
    // ========================================
    let expected_num_coeffs = 2 + (log_n + 1).max(log_m + 2);

    let (round_polys, challenges) = twin_constraint::twin_constraint_sumcheck(
        &mut codewords,
        &mut witnesses,
        &mut alphas,
        &mut betas,
        &mut tau_evals,
        &constraints,
        omega,
        log_l,
        expected_num_coeffs,
        &mut transcript_round,
    );

    // ========================================
    // Phase 3: Extract folded output (fixed size!)
    // ========================================
    debug_assert_eq!(codewords.len(), 1);
    debug_assert_eq!(witnesses.len(), 1);
    debug_assert_eq!(alphas.len(), 1);
    debug_assert_eq!(betas.len(), 1);

    let folded_codeword = codewords.pop().unwrap();
    let folded_z = witnesses.pop().unwrap();
    let folded_alpha = alphas.pop().unwrap();
    let folded_beta_tau = betas.pop().unwrap();

    // Split z back into (x, w)
    let num_public = fresh_instances[0].public_input.len();
    let (folded_x, folded_w) = folded_z.split_at(num_public);

    // Evaluate bundled R1CS at the folded point
    let eta = evaluate_bundled_r1cs(shape, &folded_beta_tau, &folded_z);

    let instance = WarpFoldedInstance {
        eval_point: folded_alpha,
        pesat_tau: folded_beta_tau,
        pesat_x: folded_x.to_vec(),
        pesat_target: eta,
    };

    let witness = WarpAccumulatorWitness {
        codeword: crate::poly::evals::EvaluationsList::new(folded_codeword),
        witness: folded_w.to_vec(),
    };

    // Compute fresh eval claims and PESAT targets (needed by verifier)
    // μ_i for fresh instance i = codeword_i[0] (from identity encoding)
    // η_i for fresh instance i = bundled R1CS evaluation (0 if valid)
    let fresh_eval_claims: Vec<F> = fresh_instances
        .iter()
        .map(|inst| {
            // With identity encoding, codeword = witness padded to code_len
            // So μ = witness[0] (or 0 if empty)
            if inst.witness.is_empty() {
                F::ZERO
            } else {
                inst.witness[0]
            }
        })
        .collect();

    let fresh_pesat_targets: Vec<F> = fresh_instances
        .iter()
        .enumerate()
        .map(|(_i, inst)| {
            // For now, fresh PESAT targets are 0 for valid instances
            // In the full protocol, these come from the zerocheck randomness
            let z = build_z_vector(&inst.public_input, &inst.witness);
            let tau = &vec![F::ZERO; log_m]; // fresh instances start with zero tau
            evaluate_bundled_r1cs(shape, tau, &z)
        })
        .collect();

    WarpFoldResult {
        commitment_root: [F::ZERO; 8],
        fresh_commitment_roots: vec![],
        instance,
        witness,
        sumcheck_round_polys: round_polys,
        sumcheck_challenges: challenges,
        fresh_eval_claims,
        fresh_pesat_targets,
        shift_queries: vec![],
        ood_points: vec![],
        ood_answers: vec![],
        eval_batch_round_polys: vec![],
        eval_batch_challenges: vec![],
        timings: WarpFoldTimings::default(),
    }
}

/// WARP fold prover with Reed-Solomon encoding.
///
/// Same as `warp_fold_prove` but RS-encodes fresh witnesses using WHIR's DFT
/// before entering the sumcheck tables. The accumulated codeword and the fresh
/// codewords are both RS-encoded, providing actual error-correcting distance.
///
/// The accumulator's codeword must already be RS-encoded (size 2^(k + log_inv_rate)).
pub fn warp_fold_prove_rs<F, Dft>(
    shape: &R1CSShape<F>,
    fresh_instances: &[FreshInstance<F>],
    acc: &WarpAccumulator<F, F, F, 8>,
    omega: F,
    tau_challenges: &[F],
    rs_config: &RSEncodingConfig,
    dft: &Dft,
    mut transcript_round: impl FnMut(&[F]) -> F,
) -> WarpFoldResult<F>
where
    F: TwoAdicField + PrimeField64,
    Dft: TwoAdicSubgroupDft<F>,
{
    warp_fold_prove_rs_inner(
        shape, fresh_instances, acc, omega, tau_challenges,
        rs_config, dft, &mut transcript_round, None::<fn(&crate::poly::evals::EvaluationsList<F>, usize) -> [F; 8]>,
    )
}

/// WARP fold prover with RS encoding and Merkle commitment.
///
/// Same as `warp_fold_prove_rs` but also commits the folded codeword to a
/// Merkle tree via the provided `commit_fn`. The root is stored in the result's
/// `commitment_root` field.
pub fn warp_fold_prove_rs_committed<F, Dft>(
    shape: &R1CSShape<F>,
    fresh_instances: &[FreshInstance<F>],
    acc: &WarpAccumulator<F, F, F, 8>,
    omega: F,
    tau_challenges: &[F],
    rs_config: &RSEncodingConfig,
    dft: &Dft,
    mut transcript_round: impl FnMut(&[F]) -> F,
    commit_fn: impl Fn(&crate::poly::evals::EvaluationsList<F>, usize) -> [F; 8],
) -> WarpFoldResult<F>
where
    F: TwoAdicField + PrimeField64,
    Dft: TwoAdicSubgroupDft<F>,
{
    warp_fold_prove_rs_inner(
        shape, fresh_instances, acc, omega, tau_challenges,
        rs_config, dft, &mut transcript_round, Some(commit_fn),
    )
}

/// Build eq(tau, ·) table for arbitrary field-element coordinates in O(n).
///
/// Same binary tree expansion as the Spartan prover's `compute_eq_table`,
/// but takes `&[F]` coordinates directly instead of being hardcoded to the
/// Spartan-specific bit ordering.
///
/// Convention: bit j of the boolean index maps to tau[j] (LSB-first),
/// matching `eq_poly_at_index`.
fn compute_eq_table_generic<F: Field>(tau: &[F]) -> Vec<F> {
    let s = tau.len();
    let n = 1usize << s;
    let mut table = vec![F::ZERO; n];
    table[0] = F::ONE;

    // Process in reverse so tau[0] ends up as LSB (matching eq_poly_at_index)
    for j in (0..s).rev() {
        let tau_j = tau[j];
        let one_minus = F::ONE - tau_j;
        let half = 1usize << (s - 1 - j);
        for i in (0..half).rev() {
            table[2 * i + 1] = table[i] * tau_j;
            table[2 * i] = table[i] * one_minus;
        }
    }
    table
}

/// Evaluation batching sumcheck: reduces multiple eval claims on a codeword
/// to a single `(α, μ)` claim via a degree-2 table-based sumcheck.
///
/// Given claims `{(p_k, v_k)}` asserting `f̃(p_k) = v_k`, this proves:
///   Σ_{x ∈ {0,1}^{log n}} B(x) · f(x) = T
/// where B(x) = Σ_k ρ^k · eq(p_k, x) and T = Σ_k ρ^k · v_k.
///
/// After the sumcheck, `f̃(α) = μ` where α is the sumcheck challenge point.
fn evaluation_batching_sumcheck<F: Field>(
    codeword: &[F],
    eval_claims: &[(Vec<F>, F)], // (point, value) pairs
    rho: F,
    log_n: usize,
    transcript_round: &mut impl FnMut(&[F]) -> F,
) -> (Vec<F>, F, Vec<Vec<F>>, Vec<F>) {
    let n = 1usize << log_n;
    assert_eq!(codeword.len(), n);

    // Build the batched eq table: B[x] = Σ_k ρ^k · eq(p_k, x)
    //
    // Optimization from [CBBZ23, Sec 3.8.1]: for claims at BOOLEAN points
    // (shift queries), eq(boolean_p, x) is 1 at exactly one index and 0
    // elsewhere, so we just add ρ^k to that single entry in O(1) instead
    // of building a full O(n) eq table.
    let mut b_table = vec![F::ZERO; n];
    let mut initial_claim = F::ZERO;
    let mut rho_pow = F::ONE;

    for (point, v) in eval_claims {
        // Check if this is a boolean point (all coordinates are 0 or 1)
        let is_boolean = point.iter().all(|&c| c == F::ZERO || c == F::ONE);

        if is_boolean {
            // Boolean point: eq(p, x) = 1 only at x = p, so just add ρ^k at index p.
            // Convert boolean point to index (LSB-first: point[0] = bit 0)
            let mut idx = 0usize;
            for (bit, &c) in point.iter().enumerate() {
                if c == F::ONE {
                    idx |= 1 << bit;
                }
            }
            b_table[idx] += rho_pow;
        } else {
            // Arbitrary field point: build full eq table in O(n)
            let eq_table = compute_eq_table_generic(point);
            for idx in 0..n {
                b_table[idx] += rho_pow * eq_table[idx];
            }
        }

        initial_claim += rho_pow * *v;
        rho_pow *= rho;
    }

    // Sanity check: Σ_x B[x] · f[x] should equal T
    #[cfg(debug_assertions)]
    {
        let check: F = (0..n).map(|i| b_table[i] * codeword[i]).sum();
        assert_eq!(check, initial_claim, "eval batching: initial claim mismatch");
    }

    // Table-based degree-2 sumcheck: Σ_x B(x) · f(x) = T
    let mut f_table = codeword.to_vec();
    let mut current_claim = initial_claim;
    let mut round_polys = Vec::with_capacity(log_n);
    let mut challenges = Vec::with_capacity(log_n);

    for _round in 0..log_n {
        let half = f_table.len() / 2;
        let mut evals = [F::ZERO; 3];

        for i in 0..half {
            let b_lo = b_table[2 * i];
            let b_hi = b_table[2 * i + 1];
            let f_lo = f_table[2 * i];
            let f_hi = f_table[2 * i + 1];

            let b_d = b_hi - b_lo;
            let f_d = f_hi - f_lo;

            // t=0
            evals[0] += b_lo * f_lo;
            // t=1
            evals[1] += b_hi * f_hi;
            // t=2
            let b_2 = b_lo + b_d.double();
            let f_2 = f_lo + f_d.double();
            evals[2] += b_2 * f_2;
        }

        assert_eq!(
            evals[0] + evals[1], current_claim,
            "eval batching sumcheck: round claim mismatch"
        );

        let round_evals = evals.to_vec();

        let r = transcript_round(&round_evals);
        // Evaluate degree-2 polynomial at r via Lagrange interpolation from evals at 0,1,2
        let e0 = round_evals[0];
        let e1 = round_evals[1];
        let e2 = round_evals[2];
        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        current_claim = e0 + c1 * r + c2 * r * r;

        challenges.push(r);
        round_polys.push(round_evals);

        // Bind both tables
        for i in 0..half {
            b_table[i] = b_table[2 * i] + r * (b_table[2 * i + 1] - b_table[2 * i]);
            f_table[i] = f_table[2 * i] + r * (f_table[2 * i + 1] - f_table[2 * i]);
        }
        b_table.truncate(half);
        f_table.truncate(half);
    }

    // After all rounds: f_table[0] = f̃(α), b_table[0] = B̃(α)
    // current_claim = B̃(α) · f̃(α) = μ_batched
    // The new eval claim is: f̃(α) = f_table[0]
    let new_eval_point = challenges.clone();
    let new_eval_claim = f_table[0];

    (new_eval_point, new_eval_claim, round_polys, challenges)
}

fn warp_fold_prove_rs_inner<F, Dft>(
    shape: &R1CSShape<F>,
    fresh_instances: &[FreshInstance<F>],
    acc: &WarpAccumulator<F, F, F, 8>,
    omega: F,
    tau_challenges: &[F],
    rs_config: &RSEncodingConfig,
    dft: &Dft,
    transcript_round: &mut impl FnMut(&[F]) -> F,
    commit_fn: Option<impl Fn(&crate::poly::evals::EvaluationsList<F>, usize) -> [F; 8]>,
) -> WarpFoldResult<F>
where
    F: TwoAdicField + PrimeField64,
    Dft: TwoAdicSubgroupDft<F>,
{
    let l1 = fresh_instances.len();
    assert!(l1 > 0, "need at least one fresh instance");

    let l2 = 1usize;
    let l = (l2 + l1).next_power_of_two();
    let log_l = l.trailing_zeros() as usize;

    assert_eq!(tau_challenges.len(), log_l);

    let num_cons = shape.num_cons().next_power_of_two();
    let log_m = num_cons.trailing_zeros() as usize;

    let code_len = acc.witness.codeword.as_slice().len();
    let log_n = code_len.trailing_zeros() as usize;

    let num_shift_queries = if commit_fn.is_some() {
        WarpFoldConfig::default().num_shift_queries
    } else {
        0
    };

    let constraints = shape_to_sparse_constraints(shape);

    #[cfg(feature = "bench-timing")]
    let mut timings = WarpFoldTimings::default();
    #[cfg(not(feature = "bench-timing"))]
    let timings = WarpFoldTimings::default();

    // ========================================
    // Phase 1: RS-encode fresh witnesses + commit
    // ========================================
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();
    let _witness_num_vars = (fresh_instances[0].witness.len()).trailing_zeros() as usize;

    let mut codewords: Vec<Vec<F>> = Vec::with_capacity(l);
    codewords.push(acc.witness.codeword.as_slice().to_vec());

    let mut fresh_commitment_roots = Vec::new();
    for inst in fresh_instances {
        let witness_poly = crate::poly::evals::EvaluationsList::new(inst.witness.clone());
        let cw = rs_encode(&witness_poly, rs_config.folding_factor, rs_config.log_inv_rate, dft);
        // Commit fresh codeword if commit function provided
        if let Some(ref f) = commit_fn {
            fresh_commitment_roots.push(f(&cw, rs_config.folding_factor));
        }
        codewords.push(cw.as_slice().to_vec());
    }
    while codewords.len() < l {
        codewords.push(vec![F::ZERO; code_len]);
    }

    #[cfg(feature = "bench-timing")]
    {
        timings.rs_encode_us = _phase_start.elapsed().as_micros() as u64;
    }

    // Save original codewords for shift query verification (before sumcheck consumes them)
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();
    let saved_codewords = if num_shift_queries > 0 {
        codewords.clone()
    } else {
        vec![]
    };
    #[cfg(feature = "bench-timing")]
    {
        timings.codeword_clone_us = _phase_start.elapsed().as_micros() as u64;
    }

    // Witness (z = x||w) table — uses raw witnesses, NOT codewords
    // All z-vectors must have the same length (num_vars_y), padded if necessary.
    let num_vars_y = 1 << shape.num_poly_vars_y();
    let mut witnesses: Vec<Vec<F>> = Vec::with_capacity(l);
    let mut z_acc = build_z_vector(&acc.instance.pesat_x, &acc.witness.witness);
    z_acc.resize(num_vars_y, F::ZERO);
    witnesses.push(z_acc);
    for inst in fresh_instances {
        let mut z = build_z_vector(&inst.public_input, &inst.witness);
        z.resize(num_vars_y, F::ZERO);
        witnesses.push(z);
    }
    while witnesses.len() < l {
        witnesses.push(vec![F::ZERO; num_vars_y]);
    }

    // Alpha table
    let mut alphas: Vec<Vec<F>> = Vec::with_capacity(l);
    alphas.push(acc.instance.eval_point.clone());
    for _ in 0..l1 {
        alphas.push(vec![F::ZERO; log_n]);
    }
    while alphas.len() < l {
        alphas.push(vec![F::ZERO; log_n]);
    }

    // Beta table
    let mut betas: Vec<Vec<F>> = Vec::with_capacity(l);
    betas.push(acc.instance.pesat_tau.clone());
    for _ in 0..l1 {
        betas.push(vec![F::ZERO; log_m]);
    }
    while betas.len() < l {
        betas.push(vec![F::ZERO; log_m]);
    }

    // Tau eq-evals
    let mut tau_evals: Vec<F> = (0..l)
        .map(|idx| eq_poly_at_index::<F, F>(idx, tau_challenges))
        .collect();

    // ========================================
    // Phase 2: Twin-constraint sumcheck
    // ========================================
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();

    let expected_num_coeffs = 2 + (log_n + 1).max(log_m + 2);

    let (round_polys, challenges) = twin_constraint::twin_constraint_sumcheck(
        &mut codewords, &mut witnesses, &mut alphas, &mut betas, &mut tau_evals,
        &constraints, omega, log_l, expected_num_coeffs, &mut *transcript_round,
    );

    #[cfg(feature = "bench-timing")]
    {
        timings.twin_sumcheck_us = _phase_start.elapsed().as_micros() as u64;
    }

    // ========================================
    // Phase 3: Extract folded output
    // ========================================
    let folded_codeword = codewords.pop().unwrap();
    let folded_z = witnesses.pop().unwrap();
    let folded_alpha = alphas.pop().unwrap();
    let folded_beta_tau = betas.pop().unwrap();

    let num_public = fresh_instances[0].public_input.len();
    let (folded_x, folded_w) = folded_z.split_at(num_public);

    let eta = evaluate_bundled_r1cs(shape, &folded_beta_tau, &folded_z);

    #[allow(unused_mut)]
    let mut instance = WarpFoldedInstance {
        eval_point: folded_alpha,
        pesat_tau: folded_beta_tau,
        pesat_x: folded_x.to_vec(),
        pesat_target: eta,
    };

    let witness = WarpAccumulatorWitness {
        codeword: crate::poly::evals::EvaluationsList::new(folded_codeword),
        witness: folded_w.to_vec(),
    };

    let fresh_eval_claims: Vec<F> = fresh_instances
        .iter()
        .map(|inst| if inst.witness.is_empty() { F::ZERO } else { inst.witness[0] })
        .collect();

    let fresh_pesat_targets: Vec<F> = fresh_instances
        .iter()
        .map(|inst| {
            let z = build_z_vector(&inst.public_input, &inst.witness);
            let tau = vec![F::ZERO; log_m];
            evaluate_bundled_r1cs(shape, &tau, &z)
        })
        .collect();

    // Commit the folded codeword if a commit function was provided
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();
    let commitment_root = match &commit_fn {
        Some(f) => f(&witness.codeword, rs_config.folding_factor),
        None => [F::ZERO; 8],
    };
    #[cfg(feature = "bench-timing")]
    {
        timings.merkle_folded_us = _phase_start.elapsed().as_micros() as u64;
    }

    // ========================================
    // Phase 4: Shift queries (proximity check)
    // ========================================
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();
    // Verify that the folded codeword is consistent with the eq-weighted
    // linear combination of the original input codewords at random positions.
    let shift_queries = if num_shift_queries > 0 {
        // Precompute eq(γ, i) weights from sumcheck challenges
        let eq_weights: Vec<F> = (0..l)
            .map(|idx| eq_poly_at_index::<F, F>(idx, &challenges))
            .collect();

        // Sample shift positions from the transcript
        // Use transcript_round to derive deterministic positions (Fiat-Shamir)
        let height = code_len >> rs_config.folding_factor;
        let mut queries = Vec::with_capacity(num_shift_queries);

        for q in 0..num_shift_queries {
            // Derive position from transcript (Fiat-Shamir)
            let pos_challenge = transcript_round(&[F::from_usize(q)]);
            let pos = pos_challenge.as_canonical_u64() as usize % height;

            let width = 1usize << rs_config.folding_factor;
            let row_start = pos * width;
            let row_end = row_start + width;

            // Collect input codeword values at this row
            let input_values: Vec<Vec<F>> = saved_codewords
                .iter()
                .map(|cw| cw[row_start..row_end].to_vec())
                .collect();

            // Compute expected folded row: Σ_i eq(γ, i) * cw_i[row]
            let mut expected_folded = vec![F::ZERO; width];
            for (i, row_vals) in input_values.iter().enumerate() {
                for (j, &val) in row_vals.iter().enumerate() {
                    expected_folded[j] += eq_weights[i] * val;
                }
            }

            // Verify against the actual folded codeword
            let actual_folded: Vec<F> = witness.codeword.as_slice()[row_start..row_end].to_vec();
            assert_eq!(
                expected_folded, actual_folded,
                "shift query {q} at row {pos}: folded codeword inconsistent with input linear combination"
            );

            queries.push(ShiftQueryOpening {
                position: pos,
                input_values,
                auth_paths: vec![], // Merkle auth paths added when verifier is implemented
                expected_folded,
            });
        }

        queries
    } else {
        vec![]
    };
    #[cfg(feature = "bench-timing")]
    {
        timings.shift_queries_us = _phase_start.elapsed().as_micros() as u64;
    }

    // ========================================
    // Phase 5: OOD sampling (list decoding disambiguation)
    // ========================================
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();
    // Evaluate the folded codeword's MLE at random out-of-domain points.
    // This pins the prover to a unique codeword in the list-decoding regime.
    let num_ood_samples = if commit_fn.is_some() {
        WarpFoldConfig::default().num_ood_samples
    } else {
        0
    };

    let (ood_points, ood_answers) = if num_ood_samples > 0 {
        let mut points: Vec<Vec<F>> = Vec::with_capacity(num_ood_samples);
        let mut answers: Vec<F> = Vec::with_capacity(num_ood_samples);

        for k in 0..num_ood_samples {
            // Squeeze a univariate challenge from the transcript and expand to
            // a multilinear point (same pattern as WHIR's CommitmentWriter).
            let univariate_challenge = transcript_round(
                &[F::from_usize(k + num_shift_queries + 1000)],
            );
            let point = crate::poly::multilinear::MultilinearPoint::expand_from_univariate(
                univariate_challenge,
                log_n,
            );

            // Evaluate the folded codeword's MLE at this OOD point
            let eval = witness.codeword.evaluate_hypercube_base::<F>(&point);

            // Absorb the answer into the transcript (Fiat-Shamir binding)
            let _ = transcript_round(&[eval]);

            points.push(point.into_iter().collect());
            answers.push(eval);
        }

        (points, answers)
    } else {
        (vec![], vec![])
    };
    #[cfg(feature = "bench-timing")]
    {
        timings.ood_sampling_us = _phase_start.elapsed().as_micros() as u64;
    }

    // ========================================
    // Phase 6: Evaluation batching sumcheck
    // ========================================
    #[cfg(feature = "bench-timing")]
    let _phase_start = std::time::Instant::now();
    // Batch all eval claims (folded alpha + OOD + shift queries) into one (α, μ).
    let (eval_batch_round_polys, eval_batch_challenges) = if commit_fn.is_some()
        && (!ood_points.is_empty() || !shift_queries.is_empty())
    {
        // Collect all evaluation claims on the folded codeword
        let mut eval_claims: Vec<(Vec<F>, F)> = Vec::new();

        // 1. The twin-constraint sumcheck's folded eval claim
        // instance.eval_point is in eq_poly_at_index convention (LSB-first).
        // evaluate_hypercube_base uses MultilinearPoint convention (MSB-first).
        // We reverse for evaluate_hypercube_base, but keep LSB-first for eq_poly_at_index.
        let alpha_msb: Vec<F> = instance.eval_point.iter().rev().cloned().collect();
        let alpha_eval = witness.codeword.evaluate_hypercube_base::<F>(
            &crate::poly::multilinear::MultilinearPoint::new(alpha_msb),
        );
        eval_claims.push((instance.eval_point.clone(), alpha_eval));

        // 2. OOD claims
        // OOD points were computed via MultilinearPoint (MSB-first convention) but
        // eq_poly_at_index in the batching sumcheck uses LSB-first. Reverse to match.
        for (point, &answer) in ood_points.iter().zip(ood_answers.iter()) {
            let mut reversed = point.clone();
            reversed.reverse();
            eval_claims.push((reversed, answer));
        }

        // 3. Shift query claims (in-domain evaluation claims)
        // Each shift query at position `pos` with row values `v` asserts:
        // f̃(binary(pos * width + j)) = v[j] for each column j.
        // For batching, we use a single point per query: the first column.
        let width = 1usize << rs_config.folding_factor;
        for sq in &shift_queries {
            // Convert row position to a multilinear point for the first column element
            let flat_idx = sq.position * width;
            let point: Vec<F> = (0..log_n)
                .map(|bit| {
                    if (flat_idx >> bit) & 1 == 1 {
                        F::ONE
                    } else {
                        F::ZERO
                    }
                })
                .collect();
            let val = witness.codeword.as_slice()[flat_idx];
            eval_claims.push((point, val));
        }

        // Sample batching challenge ρ from transcript
        let rho = transcript_round(&[F::from_usize(2000)]);

        // Run the evaluation batching sumcheck
        let (new_eval_point, new_eval_claim, batch_round_polys, batch_challenges) =
            evaluation_batching_sumcheck(
                witness.codeword.as_slice(),
                &eval_claims,
                rho,
                log_n,
                transcript_round,
            );

        // Update the instance's eval point and claim with the batched result
        instance.eval_point = new_eval_point;

        (batch_round_polys, batch_challenges)
    } else {
        (vec![], vec![])
    };
    #[cfg(feature = "bench-timing")]
    {
        timings.eval_batch_us = _phase_start.elapsed().as_micros() as u64;
    }

    WarpFoldResult {
        commitment_root,
        fresh_commitment_roots,
        instance, witness,
        sumcheck_round_polys: round_polys,
        sumcheck_challenges: challenges,
        fresh_eval_claims,
        fresh_pesat_targets,
        shift_queries,
        ood_points,
        ood_answers,
        eval_batch_round_polys,
        eval_batch_challenges,
        timings,
    }
}

/// Evaluate a univariate polynomial given by evaluations at 0, 1, 2, ...
/// at an arbitrary point r via Lagrange interpolation.
fn eval_poly_from_evals<F: Field>(evals: &[F], r: F) -> F {
    let degree = evals.len() - 1;
    let mut result = F::ZERO;
    for (i, &y_i) in evals.iter().enumerate() {
        let x_i = F::from_usize(i);
        let mut basis = F::ONE;
        for j in 0..=degree {
            if i == j {
                continue;
            }
            let x_j = F::from_usize(j);
            basis *= (r - x_j) * (x_i - x_j).inverse();
        }
        result += y_i * basis;
    }
    result
}

/// Verify the twin-constraint sumcheck portion of a WARP fold.
///
/// Checks that h_i(0) + h_i(1) == target at each round, and that
/// consecutive rounds are consistent: h_i(0)+h_i(1) == h_{i-1}(γ_{i-1}).
pub fn warp_fold_verify_sumcheck<F: Field>(
    initial_target: F,
    round_polys: &[Vec<F>],
    challenges: &[F],
) -> Result<F, &'static str> {
    if round_polys.is_empty() {
        return Ok(initial_target);
    }

    // Check round 0: h(0) + h(1) == initial_target
    let sum_0 = round_polys[0][0] + round_polys[0][1];
    if sum_0 != initial_target {
        return Err("sumcheck: round 0 sum mismatch");
    }

    // Check subsequent rounds
    for i in 1..round_polys.len() {
        let prev_at_challenge = eval_poly_from_evals(&round_polys[i - 1], challenges[i - 1]);
        let curr_sum = round_polys[i][0] + round_polys[i][1];
        if curr_sum != prev_at_challenge {
            return Err("sumcheck: round consistency mismatch");
        }
    }

    // Return the final evaluation at the last challenge
    let last_idx = round_polys.len() - 1;
    Ok(eval_poly_from_evals(&round_polys[last_idx], challenges[last_idx]))
}

/// Public input data for the WARP fold verifier.
///
/// This is the verifier's view of a fresh instance — no witness, just the
/// public input and the (claimed) PESAT satisfaction value.
#[derive(Clone, Debug)]
pub struct FreshInstancePublic<F: Field> {
    /// Public input for this computation step.
    pub public_input: Vec<F>,
}

/// Compute the folded evaluation point α from input alpha vectors and sumcheck challenges.
///
/// After the sumcheck, the folded alpha is the eq-weighted linear combination:
///   α_folded = Σ_i eq(γ, i) · α_i
/// where γ are the sumcheck challenges and α_i are the input eval points.
fn compute_folded_point<F: Field>(
    input_points: &[Vec<F>],
    sumcheck_challenges: &[F],
) -> Vec<F> {
    let l = input_points.len();
    let log_l = sumcheck_challenges.len();
    debug_assert_eq!(l, 1 << log_l);

    let dim = input_points[0].len();
    let mut folded = vec![F::ZERO; dim];

    for (idx, point) in input_points.iter().enumerate() {
        let eq_val = eq_poly_at_index::<F, F>(idx, sumcheck_challenges);
        for (j, &p) in point.iter().enumerate() {
            folded[j] += eq_val * p;
        }
    }
    folded
}

/// Compute the initial sumcheck target σ₁ from public instance data.
///
/// σ₁ = Σ_i eq(τ, i) · (μ_i + ω · η_i)
///
/// where μ_i are the evaluation claims and η_i are the PESAT targets.
fn compute_initial_target<F: Field>(
    tau_challenges: &[F],
    eval_claims: &[F],
    pesat_targets: &[F],
    omega: F,
) -> F {
    let l = eval_claims.len();
    debug_assert_eq!(pesat_targets.len(), l);

    let mut target = F::ZERO;
    for idx in 0..l {
        let eq_val = eq_poly_at_index::<F, F>(idx, tau_challenges);
        target += eq_val * (eval_claims[idx] + omega * pesat_targets[idx]);
    }
    target
}

/// Run the WARP fold verifier.
///
/// The verifier checks the sumcheck proof and recomputes the folded instance
/// from public data only (no access to witnesses).
///
/// # Arguments
/// - `shape`: R1CS constraint shape
/// - `fresh_public`: public inputs of the l fresh instances
/// - `acc_instance`: the running accumulator's public instance
/// - `omega`: batching challenge (must match prover's)
/// - `tau_challenges`: log_l challenges for the sumcheck eq polynomial
/// - `sumcheck_round_polys`: round polynomials from the prover
/// - `sumcheck_challenges`: challenges derived by the transcript
/// - `claimed_output`: the prover's claimed output instance
///
/// # Returns
/// Ok(verified_instance) if verification passes, Err otherwise.
pub fn warp_fold_verify<F: Field>(
    shape: &R1CSShape<F>,
    fresh_public: &[FreshInstancePublic<F>],
    acc_instance: &super::accumulator::WarpAccumulatorInstance<F, F, F, 8>,
    omega: F,
    tau_challenges: &[F],
    sumcheck_round_polys: &[Vec<F>],
    sumcheck_challenges: &[F],
    claimed_output: &WarpFoldedInstance<F>,
    fresh_eval_claims: &[F],
    fresh_pesat_targets: &[F],
) -> Result<WarpFoldedInstance<F>, &'static str> {
    let l1 = fresh_public.len();
    let l2 = 1usize;
    let l = (l2 + l1).next_power_of_two();
    let log_l = l.trailing_zeros() as usize;

    if tau_challenges.len() != log_l {
        return Err("wrong number of tau challenges");
    }
    if sumcheck_round_polys.len() != log_l {
        return Err("wrong number of sumcheck rounds");
    }
    if sumcheck_challenges.len() != log_l {
        return Err("wrong number of sumcheck challenges");
    }

    let num_cons = shape.num_cons().next_power_of_two();
    let log_m = num_cons.trailing_zeros() as usize;
    let code_len = acc_instance.eval_point.len(); // log_n
    let log_n = code_len;

    // ========================================
    // 1. Reconstruct the input data tables (public parts only)
    // ========================================

    // Evaluation claims: acc's μ, then fresh μ_i from the proof
    let mut eval_claims = Vec::with_capacity(l);
    eval_claims.push(acc_instance.eval_claim);
    eval_claims.extend_from_slice(fresh_eval_claims);
    while eval_claims.len() < l {
        eval_claims.push(F::ZERO);
    }

    // PESAT targets: acc's η, then fresh η_i from the proof
    let mut pesat_targets = Vec::with_capacity(l);
    pesat_targets.push(acc_instance.pesat_target);
    pesat_targets.extend_from_slice(fresh_pesat_targets);
    while pesat_targets.len() < l {
        pesat_targets.push(F::ZERO);
    }

    // ========================================
    // 2. Compute initial sumcheck target
    // ========================================
    let initial_target = compute_initial_target(
        tau_challenges,
        &eval_claims,
        &pesat_targets,
        omega,
    );

    // ========================================
    // 3. Verify the twin-constraint sumcheck
    // ========================================
    let _final_eval = warp_fold_verify_sumcheck(
        initial_target,
        sumcheck_round_polys,
        sumcheck_challenges,
    )?;

    // ========================================
    // 4. Recompute folded α and β from sumcheck challenges
    // ========================================

    // Alpha (eval point) table — same as prover assembled
    let mut alpha_inputs = Vec::with_capacity(l);
    alpha_inputs.push(acc_instance.eval_point.clone());
    for _ in 0..l1 {
        alpha_inputs.push(vec![F::ZERO; log_n]);
    }
    while alpha_inputs.len() < l {
        alpha_inputs.push(vec![F::ZERO; log_n]);
    }

    let expected_alpha = compute_folded_point(&alpha_inputs, sumcheck_challenges);

    // Beta (PESAT tau) table
    let mut beta_inputs = Vec::with_capacity(l);
    beta_inputs.push(acc_instance.pesat_tau.clone());
    for _ in 0..l1 {
        beta_inputs.push(vec![F::ZERO; log_m]);
    }
    while beta_inputs.len() < l {
        beta_inputs.push(vec![F::ZERO; log_m]);
    }

    let expected_beta_tau = compute_folded_point(&beta_inputs, sumcheck_challenges);

    // PESAT x (public input) table
    let mut x_inputs = Vec::with_capacity(l);
    x_inputs.push(acc_instance.pesat_x.clone());
    for inst in fresh_public {
        x_inputs.push(inst.public_input.clone());
    }
    while x_inputs.len() < l {
        x_inputs.push(vec![F::ZERO; acc_instance.pesat_x.len()]);
    }

    let expected_pesat_x = compute_folded_point(&x_inputs, sumcheck_challenges);

    // ========================================
    // 5. Check claimed output matches derived values
    // ========================================
    if claimed_output.eval_point != expected_alpha {
        return Err("folded eval_point mismatch");
    }
    if claimed_output.pesat_tau != expected_beta_tau {
        return Err("folded pesat_tau mismatch");
    }
    if claimed_output.pesat_x != expected_pesat_x {
        return Err("folded pesat_x mismatch");
    }

    // The verifier accepts and returns the verified instance
    // (pesat_target η is trusted from the proof — verified at the decider)
    Ok(WarpFoldedInstance {
        eval_point: expected_alpha,
        pesat_tau: expected_beta_tau,
        pesat_x: expected_pesat_x,
        pesat_target: claimed_output.pesat_target,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        accumulation::warp::accumulator::{
            WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness,
        },
        poly::evals::EvaluationsList,
        spartan::r1cs::{R1CSShape, SparseMatEntry},
    };
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    /// Build a simple R1CS shape: x₀ * x₀ = x₁ (4 padded constraints, 4 vars)
    fn make_square_shape() -> R1CSShape<F> {
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 2;
        R1CSShape::new(
            num_cons,
            num_vars,
            num_inputs,
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 1, F::ONE)],
        )
    }

    /// Create a valid witness for the squaring circuit: x₀² = x₁
    fn make_square_witness(root: u64) -> FreshInstance<F> {
        let square = root * root;
        FreshInstance {
            public_input: vec![F::ZERO; 2],
            witness: vec![
                F::from_u64(root),
                F::from_u64(square),
                F::ZERO,
                F::ZERO,
            ],
        }
    }

    /// Create a dummy initial accumulator (zeroed).
    fn make_initial_accumulator(code_len: usize, log_m: usize) -> WarpAccumulator<F, F, F, 8> {
        WarpAccumulator::new(
            WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; code_len.trailing_zeros() as usize],
                eval_claim: F::ZERO,
                pesat_tau: vec![F::ZERO; log_m],
                pesat_x: vec![F::ZERO; 2], // 2 public inputs
                pesat_target: F::ZERO,
            },
            WarpAccumulatorWitness {
                codeword: EvaluationsList::new(vec![F::ZERO; code_len]),
                witness: vec![F::ZERO; 4], // 4 vars
            },
        )
    }

    #[test]
    fn warp_fold_produces_fixed_size_output() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();

        // Initial accumulator with code_len = num_vars_y
        let acc = make_initial_accumulator(num_vars_y, 2);

        // Fresh instance
        let fresh = make_square_witness(3);

        // l = 1 (acc) + 1 (fresh) = 2 → log_l = 1
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        // Output witness should have the SAME size as input
        assert_eq!(
            result.witness.codeword.as_slice().len(),
            acc.witness.codeword.as_slice().len(),
            "codeword size changed during fold!"
        );
        assert_eq!(
            result.witness.witness.len(),
            acc.witness.witness.len(),
            "witness size changed during fold!"
        );

        // Eval point should have the same length
        assert_eq!(
            result.instance.eval_point.len(),
            acc.instance.eval_point.len(),
            "eval_point size changed during fold!"
        );
    }

    #[test]
    fn warp_fold_sumcheck_verifies() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        let fresh = make_square_witness(3);
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        // Verify the sumcheck: consecutive rounds must be consistent
        for i in 1..result.sumcheck_round_polys.len() {
            let prev_at_challenge =
                eval_poly_from_evals(&result.sumcheck_round_polys[i - 1], result.sumcheck_challenges[i - 1]);
            let curr_sum = result.sumcheck_round_polys[i][0]
                + result.sumcheck_round_polys[i][1];
            assert_eq!(
                prev_at_challenge, curr_sum,
                "sumcheck relation violated at round {i}"
            );
        }
    }

    #[test]
    fn warp_fold_multiple_fresh_instances() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        // 3 fresh instances → padded to 4 total (with acc) → log_l = 2
        let fresh = vec![
            make_square_witness(2),
            make_square_witness(3),
            make_square_witness(5),
        ];
        let tau_challenges = vec![F::from_u64(11), F::from_u64(13)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &fresh,
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 300)
            },
        );

        // Fixed size preserved
        assert_eq!(
            result.witness.codeword.as_slice().len(),
            acc.witness.codeword.as_slice().len(),
        );

        // 2 sumcheck rounds
        assert_eq!(result.sumcheck_round_polys.len(), 2);
    }

    #[test]
    fn warp_fold_sequential_preserves_size() {
        // Most critical test: run multiple sequential folds and verify
        // the witness size NEVER grows.
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let initial_code_len = num_vars_y;
        let initial_witness_len = 4;

        let mut acc = make_initial_accumulator(num_vars_y, 2);

        for step in 0..4 {
            let fresh = make_square_witness((step + 2) as u64);
            let tau_challenges = vec![F::from_u64(step as u64 + 42)];
            let omega = F::from_u64(7);

            let mut round_counter = step as u64 * 100;
            let result = warp_fold_prove(
                &shape,
                &[fresh],
                &acc,
                omega,
                &tau_challenges,
                |_coeffs| {
                    round_counter += 1;
                    F::from_u64(round_counter + 500)
                },
            );

            // CRITICAL CHECK: sizes must never change
            assert_eq!(
                result.witness.codeword.as_slice().len(),
                initial_code_len,
                "codeword grew at step {step}!"
            );
            assert_eq!(
                result.witness.witness.len(),
                initial_witness_len,
                "witness grew at step {step}!"
            );

            // Rebuild accumulator for next step
            acc = WarpAccumulator::new(
                WarpAccumulatorInstance {
                    commitment_root: [F::ZERO; 8], // placeholder
                    eval_point: result.instance.eval_point,
                    eval_claim: F::ZERO, // will be set by codeword batching
                    pesat_tau: result.instance.pesat_tau,
                    pesat_x: result.instance.pesat_x,
                    pesat_target: result.instance.pesat_target,
                },
                result.witness,
            );
        }
    }

    #[test]
    fn warp_fold_verify_sumcheck_function() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);
        let fresh = make_square_witness(3);
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        // Compute initial target from the round 0 polynomial
        let initial_target = result.sumcheck_round_polys[0][0]
            + result.sumcheck_round_polys[0][1];

        // Verify using the dedicated function
        let final_eval = warp_fold_verify_sumcheck(
            initial_target,
            &result.sumcheck_round_polys,
            &result.sumcheck_challenges,
        );
        assert!(final_eval.is_ok(), "sumcheck verification failed");
    }

    // ========================================
    // Step 5: Verifier tests
    // ========================================

    #[test]
    fn warp_fold_verifier_accepts_honest_proof() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        let fresh = make_square_witness(3);
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh.clone()],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        let fresh_public = vec![FreshInstancePublic {
            public_input: fresh.public_input.clone(),
        }];

        let verified = warp_fold_verify(
            &shape,
            &fresh_public,
            &acc.instance,
            omega,
            &tau_challenges,
            &result.sumcheck_round_polys,
            &result.sumcheck_challenges,
            &result.instance,
            &result.fresh_eval_claims,
            &result.fresh_pesat_targets,
        );

        assert!(verified.is_ok(), "verifier should accept honest proof");

        let verified_instance = verified.unwrap();
        assert_eq!(
            verified_instance.eval_point, result.instance.eval_point,
            "verified eval_point should match prover's"
        );
        assert_eq!(
            verified_instance.pesat_tau, result.instance.pesat_tau,
            "verified pesat_tau should match prover's"
        );
        assert_eq!(
            verified_instance.pesat_x, result.instance.pesat_x,
            "verified pesat_x should match prover's"
        );
    }

    #[test]
    fn warp_fold_verifier_rejects_tampered_eval_point() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        let fresh = make_square_witness(3);
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh.clone()],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        // Tamper with the claimed output eval_point
        let mut tampered = result.instance.clone();
        tampered.eval_point[0] += F::ONE;

        let fresh_public = vec![FreshInstancePublic {
            public_input: fresh.public_input.clone(),
        }];

        let verified = warp_fold_verify(
            &shape,
            &fresh_public,
            &acc.instance,
            omega,
            &tau_challenges,
            &result.sumcheck_round_polys,
            &result.sumcheck_challenges,
            &tampered,
            &result.fresh_eval_claims,
            &result.fresh_pesat_targets,
        );

        assert!(verified.is_err(), "verifier should reject tampered eval_point");
    }

    #[test]
    fn warp_fold_verifier_rejects_tampered_sumcheck() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        let fresh = make_square_witness(3);
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh.clone()],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        // Tamper with a sumcheck round polynomial
        let mut tampered_polys = result.sumcheck_round_polys.clone();
        tampered_polys[0][0] += F::ONE;

        let fresh_public = vec![FreshInstancePublic {
            public_input: fresh.public_input.clone(),
        }];

        let verified = warp_fold_verify(
            &shape,
            &fresh_public,
            &acc.instance,
            omega,
            &tau_challenges,
            &tampered_polys,
            &result.sumcheck_challenges,
            &result.instance,
            &result.fresh_eval_claims,
            &result.fresh_pesat_targets,
        );

        assert!(verified.is_err(), "verifier should reject tampered sumcheck");
    }

    #[test]
    fn warp_fold_verifier_rejects_tampered_pesat_tau() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        let fresh = make_square_witness(3);
        let tau_challenges = vec![F::from_u64(42)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &[fresh.clone()],
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 200)
            },
        );

        // Tamper with pesat_tau
        let mut tampered = result.instance.clone();
        tampered.pesat_tau[0] += F::ONE;

        let fresh_public = vec![FreshInstancePublic {
            public_input: fresh.public_input.clone(),
        }];

        let verified = warp_fold_verify(
            &shape,
            &fresh_public,
            &acc.instance,
            omega,
            &tau_challenges,
            &result.sumcheck_round_polys,
            &result.sumcheck_challenges,
            &tampered,
            &result.fresh_eval_claims,
            &result.fresh_pesat_targets,
        );

        assert!(verified.is_err(), "verifier should reject tampered pesat_tau");
    }

    #[test]
    fn warp_fold_prover_verifier_agree_multi_instance() {
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let acc = make_initial_accumulator(num_vars_y, 2);

        // 3 fresh instances → padded to 4 → log_l = 2
        let fresh = vec![
            make_square_witness(2),
            make_square_witness(3),
            make_square_witness(5),
        ];
        let tau_challenges = vec![F::from_u64(11), F::from_u64(13)];
        let omega = F::from_u64(7);

        let mut round_counter = 0u64;
        let result = warp_fold_prove(
            &shape,
            &fresh,
            &acc,
            omega,
            &tau_challenges,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 300)
            },
        );

        let fresh_public: Vec<FreshInstancePublic<F>> = fresh
            .iter()
            .map(|f| FreshInstancePublic {
                public_input: f.public_input.clone(),
            })
            .collect();

        let verified = warp_fold_verify(
            &shape,
            &fresh_public,
            &acc.instance,
            omega,
            &tau_challenges,
            &result.sumcheck_round_polys,
            &result.sumcheck_challenges,
            &result.instance,
            &result.fresh_eval_claims,
            &result.fresh_pesat_targets,
        );

        assert!(verified.is_ok(), "verifier should accept multi-instance fold");
    }

    #[test]
    fn warp_fold_sequential_prover_verifier_agree() {
        // Run 3 sequential folds, verify each one
        let shape = make_square_shape();
        let num_vars_y = 1 << shape.num_poly_vars_y();
        let mut acc = make_initial_accumulator(num_vars_y, 2);

        for step in 0..3u64 {
            let fresh = make_square_witness(step + 2);
            let tau_challenges = vec![F::from_u64(step + 42)];
            let omega = F::from_u64(7);

            let mut round_counter = step * 100;
            let result = warp_fold_prove(
                &shape,
                &[fresh.clone()],
                &acc,
                omega,
                &tau_challenges,
                |_coeffs| {
                    round_counter += 1;
                    F::from_u64(round_counter + 500)
                },
            );

            // Verify this step
            let fresh_public = vec![FreshInstancePublic {
                public_input: fresh.public_input.clone(),
            }];

            let verified = warp_fold_verify(
                &shape,
                &fresh_public,
                &acc.instance,
                omega,
                &tau_challenges,
                &result.sumcheck_round_polys,
                &result.sumcheck_challenges,
            &result.instance,
            &result.fresh_eval_claims,
            &result.fresh_pesat_targets,
            );
            assert!(
                verified.is_ok(),
                "verifier should accept at step {step}: {:?}",
                verified.err()
            );

            // Rebuild accumulator for next step
            // Compute the actual eval_claim: f̂(α) where f̂ is the MLE of the codeword
            let eval_claim = result
                .witness
                .codeword
                .evaluate_hypercube_base(
                    &crate::poly::multilinear::MultilinearPoint::new(
                        result.instance.eval_point.iter().copied().collect(),
                    ),
                );

            acc = WarpAccumulator::new(
                WarpAccumulatorInstance {
                    commitment_root: [F::ZERO; 8],
                    eval_point: result.instance.eval_point,
                    eval_claim,
                    pesat_tau: result.instance.pesat_tau,
                    pesat_x: result.instance.pesat_x,
                    pesat_target: result.instance.pesat_target,
                },
                result.witness,
            );
        }
    }
}
