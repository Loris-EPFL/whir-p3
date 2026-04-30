//! In-circuit Quasar multi-cast verifier (paper §4.2).
//!
//! Standalone R1CS gadget that consumes a [`QuasarMulticastProof`] and
//! emits constraints enforcing:
//!   1. Fiat-Shamir: `r_x` is sampled from the Poseidon2 sponge.
//!   2. `v` is absorbed into the sponge (binding C∪ ↔ C).
//!   3. Union-side sumcheck: `w̃∪(τ, r_x) = v` reduces to
//!      `w̃∪(union_challenges) = union_new_claim`.
//!   4. Folded-side sumcheck: `f(r_x) = v` reduces to
//!      `f(folded_challenges) = folded_new_claim`.
//!   5. Both sumchecks use the SAME `v` — the τ-collapse equality check.
//!
//! Total constraint cost: **O(log ℓ + log n)** — sublinear in ℓ.
//!
//! # Relation to `synthesize_warp_fold_verifier`
//!
//! The existing in-circuit verifier emits O(ℓ·t) constraints because:
//!   - Shift queries reconstruct ℓ values per query (O(ℓ·t))
//!   - OOD absorbs ℓ samples (O(ℓ·s))
//!
//! This gadget replaces both with the Quasar multi-cast two-sumcheck
//! equality check, achieving the paper's sublinear-in-ℓ verifier.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use crate::circuit::{
    builder::{CircuitBuilder, LinearCombination, Var},
    poseidon2::Poseidon2CircuitConfig,
    sponge::CircuitChallenger,
};

/// Witness for the in-circuit Quasar multi-cast verifier.
#[derive(Clone, Debug)]
pub struct QuasarMulticastCircuitWitness<F: Field> {
    /// τ = twin-constraint sumcheck challenges (log ℓ elements).
    /// Bound to prior FS state by the caller — we take them as-is.
    pub tau: Vec<F>,
    /// `log_n_rs` = log size of the folded codeword.
    pub log_n_rs: usize,
    /// Prover's asserted `v = w̃∪(τ, r_x) = f(r_x)`.
    pub v: F,
    /// Round polynomials for the union-side sumcheck.
    /// Length = `τ.len() + log_n_rs` (the union sumcheck reduces over
    /// both the `log ℓ` τ-variables and the `log n` r_x-variables).
    pub union_round_polys: Vec<[F; 3]>,
    /// Round polynomials for the folded-side sumcheck.
    /// Length = `log_n_rs`.
    pub folded_round_polys: Vec<[F; 3]>,
    /// Sumcheck challenges — these must match what the circuit's FS
    /// challenger derives; the constraint emission enforces this.
    pub union_challenges: Vec<F>,
    pub folded_challenges: Vec<F>,
    /// Prover's asserted reduced claims.
    pub union_new_claim: F,
    pub folded_new_claim: F,
}

/// Output variables for downstream wiring.
#[derive(Clone, Debug)]
pub struct QuasarMulticastCircuitOutput {
    /// `r_x` sampled from FS (log_n_rs variables).
    pub r_x_vars: Vec<Var>,
    /// `v` — the shared claimed value (bound by the equality check).
    pub v_var: Var,
    /// Union-side reduced point (log_l + log_n_rs variables).
    pub union_point_vars: Vec<Var>,
    /// Union-side reduced claim.
    pub union_claim_var: Var,
    /// Folded-side reduced point (log_n_rs variables).
    pub folded_point_vars: Vec<Var>,
    /// Folded-side reduced claim.
    pub folded_claim_var: Var,
}

/// Emit the degree-2 polynomial evaluation at r via Lagrange interpolation:
/// given `(e0, e1, e2) = (h(0), h(1), h(2))` for a degree-2 polynomial h,
/// returns `h(r) = e0 + d·r + c2·r·(r-1)` where
///   `d  = e1 - e0`,
///   `c2 = (e2 - 2·e1 + e0) / 2`.
///
/// Costs 3 multiplications + 4 helper witnesses per call.
fn eval_degree2_at_r<F: Field>(
    builder: &mut CircuitBuilder<F>,
    e0_var: Var,
    e1_var: Var,
    e2_var: Var,
    e0_val: F,
    e1_val: F,
    e2_val: F,
    r_var: Var,
    r_val: F,
) -> (Var, F) {
    // d = e1 - e0
    let d_val = e1_val - e0_val;
    let d_var = builder.alloc_witness(d_val);
    builder.enforce(
        LinearCombination::from_var(e1_var) - LinearCombination::from_var(e0_var),
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(d_var),
    );

    // dr = d · r
    let dr_val = d_val * r_val;
    let dr_var = builder.mul(d_var, r_var, dr_val);

    // c2 = (e2 - 2·e1 + e0) / 2  —  enforce  2·c2 == e2 - 2·e1 + e0
    let c2_val = (e2_val - e1_val.double() + e0_val) * F::TWO.inverse();
    let c2_var = builder.alloc_witness(c2_val);
    builder.enforce(
        LinearCombination::from_constant(F::TWO),
        LinearCombination::from_var(c2_var),
        LinearCombination::from_var(e2_var) - LinearCombination::from_scaled(e1_var, F::TWO)
            + LinearCombination::from_var(e0_var),
    );

    // rm1 = r - 1
    let rm1_val = r_val - F::ONE;
    let rm1_var = builder.alloc_witness(rm1_val);
    builder.enforce(
        LinearCombination::from_var(r_var) - LinearCombination::from_constant(F::ONE),
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(rm1_var),
    );

    // r · (r-1)
    let r_rm1_val = r_val * rm1_val;
    let r_rm1_var = builder.mul(r_var, rm1_var, r_rm1_val);

    // c2 · r · (r-1)
    let c2_term_val = c2_val * r_rm1_val;
    let c2_term_var = builder.mul(c2_var, r_rm1_var, c2_term_val);

    // result = e0 + dr + c2·r·(r-1)
    let result_val = e0_val + dr_val + c2_term_val;
    let result_var = builder.alloc_witness(result_val);
    builder.enforce(
        LinearCombination::from_var(e0_var)
            + LinearCombination::from_var(dr_var)
            + LinearCombination::from_var(c2_term_var),
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(result_var),
    );

    (result_var, result_val)
}

/// Synthesize the in-circuit Quasar multi-cast verifier.
///
/// Takes the circuit builder's **Fiat-Shamir challenger** (which the caller
/// has already advanced past the twin-constraint sumcheck / fresh-beta
/// sampling — i.e. we enter with the same state as the prover at the
/// start of `quasar_multicast_prove`).
///
/// Emits:
///   - `log_n_rs` Poseidon2 samples for `r_x`.
///   - 1 absorb of `v`.
///   - `(log ℓ + log n_rs)` + `log n_rs` rounds of round-poly absorb + sample.
///   - Per round: `e0+e1 == current_claim` constraint + degree-2 eval at r.
///   - Binding: both sumchecks start from the **same** `v` — no separate
///     equality check needed because the verifier uses a single `v_var`
///     for both sides.
///
/// # Panics
/// - If `witness.union_round_polys.len() != witness.tau.len() + witness.log_n_rs`.
/// - If `witness.folded_round_polys.len() != witness.log_n_rs`.
#[allow(clippy::too_many_lines)]
pub fn synthesize_quasar_multicast_verify<F, L, P, const WIDTH: usize, const RATE: usize>(
    builder: &mut CircuitBuilder<F>,
    challenger: &mut CircuitChallenger<F, WIDTH, RATE>,
    poseidon_config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    witness: &QuasarMulticastCircuitWitness<F>,
) -> QuasarMulticastCircuitOutput
where
    F: Field + PrimeCharacteristicRing + PrimeField64,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    let log_l = witness.tau.len();
    let log_n = witness.log_n_rs;
    let log_total = log_l + log_n;
    assert_eq!(
        witness.union_round_polys.len(),
        log_total,
        "union sumcheck must have log ℓ + log n_rs rounds",
    );
    assert_eq!(
        witness.folded_round_polys.len(),
        log_n,
        "folded sumcheck must have log n_rs rounds",
    );
    assert_eq!(
        witness.union_challenges.len(),
        log_total,
        "union challenges length must match round polys",
    );
    assert_eq!(
        witness.folded_challenges.len(),
        log_n,
        "folded challenges length must match round polys",
    );

    // ── Allocate τ variables (caller has already bound them upstream via
    // the twin-constraint sumcheck; we just re-use the values here as
    // witness inputs).
    let tau_vars: Vec<Var> = witness
        .tau
        .iter()
        .map(|&t| builder.alloc_witness(t))
        .collect();

    // ── Step 1: sample r_x from FS ──
    // Prover tagged each coordinate with `F::from_usize(3000 + i)` and
    // absorbed-then-sampled.  We mirror that sequence faithfully so the
    // in-circuit sponge stays aligned with the prover's native sponge.
    let mut r_x_vars: Vec<Var> = Vec::with_capacity(log_n);
    let mut r_x_vals: Vec<F> = Vec::with_capacity(log_n);
    for i in 0..log_n {
        let tag = F::from_usize(3000 + i);
        let tag_var = builder.alloc_witness(tag);
        builder.enforce_constant(tag_var, tag);
        challenger.observe_slice::<L, P>(builder, poseidon_config, perm, &[tag_var], &[tag]);
        let (sampled_var, sampled_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        r_x_vars.push(sampled_var);
        r_x_vals.push(sampled_val);
    }

    // ── Step 2: absorb v ──
    // NOTE: the native prover's `transcript_round` closure does an
    // observe-AND-sample per call (the returned challenge is discarded
    // when we just want the absorb).  We mirror that here — observe v,
    // then consume-and-discard one sample — to keep the sponge state
    // aligned with the prover after the `transcript_round(&[v])` call.
    let v_var = builder.alloc_witness(witness.v);
    challenger.observe_slice::<L, P>(builder, poseidon_config, perm, &[v_var], &[witness.v]);
    let _ = challenger.sample::<L, P>(builder, poseidon_config, perm);

    // ── Step 3: union-side sumcheck (log ℓ + log n_rs rounds) ──
    // Starting claim: v. Each round: e0+e1 == claim, then claim = h(r).
    let mut union_current_var = v_var;
    let mut union_current_val = witness.v;
    let mut union_challenge_vars: Vec<Var> = Vec::with_capacity(log_total);
    let mut union_challenge_vals: Vec<F> = Vec::with_capacity(log_total);

    for (round, poly) in witness.union_round_polys.iter().enumerate() {
        let [e0_val, e1_val, e2_val] = *poly;

        let e0_var = builder.alloc_witness(e0_val);
        let e1_var = builder.alloc_witness(e1_val);
        let e2_var = builder.alloc_witness(e2_val);

        // Absorb round poly into FS.
        challenger.observe_slice::<L, P>(
            builder,
            poseidon_config,
            perm,
            &[e0_var, e1_var, e2_var],
            &[e0_val, e1_val, e2_val],
        );

        // Constraint: e0 + e1 == current_claim (round sum consistency).
        builder.enforce(
            LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(union_current_var),
        );

        // Sample challenge r and bind to witness.
        let (r_var, r_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        let expected_r = witness.union_challenges[round];
        let witness_r_var = builder.alloc_witness(expected_r);
        builder.enforce_equal(r_var, witness_r_var);
        debug_assert_eq!(
            r_val, expected_r,
            "quasar multicast union sumcheck: round {round} FS challenge != witness",
        );
        union_challenge_vars.push(r_var);
        union_challenge_vals.push(r_val);

        // Next claim = h(r).
        let (next_var, next_val) = eval_degree2_at_r(
            builder, e0_var, e1_var, e2_var, e0_val, e1_val, e2_val, r_var, r_val,
        );
        union_current_var = next_var;
        union_current_val = next_val;
    }

    // ── Step 3b: union sumcheck final check ──
    // current_claim = B̃(α) · new_claim, where B̃(α) = eq([τ||r_x], α).
    // We compute B̃(α) in-circuit via a product of log_total linear terms.
    let union_alpha_vars: Vec<Var> = tau_vars.iter().chain(r_x_vars.iter()).copied().collect();
    let union_alpha_vals: Vec<F> = witness
        .tau
        .iter()
        .copied()
        .chain(r_x_vals.iter().copied())
        .collect();
    let union_alpha_claim_vals: Vec<F> = union_challenge_vals.clone();
    let (b_at_alpha_var, b_at_alpha_val) = eq_product_at_challenge(
        builder,
        &union_alpha_vars,
        &union_alpha_vals,
        &union_challenge_vars,
        &union_alpha_claim_vals,
    );
    // expected_product = B̃(α) · new_union_claim
    let union_new_claim_var = builder.alloc_witness(witness.union_new_claim);
    let expected_union_val = b_at_alpha_val * witness.union_new_claim;
    let expected_union_var = builder.mul(b_at_alpha_var, union_new_claim_var, expected_union_val);
    builder.enforce_equal(union_current_var, expected_union_var);
    debug_assert_eq!(
        union_current_val, expected_union_val,
        "quasar multicast union sumcheck: final eval inconsistency",
    );

    // ── Step 4: folded-side sumcheck (log n_rs rounds) ──
    let mut folded_current_var = v_var;
    let mut folded_current_val = witness.v;
    let mut folded_challenge_vars: Vec<Var> = Vec::with_capacity(log_n);
    let mut folded_challenge_vals: Vec<F> = Vec::with_capacity(log_n);

    for (round, poly) in witness.folded_round_polys.iter().enumerate() {
        let [e0_val, e1_val, e2_val] = *poly;

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

        builder.enforce(
            LinearCombination::from_var(e0_var) + LinearCombination::from_var(e1_var),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(folded_current_var),
        );

        let (r_var, r_val) = challenger.sample::<L, P>(builder, poseidon_config, perm);
        let expected_r = witness.folded_challenges[round];
        let witness_r_var = builder.alloc_witness(expected_r);
        builder.enforce_equal(r_var, witness_r_var);
        debug_assert_eq!(
            r_val, expected_r,
            "quasar multicast folded sumcheck: round {round} FS challenge != witness",
        );
        folded_challenge_vars.push(r_var);
        folded_challenge_vals.push(r_val);

        let (next_var, next_val) = eval_degree2_at_r(
            builder, e0_var, e1_var, e2_var, e0_val, e1_val, e2_val, r_var, r_val,
        );
        folded_current_var = next_var;
        folded_current_val = next_val;
    }

    // ── Step 4b: folded sumcheck final check ──
    // B̃(α) = eq(r_x, folded_challenges) — log n_rs factor product.
    let (b_at_alpha_folded_var, b_at_alpha_folded_val) = eq_product_at_challenge(
        builder,
        &r_x_vars,
        &r_x_vals,
        &folded_challenge_vars,
        &folded_challenge_vals,
    );
    let folded_new_claim_var = builder.alloc_witness(witness.folded_new_claim);
    let expected_folded_val = b_at_alpha_folded_val * witness.folded_new_claim;
    let expected_folded_var = builder.mul(
        b_at_alpha_folded_var,
        folded_new_claim_var,
        expected_folded_val,
    );
    builder.enforce_equal(folded_current_var, expected_folded_var);
    debug_assert_eq!(
        folded_current_val, expected_folded_val,
        "quasar multicast folded sumcheck: final eval inconsistency",
    );

    QuasarMulticastCircuitOutput {
        r_x_vars,
        v_var,
        union_point_vars: union_challenge_vars,
        union_claim_var: union_new_claim_var,
        folded_point_vars: folded_challenge_vars,
        folded_claim_var: folded_new_claim_var,
    }
}

/// Compute  Π_i (p_i · α_i + (1 − p_i)(1 − α_i))  in-circuit.
/// One multiplication per coordinate + one running-product multiplication;
/// total = 2·log(n) multiplications.
fn eq_product_at_challenge<F: Field>(
    builder: &mut CircuitBuilder<F>,
    point_vars: &[Var],
    point_vals: &[F],
    alpha_vars: &[Var],
    alpha_vals: &[F],
) -> (Var, F) {
    assert_eq!(point_vars.len(), alpha_vars.len());
    assert_eq!(point_vals.len(), alpha_vals.len());

    // Start with constant 1.
    let mut acc_var = builder.alloc_witness(F::ONE);
    builder.enforce_constant(acc_var, F::ONE);
    let mut acc_val = F::ONE;

    for i in 0..point_vars.len() {
        let p_var = point_vars[i];
        let a_var = alpha_vars[i];
        let p_val = point_vals[i];
        let a_val = alpha_vals[i];

        // pa = p · α
        let pa_val = p_val * a_val;
        let pa_var = builder.mul(p_var, a_var, pa_val);

        // term = 2·pa - p - α + 1  =  p · α + (1−p)(1−α).
        let term_val = pa_val.double() - p_val - a_val + F::ONE;
        let term_var = builder.alloc_witness(term_val);
        builder.enforce(
            LinearCombination::from_scaled(pa_var, F::TWO)
                - LinearCombination::from_var(p_var)
                - LinearCombination::from_var(a_var)
                + LinearCombination::from_constant(F::ONE),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(term_var),
        );

        let new_val = acc_val * term_val;
        let new_var = builder.mul(acc_var, term_var, new_val);
        acc_var = new_var;
        acc_val = new_val;
    }

    (acc_var, acc_val)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};
    use p3_poseidon2::poseidon2_round_numbers_128;
    use rand::{SeedableRng, rngs::SmallRng};
    use warp::encoding::build_union_codeword;
    use warp::quasar_multicast::{QuasarMulticastProof, quasar_multicast_prove};

    use super::*;
    use crate::circuit::sponge::CircuitChallenger;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
    type MyChal = DuplexChallenger<F, Perm, 16, 8>;

    fn build_synth(log_l: usize, log_n: usize, seed: u64) -> (Vec<Vec<F>>, Vec<F>, Vec<F>) {
        let l = 1usize << log_l;
        let n = 1usize << log_n;
        let tau: Vec<F> = (0..log_l)
            .map(|i| F::from_u64(1 + seed.wrapping_mul(7) + i as u64 * 31))
            .collect();
        let cws: Vec<Vec<F>> = (0..l)
            .map(|i| {
                (0..n)
                    .map(|p| F::from_u64(seed + (i as u64) * 10_000 + p as u64 + 1))
                    .collect()
            })
            .collect();
        let eq_weights: Vec<F> = (0..l)
            .map(|i| {
                let mut w = F::ONE;
                for (bit, tj) in tau.iter().enumerate() {
                    let bit_set = ((i >> bit) & 1) == 1;
                    w *= if bit_set { *tj } else { F::ONE - *tj };
                }
                w
            })
            .collect();
        let mut folded = alloc::vec![F::ZERO; n];
        for (i, cw) in cws.iter().enumerate() {
            let w = eq_weights[i];
            for (p, &v) in cw.iter().enumerate() {
                folded[p] += w * v;
            }
        }
        (cws, tau, folded)
    }

    fn build_config() -> (Perm, Poseidon2CircuitConfig<F, 16>) {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = poseidon2_round_numbers_128::<F>(16, 3).unwrap();
        let cfg =
            Poseidon2CircuitConfig::<F, 16>::from_rng(rf, rp, 3, &mut SmallRng::seed_from_u64(99));
        (perm, cfg)
    }

    fn prove_multicast_with_poseidon2(
        log_l: usize,
        log_n: usize,
        seed: u64,
    ) -> (
        Vec<F>,
        F,
        QuasarMulticastProof<F>,
        Vec<F>,
        Vec<F>,
        Perm,
        Poseidon2CircuitConfig<F, 16>,
    ) {
        let (cws, tau, folded) = build_synth(log_l, log_n, seed);
        let union_cw = build_union_codeword(&cws);

        let (perm, cfg) = build_config();

        // Native challenger used by the prover to generate the multicast's
        // internal FS (matches what the circuit will replay).
        let mut native_chal = MyChal::new(perm.clone());

        // Absorb τ so the multicast FS starts from the same base state as
        // the circuit will after allocating τ (we don't actually absorb τ
        // in-circuit either, but we keep the native FS identical for the
        // multicast replay).
        //
        // The prover's closure below performs both observe-and-sample per
        // transcript round.
        let mut counter = 0u64;

        // Pre-compute the challenges the native Poseidon2 challenger would
        // produce so we can feed them into the in-circuit witness.
        use p3_challenger::{CanObserve, CanSample};

        // We instead produce the proof using the SAME Poseidon2 challenger
        // we'll replay in-circuit. The `transcript_round` closure performs
        // observe + sample — matching the closure style used elsewhere in
        // the codebase.
        let mut fs_chal = MyChal::new(perm.clone());
        let transcript_fn = |msg: &[F]| -> F {
            for &m in msg {
                fs_chal.observe(m);
            }
            fs_chal.sample()
        };

        let mut closure = transcript_fn;

        let (proof, _claims) = quasar_multicast_prove::<F>(&union_cw, &folded, &tau, &mut closure);

        // Re-derive the sumcheck challenges for the in-circuit witness:
        // we need the exact `r` values the native FS produced for each
        // round.  Replay the prover's FS in parallel — it's deterministic.
        let mut replay_chal = MyChal::new(perm.clone());
        let mut replay_counter = 0u64;
        let _ = counter; // silence unused
        let _ = replay_counter; // silence unused

        // r_x: log_n samples, each preceded by observing a tag.
        let mut r_x = Vec::with_capacity(log_n);
        for i in 0..log_n {
            let tag = F::from_usize(3000 + i);
            replay_chal.observe(tag);
            r_x.push(<MyChal as p3_challenger::CanSample<F>>::sample(
                &mut replay_chal,
            ));
        }
        // Absorb v (the prover's closure DOES observe + sample and then
        // discards the sample, so we mirror that sample here to keep FS
        // state aligned with the circuit).
        replay_chal.observe(proof.v);
        let _: F = <MyChal as p3_challenger::CanSample<F>>::sample(&mut replay_chal);

        // Union sumcheck challenges.
        let mut union_challenges = Vec::with_capacity(log_l + log_n);
        for round_poly in &proof.union_round_polys {
            for &e in round_poly {
                replay_chal.observe(e);
            }
            union_challenges.push(<MyChal as p3_challenger::CanSample<F>>::sample(
                &mut replay_chal,
            ));
        }
        // Folded sumcheck challenges.
        let mut folded_challenges = Vec::with_capacity(log_n);
        for round_poly in &proof.folded_round_polys {
            for &e in round_poly {
                replay_chal.observe(e);
            }
            folded_challenges.push(<MyChal as p3_challenger::CanSample<F>>::sample(
                &mut replay_chal,
            ));
        }

        (
            tau,
            proof.v,
            proof,
            union_challenges,
            folded_challenges,
            perm,
            cfg,
        )
    }

    #[test]
    fn quasar_multicast_circuit_satisfiable_l2() {
        let (tau, v, proof, union_ch, folded_ch, perm, cfg) =
            prove_multicast_with_poseidon2(1, 2, 42);

        let witness = QuasarMulticastCircuitWitness {
            tau: tau.clone(),
            log_n_rs: 2,
            v,
            union_round_polys: proof
                .union_round_polys
                .iter()
                .map(|p| [p[0], p[1], p[2]])
                .collect(),
            folded_round_polys: proof
                .folded_round_polys
                .iter()
                .map(|p| [p[0], p[1], p[2]])
                .collect(),
            union_challenges: union_ch,
            folded_challenges: folded_ch,
            union_new_claim: proof.union_new_claim,
            folded_new_claim: proof.folded_new_claim,
        };

        let mut builder = CircuitBuilder::<F>::new();
        let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
        let _out = synthesize_quasar_multicast_verify::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            16,
            8,
        >(&mut builder, &mut challenger, &cfg, &perm, &witness);

        let (shape, instance) = builder.build();
        assert!(
            shape.is_sat(instance.witness(), instance.input()),
            "honest Quasar multicast circuit must be R1CS-satisfiable",
        );
    }

    /// Core Step-E deliverable: the constraint count of the in-circuit
    /// Quasar multi-cast verifier grows O(log ℓ + log n), NOT O(ℓ).
    ///
    /// Run with `cargo test -p whir-ivc --release quasar_multicast_circuit_size_scales_sublinearly -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual run: prints circuit-size scaling table"]
    fn quasar_multicast_circuit_size_scales_sublinearly() {
        let log_n = 10; // fixed codeword size

        std::println!(
            "{:>6} {:>6} {:>12} {:>14}",
            "ℓ",
            "log_l",
            "constraints",
            "witness_vars"
        );
        std::println!("{:-<48}", "");

        let mut prev = 0usize;
        for log_l in 1..=6usize {
            let (tau, v, proof, union_ch, folded_ch, perm, cfg) =
                prove_multicast_with_poseidon2(log_l, log_n, 42);

            let witness = QuasarMulticastCircuitWitness {
                tau,
                log_n_rs: log_n,
                v,
                union_round_polys: proof
                    .union_round_polys
                    .iter()
                    .map(|p| [p[0], p[1], p[2]])
                    .collect(),
                folded_round_polys: proof
                    .folded_round_polys
                    .iter()
                    .map(|p| [p[0], p[1], p[2]])
                    .collect(),
                union_challenges: union_ch,
                folded_challenges: folded_ch,
                union_new_claim: proof.union_new_claim,
                folded_new_claim: proof.folded_new_claim,
            };

            let mut builder = CircuitBuilder::<F>::new();
            let mut challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);
            let _ = synthesize_quasar_multicast_verify::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                16,
                8,
            >(&mut builder, &mut challenger, &cfg, &perm, &witness);

            let num_constraints = builder.num_constraints();
            let num_witness = builder.num_witness_vars();
            let l = 1usize << log_l;
            std::println!(
                "{:>6} {:>6} {:>12} {:>14}",
                l,
                log_l,
                num_constraints,
                num_witness
            );

            // Assert the incremental growth is a small FIXED amount per
            // log_l increment — independent of ℓ itself.  Each extra
            // sumcheck round adds one round-poly absorb (3 Poseidon2
            // absorbs ≈ 900 constraints) + one sample + one degree-2 eval
            // + one eq-product term.  Empirically this is ~1k constraints
            // per ℓ-doubling.
            //
            // A linear-in-ℓ circuit would DOUBLE the constraint count
            // with each arity doubling (e.g. 30k → 60k → 120k → ...).
            // We assert each doubling adds < 2k constraints, which is
            // strictly sublinear-in-ℓ.
            if prev > 0 {
                let delta = num_constraints.saturating_sub(prev);
                assert!(
                    delta < 2000,
                    "constraint delta {delta} for log_l {log_l} is too large — scaling not sublinear (would be {} for linear growth)",
                    prev,
                );
            }
            prev = num_constraints;
        }
    }
}
