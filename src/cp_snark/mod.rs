//! CP-SNARK compiler: deferred Fiat-Shamir verification for WARP fold.
//!
//! Based on Symphony (Chen 2025), Section 6. Instead of embedding Poseidon2
//! hashing in the recursive circuit (~94% of constraints), the CP-SNARK
//! approach stores fold transcript data and defers hash verification to
//! terminal. The recursive circuit only checks algebraic sumcheck consistency.
//!
//! # Architecture
//!
//! ```text
//! Current recursive IVC step:
//!   Circuit = step_fn + Poseidon2_FS + algebraic_sumcheck_check
//!   ~5000 constraints (94% Poseidon2)
//!
//! CP-SNARK recursive IVC step:
//!   Circuit = step_fn + algebraic_sumcheck_check  (NO Poseidon2)
//!   ~300 constraints
//!   + DeferredFoldTranscript stored for terminal verification
//! ```
//!
//! At terminal, the verifier replays all deferred transcripts with native
//! Poseidon2 to verify challenges were correctly derived, then checks the
//! accumulated WHIR proof as usual.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, CanSample};
use p3_field::Field;

use crate::{
    accumulation::warp::{
        accumulator::WarpAccumulator,
        decider::{warp_decide_algebraic_rs, WarpDeciderError},
    },
    spartan::r1cs::R1CSShape,
};

/// Deferred fold transcript data for terminal verification.
///
/// At each IVC step, instead of verifying Fiat-Shamir challenges in-circuit
/// (via Poseidon2 constraints), we store the transcript data and derived
/// challenges. The terminal verifier replays the transcript natively to
/// check consistency.
///
/// This corresponds to the FS commitments `{c_{fs,i}}` in Symphony Section 6,
/// Equation 55: the verifier recomputes `(r_i)` from `(x, {c_{fs,i}})` and
/// checks them against the challenges used in the proof.
#[derive(Clone, Debug)]
pub struct DeferredFoldTranscript<F: Field> {
    /// IVC step index (for ordering and debugging).
    pub step: usize,
    /// Commitment roots of input accumulators (each is `DIGEST_ELEMS` base elements).
    pub input_commitment_roots: Vec<Vec<F>>,
    /// Eval claims `μ_i` from each input accumulator.
    pub input_eval_claims: Vec<F>,
    /// Eval points `α_i` from each input accumulator (variable length per accumulator).
    pub input_eval_points: Vec<Vec<F>>,
    /// PESAT targets `η_i` from each input accumulator.
    pub input_pesat_targets: Vec<F>,
    /// Twin-constraint sumcheck round polynomials `[h(0), h(1), h(2)]` per round.
    pub sumcheck_evals: Vec<[F; 3]>,
    /// The batching challenge `ω` used in twin-constraint: `target_i = μ_i + ω·η_i`.
    pub omega: F,
    /// Tau challenges for the sumcheck eq polynomial (`log_l` elements).
    pub tau_challenges: Vec<F>,
    /// Per-round sumcheck challenges `r_i` derived from the transcript.
    pub sumcheck_challenges: Vec<F>,
}

/// Verify all deferred fold transcripts at terminal.
///
/// Re-derives Fiat-Shamir challenges using a native Poseidon2 challenger
/// and checks they match the challenges used during IVC. This is the
/// "verifier step 2" from Symphony Construction 6.1:
///
/// ```text
/// Vf: Parse π* = (π_cp, π, {c_{fs,i}}, x_o)
///     Recompute (r_i) from (x, {c_{fs,i}}) and H
///     Check Π_cp.Vf(vk_cp, x_cp, π_cp) ∧ Π_snark.Vf(vk, x_o, π)
/// ```
///
/// Returns `true` if all transcripts verify (challenges match).
pub fn verify_deferred_transcripts<F, Challenger>(
    transcripts: &[DeferredFoldTranscript<F>],
    mut make_challenger: impl FnMut() -> Challenger,
) -> bool
where
    F: Field + PartialEq,
    Challenger: CanObserve<F> + CanSample<F>,
{
    for transcript in transcripts {
        let mut challenger = make_challenger();

        // Replay observations in the same order as the prover's circuit would.
        // For each input accumulator i ∈ [k]:
        //   observe(commitment_root[8]), observe(μ_i), observe(α_i), observe(η_i)
        let k = transcript.input_commitment_roots.len();
        for i in 0..k {
            for &val in &transcript.input_commitment_roots[i] {
                challenger.observe(val);
            }
            challenger.observe(transcript.input_eval_claims[i]);
            for &val in &transcript.input_eval_points[i] {
                challenger.observe(val);
            }
            challenger.observe(transcript.input_pesat_targets[i]);
        }

        // Derive and check ω (batching challenge)
        let omega: F = challenger.sample();
        if omega != transcript.omega {
            return false;
        }

        // Derive and check τ challenges (log_l elements)
        for &expected_tau in &transcript.tau_challenges {
            let tau: F = challenger.sample();
            if tau != expected_tau {
                return false;
            }
        }

        // For each sumcheck round: observe round poly, derive and check r
        for (round, &expected_r) in transcript.sumcheck_challenges.iter().enumerate() {
            let [e0, e1, e2] = transcript.sumcheck_evals[round];
            challenger.observe(e0);
            challenger.observe(e1);
            challenger.observe(e2);
            let r: F = challenger.sample();
            if r != expected_r {
                return false;
            }
        }
    }

    true
}

/// Errors from the CP-SNARK terminal decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpSnarkDeciderError {
    /// Algebraic decider failed (eval claim, PESAT, or codeword validity).
    AlgebraicCheck(WarpDeciderError),
    /// Deferred fold transcript verification failed — Fiat-Shamir challenges
    /// don't match what native Poseidon2 would derive from the observed data.
    TranscriptMismatch,
}

/// CP-SNARK terminal verification (Symphony Construction 6.1, "Vf" step).
///
/// Performs the two CP-SNARK-specific checks at the end of an IVC chain:
///
/// 1. **Deferred transcript replay**: Re-derives all Fiat-Shamir challenges
///    using a native Poseidon2 challenger and checks they match the challenges
///    used during each IVC fold step.
///
/// 2. **Algebraic decider**: Checks the three WARP accumulator conditions on
///    the final accumulated witness:
///    - f̂(α) = μ (evaluation claim)
///    - P*(β, z) = η (PESAT / bundled R1CS)
///    - f = encode(w) (codeword validity)
///
/// The caller is responsible for the terminal WHIR proof separately.
pub fn cp_snark_terminal_verify<F, Challenger>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
    transcripts: &[DeferredFoldTranscript<F>],
    make_challenger: impl FnMut() -> Challenger,
) -> Result<(), CpSnarkDeciderError>
where
    F: Field + PartialEq,
    Challenger: CanObserve<F> + CanSample<F>,
{
    // Step 1: Verify all deferred transcripts (Fiat-Shamir consistency)
    if !verify_deferred_transcripts(transcripts, make_challenger) {
        return Err(CpSnarkDeciderError::TranscriptMismatch);
    }

    // Step 2: Algebraic decider (eval claim + PESAT; codeword validity
    // deferred to WHIR proof since accumulators use RS encoding)
    warp_decide_algebraic_rs(shape, acc).map_err(CpSnarkDeciderError::AlgebraicCheck)
}

/// Build a `DeferredFoldTranscript` from fold data and Poseidon2-derived challenges.
///
/// This is the prover's side: after running the WARP fold with Poseidon2 challenges,
/// package the transcript data for terminal verification.
pub fn build_deferred_transcript<F: Field>(
    step: usize,
    input_commitment_roots: Vec<Vec<F>>,
    input_eval_claims: Vec<F>,
    input_eval_points: Vec<Vec<F>>,
    input_pesat_targets: Vec<F>,
    sumcheck_round_polys: &[Vec<F>],
    omega: F,
    tau_challenges: Vec<F>,
    sumcheck_challenges: Vec<F>,
) -> DeferredFoldTranscript<F> {
    let sumcheck_evals = sumcheck_round_polys
        .iter()
        .map(|evals| {
            assert!(evals.len() >= 3);
            [evals[0], evals[1], evals[2]]
        })
        .collect();

    DeferredFoldTranscript {
        step,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        sumcheck_evals,
        omega,
        tau_challenges,
        sumcheck_challenges,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;
    type MyChal = DuplexChallenger<F, Perm, 16, 8>;

    fn make_perm() -> Perm {
        Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42))
    }

    /// Build a transcript by running the native challenger, then verify it.
    #[test]
    fn deferred_transcript_roundtrip() {
        let perm = make_perm();

        // Simulate: prover observes data and derives challenges
        let mut prover_chal = MyChal::new(perm.clone());

        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::from_u64(10), F::from_u64(20)];
        let eval_points = vec![vec![F::from_u64(1), F::from_u64(2), F::from_u64(3)]; 2];
        let pesat_targets = vec![F::ZERO; 2];

        // Observe
        for i in 0..2 {
            for &val in &roots[i] {
                prover_chal.observe(val);
            }
            prover_chal.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                prover_chal.observe(val);
            }
            prover_chal.observe(pesat_targets[i]);
        }
        let omega: F = prover_chal.sample();
        let tau: Vec<F> = (0..1).map(|_| prover_chal.sample()).collect();

        // Sumcheck round
        let round_evals = vec![vec![F::from_u64(15), F::from_u64(15), F::from_u64(25)]];
        for &e in &round_evals[0] {
            prover_chal.observe(e);
        }
        let r: F = prover_chal.sample();

        let transcript = build_deferred_transcript(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &round_evals,
            omega,
            tau,
            vec![r],
        );

        // Terminal verification should pass
        assert!(verify_deferred_transcripts(
            &[transcript.clone()],
            || MyChal::new(perm.clone()),
        ));

        // Tampered challenge should fail
        let mut bad = transcript;
        bad.omega = F::from_u64(999);
        assert!(!verify_deferred_transcripts(
            &[bad],
            || MyChal::new(perm.clone()),
        ));
    }
}
