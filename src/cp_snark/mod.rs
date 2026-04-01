//! CP-SNARK compiler using Symphony's commitment-based approach.
//!
//! Based on Symphony (Chen 2025), Section 6. Instead of embedding Poseidon2
//! hashing in the recursive circuit, the prover commits to fold transcript
//! data using Symphony's `HashCommitment` (SHA-256, straightline extractable)
//! and defers verification to terminal.
//!
//! # Soundness
//!
//! The previous wrapper stored fold transcript data without a binding
//! commitment, allowing a malicious prover to fabricate transcript data
//! and choose adversarial Fiat-Shamir challenges. This module fixes that
//! by using Symphony's `FSCommitment` trait:
//!
//! 1. At each IVC step, the fold data is committed via `HashCommitment::commit`
//! 2. The commitment (32 bytes) is propagated through the IVC chain
//! 3. At terminal, `HashCommitment::verify` checks commitment binding before
//!    replaying the Fiat-Shamir transcript
//!
//! The binding property of SHA-256 prevents the prover from altering the
//! transcript data after committing, ensuring FS challenges are honestly derived.

use std::vec::Vec;

use p3_challenger::{CanObserve, CanSample};
use p3_field::{Field, PrimeField64};

use symphony::fiat_shamir::FSCommitment;
use symphony::HashCommitment;

use crate::{
    accumulation::warp::{
        accumulator::WarpAccumulator,
        decider::{warp_decide_algebraic_rs, WarpDeciderError},
    },
    spartan::r1cs::R1CSShape,
};

/// Fold transcript data for a single IVC step.
///
/// Contains all the data the prover observed into the Fiat-Shamir
/// transcript during a WARP fold, plus the derived challenges.
#[derive(Clone, Debug)]
pub struct FoldTranscriptData<F: Field> {
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

/// A committed fold transcript: binding commitment + data + opening.
///
/// Uses Symphony's [`HashCommitment`] (SHA-256-based, straightline extractable)
/// to bind the fold data. The commitment is propagated through the IVC chain
/// so the prover cannot fabricate transcript data after the fact.
#[derive(Clone, Debug)]
pub struct CommittedFoldTranscript<F: Field> {
    /// IVC step index (for ordering).
    pub step: usize,
    /// SHA-256 binding commitment to the serialized fold data.
    pub commitment: [u8; 32],
    /// Opening randomness for the commitment.
    pub opening: [u8; 32],
    /// The fold transcript data.
    pub data: FoldTranscriptData<F>,
}

/// WARP fold verification as a Symphony [`CommittedRelation`].
///
/// Verifies that committed fold transcript data, when replayed through
/// Fiat-Shamir, produces the stored challenges. This is the relation R
/// in Symphony's CP-SNARK: "the committed messages satisfy the fold
/// verification protocol."
pub struct WarpFoldRelation;

impl symphony::CommittedRelation for WarpFoldRelation {
    fn check(&self, messages: &[&[u8]], _public_statement: &[u8]) -> bool {
        // Each message is a serialized FoldTranscriptData.
        // Structural check: all messages are non-empty and well-formed.
        // The full FS replay (Poseidon2-based) is done by
        // verify_committed_transcripts, which operates on typed data.
        messages.iter().all(|m| m.len() >= 8)
    }
}

/// Errors from the CP-SNARK terminal decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpSnarkDeciderError {
    /// Algebraic decider failed (eval claim, PESAT, or codeword validity).
    AlgebraicCheck(WarpDeciderError),
    /// Commitment binding failed — data was tampered.
    CommitmentBindingFailed { step: usize },
    /// Fiat-Shamir challenge mismatch after binding verification.
    ChallengeMismatch { step: usize },
}

// ─── Serialization ────────────────────────────────────────────────────

/// Serialize fold transcript data to bytes for commitment.
///
/// Deterministic: same data always produces the same bytes.
/// Format: length-prefixed vectors of little-endian u64 field elements.
pub fn serialize_fold_data<F: Field + PrimeField64>(data: &FoldTranscriptData<F>) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Helper: write a single field element as 8 LE bytes
    let write_f = |bytes: &mut Vec<u8>, f: F| {
        bytes.extend_from_slice(&f.as_canonical_u64().to_le_bytes());
    };

    // Helper: write a length-prefixed vec of field elements
    let write_vec = |bytes: &mut Vec<u8>, v: &[F]| {
        bytes.extend_from_slice(&(v.len() as u64).to_le_bytes());
        for &f in v {
            bytes.extend_from_slice(&f.as_canonical_u64().to_le_bytes());
        }
    };

    // input_commitment_roots: Vec<Vec<F>>
    bytes.extend_from_slice(&(data.input_commitment_roots.len() as u64).to_le_bytes());
    for root in &data.input_commitment_roots {
        write_vec(&mut bytes, root);
    }

    // input_eval_claims
    write_vec(&mut bytes, &data.input_eval_claims);

    // input_eval_points: Vec<Vec<F>>
    bytes.extend_from_slice(&(data.input_eval_points.len() as u64).to_le_bytes());
    for pts in &data.input_eval_points {
        write_vec(&mut bytes, pts);
    }

    // input_pesat_targets
    write_vec(&mut bytes, &data.input_pesat_targets);

    // sumcheck_evals: Vec<[F; 3]>
    bytes.extend_from_slice(&(data.sumcheck_evals.len() as u64).to_le_bytes());
    for &[e0, e1, e2] in &data.sumcheck_evals {
        write_f(&mut bytes, e0);
        write_f(&mut bytes, e1);
        write_f(&mut bytes, e2);
    }

    // omega, tau_challenges, sumcheck_challenges
    write_f(&mut bytes, data.omega);
    write_vec(&mut bytes, &data.tau_challenges);
    write_vec(&mut bytes, &data.sumcheck_challenges);

    bytes
}

// ─── Commitment ───────────────────────────────────────────────────────

/// Build a committed fold transcript using Symphony's `HashCommitment`.
///
/// Serializes the fold data deterministically, then commits via
/// `SHA-256(r ‖ data)` where `r` is 32 bytes of fresh randomness.
/// The commitment is binding (collision resistance of SHA-256) and
/// straightline extractable (ROM).
pub fn commit_fold_transcript<F: Field + PrimeField64>(
    step: usize,
    input_commitment_roots: Vec<Vec<F>>,
    input_eval_claims: Vec<F>,
    input_eval_points: Vec<Vec<F>>,
    input_pesat_targets: Vec<F>,
    sumcheck_round_polys: &[Vec<F>],
    omega: F,
    tau_challenges: Vec<F>,
    sumcheck_challenges: Vec<F>,
) -> CommittedFoldTranscript<F> {
    let sumcheck_evals = sumcheck_round_polys
        .iter()
        .map(|evals| {
            assert!(evals.len() >= 3);
            [evals[0], evals[1], evals[2]]
        })
        .collect();

    let data = FoldTranscriptData {
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        sumcheck_evals,
        omega,
        tau_challenges,
        sumcheck_challenges,
    };

    let serialized = serialize_fold_data(&data);
    let scheme = HashCommitment::new();
    let (commitment, opening) = scheme.commit(&serialized);

    CommittedFoldTranscript { step, commitment, opening, data }
}

// ─── Verification ─────────────────────────────────────────────────────

/// Verify all committed fold transcripts at terminal.
///
/// Two-phase verification per transcript:
///
/// 1. **Binding check** (Symphony `HashCommitment::verify`): ensures the
///    fold data has not been tampered with since commitment.
///
/// 2. **FS replay** (Poseidon2 challenger): re-derives challenges from
///    the verified data and checks they match the stored challenges.
///
/// This corresponds to Symphony Construction 6.1, "Vf" step:
/// ```text
/// Vf: Parse π* = (π_cp, π, {c_{fs,i}}, x_o)
///     Recompute (r_i) from (x, {c_{fs,i}}) and H
///     Check Π_cp.Vf(vk_cp, x_cp, π_cp) ∧ Π_snark.Vf(vk, x_o, π)
/// ```
pub fn verify_committed_transcripts<F, Challenger>(
    transcripts: &[CommittedFoldTranscript<F>],
    mut make_challenger: impl FnMut() -> Challenger,
) -> Result<(), CpSnarkDeciderError>
where
    F: Field + PrimeField64,
    Challenger: CanObserve<F> + CanSample<F>,
{
    let scheme = HashCommitment::new();

    for ct in transcripts {
        // Phase 1: Verify commitment binding via Symphony's HashCommitment
        let serialized = serialize_fold_data(&ct.data);
        if !scheme.verify(&ct.commitment, &serialized, &ct.opening) {
            return Err(CpSnarkDeciderError::CommitmentBindingFailed { step: ct.step });
        }

        // Phase 2: Replay Fiat-Shamir from the now-verified data
        let mut challenger = make_challenger();
        let t = &ct.data;

        // Observe input accumulators in the same order as the prover
        let k = t.input_commitment_roots.len();
        for i in 0..k {
            for &val in &t.input_commitment_roots[i] {
                challenger.observe(val);
            }
            challenger.observe(t.input_eval_claims[i]);
            for &val in &t.input_eval_points[i] {
                challenger.observe(val);
            }
            challenger.observe(t.input_pesat_targets[i]);
        }

        // Derive and check ω
        let omega: F = challenger.sample();
        if omega != t.omega {
            return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
        }

        // Derive and check τ challenges
        for &expected_tau in &t.tau_challenges {
            let tau: F = challenger.sample();
            if tau != expected_tau {
                return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
            }
        }

        // For each sumcheck round: observe round poly, derive and check r
        for (round, &expected_r) in t.sumcheck_challenges.iter().enumerate() {
            let [e0, e1, e2] = t.sumcheck_evals[round];
            challenger.observe(e0);
            challenger.observe(e1);
            challenger.observe(e2);
            let r: F = challenger.sample();
            if r != expected_r {
                return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
            }
        }
    }

    Ok(())
}

/// CP-SNARK terminal verification (Symphony Construction 6.1).
///
/// Performs three checks at the end of an IVC chain:
///
/// 1. **Commitment binding** (Symphony `HashCommitment`): verify all fold
///    transcript commitments open correctly.
///
/// 2. **FS replay** (Poseidon2): re-derive challenges from verified data
///    and check they match.
///
/// 3. **Algebraic decider** (WARP): check the final accumulator's eval
///    claim, PESAT, and codeword validity.
pub fn cp_snark_terminal_verify<F, Challenger>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
    transcripts: &[CommittedFoldTranscript<F>],
    make_challenger: impl FnMut() -> Challenger,
) -> Result<(), CpSnarkDeciderError>
where
    F: Field + PrimeField64,
    Challenger: CanObserve<F> + CanSample<F>,
{
    // Steps 1+2: Verify commitment binding + FS replay
    verify_committed_transcripts(transcripts, make_challenger)?;

    // Step 3: Algebraic decider (eval claim + PESAT; codeword deferred to WHIR)
    warp_decide_algebraic_rs(shape, acc).map_err(CpSnarkDeciderError::AlgebraicCheck)
}

#[cfg(test)]
mod tests {
    use std::vec;

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

    /// Build a transcript by running the native challenger, then commit and verify.
    #[test]
    fn committed_transcript_roundtrip() {
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

        // Build committed transcript using Symphony's HashCommitment
        let ct = commit_fold_transcript(
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

        // Verify: should pass
        assert!(verify_committed_transcripts(
            &[ct.clone()],
            || MyChal::new(perm.clone()),
        )
        .is_ok());

        // Tamper with challenge: should fail at FS replay
        let mut bad = ct.clone();
        bad.data.omega = F::from_u64(999);
        // Re-serialize and re-commit to simulate honest commitment to bad data
        // (tests the FS replay, not the binding)
        let bad_serialized = serialize_fold_data(&bad.data);
        let scheme = HashCommitment::new();
        let (bad_c, bad_o) = scheme.commit(&bad_serialized);
        bad.commitment = bad_c;
        bad.opening = bad_o;
        assert!(matches!(
            verify_committed_transcripts(&[bad], || MyChal::new(perm.clone())),
            Err(CpSnarkDeciderError::ChallengeMismatch { step: 0 })
        ));

        // Tamper with data WITHOUT updating commitment: should fail at binding
        let mut tampered = ct;
        tampered.data.omega = F::from_u64(999);
        // Don't re-commit — commitment still refers to original data
        assert!(matches!(
            verify_committed_transcripts(&[tampered], || MyChal::new(perm.clone())),
            Err(CpSnarkDeciderError::CommitmentBindingFailed { step: 0 })
        ));
    }

    #[test]
    fn serialize_deterministic() {
        let data = FoldTranscriptData {
            input_commitment_roots: vec![vec![F::from_u64(1); 8]],
            input_eval_claims: vec![F::from_u64(42)],
            input_eval_points: vec![vec![F::from_u64(3), F::from_u64(4)]],
            input_pesat_targets: vec![F::ZERO],
            sumcheck_evals: vec![[F::from_u64(10), F::from_u64(20), F::from_u64(30)]],
            omega: F::from_u64(7),
            tau_challenges: vec![F::from_u64(11)],
            sumcheck_challenges: vec![F::from_u64(13)],
        };

        let bytes1 = serialize_fold_data(&data);
        let bytes2 = serialize_fold_data(&data);
        assert_eq!(bytes1, bytes2, "serialization must be deterministic");
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn commitment_binding_works() {
        let data = FoldTranscriptData {
            input_commitment_roots: vec![vec![F::ONE; 8]],
            input_eval_claims: vec![F::from_u64(5)],
            input_eval_points: vec![vec![F::from_u64(1)]],
            input_pesat_targets: vec![F::ZERO],
            sumcheck_evals: vec![[F::ONE, F::ONE, F::ONE]],
            omega: F::from_u64(7),
            tau_challenges: vec![F::from_u64(3)],
            sumcheck_challenges: vec![F::from_u64(9)],
        };

        let serialized = serialize_fold_data(&data);
        let scheme = HashCommitment::new();
        let (commitment, opening) = scheme.commit(&serialized);

        // Correct data verifies
        assert!(scheme.verify(&commitment, &serialized, &opening));

        // Modified data does NOT verify against same commitment
        let mut bad_data = data;
        bad_data.omega = F::from_u64(999);
        let bad_serialized = serialize_fold_data(&bad_data);
        assert!(!scheme.verify(&commitment, &bad_serialized, &opening));
    }
}
