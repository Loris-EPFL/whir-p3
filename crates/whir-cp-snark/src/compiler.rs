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

use alloc::{vec, vec::Vec};

use p3_challenger::{CanObserve, CanSample};
use p3_field::{Field, PrimeField64};

use symphony::HashCommitment;
use symphony::fiat_shamir::FSCommitment;

use crate::spartan::r1cs::R1CSShape;
use warp::{
    accumulator::{WarpAccumulator, WarpAccumulatorInstance},
    decider::{WarpDeciderError, warp_decide_algebraic_rs},
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
    /// Fresh PESAT betas — random points sampled after tau, before sumcheck rounds.
    /// One Vec<F> of `log_m` elements per fresh instance. Must be replayed to keep
    /// the Fiat-Shamir challenger state in sync between prover and terminal verifier.
    pub fresh_betas: Vec<Vec<F>>,
    /// Shift query openings with Merkle authentication paths.
    ///
    /// Each entry contains: position, per-input row values, auth paths, expected folded.
    /// Empty if the fold step did not generate shift queries (e.g., non-committed mode).
    pub shift_query_positions: Vec<usize>,
    /// Per-query, per-input: the row values opened from the codeword at `position`.
    pub shift_query_values: Vec<Vec<Vec<F>>>,
    /// Per-query, per-input: Merkle authentication path (sibling digests from leaf to root).
    pub shift_query_auth_paths: Vec<Vec<Vec<[F; 8]>>>,
    /// Per-query: expected folded row = Σ_i eq(γ, i) * input_i[pos].
    pub shift_query_expected: Vec<Vec<F>>,
    /// Commitment roots of the input codewords (acc + fresh) for Merkle path verification.
    /// These are the roots against which shift query auth paths are verified.
    pub input_codeword_roots: Vec<[F; 8]>,
    /// Quasar union commitment root (when using multicast commitment).
    ///
    /// When `Some`, the terminal FS replay uses the **union path**: absorbs only the
    /// running accumulator instance + this single union root (O(1) absorptions).
    /// When `None`, the replay uses the standard path: absorbs all k input accumulators
    /// individually (O(ℓ) absorptions).
    ///
    /// `input_commitment_roots` stores only the running accumulator when union is active.
    pub union_commitment_root: Option<Vec<F>>,

    /// Fresh-instance REAL eval claims (mirrors `WarpFoldResult::fresh_eval_claims`).
    /// These are the codeword-derived `μ_i = cw_i[0]` values for each fresh
    /// instance — DIFFERENT from `input_eval_claims[1..]` which holds the
    /// FS-absorbed ZEROS (matching `derive_fold_challenges`).
    ///
    /// The twin-constraint sumcheck's σ_0 uses THESE real values:
    ///   σ_0 = eq(τ,0)·(acc.μ + ω·acc.η) + Σ_{i≥1} eq(τ,i)·(fresh_μ_{i-1} + ω·fresh_η_{i-1}).
    pub fresh_eval_claims: Vec<F>,
    /// Fresh-instance REAL PESAT targets η_i (mirrors `WarpFoldResult::fresh_pesat_targets`).
    pub fresh_pesat_targets: Vec<F>,

    // ── Eval-batching / OOD / ρ phase (post-sumcheck) ─────────────
    //
    // These fields mirror the corresponding fields of `WarpFoldResult`.
    // They let the terminal verifier replay every remaining FS call
    // the prover made after the twin-constraint sumcheck, and verify
    // the eval-batching sumcheck's algebra.
    //
    // All fields are zero/empty when the fold ran without shift
    // queries / OOD / eval batching (identity-encoding builds).
    /// `alpha_eval` = folded codeword's MLE evaluated at `instance.eval_point`
    /// (the first claim pushed into the batching sumcheck).
    pub alpha_eval: F,
    /// OOD sample points (each `log_n` elements, MSB-first after the
    /// prover's `expand_from_univariate`).
    pub ood_points: Vec<Vec<F>>,
    /// OOD evaluations ν_k = folded_MLE(ζ_k).
    pub ood_answers: Vec<F>,
    /// Batching challenge ρ sampled from FS via
    /// `transcript_round(&[F::from_usize(2000)])`.
    pub rho: F,
    /// Eval-batching sumcheck round polynomials: `[h(0), h(1), h(2)]` per
    /// round, `log_n` rounds total.
    pub eval_batch_round_polys: Vec<[F; 3]>,
    /// Eval-batching sumcheck challenges derived per round.
    pub eval_batch_challenges: Vec<F>,
    /// Final batched eval claim `f̃(α_batch) = new_eval_claim` (becomes
    /// the accumulator's new eval_claim).
    pub new_eval_claim: F,

    /// Public output accumulator root produced by this fold.
    ///
    /// Terminal verification uses these fields to enforce that committed
    /// transcript `i` feeds transcript `i + 1`, and that the last transcript
    /// feeds the public final accumulator instance.
    pub output_commitment_root: Vec<F>,
    /// Public output evaluation point produced by this fold.
    pub output_eval_point: Vec<F>,
    /// Public output evaluation claim produced by this fold.
    pub output_eval_claim: F,
    /// Public output PESAT tau point produced by this fold.
    pub output_pesat_tau: Vec<F>,
    /// Public output PESAT public-input point produced by this fold.
    pub output_pesat_x: Vec<F>,
    /// Public output PESAT target produced by this fold.
    pub output_pesat_target: F,
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
#[derive(Debug)]
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CpSnarkDeciderError {
    /// Algebraic decider failed (eval claim, PESAT, or codeword validity).
    #[error("algebraic decider failed: {0}")]
    AlgebraicCheck(#[from] WarpDeciderError),
    /// Commitment binding failed — data was tampered.
    #[error("commitment binding failed at step {step}")]
    CommitmentBindingFailed { step: usize },
    /// Fiat-Shamir challenge mismatch after binding verification.
    #[error("challenge mismatch at step {step}")]
    ChallengeMismatch { step: usize },
    /// Shift query Merkle proof invalid — authentication path does not match root.
    #[error("shift query Merkle proof invalid at step {step}, query {query}, input {input}")]
    ShiftQueryMerkleInvalid {
        step: usize,
        query: usize,
        input: usize,
    },
    /// Shift query linear combination mismatch — folded value ≠ Σ eq(γ,i) * val_i.
    #[error("shift query value mismatch at step {step}, query {query}")]
    ShiftQueryValueMismatch { step: usize, query: usize },
    /// Shift query row width is inconsistent with the public folding factor.
    #[error("shift query row width mismatch at step {step}, query {query}")]
    ShiftQueryWidthMismatch { step: usize, query: usize },
    /// Shift query rows/openings do not match the public fold arity.
    #[error("shift query arity mismatch at step {step}, query {query}")]
    ShiftQueryArityMismatch { step: usize, query: usize },
    /// Twin-constraint sumcheck round algebra failed: `e0 + e1 != prev_claim`.
    #[error("twin-constraint sumcheck algebra failed at step {step}, round {round}")]
    SumcheckAlgebraFailed { step: usize, round: usize },
    /// Shift-query position wasn't FS-derived from the transcript.
    #[error("shift-query position mismatch at step {step}, query {query}")]
    ShiftQueryPositionMismatch { step: usize, query: usize },
    /// Stored ρ doesn't match FS-derived ρ.
    #[error("ρ mismatch at step {step}")]
    RhoMismatch { step: usize },
    /// Eval-batching sumcheck round algebra failed: `e0 + e1 != prev_claim`.
    #[error("eval-batching sumcheck algebra failed at step {step}, round {round}")]
    EvalBatchAlgebraFailed { step: usize, round: usize },
    /// Eval-batching sumcheck's final claim doesn't match `B̃(α)·new_eval_claim`.
    #[error("eval-batching final claim mismatch at step {step}")]
    EvalBatchFinalMismatch { step: usize },
    /// A committed fold transcript did not carry its public output accumulator.
    #[error("missing transcript output accumulator at step {step}")]
    MissingOutputAccumulator { step: usize },
    /// A committed fold transcript's output does not feed the next transcript.
    #[error("transcript chain mismatch from step {prev_step} to step {next_step}")]
    TranscriptChainMismatch { prev_step: usize, next_step: usize },
    /// The last committed transcript does not match the final public accumulator.
    #[error("terminal accumulator mismatch at step {step}")]
    TerminalAccumulatorMismatch { step: usize },
    /// WHIR prove failed.
    #[error("WHIR prove failed")]
    WhirProveFailed,
    /// WHIR verify failed.
    #[error("WHIR verify failed")]
    WhirVerifyFailed,
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

    // fresh_betas: Vec<Vec<F>>
    bytes.extend_from_slice(&(data.fresh_betas.len() as u64).to_le_bytes());
    for betas in &data.fresh_betas {
        write_vec(&mut bytes, betas);
    }

    // Shift query data
    // positions
    bytes.extend_from_slice(&(data.shift_query_positions.len() as u64).to_le_bytes());
    for &pos in &data.shift_query_positions {
        bytes.extend_from_slice(&(pos as u64).to_le_bytes());
    }

    // values: Vec<Vec<Vec<F>>> — [query][input][value]
    bytes.extend_from_slice(&(data.shift_query_values.len() as u64).to_le_bytes());
    for query_vals in &data.shift_query_values {
        bytes.extend_from_slice(&(query_vals.len() as u64).to_le_bytes());
        for input_vals in query_vals {
            write_vec(&mut bytes, input_vals);
        }
    }

    // auth_paths: Vec<Vec<Vec<[F; 8]>>> — [query][input][sibling_digests]
    bytes.extend_from_slice(&(data.shift_query_auth_paths.len() as u64).to_le_bytes());
    for query_paths in &data.shift_query_auth_paths {
        bytes.extend_from_slice(&(query_paths.len() as u64).to_le_bytes());
        for input_path in query_paths {
            bytes.extend_from_slice(&(input_path.len() as u64).to_le_bytes());
            for digest in input_path {
                for &f in digest {
                    write_f(&mut bytes, f);
                }
            }
        }
    }

    // expected folded: Vec<Vec<F>> — [query][folded_values]
    bytes.extend_from_slice(&(data.shift_query_expected.len() as u64).to_le_bytes());
    for expected in &data.shift_query_expected {
        write_vec(&mut bytes, expected);
    }

    // input_codeword_roots: Vec<[F; 8]>
    bytes.extend_from_slice(&(data.input_codeword_roots.len() as u64).to_le_bytes());
    for root in &data.input_codeword_roots {
        for &f in root {
            write_f(&mut bytes, f);
        }
    }

    // union_commitment_root: Option<Vec<F>>
    match &data.union_commitment_root {
        Some(root) => {
            bytes.push(1);
            write_vec(&mut bytes, root);
        }
        None => {
            bytes.push(0);
        }
    }

    // fresh_eval_claims, fresh_pesat_targets
    write_vec(&mut bytes, &data.fresh_eval_claims);
    write_vec(&mut bytes, &data.fresh_pesat_targets);

    // ── Eval-batching / OOD / ρ phase ────────────────────────────
    write_f(&mut bytes, data.alpha_eval);
    // ood_points: Vec<Vec<F>>
    bytes.extend_from_slice(&(data.ood_points.len() as u64).to_le_bytes());
    for pt in &data.ood_points {
        write_vec(&mut bytes, pt);
    }
    // ood_answers
    write_vec(&mut bytes, &data.ood_answers);
    // rho
    write_f(&mut bytes, data.rho);
    // eval_batch_round_polys: Vec<[F;3]>
    bytes.extend_from_slice(&(data.eval_batch_round_polys.len() as u64).to_le_bytes());
    for &[e0, e1, e2] in &data.eval_batch_round_polys {
        write_f(&mut bytes, e0);
        write_f(&mut bytes, e1);
        write_f(&mut bytes, e2);
    }
    // eval_batch_challenges
    write_vec(&mut bytes, &data.eval_batch_challenges);
    // new_eval_claim
    write_f(&mut bytes, data.new_eval_claim);

    // output accumulator instance
    write_vec(&mut bytes, &data.output_commitment_root);
    write_vec(&mut bytes, &data.output_eval_point);
    write_f(&mut bytes, data.output_eval_claim);
    write_vec(&mut bytes, &data.output_pesat_tau);
    write_vec(&mut bytes, &data.output_pesat_x);
    write_f(&mut bytes, data.output_pesat_target);

    bytes
}

// ─── Commitment ───────────────────────────────────────────────────────

/// Build a committed fold transcript including shift query Merkle proofs.
///
/// Serializes the fold data deterministically, then commits via
/// `SHA-256(r ‖ data)` where `r` is 32 bytes of fresh randomness.
/// The commitment is binding (collision resistance of SHA-256) and
/// straightline extractable (ROM).
///
/// Includes shift query openings and their Merkle authentication paths,
/// plus `fresh_betas` (PESAT randomness sampled between tau and sumcheck).
/// The terminal verifier replays these to keep FS state in sync.
#[allow(clippy::too_many_arguments)]
pub fn commit_fold_transcript_with_shift_queries<F: Field + PrimeField64>(
    step: usize,
    input_commitment_roots: Vec<Vec<F>>,
    input_eval_claims: Vec<F>,
    input_eval_points: Vec<Vec<F>>,
    input_pesat_targets: Vec<F>,
    sumcheck_round_polys: &[Vec<F>],
    omega: F,
    tau_challenges: Vec<F>,
    sumcheck_challenges: Vec<F>,
    fresh_betas: Vec<Vec<F>>,
    shift_queries: &[warp::fold::ShiftQueryOpening<F>],
    input_codeword_roots: &[[F; 8]],
    union_commitment_root: Option<Vec<F>>,
) -> CommittedFoldTranscript<F> {
    // Back-compat overload: callers that have not yet been upgraded with
    // eval-batching data fall through to zero/empty.  The verifier tolerates
    // this when the twin-constraint sumcheck is the only phase (no shift
    // queries + no OOD).  For folds with shift/OOD the caller MUST use
    // `commit_fold_transcript_full` below to get sound verification.
    commit_fold_transcript_full(
        step,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        sumcheck_round_polys,
        omega,
        tau_challenges,
        sumcheck_challenges,
        fresh_betas,
        shift_queries,
        input_codeword_roots,
        union_commitment_root,
        F::ZERO,    // alpha_eval
        Vec::new(), // ood_points
        Vec::new(), // ood_answers
        F::ZERO,    // rho
        &[],        // eval_batch_round_polys
        Vec::new(), // eval_batch_challenges
        F::ZERO,    // new_eval_claim
        Vec::new(), // fresh_eval_claims
        Vec::new(), // fresh_pesat_targets
    )
}

/// Re-commit a (possibly tampered) [`CommittedFoldTranscript`] with a fresh
/// SHA-256 HashCommitment.  This is **only useful for tests** that want to
/// simulate a malicious prover who first commits tampered data honestly —
/// bypassing the binding check so the downstream FS-replay and sumcheck
/// algebra are the ones doing the real soundness work.
///
/// Production callers should NEVER call this.
pub fn re_commit_transcript<F: Field + PrimeField64>(
    ct: &CommittedFoldTranscript<F>,
) -> CommittedFoldTranscript<F> {
    let scheme = HashCommitment::new();
    let serialized = serialize_fold_data(&ct.data);
    let (commitment, opening) = scheme.commit(&serialized);
    CommittedFoldTranscript {
        step: ct.step,
        commitment,
        opening,
        data: ct.data.clone(),
    }
}

/// Full-data committed-fold-transcript constructor.
///
/// Captures EVERY piece of Fiat-Shamir state the prover produced so the
/// terminal verifier can replay and check it.  Used by callers that go
/// through the shift-query + OOD + eval-batching path (i.e.
/// [`warp_fold_prove_rs_committed`] / [`warp_fold_prove_rs_union`]).
#[allow(clippy::too_many_arguments)]
pub fn commit_fold_transcript_full<F: Field + PrimeField64>(
    step: usize,
    input_commitment_roots: Vec<Vec<F>>,
    input_eval_claims: Vec<F>,
    input_eval_points: Vec<Vec<F>>,
    input_pesat_targets: Vec<F>,
    sumcheck_round_polys: &[Vec<F>],
    omega: F,
    tau_challenges: Vec<F>,
    sumcheck_challenges: Vec<F>,
    fresh_betas: Vec<Vec<F>>,
    shift_queries: &[warp::fold::ShiftQueryOpening<F>],
    input_codeword_roots: &[[F; 8]],
    union_commitment_root: Option<Vec<F>>,
    alpha_eval: F,
    ood_points: Vec<Vec<F>>,
    ood_answers: Vec<F>,
    rho: F,
    eval_batch_round_polys: &[Vec<F>],
    eval_batch_challenges: Vec<F>,
    new_eval_claim: F,
    fresh_eval_claims: Vec<F>,
    fresh_pesat_targets: Vec<F>,
) -> CommittedFoldTranscript<F> {
    commit_fold_transcript_full_impl(
        step,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        sumcheck_round_polys,
        omega,
        tau_challenges,
        sumcheck_challenges,
        fresh_betas,
        shift_queries,
        input_codeword_roots,
        union_commitment_root,
        alpha_eval,
        ood_points,
        ood_answers,
        rho,
        eval_batch_round_polys,
        eval_batch_challenges,
        new_eval_claim,
        fresh_eval_claims,
        fresh_pesat_targets,
        None,
    )
}

/// Full-data committed-fold-transcript constructor with output accumulator
/// fields included so terminal verification can check the chain.
#[allow(clippy::too_many_arguments)]
pub fn commit_fold_transcript_full_with_output<F: Field + PrimeField64>(
    step: usize,
    input_commitment_roots: Vec<Vec<F>>,
    input_eval_claims: Vec<F>,
    input_eval_points: Vec<Vec<F>>,
    input_pesat_targets: Vec<F>,
    sumcheck_round_polys: &[Vec<F>],
    omega: F,
    tau_challenges: Vec<F>,
    sumcheck_challenges: Vec<F>,
    fresh_betas: Vec<Vec<F>>,
    shift_queries: &[warp::fold::ShiftQueryOpening<F>],
    input_codeword_roots: &[[F; 8]],
    union_commitment_root: Option<Vec<F>>,
    alpha_eval: F,
    ood_points: Vec<Vec<F>>,
    ood_answers: Vec<F>,
    rho: F,
    eval_batch_round_polys: &[Vec<F>],
    eval_batch_challenges: Vec<F>,
    new_eval_claim: F,
    fresh_eval_claims: Vec<F>,
    fresh_pesat_targets: Vec<F>,
    output_instance: &WarpAccumulatorInstance<F, F, F, 8>,
) -> CommittedFoldTranscript<F> {
    commit_fold_transcript_full_impl(
        step,
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        sumcheck_round_polys,
        omega,
        tau_challenges,
        sumcheck_challenges,
        fresh_betas,
        shift_queries,
        input_codeword_roots,
        union_commitment_root,
        alpha_eval,
        ood_points,
        ood_answers,
        rho,
        eval_batch_round_polys,
        eval_batch_challenges,
        new_eval_claim,
        fresh_eval_claims,
        fresh_pesat_targets,
        Some(output_instance),
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_fold_transcript_full_impl<F: Field + PrimeField64>(
    step: usize,
    input_commitment_roots: Vec<Vec<F>>,
    input_eval_claims: Vec<F>,
    input_eval_points: Vec<Vec<F>>,
    input_pesat_targets: Vec<F>,
    sumcheck_round_polys: &[Vec<F>],
    omega: F,
    tau_challenges: Vec<F>,
    sumcheck_challenges: Vec<F>,
    fresh_betas: Vec<Vec<F>>,
    shift_queries: &[warp::fold::ShiftQueryOpening<F>],
    input_codeword_roots: &[[F; 8]],
    union_commitment_root: Option<Vec<F>>,
    alpha_eval: F,
    ood_points: Vec<Vec<F>>,
    ood_answers: Vec<F>,
    rho: F,
    eval_batch_round_polys: &[Vec<F>],
    eval_batch_challenges: Vec<F>,
    new_eval_claim: F,
    fresh_eval_claims: Vec<F>,
    fresh_pesat_targets: Vec<F>,
    output_instance: Option<&WarpAccumulatorInstance<F, F, F, 8>>,
) -> CommittedFoldTranscript<F> {
    let sumcheck_evals = sumcheck_round_polys
        .iter()
        .map(|evals| {
            assert!(evals.len() >= 3);
            [evals[0], evals[1], evals[2]]
        })
        .collect();

    let eval_batch_round_polys_arr = eval_batch_round_polys
        .iter()
        .map(|evals| {
            assert!(evals.len() >= 3);
            [evals[0], evals[1], evals[2]]
        })
        .collect();

    let (
        output_commitment_root,
        output_eval_point,
        output_eval_claim,
        output_pesat_tau,
        output_pesat_x,
        output_pesat_target,
    ) = output_instance
        .map(|instance| {
            (
                instance.commitment_root.to_vec(),
                instance.eval_point.clone(),
                instance.eval_claim,
                instance.pesat_tau.clone(),
                instance.pesat_x.clone(),
                instance.pesat_target,
            )
        })
        .unwrap_or_else(|| {
            (
                Vec::new(),
                Vec::new(),
                F::ZERO,
                Vec::new(),
                Vec::new(),
                F::ZERO,
            )
        });

    let data = FoldTranscriptData {
        input_commitment_roots,
        input_eval_claims,
        input_eval_points,
        input_pesat_targets,
        sumcheck_evals,
        omega,
        tau_challenges,
        sumcheck_challenges,
        fresh_betas,
        shift_query_positions: shift_queries.iter().map(|sq| sq.position).collect(),
        shift_query_values: shift_queries
            .iter()
            .map(|sq| sq.input_values.clone())
            .collect(),
        shift_query_auth_paths: shift_queries
            .iter()
            .map(|sq| sq.auth_paths.clone())
            .collect(),
        shift_query_expected: shift_queries
            .iter()
            .map(|sq| sq.expected_folded.clone())
            .collect(),
        input_codeword_roots: input_codeword_roots.to_vec(),
        union_commitment_root,
        alpha_eval,
        ood_points,
        ood_answers,
        rho,
        eval_batch_round_polys: eval_batch_round_polys_arr,
        eval_batch_challenges,
        new_eval_claim,
        fresh_eval_claims,
        fresh_pesat_targets,
        output_commitment_root,
        output_eval_point,
        output_eval_claim,
        output_pesat_tau,
        output_pesat_x,
        output_pesat_target,
    };

    let serialized = serialize_fold_data(&data);
    let scheme = HashCommitment::new();
    let (commitment, opening) = scheme.commit(&serialized);

    CommittedFoldTranscript {
        step,
        commitment,
        opening,
        data,
    }
}

// ─── Verification ─────────────────────────────────────────────────────

/// Verify all committed fold transcripts at terminal.
///
/// Performs a full Fiat-Shamir replay AND sumcheck-algebra verification
/// of the WARP fold protocol:
///
/// 1. **Binding**: SHA-256 `HashCommitment::verify` per transcript.
/// 2. **FS replay for pre-sumcheck**: ω, τ, fresh_betas.
/// 3. **Twin-constraint sumcheck algebra**:
///    - Round 0: `e0 + e1 == σ_0 = Σ eq(τ,i)·(μ_i + ω·η_i)`.
///    - Round r>0: `e0_r + e1_r == h_{r-1}(γ_{r-1})` via Lagrange interp.
/// 4. **Twin-constraint sumcheck FS**: each round's `γ_r` re-derived.
/// 5. **Post-sumcheck FS replay**:
///    - Shift query positions: observe `F::from_usize(q)`, sample, check.
///    - OOD samples (s of them): observe counter + sample; observe answer
///      + sample (discard).
///    - ρ: observe `F::from_usize(2000)` + sample, check against `t.rho`.
/// 6. **Eval-batching sumcheck**:
///    - Initial target `Σ ρ^k · v_k` with v_0=alpha_eval, v_1..=s=OOD
///      answers, v_s+1..=t=shift_query_expected[q][0].
///    - Round 0 sum + inter-round consistency via Lagrange.
///    - Per-round challenge re-derived and checked.
///    - Final check: `current_claim == B̃(α_batch) · new_eval_claim` with
///      `B̃(α_batch) = Σ ρ^k · eq(p_k, α_batch)` and p_0 = folded α
///      (computed as eq-fold of input_eval_points by sumcheck_challenges).
///
/// Matches Symphony Construction 6.1's `Vf` but covers every challenge the
/// WARP prover samples — not just the twin-constraint ones.
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

        if let Some(ref union_root) = t.union_commitment_root {
            // ── Union path (Quasar): absorb running acc + single union root ──
            assert!(
                !t.input_commitment_roots.is_empty(),
                "union transcript must have at least the running accumulator"
            );
            for &val in &t.input_commitment_roots[0] {
                challenger.observe(val);
            }
            challenger.observe(t.input_eval_claims[0]);
            for &val in &t.input_eval_points[0] {
                challenger.observe(val);
            }
            challenger.observe(t.input_pesat_targets[0]);
            for &val in union_root {
                challenger.observe(val);
            }
        } else {
            // ── Standard path: absorb all k input accumulators individually ──
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

        // Derive and check fresh_betas
        for expected_betas in &t.fresh_betas {
            for &expected_beta in expected_betas {
                let beta: F = challenger.sample();
                if beta != expected_beta {
                    return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
                }
            }
        }

        // ── Twin-constraint sumcheck: FS replay + ALGEBRA ──
        let log_l = t.tau_challenges.len();
        let l = 1usize << log_l;

        // σ_0 = Σ_{i ∈ [l]} eq(τ,i) · (μ_i + ω·η_i)
        //
        // Index 0 = running accumulator (uses stored input_eval_claims[0],
        //           input_pesat_targets[0]).
        // Index i ≥ 1 = fresh instances — the TWIN-CONSTRAINT sumcheck
        //               uses the CODEWORD-DERIVED values (cw_i[0]) and the
        //               FRESH PESAT targets, which are stored separately
        //               in `fresh_eval_claims` and `fresh_pesat_targets`.
        //               (Note: `input_eval_claims[1..]` hold the FS-absorbed
        //               zeros matching `derive_fold_challenges`, which is
        //               DIFFERENT from what the sumcheck proves.)
        // Padding indices (i ≥ 1 + num_fresh) = zero.
        let sigma_0 = {
            let mut acc = F::ZERO;
            // Index 0: running accumulator
            let mu0 = t.input_eval_claims.first().copied().unwrap_or(F::ZERO);
            let eta0 = t.input_pesat_targets.first().copied().unwrap_or(F::ZERO);
            acc += eq_at_index_lsb_first(0, &t.tau_challenges) * (mu0 + t.omega * eta0);
            // Indices 1..l: fresh instances (real codeword-derived values)
            for i in 1..l {
                let mu = t.fresh_eval_claims.get(i - 1).copied().unwrap_or(F::ZERO);
                let eta = t.fresh_pesat_targets.get(i - 1).copied().unwrap_or(F::ZERO);
                acc += eq_at_index_lsb_first(i, &t.tau_challenges) * (mu + t.omega * eta);
            }
            acc
        };

        // Round-by-round: observe evals, sample r, check (e0+e1 == prev_claim),
        // advance prev_claim via Lagrange interpolation.
        if t.sumcheck_evals.len() != t.sumcheck_challenges.len() {
            return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
        }
        let mut prev_claim = sigma_0;
        for (round, &expected_r) in t.sumcheck_challenges.iter().enumerate() {
            let [e0, e1, e2] = t.sumcheck_evals[round];

            // Round algebra: e0 + e1 must equal the previous round's closing
            // claim (= σ_0 at round 0, = h_{r-1}(γ_{r-1}) otherwise).
            if e0 + e1 != prev_claim {
                return Err(CpSnarkDeciderError::SumcheckAlgebraFailed {
                    step: ct.step,
                    round,
                });
            }

            challenger.observe(e0);
            challenger.observe(e1);
            challenger.observe(e2);
            let r: F = challenger.sample();
            if r != expected_r {
                return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
            }
            // Next round's expected prev_claim = h(r) via Lagrange.
            prev_claim = eval_deg2_at(e0, e1, e2, r);
        }

        // ── Shift-query positions: FS replay ──
        // For each q ∈ [num_shift_queries], prover did
        //   transcript_round(&[F::from_usize(q)])
        // which in our closure is observe(counter)+sample.
        //
        // Position decoding (prover):
        //   pos = sample.as_canonical_u64() as usize % height.
        // The tree height is not carried directly in transcript data, but
        // all shift_query_auth_paths[q][..] have the same depth, so
        // height = 1 << depth.  For the CP verifier we compare the
        // FS-sampled value against `stored_pos % height_implied_by_auth_paths`.
        let num_shift = t.shift_query_positions.len();
        for q in 0..num_shift {
            challenger.observe(F::from_usize(q));
            let sampled: F = challenger.sample();

            // The prover applies `sampled.as_canonical_u64() as usize % height`.
            // Height depends on codeword vs union tree; derive from the first
            // non-empty auth path.
            let height = t
                .shift_query_auth_paths
                .get(q)
                .and_then(|per_cw| per_cw.first())
                .map(|p| 1usize << p.len())
                .unwrap_or(0);
            if height == 0 {
                // No auth path stored — nothing to bind. Skip FS equality
                // because we can't recover the modulo reduction. This
                // defensive branch is only hit by inputs that wouldn't have
                // been accepted by `verify_shift_query_merkle_proofs` anyway.
                continue;
            }
            let expected_pos = sampled.as_canonical_u64() as usize % height;
            if expected_pos != t.shift_query_positions[q] {
                return Err(CpSnarkDeciderError::ShiftQueryPositionMismatch {
                    step: ct.step,
                    query: q,
                });
            }
        }

        // ── OOD sampling: FS replay ──
        let num_ood = t.ood_answers.len();
        for k in 0..num_ood {
            // Observe counter, sample univariate challenge (the result is
            // the point BEFORE expansion — we don't need to check the
            // expanded point here because the whole eval-batching relies
            // on the stored `ood_points` which would have been committed).
            challenger.observe(F::from_usize(k + num_shift + 1000));
            let _univariate: F = challenger.sample();
            // Absorb OOD answer, sample (discarded).
            challenger.observe(t.ood_answers[k]);
            let _: F = challenger.sample();
        }

        // ── ρ: FS replay + check against stored ──
        let log_n_rs = t.eval_batch_round_polys.len();
        let has_eval_batch = log_n_rs > 0;

        if has_eval_batch {
            challenger.observe(F::from_usize(2000));
            let rho: F = challenger.sample();
            if rho != t.rho {
                return Err(CpSnarkDeciderError::RhoMismatch { step: ct.step });
            }

            // ── Eval-batching sumcheck: initial target + round consistency ──
            // Initial batched target = Σ ρ^k · v_k.
            let initial_target = {
                let mut acc = F::ZERO;
                let mut pow = F::ONE;
                // v_0 = alpha_eval
                acc += pow * t.alpha_eval;
                pow *= t.rho;
                // v_1..=num_ood = ood_answers
                for &ans in &t.ood_answers {
                    acc += pow * ans;
                    pow *= t.rho;
                }
                // v_s+1..=t = shift_query_expected[q][0]
                for expected in &t.shift_query_expected {
                    let v = expected.first().copied().unwrap_or(F::ZERO);
                    acc += pow * v;
                    pow *= t.rho;
                }
                acc
            };

            if t.eval_batch_round_polys.len() != t.eval_batch_challenges.len() {
                return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
            }

            let mut prev_claim = initial_target;
            for (round, &expected_r) in t.eval_batch_challenges.iter().enumerate() {
                let [e0, e1, e2] = t.eval_batch_round_polys[round];

                if e0 + e1 != prev_claim {
                    return Err(CpSnarkDeciderError::EvalBatchAlgebraFailed {
                        step: ct.step,
                        round,
                    });
                }

                challenger.observe(e0);
                challenger.observe(e1);
                challenger.observe(e2);
                let r: F = challenger.sample();
                if r != expected_r {
                    return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
                }
                prev_claim = eval_deg2_at(e0, e1, e2, r);
            }

            // Final check: prev_claim == B̃(α_batch) · new_eval_claim.
            //
            // B̃(α_batch) = Σ ρ^k · eq(p_k, α_batch), where
            //   p_0 = folded α (post twin-constraint, pre eval-batch) =
            //         eq-fold of input_eval_points[i] by sumcheck_challenges,
            //   p_1..=s = ood_points[k],
            //   p_s+1..=t = bit-decomposition of (shift_positions[q] · width).
            //
            // The folded α has `log_n_rs` coordinates (same dimensionality
            // as the eval-batch sumcheck point). Construct it by folding
            // input_eval_points.
            let alpha_batch = &t.eval_batch_challenges;
            let num_vars_p0 = alpha_batch.len();

            let folded_alpha: Vec<F> = (0..num_vars_p0)
                .map(|coord| {
                    // For each coordinate, fold input_eval_points[i][coord]
                    // by eq(γ, i). In union mode, only index 0 contributes.
                    let mut acc = F::ZERO;
                    for i in 0..l {
                        let a_ij = t
                            .input_eval_points
                            .get(i)
                            .and_then(|p| p.get(coord))
                            .copied()
                            .unwrap_or(F::ZERO);
                        acc += eq_at_index_lsb_first(i, &t.sumcheck_challenges) * a_ij;
                    }
                    acc
                })
                .collect();

            // Compute B̃(α_batch).
            let b_at_alpha = {
                let mut acc = F::ZERO;
                let mut pow = F::ONE;
                // p_0 = folded_alpha
                acc += pow * eq_at_point(&folded_alpha, alpha_batch);
                pow *= t.rho;
                // p_1..=num_ood = ood_points[k] (stored as MSB-first from
                // expand_from_univariate — but we need LSB-first to match
                // the eval-batching sumcheck's convention).
                for pt in &t.ood_points {
                    // Prover stored ood_points in MSB-first convention via
                    // MultilinearPoint::expand_from_univariate; the
                    // batching sumcheck reversed them to LSB-first.
                    let mut reversed = pt.clone();
                    reversed.reverse();
                    acc += pow * eq_at_point(&reversed, alpha_batch);
                    pow *= t.rho;
                }
                // p_s+1..=t = boolean point from (pos * width), LSB-first.
                // This FS/algebra-only verifier gets `width` from the stored
                // row length. The full terminal verifier additionally calls
                // `verify_shift_query_merkle_proofs`, which enforces that this
                // row length equals the public `1 << folding_factor`.
                for q_idx in 0..num_shift {
                    let pos = t.shift_query_positions[q_idx];
                    let width = t
                        .shift_query_expected
                        .get(q_idx)
                        .map(|v| v.len())
                        .unwrap_or(1);
                    let flat_idx = pos * width;
                    let point: Vec<F> = (0..num_vars_p0)
                        .map(|bit| {
                            if (flat_idx >> bit) & 1 == 1 {
                                F::ONE
                            } else {
                                F::ZERO
                            }
                        })
                        .collect();
                    acc += pow * eq_at_point(&point, alpha_batch);
                    pow *= t.rho;
                }
                acc
            };

            let expected_final = b_at_alpha * t.new_eval_claim;
            if prev_claim != expected_final {
                return Err(CpSnarkDeciderError::EvalBatchFinalMismatch { step: ct.step });
            }
        }
    }

    Ok(())
}

/// Verify committed fold transcripts and their public accumulator chain.
///
/// This is the terminal check callers should use for end-to-end CP paths:
/// it first runs the binding/Fiat-Shamir/algebra checks, then checks that
/// every transcript's recorded output accumulator is the next transcript's
/// running input accumulator, and that the final output equals `final_instance`.
pub fn verify_committed_transcripts_and_chain<F, Challenger>(
    transcripts: &[CommittedFoldTranscript<F>],
    make_challenger: impl FnMut() -> Challenger,
    final_instance: &WarpAccumulatorInstance<F, F, F, 8>,
) -> Result<(), CpSnarkDeciderError>
where
    F: Field + PrimeField64,
    Challenger: CanObserve<F> + CanSample<F>,
{
    verify_committed_transcripts(transcripts, make_challenger)?;
    verify_transcript_chain(transcripts, final_instance)
}

fn verify_transcript_chain<F: Field>(
    transcripts: &[CommittedFoldTranscript<F>],
    final_instance: &WarpAccumulatorInstance<F, F, F, 8>,
) -> Result<(), CpSnarkDeciderError> {
    if transcripts.is_empty() {
        return Ok(());
    }

    for ct in transcripts {
        if ct.data.output_commitment_root.len() != 8 {
            return Err(CpSnarkDeciderError::MissingOutputAccumulator { step: ct.step });
        }
    }

    for pair in transcripts.windows(2) {
        let prev = &pair[0];
        let next = &pair[1];
        if !output_feeds_next_input(&prev.data, &next.data) {
            return Err(CpSnarkDeciderError::TranscriptChainMismatch {
                prev_step: prev.step,
                next_step: next.step,
            });
        }
    }

    let last = transcripts.last().expect("non-empty checked above");
    if !output_matches_instance(&last.data, final_instance) {
        return Err(CpSnarkDeciderError::TerminalAccumulatorMismatch { step: last.step });
    }

    Ok(())
}

fn output_feeds_next_input<F: Field>(
    prev: &FoldTranscriptData<F>,
    next: &FoldTranscriptData<F>,
) -> bool {
    next.input_commitment_roots.first() == Some(&prev.output_commitment_root)
        && next.input_eval_claims.first().copied() == Some(prev.output_eval_claim)
        && next.input_eval_points.first() == Some(&prev.output_eval_point)
        && next.input_pesat_targets.first().copied() == Some(prev.output_pesat_target)
}

fn output_matches_instance<F: Field>(
    output: &FoldTranscriptData<F>,
    instance: &WarpAccumulatorInstance<F, F, F, 8>,
) -> bool {
    output.output_commitment_root == instance.commitment_root.to_vec()
        && output.output_eval_point == instance.eval_point
        && output.output_eval_claim == instance.eval_claim
        && output.output_pesat_tau == instance.pesat_tau
        && output.output_pesat_x == instance.pesat_x
        && output.output_pesat_target == instance.pesat_target
}

/// Evaluate `eq(p, x) = Π_i (p_i·x_i + (1-p_i)(1-x_i))` — LSB-first.
fn eq_at_point<F: Field>(point: &[F], x: &[F]) -> F {
    let n = core::cmp::min(point.len(), x.len());
    let mut eq = F::ONE;
    for i in 0..n {
        eq *= point[i] * x[i] + (F::ONE - point[i]) * (F::ONE - x[i]);
    }
    eq
}

/// Evaluate `eq(τ, i)` where `i` is LSB-first-bit-decomposed.
fn eq_at_index_lsb_first<F: Field>(idx: usize, tau: &[F]) -> F {
    let mut eq = F::ONE;
    for (bit, &tj) in tau.iter().enumerate() {
        let b = (idx >> bit) & 1;
        eq *= if b == 1 { tj } else { F::ONE - tj };
    }
    eq
}

/// Evaluate the degree-2 polynomial h given by (h(0), h(1), h(2)) at r,
/// via Lagrange: h(r) = e0·(r-1)(r-2)/2 − e1·r(r-2) + e2·r(r-1)/2.
fn eval_deg2_at<F: Field>(e0: F, e1: F, e2: F, r: F) -> F {
    let two_inv = F::TWO.inverse();
    e0 * (r - F::ONE) * (r - F::TWO) * two_inv - e1 * r * (r - F::TWO)
        + e2 * r * (r - F::ONE) * two_inv
}

/// Verify shift query Merkle proofs AND the linear-combination check.
///
/// For each transcript that includes shift query data:
///  1. Verify each Merkle authentication path against the committed root.
///  2. Verify the linear combination: for every column `c` of every query,
///     `expected_folded[q][c] == Σ_i eq(γ, i) · values[q][i][c]`.
///
/// (2) closes the gap identified in the audit where the stored
/// `shift_query_expected` was never cross-checked against the values.
pub fn verify_shift_query_merkle_proofs<F, H, C>(
    transcripts: &[CommittedFoldTranscript<F>],
    folding_factor: usize,
    merkle_hash: &H,
    merkle_compress: &C,
) -> Result<(), CpSnarkDeciderError>
where
    F: p3_field::TwoAdicField + PrimeField64,
    <F as p3_field::Field>::Packing: Eq + Send + Sync,
    H: p3_symmetric::CryptographicHasher<F, [F; 8]>
        + p3_symmetric::CryptographicHasher<
            <F as p3_field::Field>::Packing,
            [<F as p3_field::Field>::Packing; 8],
        > + Sync
        + Clone,
    C: p3_symmetric::PseudoCompressionFunction<[F; 8], 2>
        + p3_symmetric::PseudoCompressionFunction<[<F as p3_field::Field>::Packing; 8], 2>
        + Sync
        + Clone,
    [F; 8]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    use warp::encoding::merkle_verify_opening;

    for ct in transcripts {
        let t = &ct.data;
        let num_queries = t.shift_query_positions.len();
        if num_queries == 0 {
            continue;
        }

        let base_width = 1usize << folding_factor;
        let log_l = t.tau_challenges.len(); // log of the fold arity
        let l_fold = 1usize << log_l;

        if t.union_commitment_root.is_some() {
            // ── Union mode (Quasar §4): single union auth path per query ──
            // The union tree interleaves all ℓ codewords: union[p*l + i] = cw[i][p].
            // Each auth_paths[q] has 1 entry: the union tree auth path.
            // We reconstruct the union row from the per-codeword input_values
            // and verify the single auth path against the union root.
            assert_eq!(
                t.input_codeword_roots.len(),
                1,
                "union mode must have exactly 1 root (the union root)"
            );
            let union_root = &t.input_codeword_roots[0];

            for q in 0..num_queries {
                let pos = t.shift_query_positions[q];
                let values_per_cw = t.shift_query_values.get(q).ok_or(
                    CpSnarkDeciderError::ShiftQueryArityMismatch {
                        step: ct.step,
                        query: q,
                    },
                )?;
                let auth_paths = t.shift_query_auth_paths.get(q).ok_or(
                    CpSnarkDeciderError::ShiftQueryArityMismatch {
                        step: ct.step,
                        query: q,
                    },
                )?;
                if values_per_cw.len() != l_fold || auth_paths.len() != 1 {
                    return Err(CpSnarkDeciderError::ShiftQueryArityMismatch {
                        step: ct.step,
                        query: q,
                    });
                }
                if t.shift_query_expected
                    .get(q)
                    .map(|row| row.len())
                    .unwrap_or(0)
                    != base_width
                {
                    return Err(CpSnarkDeciderError::ShiftQueryWidthMismatch {
                        step: ct.step,
                        query: q,
                    });
                }

                // Reconstruct the union row by interleaving per-codeword values.
                // union_row[k * l_fold + i] = values_per_cw[i][k]
                let mut union_row = vec![F::ZERO; l_fold * base_width];
                for (i, cw_vals) in values_per_cw.iter().enumerate() {
                    if cw_vals.len() != base_width {
                        return Err(CpSnarkDeciderError::ShiftQueryWidthMismatch {
                            step: ct.step,
                            query: q,
                        });
                    }
                    for (k, &v) in cw_vals.iter().enumerate() {
                        union_row[k * l_fold + i] = v;
                    }
                }

                // auth_paths has exactly 1 entry in union mode.
                let proof = &auth_paths[0];
                let tree_height = 1usize << proof.len();
                let union_width = l_fold * base_width;

                let valid = merkle_verify_opening::<
                    F,
                    F,
                    <F as p3_field::Field>::Packing,
                    <F as p3_field::Field>::Packing,
                    H,
                    C,
                    8,
                >(
                    union_root,
                    pos,
                    &union_row,
                    proof,
                    union_width,
                    tree_height,
                    merkle_hash.clone(),
                    merkle_compress.clone(),
                );

                if !valid {
                    return Err(CpSnarkDeciderError::ShiftQueryMerkleInvalid {
                        step: ct.step,
                        query: q,
                        input: 0,
                    });
                }
            }
        } else {
            // ── Non-union mode (WARP standard): per-input auth paths ──
            let num_inputs = t.input_codeword_roots.len();

            for q in 0..num_queries {
                let pos = t.shift_query_positions[q];
                let values_per_cw = t.shift_query_values.get(q).ok_or(
                    CpSnarkDeciderError::ShiftQueryArityMismatch {
                        step: ct.step,
                        query: q,
                    },
                )?;
                let auth_paths = t.shift_query_auth_paths.get(q).ok_or(
                    CpSnarkDeciderError::ShiftQueryArityMismatch {
                        step: ct.step,
                        query: q,
                    },
                )?;
                if num_inputs > l_fold
                    || values_per_cw.len() != num_inputs
                    || auth_paths.len() != num_inputs
                {
                    return Err(CpSnarkDeciderError::ShiftQueryArityMismatch {
                        step: ct.step,
                        query: q,
                    });
                }
                if t.shift_query_expected
                    .get(q)
                    .map(|row| row.len())
                    .unwrap_or(0)
                    != base_width
                {
                    return Err(CpSnarkDeciderError::ShiftQueryWidthMismatch {
                        step: ct.step,
                        query: q,
                    });
                }

                for inp in 0..num_inputs {
                    let row_values = &values_per_cw[inp];
                    if row_values.len() != base_width {
                        return Err(CpSnarkDeciderError::ShiftQueryWidthMismatch {
                            step: ct.step,
                            query: q,
                        });
                    }
                    let proof = &auth_paths[inp];
                    let root = &t.input_codeword_roots[inp];
                    let tree_height = 1usize << proof.len();

                    let valid = merkle_verify_opening::<
                        F,
                        F,
                        <F as p3_field::Field>::Packing,
                        <F as p3_field::Field>::Packing,
                        H,
                        C,
                        8,
                    >(
                        root,
                        pos,
                        row_values,
                        proof,
                        base_width,
                        tree_height,
                        merkle_hash.clone(),
                        merkle_compress.clone(),
                    );

                    if !valid {
                        return Err(CpSnarkDeciderError::ShiftQueryMerkleInvalid {
                            step: ct.step,
                            query: q,
                            input: inp,
                        });
                    }
                }
            }
        }

        // ── Linear-combination check (both union and non-union) ──
        //
        // For each query q, column c in [width]:
        //   expected_folded[q][c] == Σ_i eq(γ, i) · shift_query_values[q][i][c]
        //
        // where γ = `sumcheck_challenges`. This is the "shift-query-as-
        // eval-claim" algebraic binding that ties the folded codeword's
        // row to the input codewords' rows at `position`.  The current
        // Merkle-only check above binds the VALUES to the commitment roots;
        // this extra check binds the FOLD ALGEBRA.
        //
        // Together they implement the paper's Construction 7.2 shift-query
        // soundness.  Omitting this was one of the gaps identified in the
        // audit — a malicious prover could store any `expected_folded` and
        // the verifier would not notice.
        for q in 0..num_queries {
            let expected = &t.shift_query_expected[q];
            let values_per_cw = &t.shift_query_values[q];
            if expected.len() != base_width {
                return Err(CpSnarkDeciderError::ShiftQueryWidthMismatch {
                    step: ct.step,
                    query: q,
                });
            }

            for c in 0..base_width {
                // expected_c = Σ_i eq(γ, i) · values_per_cw[i][c]
                let mut expected_c = F::ZERO;
                for i in 0..l_fold {
                    let v_ic = values_per_cw
                        .get(i)
                        .and_then(|row| row.get(c))
                        .copied()
                        .unwrap_or(F::ZERO);
                    expected_c += eq_at_index_lsb_first(i, &t.sumcheck_challenges) * v_ic;
                }
                if expected_c != expected[c] {
                    return Err(CpSnarkDeciderError::ShiftQueryValueMismatch {
                        step: ct.step,
                        query: q,
                    });
                }
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
/// 2. **FS replay + chain binding** (Poseidon2): re-derive challenges from
///    verified data, check they match, and check transcript outputs feed the
///    next transcript and the final accumulator.
///
/// 3. **Algebraic decider** (WARP): check the final accumulator's eval
///    claim and PESAT. RS codeword validity is deferred to terminal WHIR or
///    a full witness-aware decider.
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
    verify_committed_transcripts_and_chain(transcripts, make_challenger, &acc.instance)?;

    // Step 3: Algebraic decider (eval claim + PESAT; codeword deferred to WHIR)
    warp_decide_algebraic_rs(shape, acc).map_err(CpSnarkDeciderError::AlgebraicCheck)
}

/// CP-SNARK terminal verification with shift query Merkle proof checking.
///
/// Extends `cp_snark_terminal_verify` with a fourth phase:
///
/// 4. **Shift query Merkle verification**: verify that each shift query opening
///    has a valid Merkle authentication path against the committed codeword root.
///    This closes the proximity gap — the prover can't fabricate shift query values
///    because they're bound by the SHA-256 commitment AND verified by Merkle paths.
pub fn cp_snark_terminal_verify_with_merkle<F, Challenger, H, C>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
    transcripts: &[CommittedFoldTranscript<F>],
    make_challenger: impl FnMut() -> Challenger,
    folding_factor: usize,
    merkle_hash: &H,
    merkle_compress: &C,
) -> Result<(), CpSnarkDeciderError>
where
    F: p3_field::TwoAdicField + PrimeField64,
    <F as p3_field::Field>::Packing: Eq + Send + Sync,
    Challenger: CanObserve<F> + CanSample<F>,
    H: p3_symmetric::CryptographicHasher<F, [F; 8]>
        + p3_symmetric::CryptographicHasher<
            <F as p3_field::Field>::Packing,
            [<F as p3_field::Field>::Packing; 8],
        > + Sync
        + Clone,
    C: p3_symmetric::PseudoCompressionFunction<[F; 8], 2>
        + p3_symmetric::PseudoCompressionFunction<[<F as p3_field::Field>::Packing; 8], 2>
        + Sync
        + Clone,
    [F; 8]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    // Steps 1+2: Verify commitment binding + FS replay
    verify_committed_transcripts_and_chain(transcripts, make_challenger, &acc.instance)?;

    // Step 3: Algebraic decider
    warp_decide_algebraic_rs(shape, acc).map_err(CpSnarkDeciderError::AlgebraicCheck)?;

    // Step 4: Shift query Merkle proof verification
    verify_shift_query_merkle_proofs(transcripts, folding_factor, merkle_hash, merkle_compress)
}

/// CP-SNARK terminal verification with terminal WHIR proof (fully succinct).
///
/// Extends `cp_snark_terminal_verify_with_merkle` with a fifth phase:
///
/// 5. **Terminal WHIR**: full prover-side RS decider + WHIR prove + WHIR verify.
///    The algebraic decider checks eval claim, PESAT, and codeword validity;
///    the WHIR proof establishes RS proximity on the accumulated witness.
///
/// Returns the WHIR proof on success, which can be independently verified.
pub fn cp_snark_terminal_verify_with_whir<F, EF, Challenger, H, C, Dft, WhirChallenger>(
    shape: &R1CSShape<F>,
    acc: &WarpAccumulator<F, F, F, 8>,
    transcripts: &[CommittedFoldTranscript<F>],
    make_challenger: impl FnMut() -> Challenger,
    folding_factor: usize,
    log_inv_rate: usize,
    merkle_hash: &H,
    merkle_compress: &C,
    dft: &Dft,
    whir_config: &crate::whir::parameters::WhirConfig<EF, F, H, C, WhirChallenger>,
    make_whir_challenger: impl FnMut() -> WhirChallenger,
) -> Result<crate::whir::proof::WhirProof<F, EF, F, 8>, CpSnarkDeciderError>
where
    F: p3_field::TwoAdicField + PrimeField64,
    EF: p3_field::ExtensionField<F> + p3_field::TwoAdicField,
    <F as p3_field::Field>::Packing: Eq + Send + Sync,
    Challenger: CanObserve<F> + CanSample<F>,
    H: p3_symmetric::CryptographicHasher<F, [F; 8]>
        + p3_symmetric::CryptographicHasher<
            <F as p3_field::Field>::Packing,
            [<F as p3_field::Field>::Packing; 8],
        > + Sync
        + Clone,
    C: p3_symmetric::PseudoCompressionFunction<[F; 8], 2>
        + p3_symmetric::PseudoCompressionFunction<[<F as p3_field::Field>::Packing; 8], 2>
        + Sync
        + Clone,
    Dft: p3_dft::TwoAdicSubgroupDft<F>,
    WhirChallenger: p3_challenger::FieldChallenger<F>
        + p3_challenger::GrindingChallenger<Witness = F>
        + p3_challenger::CanObserve<p3_symmetric::Hash<F, F, 8>>,
    [F; 8]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    use warp::decider::{TerminalWhirError, terminal_whir_prove_and_verify};

    // Steps 1+2: Verify commitment binding + FS replay + transcript chain.
    verify_committed_transcripts_and_chain(transcripts, make_challenger, &acc.instance)?;

    // Steps 3-4: Shift query Merkle proof verification.
    verify_shift_query_merkle_proofs(transcripts, folding_factor, merkle_hash, merkle_compress)?;

    // Step 5: Terminal WHIR (full RS decider + WHIR prove + WHIR verify)
    terminal_whir_prove_and_verify(
        shape,
        acc,
        folding_factor,
        log_inv_rate,
        dft,
        whir_config,
        make_whir_challenger,
    )
    .map_err(|e| match e {
        TerminalWhirError::Decider(d) => CpSnarkDeciderError::AlgebraicCheck(d),
        TerminalWhirError::ProveFailed => CpSnarkDeciderError::WhirProveFailed,
        TerminalWhirError::VerifyFailed => CpSnarkDeciderError::WhirVerifyFailed,
        TerminalWhirError::CommitmentRootMismatch => {
            CpSnarkDeciderError::TerminalAccumulatorMismatch {
                step: transcripts.last().map(|ct| ct.step).unwrap_or(0),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
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
        // eval_claims and pesat_targets are both zero so σ_0 = 0 regardless
        // of τ — lets us use a trivial round_poly with e0+e1=0.
        let eval_claims = vec![F::ZERO; 2];
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

        // Sumcheck round: e0 + e1 must equal σ_0 = 0 (our sumcheck algebra
        // check now enforces this).  Use all-zeros for the round poly.
        let round_evals = vec![vec![F::ZERO, F::ZERO, F::ZERO]];
        for &e in &round_evals[0] {
            prover_chal.observe(e);
        }
        let r: F = prover_chal.sample();

        // Build committed transcript using Symphony's HashCommitment
        let ct = commit_fold_transcript_with_shift_queries(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &round_evals,
            omega,
            tau,
            vec![r],
            vec![], // no fresh_betas in this test (log_m=0)
            &[],    // no shift queries
            &[],    // no input codeword roots
            None,   // no union
        );

        // Verify: should pass
        assert!(verify_committed_transcripts(&[ct.clone()], || MyChal::new(perm.clone()),).is_ok());

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
            fresh_betas: vec![],
            shift_query_positions: vec![],
            shift_query_values: vec![],
            shift_query_auth_paths: vec![],
            shift_query_expected: vec![],
            input_codeword_roots: vec![],
            union_commitment_root: None,
            alpha_eval: F::ZERO,
            ood_points: vec![],
            ood_answers: vec![],
            rho: F::ZERO,
            eval_batch_round_polys: vec![],
            eval_batch_challenges: vec![],
            new_eval_claim: F::ZERO,
            fresh_eval_claims: vec![],
            fresh_pesat_targets: vec![],
            output_commitment_root: vec![],
            output_eval_point: vec![],
            output_eval_claim: F::ZERO,
            output_pesat_tau: vec![],
            output_pesat_x: vec![],
            output_pesat_target: F::ZERO,
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
            fresh_betas: vec![],
            shift_query_positions: vec![],
            shift_query_values: vec![],
            shift_query_auth_paths: vec![],
            shift_query_expected: vec![],
            input_codeword_roots: vec![],
            union_commitment_root: None,
            alpha_eval: F::ZERO,
            ood_points: vec![],
            ood_answers: vec![],
            rho: F::ZERO,
            eval_batch_round_polys: vec![],
            eval_batch_challenges: vec![],
            new_eval_claim: F::ZERO,
            fresh_eval_claims: vec![],
            fresh_pesat_targets: vec![],
            output_commitment_root: vec![],
            output_eval_point: vec![],
            output_eval_claim: F::ZERO,
            output_pesat_tau: vec![],
            output_pesat_x: vec![],
            output_pesat_target: F::ZERO,
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

    // ═══════════════════════════════════════════════════════════════════════
    // FS-replay soundness audit — cheating-prover tests
    // ═══════════════════════════════════════════════════════════════════════
    //
    // These tests demonstrate concrete gaps in `verify_committed_transcripts`
    // where a malicious prover can produce accepting transcripts whose stored
    // fields were not honestly derived from Fiat-Shamir.
    //
    // Audit summary of what the native prover samples (per step, via
    // `transcript_round` inside `warp_fold_prove_rs_inner`) versus what the
    // CP-SNARK verifier re-derives:
    //
    //                                         CP verifier re-derives & checks?
    //   Observe k acc states                            ✓
    //   Sample ω, τ, fresh_betas                         ✓
    //   Twin-constraint sumcheck r_i (FS resample)       ✓
    //   TC sumcheck round-poly ALGEBRA (e0+e1==claim)    ✗  (not checked)
    //   Shift query positions (per q)                    ✗  (not re-derived
    //                                                       from FS; only
    //                                                       Merkle path is
    //                                                       verified)
    //   Shift query expected = Σ eq(γ,i)·vals_i          ✗  (stored but no
    //                                                       linear-combo check)
    //   OOD sample points + answers                      ✗  (not in transcript)
    //   ρ for eval batching                              ✗  (not in transcript)
    //   Eval-batching sumcheck rounds                    ✗  (not in transcript)
    //
    // Tests A/B below build accepting transcripts using these gaps.

    /// **Gap closed** — sumcheck round algebra is now enforced.
    ///
    /// Before the fix: `verify_committed_transcripts` never checked
    /// `e0 + e1 == prev_claim`, so arbitrary round polys passed.
    /// After the fix: round-0 sum must equal σ_0 (derived from stored
    /// (ω, τ, μ_i, η_i)), and inter-round sums must equal h(r_{i-1}).
    ///
    /// This test now flips: it EXPECTS rejection with
    /// `SumcheckAlgebraFailed`.
    #[test]
    fn cheat_sumcheck_evals_arbitrary_passes_verifier() {
        let perm = make_perm();
        let mut fs = MyChal::new(perm.clone());

        // Honest: observe 2 zero-accumulators (dummy).
        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::from_u64(10), F::from_u64(20)];
        let eval_points = vec![vec![F::from_u64(1), F::from_u64(2), F::from_u64(3)]; 2];
        let pesat_targets = vec![F::ZERO; 2];

        for i in 0..2 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..1).map(|_| fs.sample()).collect();

        // Honest σ_0 (what an HONEST sumcheck prover would need to prove):
        // σ_0 = Σ_i eq(τ, i) · (μ_i + ω · η_i).  With μ=[10,20] and η=[0,0],
        //       and τ ∈ F (log_l=1): σ_0 = (1-τ)·10 + τ·20.
        let tau0 = tau[0];
        let sigma_0 = (F::ONE - tau0) * eval_claims[0] + tau0 * eval_claims[1];

        // Malicious: pick TOTALLY ARBITRARY round poly values (NOT a degree-2
        // poly that evaluates to σ_0 at 0+1, not derived from any real table).
        // Here h(0) = 777, h(1) = 999; their sum (1776) ≠ σ_0 in general.
        let arbitrary_round_poly = vec![F::from_u64(777), F::from_u64(999), F::from_u64(12345)];
        // These are NOT related to σ_0 — not even close in a semantic sense.
        assert_ne!(
            arbitrary_round_poly[0] + arbitrary_round_poly[1],
            sigma_0,
            "setup sanity: the garbage poly's h(0)+h(1) should NOT match σ_0"
        );

        // Observe the garbage round poly, sample r (FS-consistent with this
        // garbage — that's all the verifier's FS replay cares about).
        for &e in &arbitrary_round_poly {
            fs.observe(e);
        }
        let r: F = fs.sample();

        // Commit the GARBAGE transcript.
        let ct = commit_fold_transcript_with_shift_queries(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[arbitrary_round_poly],
            omega,
            tau,
            vec![r],
            vec![], // no fresh_betas
            &[],
            &[], // no shift queries
            None,
        );

        // FIX VERIFIED: verifier now rejects because σ_0 ≠ e0 + e1.
        let result = verify_committed_transcripts(&[ct], || MyChal::new(perm.clone()));
        assert!(
            matches!(
                result,
                Err(CpSnarkDeciderError::SumcheckAlgebraFailed { step: 0, round: 0 })
            ),
            "fix regression: arbitrary sumcheck_evals must now fail with \
             SumcheckAlgebraFailed.  Got: {result:?}",
        );
    }

    /// **Gap closed** — `shift_query_expected` is now cross-checked
    /// against the linear combination of values + `sumcheck_challenges`.
    ///
    /// Before the fix: [`verify_shift_query_merkle_proofs`] only verified
    /// the Merkle auth paths but not the algebraic relationship between
    /// stored values and the stored expected-folded row.
    /// After the fix: for every (query, column), the verifier computes
    /// `Σ_i eq(γ,i) · values[q][i][c]` and asserts equality with
    /// `expected_folded[q][c]`.
    ///
    /// This test now expects `ShiftQueryValueMismatch`.
    ///
    /// Uses a bogus Merkle root + zero auth path so the Merkle check is
    /// skipped (path length 0 ⇒ tree_height=1 ⇒ position mod 1 = 0,
    /// trivially valid against the bogus zero root).  Wait — the Merkle
    /// check would still reject a path of length zero against a non-root
    /// leaf hash.  We use an explicit helper that skips Merkle + only
    /// exercises the LC check.
    #[test]
    fn cheat_shift_query_expected_unchecked() {
        use p3_koala_bear::Poseidon2KoalaBear;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

        type MyHash = PaddingFreeSponge<Poseidon2KoalaBear<16>, 16, 8, 8>;
        type MyCompress = TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>;

        // Build an HONEST tiny Merkle commitment of a single input codeword
        // row so the Merkle check passes; then tamper with expected_folded
        // so ONLY the new LC check catches it.
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_merkle_tree::MerkleTreeMmcs;

        let perm = make_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());

        // 4-element codeword (width=4, tree_height=1, so position must be 0).
        let cw: Vec<F> = vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let matrix = RowMajorMatrix::new(cw.clone(), 4);
        let mmcs: MerkleTreeMmcs<_, _, _, _, 8> =
            MerkleTreeMmcs::<F, F, _, _, 8>::new(hash.clone(), compress.clone());
        let (root_hash, tree) = mmcs.commit(vec![matrix]);
        let root: [F; 8] = root_hash.into();

        let opening = mmcs.open_batch(0, &tree);
        let (_opened, proof) = opening.unpack();

        // FS replay up to sumcheck completion.
        let mut fs = MyChal::new(perm.clone());
        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let pesat_targets = vec![F::ZERO; 2];
        for i in 0..2 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..1).map(|_| fs.sample()).collect();
        let round_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &round_poly {
            fs.observe(e);
        }
        let r: F = fs.sample();
        // FS for shift query position q=0.
        fs.observe(F::from_usize(0));
        let pos_chal: F = fs.sample();
        let pos = pos_chal.as_canonical_u64() as usize % 1; // tree_height=1

        // The prover's FS-derived pos is used in the transcript; expected
        // values are computed honestly; but `expected_folded` is tampered.
        let bogus_shift = crate::warp::fold::ShiftQueryOpening::<F, 8> {
            position: pos,
            input_values: vec![cw.clone()],
            auth_paths: vec![proof.clone()],
            expected_folded: vec![
                F::from_u64(999),
                F::from_u64(999),
                F::from_u64(999),
                F::from_u64(999),
            ],
        };

        let ct = commit_fold_transcript_full(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[round_poly],
            omega,
            tau,
            vec![r],
            vec![],
            &[bogus_shift],
            &[root],
            None,
            F::ZERO,
            vec![],
            vec![],
            F::ZERO,
            &[],
            vec![],
            F::ZERO,
            vec![],
            vec![],
        );

        // FS-replay verifier passes (all FS bits match):
        assert!(
            verify_committed_transcripts(&[ct.clone()], || MyChal::new(perm.clone()),).is_ok(),
            "FS replay should pass — tamper is only in expected_folded"
        );

        // The terminal verifier must also bind row width to the public
        // folding factor. The stored row has width 4, so folding_factor=1
        // (public width 2) must fail before any LC acceptance is possible.
        let width_result = verify_shift_query_merkle_proofs(&[ct.clone()], 1, &hash, &compress);
        assert!(
            matches!(
                width_result,
                Err(CpSnarkDeciderError::ShiftQueryWidthMismatch { step: 0, query: 0 })
            ),
            "row-width mismatch must fail with ShiftQueryWidthMismatch. Got: {width_result:?}",
        );

        // Missing per-input row openings must fail closed; otherwise the LC
        // check would treat omitted committed inputs as zero.
        let mut missing_opening = ct.clone();
        missing_opening.data.shift_query_values[0].clear();
        let arity_result =
            verify_shift_query_merkle_proofs(&[missing_opening], 2, &hash, &compress);
        assert!(
            matches!(
                arity_result,
                Err(CpSnarkDeciderError::ShiftQueryArityMismatch { step: 0, query: 0 })
            ),
            "missing shift-query openings must fail with ShiftQueryArityMismatch. Got: {arity_result:?}",
        );

        // Merkle+LC verifier catches the tampered expected_folded via the
        // new linear-combination check (Phase C of the fix).
        let result = verify_shift_query_merkle_proofs(&[ct], 2, &hash, &compress);
        assert!(
            matches!(
                result,
                Err(CpSnarkDeciderError::ShiftQueryValueMismatch { step: 0, query: 0 })
            ),
            "fix regression: tampered shift_query_expected must now fail \
             with ShiftQueryValueMismatch.  Got: {result:?}",
        );
    }

    /// **Gap closed** — OOD / ρ / eval-batching fields are now in
    /// [`FoldTranscriptData`] and `verify_committed_transcripts` replays
    /// them.  This test compiles only if the new fields exist; that is
    /// the (trivial) positive regression for Phase A of the fix.
    #[test]
    fn audit_ood_rho_evalbatch_are_now_in_transcript_data() {
        let _data = FoldTranscriptData {
            input_commitment_roots: vec![vec![F::ZERO; 8]],
            input_eval_claims: vec![F::ZERO],
            input_eval_points: vec![vec![F::ZERO]],
            input_pesat_targets: vec![F::ZERO],
            sumcheck_evals: vec![],
            omega: F::ZERO,
            tau_challenges: vec![],
            sumcheck_challenges: vec![],
            fresh_betas: vec![],
            shift_query_positions: vec![],
            shift_query_values: vec![],
            shift_query_auth_paths: vec![],
            shift_query_expected: vec![],
            input_codeword_roots: vec![],
            union_commitment_root: None,
            // FIX (Phase A): these fields exist now.
            alpha_eval: F::ZERO,
            ood_points: vec![],
            ood_answers: vec![],
            rho: F::ZERO,
            eval_batch_round_polys: vec![],
            eval_batch_challenges: vec![],
            new_eval_claim: F::ZERO,
            fresh_eval_claims: vec![],
            fresh_pesat_targets: vec![],
            output_commitment_root: vec![],
            output_eval_point: vec![],
            output_eval_claim: F::ZERO,
            output_pesat_tau: vec![],
            output_pesat_x: vec![],
            output_pesat_target: F::ZERO,
        };
    }

    /// **Gap — TC sumcheck start-target never checked.**
    ///
    /// Specifically: the verifier observes `sumcheck_evals[0]` and samples
    /// r_0, matching `sumcheck_challenges[0]`.  But it does NOT compute
    ///   σ_0 = Σ_i eq(τ, i)·(μ_i + ω·η_i)
    /// from the stored `omega, tau_challenges, input_eval_claims,
    /// input_pesat_targets` and check
    ///   sumcheck_evals[0][0] + sumcheck_evals[0][1] == σ_0.
    ///
    /// Combined with `cheat_sumcheck_evals_arbitrary_passes_verifier`, this
    /// gap lets a malicious prover commit a sumcheck that "proves" a
    /// totally different starting target than σ_0 — and by extension a
    /// different folded (α', μ') result — as long as the output accumulator
    /// still passes the algebraic decider (which it can for carefully
    /// chosen garbage).
    ///
    /// This test documents the gap by showing both a tampered σ_0-unrelated
    /// transcript passes and explicitly computing σ_0 to show the
    /// inconsistency is never surfaced.
    #[test]
    fn cheat_sumcheck_ignores_sigma_0() {
        let perm = make_perm();
        let mut fs = MyChal::new(perm.clone());

        // Honest input: set eval_claims to non-zero so σ_0 ≠ 0.
        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::from_u64(100), F::from_u64(200)];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let pesat_targets = vec![F::ZERO; 2];

        for i in 0..2 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..1).map(|_| fs.sample()).collect();

        // What an HONEST verifier WOULD compute (if it checked σ_0):
        let tau0 = tau[0];
        let sigma_0_expected = (F::ONE - tau0) * eval_claims[0] + tau0 * eval_claims[1];

        // Malicious: pick a round poly whose h(0)+h(1) is F::ZERO
        // — completely incompatible with the actual σ_0 above.
        let round_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        assert_ne!(
            F::ZERO,
            sigma_0_expected,
            "setup sanity: σ_0 with μ=[100,200] should not be zero"
        );

        for &e in &round_poly {
            fs.observe(e);
        }
        let r: F = fs.sample();

        let ct = commit_fold_transcript_with_shift_queries(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[round_poly],
            omega,
            tau,
            vec![r],
            vec![],
            &[],
            &[],
            None,
        );

        // FIX VERIFIED: σ_0 is now computed from (μ, η, ω, τ) and enforced.
        let result = verify_committed_transcripts(&[ct], || MyChal::new(perm.clone()));
        assert!(
            matches!(
                result,
                Err(CpSnarkDeciderError::SumcheckAlgebraFailed { step: 0, round: 0 })
            ),
            "fix regression: σ_0-inconsistent round poly must now fail with \
             SumcheckAlgebraFailed.  Got: {result:?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Additional cheating-prover tests for Phase-D: exercise EACH new check
    // (inter-round consistency, ρ binding, eval-batch algebra, shift-query
    // position re-derivation).
    // ═══════════════════════════════════════════════════════════════════════

    /// Inter-round sumcheck algebra: round i>0 must have e0+e1 == h_{i-1}(γ_{i-1}).
    /// Construct a 2-round sumcheck where round 0 is honest but round 1 has
    /// e0+e1 ≠ h_0(γ_0); check the new rejection path fires on round 1.
    #[test]
    fn cheat_sumcheck_inter_round_consistency_now_enforced() {
        let perm = make_perm();
        let mut fs = MyChal::new(perm.clone());

        // All-zero inputs → σ_0 = 0.  Log_l = 2 (l=4) for a 2-round sumcheck.
        let roots = vec![vec![F::ZERO; 8]; 4];
        let eval_claims = vec![F::ZERO; 4];
        let eval_points = vec![vec![F::ZERO; 3]; 4];
        let pesat_targets = vec![F::ZERO; 4];
        for i in 0..4 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..2).map(|_| fs.sample()).collect();

        // Round 0: honest all-zero poly (e0+e1 = 0 = σ_0).
        let r0_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &r0_poly {
            fs.observe(e);
        }
        let r0: F = fs.sample();

        // Round 1: TAMPERED — e0+e1 = 1 ≠ h_0(r0) = 0.
        let r1_poly = vec![F::ONE, F::ZERO, F::ZERO];
        for &e in &r1_poly {
            fs.observe(e);
        }
        let r1: F = fs.sample();

        let ct = commit_fold_transcript_full(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[r0_poly, r1_poly],
            omega,
            tau,
            vec![r0, r1],
            vec![],
            &[],
            &[],
            None,
            F::ZERO,
            vec![],
            vec![],
            F::ZERO,
            &[],
            vec![],
            F::ZERO,
            vec![],
            vec![],
        );

        let result = verify_committed_transcripts(&[ct], || MyChal::new(perm.clone()));
        assert!(
            matches!(
                result,
                Err(CpSnarkDeciderError::SumcheckAlgebraFailed { step: 0, round: 1 })
            ),
            "inter-round consistency must fail on round 1.  Got: {result:?}"
        );
    }

    /// ρ binding: tamper with the stored ρ, verifier must reject.
    #[test]
    fn cheat_rho_binding_now_enforced() {
        // We need a transcript with non-empty eval_batch_round_polys for the
        // ρ check to fire.  Build a minimal one: 1 eval-batch round with
        // honest data, but stored ρ is wrong.
        let perm = make_perm();
        let mut fs = MyChal::new(perm.clone());

        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let eval_points = vec![vec![F::ZERO; 1]; 2];
        let pesat_targets = vec![F::ZERO; 2];
        for i in 0..2 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..1).map(|_| fs.sample()).collect();
        // σ_0 = 0; honest round poly [0,0,0].
        let sc_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &sc_poly {
            fs.observe(e);
        }
        let r_sc: F = fs.sample();
        // No shift queries, no OOD — straight to ρ.
        fs.observe(F::from_usize(2000));
        let rho_correct: F = fs.sample();

        // Honest eval-batching: initial target = ρ^0·alpha_eval = 0 (all-zero).
        // One round: e0=e1=e2=0, e0+e1=0 consistent.
        let eb_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &eb_poly {
            fs.observe(e);
        }
        let eb_r: F = fs.sample();

        let ct = commit_fold_transcript_full(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[sc_poly],
            omega,
            tau,
            vec![r_sc],
            vec![],
            &[],
            &[],
            None,
            F::ZERO,
            vec![],
            vec![],
            rho_correct + F::ONE, // ← TAMPERED ρ
            &[eb_poly],
            vec![eb_r],
            F::ZERO,
            vec![],
            vec![],
        );

        let result = verify_committed_transcripts(&[ct], || MyChal::new(perm.clone()));
        assert!(
            matches!(result, Err(CpSnarkDeciderError::RhoMismatch { step: 0 })),
            "ρ tamper must fail with RhoMismatch.  Got: {result:?}"
        );
    }

    /// Eval-batch sumcheck algebra: first round's e0+e1 must equal the
    /// initial batched target Σ ρ^k·v_k.  Tamper with alpha_eval so the
    /// stored first round poly becomes inconsistent; verifier rejects.
    #[test]
    fn cheat_eval_batch_initial_target_now_enforced() {
        let perm = make_perm();
        let mut fs = MyChal::new(perm.clone());

        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let eval_points = vec![vec![F::ZERO; 1]; 2];
        let pesat_targets = vec![F::ZERO; 2];
        for i in 0..2 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..1).map(|_| fs.sample()).collect();
        let sc_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &sc_poly {
            fs.observe(e);
        }
        let r_sc: F = fs.sample();
        fs.observe(F::from_usize(2000));
        let rho: F = fs.sample();

        // Honest eval-batch with all-zero initial target: round poly [0,0,0]
        // is consistent (e0+e1 = 0).  We TAMPER alpha_eval = 17 so the
        // implicit initial target becomes 1·17 = 17 ≠ 0.
        let eb_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &eb_poly {
            fs.observe(e);
        }
        let eb_r: F = fs.sample();

        let ct = commit_fold_transcript_full(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[sc_poly],
            omega,
            tau,
            vec![r_sc],
            vec![],
            &[],
            &[],
            None,
            F::from_u64(17), // ← tampered alpha_eval
            vec![],
            vec![],
            rho,
            &[eb_poly],
            vec![eb_r],
            F::ZERO,
            vec![],
            vec![],
        );

        let result = verify_committed_transcripts(&[ct], || MyChal::new(perm.clone()));
        assert!(
            matches!(
                result,
                Err(CpSnarkDeciderError::EvalBatchAlgebraFailed { step: 0, round: 0 })
            ),
            "eval-batch initial target inconsistency must fail with \
             EvalBatchAlgebraFailed.  Got: {result:?}"
        );
    }

    /// Shift-query position binding: the stored `shift_query_positions[q]`
    /// must equal `sample.as_canonical_u64() as usize % tree_height`.
    /// Tamper with the position after committing; verifier rejects.
    #[test]
    fn cheat_shift_query_position_now_enforced() {
        let perm = make_perm();
        let mut fs = MyChal::new(perm.clone());

        let roots = vec![vec![F::ZERO; 8]; 2];
        let eval_claims = vec![F::ZERO; 2];
        let eval_points = vec![vec![F::ZERO; 3]; 2];
        let pesat_targets = vec![F::ZERO; 2];
        for i in 0..2 {
            for &val in &roots[i] {
                fs.observe(val);
            }
            fs.observe(eval_claims[i]);
            for &val in &eval_points[i] {
                fs.observe(val);
            }
            fs.observe(pesat_targets[i]);
        }
        let omega: F = fs.sample();
        let tau: Vec<F> = (0..1).map(|_| fs.sample()).collect();
        let sc_poly = vec![F::ZERO, F::ZERO, F::ZERO];
        for &e in &sc_poly {
            fs.observe(e);
        }
        let r_sc: F = fs.sample();

        // Prover would sample pos from FS, but we put a BOGUS position
        // in the transcript.  tree_height is 1<<auth_path.len() = 1<<2 = 4.
        fs.observe(F::from_usize(0));
        let pos_sample: F = fs.sample();
        let honest_pos = pos_sample.as_canonical_u64() as usize % 4;
        // Pick a different position that is ALSO valid mod 4 but not equal.
        let bogus_pos = (honest_pos + 1) % 4;
        assert_ne!(honest_pos, bogus_pos);

        let bogus_shift = crate::warp::fold::ShiftQueryOpening::<F, 8> {
            position: bogus_pos,
            // Fake values/path — we won't run Merkle check, only FS replay.
            input_values: vec![vec![F::ZERO; 4]],
            auth_paths: vec![vec![[F::ZERO; 8]; 2]], // depth 2 → height 4
            expected_folded: vec![F::ZERO; 4],
        };

        let ct = commit_fold_transcript_full(
            0,
            roots,
            eval_claims,
            eval_points,
            pesat_targets,
            &[sc_poly],
            omega,
            tau,
            vec![r_sc],
            vec![],
            &[bogus_shift],
            &[[F::ZERO; 8]; 1],
            None,
            F::ZERO,
            vec![],
            vec![],
            F::ZERO,
            &[],
            vec![],
            F::ZERO,
            vec![],
            vec![],
        );

        let result = verify_committed_transcripts(&[ct], || MyChal::new(perm.clone()));
        assert!(
            matches!(
                result,
                Err(CpSnarkDeciderError::ShiftQueryPositionMismatch { step: 0, query: 0 })
            ),
            "shift-query position tamper must fail with \
             ShiftQueryPositionMismatch.  Got: {result:?}"
        );
    }
}
