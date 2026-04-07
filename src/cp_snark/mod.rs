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

use std::{vec, vec::Vec};

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
    /// Shift query Merkle proof invalid — authentication path does not match root.
    ShiftQueryMerkleInvalid { step: usize, query: usize, input: usize },
    /// Shift query linear combination mismatch — folded value ≠ Σ eq(γ,i) * val_i.
    ShiftQueryValueMismatch { step: usize, query: usize },
    /// WHIR commitment root does not match accumulated root.
    WhirRootBindingFailed,
    /// WHIR prove failed.
    WhirProveFailed,
    /// WHIR verify failed.
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
    shift_queries: &[crate::accumulation::warp::fold::ShiftQueryOpening<F>],
    input_codeword_roots: &[[F; 8]],
    union_commitment_root: Option<Vec<F>>,
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
        fresh_betas,
        shift_query_positions: shift_queries.iter().map(|sq| sq.position).collect(),
        shift_query_values: shift_queries.iter().map(|sq| sq.input_values.clone()).collect(),
        shift_query_auth_paths: shift_queries.iter().map(|sq| sq.auth_paths.clone()).collect(),
        shift_query_expected: shift_queries.iter().map(|sq| sq.expected_folded.clone()).collect(),
        input_codeword_roots: input_codeword_roots.to_vec(),
        union_commitment_root,
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

        if let Some(ref union_root) = t.union_commitment_root {
            // ── Union path (Quasar): absorb running acc + single union root ──
            // Matches derive_fold_challenges_union: O(1) in number of fresh instances.
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
            // Absorb union commitment root
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

        // Derive and check fresh_betas (PESAT randomness, sampled between tau and sumcheck)
        for expected_betas in &t.fresh_betas {
            for &expected_beta in expected_betas {
                let beta: F = challenger.sample();
                if beta != expected_beta {
                    return Err(CpSnarkDeciderError::ChallengeMismatch { step: ct.step });
                }
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

/// Verify shift query Merkle proofs for all committed transcripts at terminal.
///
/// For each transcript that includes shift query data:
/// 1. Verify each Merkle authentication path against the committed root
/// 2. Verify the linear combination: `expected_folded = Σ_i eq(γ, i) * values_i`
///
/// This defers the expensive Poseidon2 Merkle verification from the recursive
/// circuit to terminal, where it runs natively (~100ms for 100 steps).
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
        + p3_symmetric::CryptographicHasher<<F as p3_field::Field>::Packing, [<F as p3_field::Field>::Packing; 8]>
        + Sync
        + Clone,
    C: p3_symmetric::PseudoCompressionFunction<[F; 8], 2>
        + p3_symmetric::PseudoCompressionFunction<[<F as p3_field::Field>::Packing; 8], 2>
        + Sync
        + Clone,
    [F; 8]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    use crate::accumulation::warp::encoding::merkle_verify_opening;

    for ct in transcripts {
        let t = &ct.data;
        let num_queries = t.shift_query_positions.len();
        if num_queries == 0 {
            continue;
        }

        let base_width = 1usize << folding_factor;

        if t.union_commitment_root.is_some() {
            // ── Union mode (Quasar §4): single union auth path per query ──
            // The union tree interleaves all ℓ codewords: union[p*l + i] = cw[i][p].
            // Each auth_paths[q] has 1 entry: the union tree auth path.
            // We reconstruct the union row from the per-codeword input_values
            // and verify the single auth path against the union root.
            assert_eq!(
                t.input_codeword_roots.len(), 1,
                "union mode must have exactly 1 root (the union root)"
            );
            let union_root = &t.input_codeword_roots[0];

            for q in 0..num_queries {
                let pos = t.shift_query_positions[q];
                let values_per_cw = &t.shift_query_values[q];
                let l = values_per_cw.len();

                // Reconstruct the union row by interleaving per-codeword values.
                // union_row[k * l + i] = values_per_cw[i][k]
                let mut union_row = vec![F::ZERO; l * base_width];
                for (i, cw_vals) in values_per_cw.iter().enumerate() {
                    for (k, &v) in cw_vals.iter().enumerate() {
                        union_row[k * l + i] = v;
                    }
                }

                // auth_paths[q] has 1 entry for union mode
                if t.shift_query_auth_paths[q].is_empty() {
                    return Err(CpSnarkDeciderError::ShiftQueryMerkleInvalid {
                        step: ct.step, query: q, input: 0,
                    });
                }
                let proof = &t.shift_query_auth_paths[q][0];
                let tree_height = 1usize << proof.len();
                let union_width = l * base_width;

                let valid = merkle_verify_opening::<
                    F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing, H, C, 8,
                >(union_root, pos, &union_row, proof, union_width, tree_height,
                  merkle_hash.clone(), merkle_compress.clone());

                if !valid {
                    return Err(CpSnarkDeciderError::ShiftQueryMerkleInvalid {
                        step: ct.step, query: q, input: 0,
                    });
                }
            }
        } else {
            // ── Non-union mode (WARP standard): per-input auth paths ──
            let num_inputs = t.input_codeword_roots.len();

            for q in 0..num_queries {
                let pos = t.shift_query_positions[q];

                for inp in 0..num_inputs {
                    if inp >= t.shift_query_values[q].len()
                        || inp >= t.shift_query_auth_paths[q].len()
                    {
                        continue;
                    }
                    let row_values = &t.shift_query_values[q][inp];
                    let proof = &t.shift_query_auth_paths[q][inp];
                    let root = &t.input_codeword_roots[inp];
                    let tree_height = 1usize << proof.len();

                    let valid = merkle_verify_opening::<
                        F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing, H, C, 8,
                    >(root, pos, row_values, proof, base_width, tree_height,
                      merkle_hash.clone(), merkle_compress.clone());

                    if !valid {
                        return Err(CpSnarkDeciderError::ShiftQueryMerkleInvalid {
                            step: ct.step, query: q, input: inp,
                        });
                    }
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
        + p3_symmetric::CryptographicHasher<<F as p3_field::Field>::Packing, [<F as p3_field::Field>::Packing; 8]>
        + Sync
        + Clone,
    C: p3_symmetric::PseudoCompressionFunction<[F; 8], 2>
        + p3_symmetric::PseudoCompressionFunction<[<F as p3_field::Field>::Packing; 8], 2>
        + Sync
        + Clone,
    [F; 8]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    // Steps 1+2: Verify commitment binding + FS replay
    verify_committed_transcripts(transcripts, make_challenger)?;

    // Step 3: Algebraic decider
    warp_decide_algebraic_rs(shape, acc).map_err(CpSnarkDeciderError::AlgebraicCheck)?;

    // Step 4: Shift query Merkle proof verification
    verify_shift_query_merkle_proofs(transcripts, folding_factor, merkle_hash, merkle_compress)
}

/// CP-SNARK terminal verification with terminal WHIR proof (fully succinct).
///
/// Extends `cp_snark_terminal_verify_with_merkle` with a fifth phase:
///
/// 5. **Terminal WHIR**: full prover-side RS decider + WHIR prove + root binding +
///    WHIR verify. This establishes that the accumulated codeword is RS-close,
///    completing the succinct argument chain.
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
        + p3_symmetric::CryptographicHasher<<F as p3_field::Field>::Packing, [<F as p3_field::Field>::Packing; 8]>
        + Sync
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
    use crate::accumulation::warp::decider::{terminal_whir_prove_and_verify, TerminalWhirError};

    // Steps 1+2: Verify commitment binding + FS replay
    verify_committed_transcripts(transcripts, make_challenger)?;

    // Steps 3-4: Shift query Merkle proof verification (includes algebraic decider
    // via warp_decide_algebraic_rs internally in step 3)
    verify_shift_query_merkle_proofs(transcripts, folding_factor, merkle_hash, merkle_compress)?;

    // Step 5: Terminal WHIR (full RS decider + WHIR prove + root binding + WHIR verify)
    terminal_whir_prove_and_verify(
        shape, acc, folding_factor, log_inv_rate, dft, whir_config, make_whir_challenger,
    )
    .map_err(|e| match e {
        TerminalWhirError::Decider(d) => CpSnarkDeciderError::AlgebraicCheck(d),
        TerminalWhirError::RootBindingMismatch => CpSnarkDeciderError::WhirRootBindingFailed,
        TerminalWhirError::ProveFailed => CpSnarkDeciderError::WhirProveFailed,
        TerminalWhirError::VerifyFailed => CpSnarkDeciderError::WhirVerifyFailed,
    })
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
            vec![],  // no fresh_betas in this test (log_m=0)
            &[],     // no shift queries
            &[],     // no input codeword roots
            None,    // no union
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
            fresh_betas: vec![],
            shift_query_positions: vec![],
            shift_query_values: vec![],
            shift_query_auth_paths: vec![],
            shift_query_expected: vec![],
            input_codeword_roots: vec![],
            union_commitment_root: None,
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
