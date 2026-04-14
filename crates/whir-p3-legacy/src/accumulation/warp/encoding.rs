//! Reed-Solomon encoding and Merkle commitment for WARP accumulation.
//!
//! This module provides standalone RS encoding using WHIR's DFT infrastructure
//! and Merkle commitment of RS codewords using Plonky3's MerkleTreeMmcs.
//!
//! The encoding expands a witness polynomial from 2^k evaluations to
//! 2^(k + log_inv_rate) evaluations on a smooth multiplicative coset,
//! creating the error-correcting redundancy that makes proximity testing meaningful.
//!
//! The encoding follows exactly the same process as CommitmentWriter::commit
//! (transpose → pad → DFT) but decoupled from the WHIR proof flow so it can
//! be used during each fold step.

use alloc::{vec, vec::Vec};

use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;

use crate::poly::evals::EvaluationsList;

/// RS-encode a witness polynomial using WHIR's DFT expansion.
///
/// Given a witness polynomial of size 2^num_variables, produces a codeword
/// of size 2^(num_variables + log_inv_rate) by:
/// 1. Reshaping the evaluations into a matrix (transpose for variable ordering)
/// 2. Zero-padding to the expanded domain size (creates the rate blowup)
/// 3. DFT-expanding each row onto the smooth multiplicative subgroup
///
/// The result is a flat vector of field elements representing the RS codeword
/// in the same format that CommitmentWriter::commit would produce before
/// Merkle tree construction.
///
/// # Arguments
/// - `witness`: the witness polynomial as evaluations on {0,1}^num_variables
/// - `folding_factor`: WHIR's initial folding factor (determines matrix width)
/// - `log_inv_rate`: log₂ of the inverse rate (1 → rate 1/2, 2 → rate 1/4, etc.)
/// - `dft`: the DFT engine (Radix2DFTSmallBatch)
///
/// # Returns
/// An EvaluationsList containing the RS codeword of size 2^(num_variables + log_inv_rate).
pub fn rs_encode<F, Dft>(
    witness: &EvaluationsList<F>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Dft,
) -> EvaluationsList<F>
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    let num_variables = witness.num_variables();
    assert!(
        folding_factor <= num_variables,
        "folding_factor ({folding_factor}) must be <= num_variables ({num_variables})"
    );

    // Step 1: Reshape into matrix and transpose
    // Width before transpose: 2^(num_variables - folding_factor)
    // After transpose: width = 2^folding_factor, height = 2^(num_variables - folding_factor)
    let width_before = 1usize << (num_variables - folding_factor);
    let mat = p3_matrix::dense::RowMajorMatrixView::new(witness.as_slice(), width_before)
        .transpose();

    // Step 2: Pad height for rate blowup
    // Padded height: 2^(num_variables + log_inv_rate - folding_factor)
    let padded_height = 1usize << (num_variables + log_inv_rate - folding_factor);
    let mut padded = mat;
    padded.pad_to_height(padded_height, F::ZERO);

    // Step 3: DFT expansion (this is the actual RS encoding)
    let expanded = dft.dft_batch(padded).to_row_major_matrix();

    // Flatten the matrix back to a single vector
    // Total size: height * width = 2^(num_variables + log_inv_rate)
    let total_size = expanded.height() * expanded.width();
    debug_assert_eq!(total_size, 1 << (num_variables + log_inv_rate));

    EvaluationsList::new(expanded.values)
}

/// Verify that a codeword is a valid RS encoding of a witness.
///
/// Re-encodes the witness and checks equality with the claimed codeword.
/// This is the "codeword validity" check in the WARP decider.
pub fn verify_rs_encoding<F, Dft>(
    witness: &EvaluationsList<F>,
    codeword: &EvaluationsList<F>,
    folding_factor: usize,
    log_inv_rate: usize,
    dft: &Dft,
) -> bool
where
    F: TwoAdicField,
    Dft: TwoAdicSubgroupDft<F>,
{
    let expected = rs_encode(witness, folding_factor, log_inv_rate, dft);
    expected.as_slice() == codeword.as_slice()
}

/// Build a union codeword by column-major interleaving of ℓ codewords.
///
/// Given ℓ codewords of size n, produces a union codeword of size ℓ·n where:
///   `union[p * ℓ + i] = codewords[i][p]`
///
/// Column-major layout ensures that one Merkle leaf (when committed with
/// `folding_factor = base_ff + log2(ℓ)`) contains all ℓ values at one
/// position block. This lets the verifier check shift queries with a
/// single Merkle path per query position instead of ℓ separate paths.
///
/// # Arguments
/// - `codewords`: ℓ codewords, each of size n (must all be equal size)
///
/// # Returns
/// A flat vector of size ℓ·n in column-major interleaved order.
pub fn build_union_codeword<F: Copy + Default>(codewords: &[Vec<F>]) -> Vec<F> {
    let l = codewords.len();
    assert!(l > 0, "need at least one codeword");
    let n = codewords[0].len();
    assert!(
        codewords.iter().all(|cw| cw.len() == n),
        "all codewords must have equal length"
    );

    let mut union = vec![F::default(); l * n];
    for (i, cw) in codewords.iter().enumerate() {
        for (p, &val) in cw.iter().enumerate() {
            union[p * l + i] = val;
        }
    }
    union
}

/// Extract the column of ℓ values at a given position from a union codeword.
///
/// The inverse of `build_union_codeword` for a single position:
///   `column[i] = union[position * ℓ + i]` for `i ∈ [ℓ]`
///
/// Used by shift queries to read all ℓ codeword values at a query position
/// from a single Merkle authentication path on the union tree.
pub fn union_column_at<F: Copy>(union: &[F], l: usize, position: usize) -> Vec<F> {
    let start = position * l;
    union[start..start + l].to_vec()
}

/// Compute the Merkle folding factor for a union codeword.
///
/// The union tree uses `base_folding_factor + log2(ℓ)` so that each
/// Merkle leaf contains exactly one position-block of ℓ elements (times
/// the base leaf width). This ensures one Merkle path reveals all ℓ
/// codeword values at a position.
pub fn union_folding_factor(base_folding_factor: usize, l: usize) -> usize {
    assert!(l.is_power_of_two(), "ℓ must be a power of two");
    base_folding_factor + l.trailing_zeros() as usize
}

/// Commit a union codeword to a Merkle tree.
///
/// Uses `union_folding_factor(base_ff, ℓ)` so that each Merkle leaf
/// groups one position-block of ℓ values, enabling single-path shift
/// query openings.
pub fn merkle_commit_union_codeword<F, W, P, PW, H, C, const DIGEST_ELEMS: usize>(
    union_codeword: &[F],
    l: usize,
    base_folding_factor: usize,
    merkle_hash: H,
    merkle_compress: C,
) -> (
    [W; DIGEST_ELEMS],
    p3_merkle_tree::MerkleTree<F, W, RowMajorMatrix<F>, DIGEST_ELEMS>,
)
where
    F: TwoAdicField,
    W: p3_field::PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
    P: p3_field::PackedValue<Value = F> + Eq + Send + Sync,
    PW: p3_field::PackedValue<Value = W> + Eq + Send + Sync,
    H: p3_symmetric::CryptographicHasher<F, [W; DIGEST_ELEMS]>
        + p3_symmetric::CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: p3_symmetric::PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
        + p3_symmetric::PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
        + Sync,
    [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let ff = union_folding_factor(base_folding_factor, l);
    let width = 1usize << ff;
    let total = union_codeword.len();
    let height = total / width;
    assert_eq!(
        height * width, total,
        "union codeword length {} not divisible by 2^{} = {}",
        total, ff, width,
    );

    let matrix = RowMajorMatrix::new(union_codeword.to_vec(), width);
    let mmcs = MerkleTreeMmcs::<P, PW, H, C, DIGEST_ELEMS>::new(merkle_hash, merkle_compress);
    let (root, tree) = mmcs.commit_matrix(matrix);
    (*root.as_ref(), tree)
}

/// Compute the codeword size from witness parameters.
#[inline]
pub const fn codeword_size(num_variables: usize, log_inv_rate: usize) -> usize {
    1 << (num_variables + log_inv_rate)
}

/// Commit an RS codeword to a Merkle tree.
///
/// Reshapes the flat codeword into a matrix with width = 2^folding_factor
/// (matching WHIR's convention), then builds a Merkle tree over the rows.
///
/// Returns `(root, tree)` where root is the digest and tree is the prover data
/// needed for opening proofs.
pub fn merkle_commit_codeword<F, W, P, PW, H, C, const DIGEST_ELEMS: usize>(
    codeword: &EvaluationsList<F>,
    folding_factor: usize,
    merkle_hash: H,
    merkle_compress: C,
) -> (
    [W; DIGEST_ELEMS],
    p3_merkle_tree::MerkleTree<F, W, RowMajorMatrix<F>, DIGEST_ELEMS>,
)
where
    F: TwoAdicField,
    W: p3_field::PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
    P: p3_field::PackedValue<Value = F> + Eq + Send + Sync,
    PW: p3_field::PackedValue<Value = W> + Eq + Send + Sync,
    H: p3_symmetric::CryptographicHasher<F, [W; DIGEST_ELEMS]>
        + p3_symmetric::CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: p3_symmetric::PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
        + p3_symmetric::PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
        + Sync,
    [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let width = 1usize << folding_factor;
    let height = codeword.as_slice().len() / width;
    assert_eq!(
        height * width,
        codeword.as_slice().len(),
        "codeword length must be divisible by 2^folding_factor"
    );

    let matrix = RowMajorMatrix::new(codeword.as_slice().to_vec(), width);
    let mmcs = MerkleTreeMmcs::<P, PW, H, C, DIGEST_ELEMS>::new(merkle_hash, merkle_compress);
    let (root, tree) = mmcs.commit_matrix(matrix);
    (*root.as_ref(), tree)
}

/// Open a Merkle tree at a given row position, returning the authentication path.
///
/// Uses Plonky3's `Mmcs::open_batch` to extract the sibling digests along
/// the path from leaf to root. The returned proof is `Vec<[W; DIGEST_ELEMS]>`.
pub fn merkle_open_at<F, W, P, PW, H, C, const DIGEST_ELEMS: usize>(
    tree: &p3_merkle_tree::MerkleTree<F, W, RowMajorMatrix<F>, DIGEST_ELEMS>,
    position: usize,
    merkle_hash: H,
    merkle_compress: C,
) -> (Vec<F>, Vec<[W; DIGEST_ELEMS]>)
where
    F: TwoAdicField,
    W: p3_field::PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
    P: p3_field::PackedValue<Value = F> + Eq + Send + Sync,
    PW: p3_field::PackedValue<Value = W> + Eq + Send + Sync,
    H: p3_symmetric::CryptographicHasher<F, [W; DIGEST_ELEMS]>
        + p3_symmetric::CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: p3_symmetric::PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
        + p3_symmetric::PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
        + Sync,
    [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let mmcs = MerkleTreeMmcs::<P, PW, H, C, DIGEST_ELEMS>::new(merkle_hash, merkle_compress);
    let opening = p3_commit::Mmcs::open_batch(&mmcs, position, tree);
    let (opened_values, proof) = opening.unpack();
    // For a single-matrix commitment, opened_values has one entry: the row values
    let row_values = opened_values.into_iter().next().unwrap_or_default();
    (row_values, proof)
}

/// Verify a Merkle opening proof against a commitment root.
///
/// Checks that the claimed `row_values` at `position` are consistent with
/// the committed Merkle root via the authentication path `proof`.
pub fn merkle_verify_opening<F, W, P, PW, H, C, const DIGEST_ELEMS: usize>(
    root: &[W; DIGEST_ELEMS],
    position: usize,
    row_values: &[F],
    proof: &Vec<[W; DIGEST_ELEMS]>,
    row_width: usize,
    tree_height: usize,
    merkle_hash: H,
    merkle_compress: C,
) -> bool
where
    F: TwoAdicField,
    W: p3_field::PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
    P: p3_field::PackedValue<Value = F> + Eq + Send + Sync,
    PW: p3_field::PackedValue<Value = W> + Eq + Send + Sync,
    H: p3_symmetric::CryptographicHasher<F, [W; DIGEST_ELEMS]>
        + p3_symmetric::CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: p3_symmetric::PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
        + p3_symmetric::PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
        + Sync,
    [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    use p3_commit::Mmcs;
    use p3_matrix::Dimensions;

    let mmcs = MerkleTreeMmcs::<P, PW, H, C, DIGEST_ELEMS>::new(merkle_hash, merkle_compress);
    let dimensions = [Dimensions { width: row_width, height: tree_height }];
    let opened_values = [row_values.to_vec()];
    let opening_ref = p3_commit::BatchOpeningRef::new(&opened_values, proof);
    let hash_root: p3_symmetric::Hash<F, W, DIGEST_ELEMS> = (*root).into();
    mmcs.verify_batch(&hash_root, &dimensions, position, opening_ref).is_ok()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    #[test]
    fn rs_encode_produces_correct_size() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 6;
        let log_inv_rate = 1; // rate 1/2
        let folding_factor = 2;

        let witness = EvaluationsList::new(vec![F::ONE; 1 << num_vars]);
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        // Codeword should be 2x larger (rate 1/2)
        assert_eq!(
            codeword.as_slice().len(),
            1 << (num_vars + log_inv_rate),
            "codeword should be 2^(num_vars + log_inv_rate)"
        );
    }

    #[test]
    fn rs_encode_rate_quarter() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 6;
        let log_inv_rate = 2; // rate 1/4
        let folding_factor = 2;

        let witness = EvaluationsList::new(vec![F::from_u64(42); 1 << num_vars]);
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        assert_eq!(
            codeword.as_slice().len(),
            1 << (num_vars + log_inv_rate),
            "codeword should be 4x witness size at rate 1/4"
        );
    }

    #[test]
    fn rs_encode_is_deterministic() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let witness = EvaluationsList::new(
            (0..1u64 << num_vars).map(|i| F::from_u64(i + 1)).collect(),
        );

        let cw1 = rs_encode(&witness, folding_factor, log_inv_rate, &dft);
        let cw2 = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        assert_eq!(cw1.as_slice(), cw2.as_slice(), "encoding should be deterministic");
    }

    #[test]
    fn rs_encode_different_witnesses_differ() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let w1 = EvaluationsList::new(vec![F::ONE; 1 << num_vars]);
        let w2 = EvaluationsList::new(vec![F::from_u64(2); 1 << num_vars]);

        let cw1 = rs_encode(&w1, folding_factor, log_inv_rate, &dft);
        let cw2 = rs_encode(&w2, folding_factor, log_inv_rate, &dft);

        assert_ne!(cw1.as_slice(), cw2.as_slice(), "different witnesses should produce different codewords");
    }

    #[test]
    fn verify_rs_encoding_accepts_valid() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let witness = EvaluationsList::new(
            (0..1u64 << num_vars).map(|i| F::from_u64(i + 1)).collect(),
        );
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        assert!(verify_rs_encoding(&witness, &codeword, folding_factor, log_inv_rate, &dft));
    }

    #[test]
    fn verify_rs_encoding_rejects_tampered() {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let num_vars = 5;
        let log_inv_rate = 1;
        let folding_factor = 2;

        let witness = EvaluationsList::new(
            (0..1u64 << num_vars).map(|i| F::from_u64(i + 1)).collect(),
        );
        let mut codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        // Tamper with one position
        let vals = codeword.as_mut_slice();
        vals[0] += F::ONE;

        assert!(
            !verify_rs_encoding(&witness, &codeword, folding_factor, log_inv_rate, &dft),
            "should reject tampered codeword"
        );
    }

    #[test]
    fn rs_fold_integration_fixed_size() {
        // Full integration: RS-encode → WARP fold → verify codeword stays fixed size
        use crate::accumulation::warp::{
            accumulator::{FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
            fold::{warp_fold_prove_rs, RSEncodingConfig},
        };
        use crate::spartan::r1cs::{R1CSShape, SparseMatEntry};
        use crate::poly::multilinear::MultilinearPoint;

        let dft = Radix2DFTSmallBatch::<F>::default();
        let folding_factor = 2;
        let log_inv_rate = 1; // rate 1/2

        // Simple squaring R1CS: 4 constraints, 8 vars, 2 inputs
        let shape = R1CSShape::new(
            4, 8, 2,
            vec![SparseMatEntry::new(0, 2, F::ONE)],
            vec![SparseMatEntry::new(0, 2, F::ONE)],
            vec![SparseMatEntry::new(0, 3, F::ONE)],
        );
        let num_vars_y = 1usize << shape.num_poly_vars_y(); // 16
        let log_m = 4usize.next_power_of_two().trailing_zeros() as usize; // 2
        let num_witness = num_vars_y - 2;
        let witness_num_vars = num_witness.next_power_of_two().trailing_zeros() as usize;
        let code_len = codeword_size(witness_num_vars, log_inv_rate);
        let log_n = code_len.trailing_zeros() as usize;

        // Build initial accumulator with RS-sized codeword
        let initial_witness = EvaluationsList::new(vec![F::ZERO; 1 << witness_num_vars]);
        let initial_codeword = rs_encode(&initial_witness, folding_factor, log_inv_rate, &dft);

        let mut acc = WarpAccumulator::new(
            WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; log_n],
                eval_claim: F::ZERO,
                pesat_tau: vec![F::ZERO; log_m],
                pesat_x: vec![F::ZERO; 2],
                pesat_target: F::ZERO,
            },
            WarpAccumulatorWitness {
                codeword: initial_codeword,
                witness: vec![F::ZERO; num_witness],
            },
        );

        let initial_cw_len = acc.witness.codeword.as_slice().len();
        let rs_config = RSEncodingConfig::new(folding_factor, log_inv_rate);

        // Run 3 sequential folds with RS encoding
        for step in 0u64..3 {
            let root = step + 2;
            let mut w = vec![F::ZERO; 1 << witness_num_vars];
            w[0] = F::from_u64(root);
            w[1] = F::from_u64(root * root);

            let fresh = FreshInstance {
                public_input: vec![F::ZERO; 2],
                witness: w,
            };

            let tau = vec![F::from_u64(step + 42)];
            let mut ctr = step * 100;
            let result = warp_fold_prove_rs(
                &shape, &[fresh], &acc, F::from_u64(7), &tau, &[], &rs_config, &dft,
                |_| { ctr += 1; F::from_u64(ctr + 500) },
            );

            // CRITICAL: codeword size stays fixed
            assert_eq!(
                result.witness.codeword.as_slice().len(),
                initial_cw_len,
                "RS codeword grew at step {step}! {} vs {}",
                result.witness.codeword.as_slice().len(), initial_cw_len,
            );

            let eval_claim = result.witness.codeword.evaluate_hypercube_base(
                &MultilinearPoint::new(result.instance.eval_point.clone()),
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

    #[test]
    fn merkle_commit_produces_nonzero_root() {
        use p3_baby_bear::Poseidon2BabyBear;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
        use rand::SeedableRng;

        type Perm = Poseidon2BabyBear<16>;
        type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
        const DIGEST: usize = 8;

        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(42));
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);

        let dft = Radix2DFTSmallBatch::<F>::default();
        let folding_factor = 2;
        let log_inv_rate = 1;

        let witness = EvaluationsList::new(
            (0..1u64 << 6).map(|i| F::from_u64(i + 1)).collect(),
        );
        let codeword = rs_encode(&witness, folding_factor, log_inv_rate, &dft);

        let (root, _tree) = merkle_commit_codeword::<
            F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing,
            MyHash, MyCompress, DIGEST,
        >(&codeword, folding_factor, hash.clone(), compress.clone());

        // Root should be non-trivial
        assert!(root.iter().any(|&x| x != F::ZERO), "Merkle root should be non-zero");

        // Same codeword → same root (deterministic)
        let (root2, _) = merkle_commit_codeword::<
            F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing,
            MyHash, MyCompress, DIGEST,
        >(&codeword, folding_factor, hash.clone(), compress.clone());
        assert_eq!(root, root2, "Merkle commit should be deterministic");

        // Different codeword → different root
        let witness2 = EvaluationsList::new(vec![F::from_u64(99); 1 << 6]);
        let codeword2 = rs_encode(&witness2, folding_factor, log_inv_rate, &dft);
        let (root3, _) = merkle_commit_codeword::<
            F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing,
            MyHash, MyCompress, DIGEST,
        >(&codeword2, folding_factor, hash, compress);
        assert_ne!(root, root3, "Different codewords should have different roots");
    }

    #[test]
    fn union_codeword_interleaving() {
        // 4 codewords of length 8
        let codewords: Vec<Vec<F>> = (0..4)
            .map(|i| (0..8).map(|j| F::from_u64(i * 100 + j)).collect())
            .collect();

        let union = build_union_codeword(&codewords);
        assert_eq!(union.len(), 4 * 8);

        // Check column-major layout: union[p*l + i] = codewords[i][p]
        for i in 0..4 {
            for p in 0..8 {
                assert_eq!(
                    union[p * 4 + i],
                    codewords[i][p],
                    "union[{p}*4+{i}] should equal codewords[{i}][{p}]"
                );
            }
        }
    }

    #[test]
    fn union_column_extraction() {
        let codewords: Vec<Vec<F>> = (0..4)
            .map(|i| (0..8).map(|j| F::from_u64(i * 10 + j)).collect())
            .collect();

        let union = build_union_codeword(&codewords);

        // Column at position 3 should be [cw_0[3], cw_1[3], cw_2[3], cw_3[3]]
        let col = union_column_at(&union, 4, 3);
        assert_eq!(col.len(), 4);
        for i in 0..4 {
            assert_eq!(col[i], codewords[i][3]);
        }
    }

    #[test]
    fn union_folding_factor_calculation() {
        assert_eq!(union_folding_factor(2, 1), 2); // l=1: no change
        assert_eq!(union_folding_factor(2, 2), 3); // l=2: +1
        assert_eq!(union_folding_factor(2, 4), 4); // l=4: +2
        assert_eq!(union_folding_factor(2, 8), 5); // l=8: +3
        assert_eq!(union_folding_factor(2, 16), 6); // l=16: +4
    }

    #[test]
    fn union_merkle_commit_deterministic() {
        use p3_baby_bear::Poseidon2BabyBear;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
        use rand::{rngs::SmallRng, SeedableRng};

        type Perm = Poseidon2BabyBear<16>;
        type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
        const DIGEST: usize = 8;

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);

        let dft = Radix2DFTSmallBatch::<F>::default();
        let base_ff = 2;
        let log_inv_rate = 1;
        let l: usize = 4;

        // Create 4 RS-encoded codewords
        let codewords: Vec<Vec<F>> = (0..l)
            .map(|i| {
                let w = EvaluationsList::new(
                    (0..16).map(|j| F::from_u64((i * 100 + j) as u64)).collect(),
                );
                rs_encode(&w, base_ff, log_inv_rate, &dft)
                    .as_slice()
                    .to_vec()
            })
            .collect();

        let union = build_union_codeword(&codewords);

        let (root1, _) = merkle_commit_union_codeword::<
            F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing,
            MyHash, MyCompress, DIGEST,
        >(&union, l, base_ff, hash.clone(), compress.clone());

        let (root2, _) = merkle_commit_union_codeword::<
            F, F, <F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing,
            MyHash, MyCompress, DIGEST,
        >(&union, l, base_ff, hash, compress);

        assert_eq!(root1, root2, "union Merkle commit should be deterministic");
    }

    #[test]
    fn union_shift_query_consistency() {
        // The core soundness property: at any position p, reading from the
        // union codeword and computing the eq-weighted sum should match the
        // folded codeword at that position.
        let l = 4usize;
        let n = 16usize;

        let codewords: Vec<Vec<F>> = (0..l)
            .map(|i| (0..n).map(|j| F::from_u64(i as u64 * 100 + j as u64)).collect())
            .collect();

        let union = build_union_codeword(&codewords);

        // Simulate sumcheck challenges → eq weights
        let challenges = vec![F::from_u64(7), F::from_u64(13)]; // log_l = 2 challenges
        let eq_weights: Vec<F> = (0..l)
            .map(|idx| {
                crate::spartan::encoding::eq_poly_at_index::<F, F>(idx, &challenges)
            })
            .collect();

        // Compute folded codeword: f[p] = Σ eq(γ,i) * cw_i[p]
        let folded: Vec<F> = (0..n)
            .map(|p| {
                (0..l)
                    .map(|i| eq_weights[i] * codewords[i][p])
                    .sum()
            })
            .collect();

        // Verify: at each position, the union column gives the same result
        for p in 0..n {
            let col = union_column_at(&union, l, p);
            let from_union: F = (0..l).map(|i| eq_weights[i] * col[i]).sum();
            assert_eq!(
                from_union, folded[p],
                "shift query at position {p}: union-derived != folded"
            );
        }
    }
}
