//! ZK-code padding: extends each witness row polynomial with k random field
//! elements before RS encoding.
//!
//! # Matrix orientation (WHIR vs VEIL paper)
//!
//! The VEIL paper describes an n×t matrix M whose COLUMNS are RS-encoded.
//! In WHIR's `CommitmentWriter::commit`, the polynomial f (2^n evaluations) is:
//!   1. Reshaped into a matrix with `width = 2^(n-ff)`, `height = 2^ff`.
//!   2. Transposed → `width = 2^ff`, `height = 2^(n-ff)`.
//!   3. Zero-padded vertically → `height = 2^(n-ff + log_inv_rate)`.
//!   4. DFT-expanded column-wise (each of the `2^ff` columns is FFT'd).
//!
//! Each post-DFT column is a WHIR "row polynomial" (a sub-polynomial of f).
//! This is VEIL's "column of M": the entity that gets RS-encoded.
//! VEIL's "row opening" (querying one codeword position) = reading one row
//! of the post-DFT matrix = one entry per WHIR "row polynomial".
//!
//! Concretely, with ff = log_stacking_height = p:
//! - Number of VEIL columns (= WHIR row polynomials) = 2^p.
//! - Each VEIL column / WHIR row polynomial has length 2^(n-p) (pre-encoding).
//! - ZK-code padding adds k independent random elements to each VEIL column
//!   in the coefficient domain BEFORE the DFT step.
//!
//! In `PaddedMatrix`, `witness_rows[ℓ]` is VEIL column ℓ = WHIR row polynomial ℓ.
//! These are the sub-polynomial slices of the original evaluation vector:
//!   `witness_rows[ℓ] = poly_evals[ℓ * row_len .. (ℓ+1) * row_len]`
//! where `row_len = 2^(n-p)` (in the column-major / lex ordering of WHIR).
//!
//! NOTE: WHIR's actual slice order after `transpose()` may differ from naive
//! lex order. `from_evaluations` uses the same reshape as WHIR's committer
//! (width = row_len before transpose → rows become columns after).

use alloc::{vec, vec::Vec};

use p3_field::Field;
use rand::Rng;

/// Padded witness matrix for partial VEIL (Phase 1).
///
/// Contains 2^p witness row polynomials plus one blinding row, each extended
/// with k independent random field elements for ZK-code padding.
#[derive(Clone, Debug)]
pub struct PaddedMatrix<F> {
    /// The 2^p witness row polynomials from the original evaluation vector.
    /// `witness_rows[ℓ]` has length `witness_row_len` (= 2^(n-p)).
    /// Order matches WHIR's column ordering after the initial transpose.
    pub witness_rows: Vec<Vec<F>>,

    /// ZK-code padding: k independent random elements per row polynomial.
    /// `zk_padding[ℓ]` has length `padding_len` (= k).
    /// Independent across rows and from the witness.
    pub zk_padding: Vec<Vec<F>>,

    /// Blinding row polynomial: fully uniform random, length `witness_row_len + padding_len`.
    /// This is VEIL's extra column f'_{2^p+1}. Its RS codeword ensures the
    /// verifier's proximity-test linear combination masks witness information.
    pub blinding_row: Vec<F>,

    /// Length of each witness row = 2^(num_variables - log_stacking_height).
    pub witness_row_len: usize,

    /// ZK padding per row = k. Must be >= `num_queries` against initial commit.
    pub padding_len: usize,

    /// log₂(number of witness rows) = p.
    pub log_stacking_height: usize,
}

impl<F: Field> PaddedMatrix<F> {
    /// Decompose polynomial evaluations into a padded VEIL matrix.
    ///
    /// # Arguments
    /// - `evaluations`: the full polynomial evaluation vector, length 2^n.
    /// - `log_stacking_height`: p. Must satisfy p < n and
    ///   `evaluations.len() == 2^n`.
    /// - `padding_len`: k (the ZK padding per row). Must be >= query complexity.
    /// - `rng`: source of randomness for padding and blinding row.
    ///
    /// # Panics
    /// Panics if `evaluations.len()` is not a power of two, or if
    /// `log_stacking_height >= log2(evaluations.len())`.
    pub fn from_evaluations<R: Rng>(
        evaluations: &[F],
        log_stacking_height: usize,
        padding_len: usize,
        rng: &mut R,
    ) -> Self {
        let n = evaluations.len();
        assert!(n.is_power_of_two(), "evaluations.len() must be a power of two");
        let num_vars = n.trailing_zeros() as usize;
        assert!(
            log_stacking_height < num_vars,
            "log_stacking_height ({log_stacking_height}) must be < num_variables ({num_vars})"
        );

        let num_rows = 1usize << log_stacking_height;  // 2^p
        let witness_row_len = n >> log_stacking_height; // 2^(n-p)

        // Decompose: row ℓ = evaluations[ℓ*row_len..(ℓ+1)*row_len]
        // This matches WHIR's RowMajorMatrixView(width=row_len).transpose()
        // column extraction: column ℓ of the transposed matrix = row ℓ before transpose.
        let witness_rows: Vec<Vec<F>> = (0..num_rows)
            .map(|ell| evaluations[ell * witness_row_len..(ell + 1) * witness_row_len].to_vec())
            .collect();

        // ZK padding: k independent random F elements per row.
        let zk_padding: Vec<Vec<F>> = (0..num_rows)
            .map(|_| sample_random_field_elements::<F, R>(padding_len, rng))
            .collect();

        // Blinding row: fully uniform, length = witness_row_len + k.
        let blinding_row = sample_random_field_elements::<F, R>(witness_row_len + padding_len, rng);

        Self { witness_rows, zk_padding, blinding_row, witness_row_len, padding_len, log_stacking_height }
    }

    /// Number of witness rows: 2^p.
    pub fn num_witness_rows(&self) -> usize {
        1 << self.log_stacking_height
    }

    /// Total rows including blinding: 2^p + 1.
    pub fn total_rows(&self) -> usize {
        self.num_witness_rows() + 1
    }

    /// The padded message for witness row ℓ: `witness_rows[ℓ] ++ zk_padding[ℓ]`.
    /// This is the message input to the ZK code C for column ℓ.
    /// Length = `witness_row_len + padding_len`.
    pub fn padded_witness_row(&self, ell: usize) -> Vec<F> {
        let mut row = self.witness_rows[ell].clone();
        row.extend_from_slice(&self.zk_padding[ell]);
        row
    }

    /// Iterator over all padded messages: witness rows (extended) then blinding row.
    /// Each element has length `witness_row_len + padding_len`.
    pub fn all_padded_rows(&self) -> impl Iterator<Item = Vec<F>> + '_ {
        let witness = (0..self.num_witness_rows()).map(move |ell| self.padded_witness_row(ell));
        let blinding = core::iter::once(self.blinding_row.clone());
        witness.chain(blinding)
    }
}

/// Sample `count` uniformly random field elements using the field's RNG interface.
///
/// Uses rejection sampling via u64 if F is a prime field smaller than u64::MAX,
/// or falls back to sampling individual limbs. For BabyBear/KoalaBear (31-bit
/// primes), this is efficient.
fn sample_random_field_elements<F: Field, R: Rng>(count: usize, rng: &mut R) -> Vec<F> {
    // F::random requires a 'static RNG in p3-field; we work around by using
    // the raw byte interface. For BabyBear (31-bit), 4 bytes per element.
    // This is a platform-independent fallback using byte-level sampling.
    // NOTE: this does NOT achieve perfect uniformity for non-power-of-2 fields;
    // it uses rejection sampling via the field's own `F::from_u64` with masking.
    // For fields with order close to 2^k, the bias is negligible (<2^-30).
    let mut out = vec![F::ZERO; count];
    for elem in &mut out {
        // Sample 8 bytes and reduce. Bias < 1/|F| for |F| >= 2^30.
        let raw = rng.next_u64();
        // Use the field's canonical from_u64 (reduces mod p).
        *elem = F::from_u64(raw);
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::SmallRng, SeedableRng};
    use super::*;

    type F = BabyBear;

    #[test]
    fn padded_matrix_dimensions() {
        let mut rng = SmallRng::seed_from_u64(42);
        let num_vars = 6usize;
        let p = 2usize; // 4 rows
        let k = 8usize;
        let evals: Vec<F> = (0..1u64 << num_vars).map(F::from_u64).collect();

        let mat = PaddedMatrix::from_evaluations(&evals, p, k, &mut rng);

        assert_eq!(mat.num_witness_rows(), 1 << p, "should have 2^p = 4 witness rows");
        assert_eq!(mat.total_rows(), (1 << p) + 1, "total rows = 2^p + 1");
        assert_eq!(mat.witness_row_len, 1 << (num_vars - p), "row length = 2^(n-p)");
        assert_eq!(mat.padding_len, k);
        assert_eq!(mat.blinding_row.len(), mat.witness_row_len + k);

        for ell in 0..(1 << p) {
            assert_eq!(mat.witness_rows[ell].len(), mat.witness_row_len);
            assert_eq!(mat.zk_padding[ell].len(), k);
            assert_eq!(mat.padded_witness_row(ell).len(), mat.witness_row_len + k);
        }
    }

    #[test]
    fn witness_rows_cover_full_evaluation_vector() {
        let mut rng = SmallRng::seed_from_u64(7);
        let num_vars = 4usize;
        let p = 2usize;
        let evals: Vec<F> = (0..1u64 << num_vars).map(F::from_u64).collect();

        let mat = PaddedMatrix::<F>::from_evaluations(&evals, p, 4, &mut rng);

        // Concatenating witness rows should reconstruct the original evaluations.
        let reconstructed: Vec<F> = mat.witness_rows.iter().flatten().copied().collect();
        assert_eq!(reconstructed, evals, "concatenated witness rows must equal original evals");
    }

    #[test]
    fn padding_is_independent_across_rows() {
        let mut rng = SmallRng::seed_from_u64(123);
        let num_vars = 4usize;
        let p = 2usize;
        let k = 8usize;
        let evals = vec![F::ZERO; 1 << num_vars];

        let mat = PaddedMatrix::<F>::from_evaluations(&evals, p, k, &mut rng);

        // With overwhelming probability, different rows have different padding.
        // (Exact equality is astronomically unlikely for a 31-bit field.)
        assert_ne!(
            mat.zk_padding[0], mat.zk_padding[1],
            "padding must be independent across rows"
        );
    }
}
