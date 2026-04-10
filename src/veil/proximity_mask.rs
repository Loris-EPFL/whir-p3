//! Proximity-test masking: zero-knowledge proximity generator (zk-PG) sampling
//! and virtual oracle computation.
//!
//! # What this provides
//!
//! Given a PaddedMatrix with 2^p witness rows and one blinding row, this module:
//! 1. Samples ρ = (ρ_0,...,ρ_{2^p-1}, ρ_blind) from the augmented t-MLE
//!    zero-knowledge proximity generator (VEIL paper §2.4.1, Example 2.21.3).
//!    Guarantees ρ_blind ≠ 0.
//! 2. Computes the combined vector g' = Σ_ℓ ρ_ℓ f'_ℓ + ρ_blind f'_blind.
//! 3. Splits g' into the witness prefix g (length 2^(n-p)) and padding
//!    suffix g₁ (length k), producing the `VirtualOracle`.
//!
//! # What this does NOT do (Phase 2)
//!
//! Resolving C_ρ[i] from column openings of the interleaved VEIL matrix is
//! deferred. That requires changes to the WHIR query-opening layer so the
//! verifier can check: `C_ρ[i] = Σ_ℓ ρ_ℓ C_{ℓ,i} - (C(0,g₁))[i]`. In Phase 1,
//! the inner WHIR runs on g directly (committed separately), not via C_ρ.

use alloc::{vec, vec::Vec};

use p3_challenger::FieldChallenger;
use p3_field::Field;

use crate::veil::zk_code::PaddedMatrix;

/// A sample from the augmented t-MLE zero-knowledge proximity generator.
///
/// ρ = (eq(0,z₀), ..., eq(2^p-1, z₀), ρ_blind) ∈ F^{2^p+1}
/// where z₀ ∈ F^p is sampled from the Fiat-Shamir challenger and
/// ρ_blind ∈ F^× is sampled separately (resampled if zero).
///
/// Linear bias: ε^•_{PG} = p / |F|. Negligible for 31-bit fields.
#[derive(Clone, Debug)]
pub struct ZkProximitySample<F> {
    /// ρ_ℓ = eq(ℓ, z₀) for ℓ ∈ {0,1}^p. Length 2^p.
    pub witness_coeffs: Vec<F>,

    /// ρ_blind ∈ F^×. Guaranteed nonzero by construction.
    pub blinding_coeff: F,
}

impl<F: Field> ZkProximitySample<F> {
    /// Sample from a Fiat-Shamir challenger.
    ///
    /// Squeezes p field elements z₀ ∈ F^p, computes the eq polynomial,
    /// then squeezes ρ_blind (resampling if zero).
    ///
    /// # Errors
    /// Returns `VeilError::ZeroBlinderCoeff` if ρ_blind is zero after 64
    /// attempts (would indicate a catastrophic Fiat-Shamir failure).
    pub fn from_challenger<Challenger>(
        log_stacking_height: usize,
        challenger: &mut Challenger,
    ) -> Result<Self, crate::veil::VeilError>
    where
        Challenger: FieldChallenger<F>,
    {
        let p = log_stacking_height;
        let num_rows = 1usize << p;

        // Sample z₀ ∈ F^p from the challenger.
        let z0: Vec<F> = (0..p).map(|_| challenger.sample_algebra_element()).collect();

        // Compute eq(ℓ, z₀) for each ℓ ∈ {0,...,2^p-1}.
        let witness_coeffs = compute_eq_poly(&z0, num_rows);

        // Sample ρ_blind from the challenger; resample if zero.
        let blinding_coeff = sample_nonzero_coeff(challenger)?;

        Ok(Self { witness_coeffs, blinding_coeff })
    }

    /// Total number of coefficients: 2^p + 1.
    pub fn len(&self) -> usize {
        self.witness_coeffs.len() + 1
    }
}

/// The combined vector g' and its decomposition into witness prefix g and
/// padding suffix g₁.
///
/// g' = Σ_ℓ ρ_ℓ f'_ℓ + ρ_blind f'_blind
/// where f'_ℓ = [witness_rows[ℓ] | zk_padding[ℓ]] (padded witness row ℓ)
/// and   f'_blind = blinding_row.
///
/// Split: g = g'[..witness_row_len], g₁ = g'[witness_row_len..].
#[derive(Clone, Debug)]
pub struct VirtualOracle<F> {
    /// Witness prefix: g = Σ_ℓ ρ_ℓ witness_rows[ℓ].
    /// Length = 2^(n-p). This is the polynomial the inner WHIR proves.
    pub witness_prefix: Vec<F>,

    /// Padding suffix: g₁ = Σ_ℓ ρ_ℓ zk_padding[ℓ] + ρ_blind blinding_padding.
    /// Length = k. Sent to the verifier in the clear (VEIL paper §4.2, Fig 9).
    /// Needed for verifier to compute (C(0, g₁))[i] at each query position.
    pub padding_suffix: Vec<F>,
}

impl<F: Field> VirtualOracle<F> {
    /// Compute g' from the padded matrix and proximity sample.
    pub fn compute(matrix: &PaddedMatrix<F>, sample: &ZkProximitySample<F>) -> Self {
        let row_len = matrix.witness_row_len;
        let k = matrix.padding_len;
        let num_rows = matrix.num_witness_rows();

        // Accumulate witness prefix: g = Σ_ℓ ρ_ℓ witness_rows[ℓ]
        let mut witness_prefix = vec![F::ZERO; row_len];
        for ell in 0..num_rows {
            let rho = sample.witness_coeffs[ell];
            for (g, &w) in witness_prefix.iter_mut().zip(matrix.witness_rows[ell].iter()) {
                *g += rho * w;
            }
        }
        // Add blinding row witness part: ρ_blind * blinding_row[..row_len]
        let rho_blind = sample.blinding_coeff;
        for (g, &b) in witness_prefix.iter_mut().zip(matrix.blinding_row[..row_len].iter()) {
            *g += rho_blind * b;
        }

        // Accumulate padding suffix: g₁ = Σ_ℓ ρ_ℓ zk_padding[ℓ] + ρ_blind blinding_row[row_len..]
        let mut padding_suffix = vec![F::ZERO; k];
        for ell in 0..num_rows {
            let rho = sample.witness_coeffs[ell];
            for (g1, &p) in padding_suffix.iter_mut().zip(matrix.zk_padding[ell].iter()) {
                *g1 += rho * p;
            }
        }
        for (g1, &b) in padding_suffix.iter_mut().zip(matrix.blinding_row[row_len..].iter()) {
            *g1 += rho_blind * b;
        }

        Self { witness_prefix, padding_suffix }
    }
}

/// Compute eq(ℓ, z₀) for all ℓ ∈ {0,...,n-1} using the standard MLE eq formula.
///
/// eq(x, z) = ∏ᵢ (xᵢ zᵢ + (1-xᵢ)(1-zᵢ))
///
/// Uses the standard dynamic programming: start from [1], and for each
/// variable bit multiply by either (1-zᵢ) or zᵢ depending on ℓ's i-th bit.
fn compute_eq_poly<F: Field>(z: &[F], num_rows: usize) -> Vec<F> {
    let p = z.len();
    assert_eq!(num_rows, 1 << p);

    let mut eq = vec![F::ZERO; num_rows];
    eq[0] = F::ONE;

    // Fill eq values using the split rule:
    // eq[2i+0] *= (1 - z[bit])
    // eq[2i+1] *= z[bit]
    for (bit, &z_i) in z.iter().enumerate() {
        let half = 1usize << bit;
        // Process in reverse to avoid overwriting values still needed.
        // For each existing entry j, expand by variable `bit`:
        //   eq[j | (1 << bit)] = eq[j] * z_i     (bit `bit` of ℓ = 1)
        //   eq[j]              = eq[j] * (1 - z_i) (bit `bit` of ℓ = 0)
        // Using j | (1 << bit) rather than 2*j+1 places the bit at the
        // correct position in the LSB-first index (matching eq_poly_at_index).
        for j in (0..half).rev() {
            let v = eq[j];
            eq[j | (1 << bit)] = v * z_i;
            eq[j] = v * (F::ONE - z_i);
        }
    }

    eq
}

/// Sample a nonzero field element from the Fiat-Shamir challenger.
///
/// For a 31-bit prime field, the probability of sampling zero is ~2^{-31}.
/// We attempt up to 64 times before returning an error.
fn sample_nonzero_coeff<F: Field, Challenger: FieldChallenger<F>>(
    challenger: &mut Challenger,
) -> Result<F, crate::veil::VeilError> {
    for _ in 0..64 {
        let v: F = challenger.sample_algebra_element();
        if v != F::ZERO {
            return Ok(v);
        }
    }
    Err(crate::veil::VeilError::ZeroBlinderCoeff)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_baby_bear::Poseidon2BabyBear;
    use p3_field::{Field, PrimeCharacteristicRing};
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    fn make_challenger() -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        MyChallenger::new(perm)
    }

    #[test]
    fn blinding_coeff_is_nonzero() {
        let mut challenger = make_challenger();
        let sample = ZkProximitySample::<F>::from_challenger(2, &mut challenger).unwrap();
        assert_ne!(sample.blinding_coeff, F::ZERO, "blinding coeff must be nonzero");
    }

    #[test]
    fn witness_coeffs_have_correct_length() {
        let p = 3usize;
        let mut challenger = make_challenger();
        let sample = ZkProximitySample::<F>::from_challenger(p, &mut challenger).unwrap();
        assert_eq!(sample.witness_coeffs.len(), 1 << p);
    }

    #[test]
    fn eq_poly_sums_to_one() {
        // Sum of eq(ℓ, z) over all ℓ must equal 1 for any z.
        let z = vec![F::from_u64(3), F::from_u64(7)];
        let eq = compute_eq_poly(&z, 4);
        let sum: F = eq.iter().copied().sum();
        assert_eq!(sum, F::ONE, "eq poly must sum to 1");
    }

    #[test]
    fn eq_poly_at_basis_vectors() {
        // eq(0, e_0) = 1 (where e_0 = [1, 0, ...]) — standard basis vector
        let z = vec![F::ONE, F::ZERO];
        let eq = compute_eq_poly(&z, 4);
        // z = (1, 0): eq(ℓ, z) = 1 iff ℓ = 01 (binary, LSB first) = 1
        assert_eq!(eq[1], F::ONE);
        assert_eq!(eq[0] + eq[2] + eq[3], F::ZERO);
    }

    #[test]
    fn virtual_oracle_witness_prefix_is_linear_combination() {
        let mut rng = SmallRng::seed_from_u64(42);
        let num_vars = 4usize;
        let p = 2usize;
        let k = 4usize;
        let evals: Vec<F> = (0..1u64 << num_vars).map(F::from_u64).collect();

        let mat = crate::veil::zk_code::PaddedMatrix::from_evaluations(&evals, p, k, &mut rng);

        // Use a fixed sample for verification.
        let rho = vec![F::from_u64(2), F::from_u64(3), F::from_u64(5), F::from_u64(7)];
        let rho_blind = F::from_u64(11);
        let sample = ZkProximitySample { witness_coeffs: rho.clone(), blinding_coeff: rho_blind };

        let oracle = VirtualOracle::compute(&mat, &sample);

        // Manually compute expected witness prefix.
        let row_len = mat.witness_row_len;
        let mut expected = vec![F::ZERO; row_len];
        for ell in 0..4 {
            for (e, &w) in expected.iter_mut().zip(mat.witness_rows[ell].iter()) {
                *e += rho[ell] * w;
            }
        }
        for (e, &b) in expected.iter_mut().zip(mat.blinding_row[..row_len].iter()) {
            *e += rho_blind * b;
        }

        assert_eq!(oracle.witness_prefix, expected, "witness prefix must be the RLC");
    }

    #[test]
    fn virtual_oracle_padding_suffix_is_linear_combination() {
        let mut rng = SmallRng::seed_from_u64(42);
        let num_vars = 4usize;
        let p = 2usize;
        let k = 4usize;
        let evals = vec![F::ZERO; 1 << num_vars];

        let mat = crate::veil::zk_code::PaddedMatrix::from_evaluations(&evals, p, k, &mut rng);

        let rho = vec![F::from_u64(2), F::from_u64(3), F::from_u64(5), F::from_u64(7)];
        let rho_blind = F::from_u64(11);
        let sample = ZkProximitySample { witness_coeffs: rho.clone(), blinding_coeff: rho_blind };

        let oracle = VirtualOracle::compute(&mat, &sample);

        let row_len = mat.witness_row_len;
        let mut expected = vec![F::ZERO; k];
        for ell in 0..4 {
            for (e, &p_val) in expected.iter_mut().zip(mat.zk_padding[ell].iter()) {
                *e += rho[ell] * p_val;
            }
        }
        for (e, &b) in expected.iter_mut().zip(mat.blinding_row[row_len..].iter()) {
            *e += rho_blind * b;
        }

        assert_eq!(oracle.padding_suffix, expected, "padding suffix must be the RLC of padding columns");
    }
}
