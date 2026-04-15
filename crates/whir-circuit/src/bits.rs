//! Bit decomposition gadget for R1CS circuits.
//!
//! Decomposes a field element into its binary representation and constrains
//! each bit to be 0 or 1. Used for `sample_bits` verification in the
//! recursive accumulation verifier.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};

use super::builder::{CircuitBuilder, LinearCombination, Var};

/// Decompose a field element into `num_bits` low bits as R1CS constraints.
///
/// Each bit is constrained to be boolean: `b_i * (1 - b_i) = 0`.
/// The full reconstruction is constrained: `Σ 2^i * b_i + remainder * 2^num_bits = val`.
pub fn decompose_low_bits<F: Field + PrimeField64 + PrimeCharacteristicRing>(
    builder: &mut CircuitBuilder<F>,
    var: Var,
    val: F,
    num_bits: usize,
) -> Vec<Var> {
    let val_u64 = val.as_canonical_u64();
    let two = F::TWO;

    let mut bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let bit_val = if (val_u64 >> i) & 1 == 1 {
            F::ONE
        } else {
            F::ZERO
        };
        let bit = builder.alloc_witness(bit_val);

        // Boolean constraint: bit * (1 - bit) = 0
        builder.enforce(
            LinearCombination::from_var(bit),
            LinearCombination::from_constant(F::ONE) - LinearCombination::from_var(bit),
            LinearCombination::from_constant(F::ZERO),
        );

        bits.push(bit);
    }

    // Reconstruction constraint: Σ 2^i * bits[i] + remainder * 2^num_bits = val
    let low_bits_val = val_u64 & ((1u64 << num_bits) - 1);
    let remainder_val = F::from_u64((val_u64 - low_bits_val) >> num_bits);

    let remainder = builder.alloc_witness(remainder_val);

    let mut reconstruction = LinearCombination::from_constant(F::ZERO);
    let mut power = F::ONE;
    for &bit in &bits {
        reconstruction.add_term(bit, power);
        power *= two;
    }
    // power is now 2^num_bits
    reconstruction.add_term(remainder, power);

    builder.enforce(
        reconstruction,
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(var),
    );

    bits
}

/// Extract the low `num_bits` of a field element as a `usize`.
pub fn bits_to_index<F: PrimeField64>(val: F, num_bits: usize) -> usize {
    (val.as_canonical_u64() as usize) & ((1 << num_bits) - 1)
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    type F = KoalaBear;

    #[test]
    fn bit_decomposition_round_trip() {
        let val = F::from_u64(42); // 42 = 0b101010
        let mut builder = CircuitBuilder::<F>::new();
        let var = builder.alloc_witness(val);
        let bits = decompose_low_bits(&mut builder, var, val, 6);

        assert_eq!(bits.len(), 6);

        let (_, instance) = builder.build();
        assert!(instance.verify(), "bit decomposition R1CS not satisfied");
    }

    #[test]
    fn bits_to_index_matches_canonical() {
        for val_u64 in [0u64, 1, 7, 42, 255, 1023] {
            let val = F::from_u64(val_u64);
            let index = bits_to_index(val, 10);
            let expected = (val.as_canonical_u64() as usize) & ((1 << 10) - 1);
            assert_eq!(index, expected, "bits_to_index mismatch for {val_u64}");
        }
    }

    #[test]
    fn bit_decomposition_large_value() {
        let val = F::from_u64(1000); // 1000 = 0b1111101000
        let mut builder = CircuitBuilder::<F>::new();
        let var = builder.alloc_witness(val);
        let bits = decompose_low_bits(&mut builder, var, val, 4);

        assert_eq!(bits.len(), 4);
        assert_eq!(bits_to_index(val, 4), 8); // low 4 bits of 1000

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }
}
