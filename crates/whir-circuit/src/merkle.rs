//! In-circuit Poseidon2-based Merkle verification gadgets.
//!
//! Provides two gadgets used by the recursive fold verifier to bind
//! prover-claimed shift-query values to a stored commitment root:
//!
//! - [`poseidon2_compress_circuit`] — 2-to-1 compression via a single
//!   Poseidon2 permutation over a width-16 state (mirrors the native
//!   `p3_symmetric::TruncatedPermutation<Perm, 2, 8, 16>`).
//!
//! - [`merkle_verify_path_circuit`] — hashes a leaf row, climbs a Merkle
//!   path using the compression gadget, and enforces equality with the
//!   expected root.
//!
//! The leaf-hash path assumes `row_width <= 8` (one absorption block of
//! `PaddingFreeSponge<Perm, 16, 8, 8>`). This covers the common case in
//! the WARP pipeline where the RS folding factor is 2 (row width 4).
//! Larger rows will require chunked absorption — noted as a TODO at the
//! relevant site.

use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use crate::builder::{CircuitBuilder, LinearCombination, Var};
use crate::poseidon2::{Poseidon2CircuitConfig, poseidon2_permute_circuit};

/// Poseidon2 2-to-1 compression over a width-16 state.
///
/// Concatenates `left` and `right` into a 16-element state, applies the
/// full permutation, and returns the first 8 output elements — matching
/// the behaviour of `p3_symmetric::TruncatedPermutation<Perm, 2, 8, 16>`.
///
/// Cost: one `poseidon2_permute_circuit` invocation (~340 constraints
/// at WIDTH=16, sbox_degree=3).
pub fn poseidon2_compress_circuit<F, L, P, const WIDTH: usize>(
    builder: &mut CircuitBuilder<F>,
    config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    left_vars: &[Var; 8],
    left_vals: &[F; 8],
    right_vars: &[Var; 8],
    right_vals: &[F; 8],
) -> ([Var; 8], [F; 8])
where
    F: Field + PrimeCharacteristicRing,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    assert_eq!(
        WIDTH, 16,
        "compress_circuit currently supports WIDTH=16 only"
    );

    // Build a width-WIDTH state = left || right.
    let mut state_vars = [left_vars[0]; WIDTH];
    let mut state_vals = [F::ZERO; WIDTH];
    for i in 0..8 {
        state_vars[i] = left_vars[i];
        state_vars[i + 8] = right_vars[i];
        state_vals[i] = left_vals[i];
        state_vals[i + 8] = right_vals[i];
    }

    let (out_vars, out_vals) = poseidon2_permute_circuit::<F, L, P, WIDTH>(
        builder,
        config,
        perm,
        &state_vars,
        &state_vals,
    );

    // Truncate to first 8.
    let mut compressed_vars = [out_vars[0]; 8];
    let mut compressed_vals = [F::ZERO; 8];
    for i in 0..8 {
        compressed_vars[i] = out_vars[i];
        compressed_vals[i] = out_vals[i];
    }
    (compressed_vars, compressed_vals)
}

/// Hash a leaf row using Poseidon2 as a `PaddingFreeSponge<Perm, 16, 8, 8>`.
///
/// For row sizes `row_len <= 8` this is a single absorption: the row is
/// placed into the first `row_len` positions of a width-16 state, the
/// remaining positions are zero, Poseidon2 permutes, and the first 8
/// elements are returned.
///
/// For `row_len > 8`, TODO: multiple absorption blocks would be needed
/// (not yet implemented; the WARP pipeline with folding_factor=2 hits
/// row_len = 4 which fits in one block).
pub fn poseidon2_hash_leaf_circuit<F, L, P, const WIDTH: usize>(
    builder: &mut CircuitBuilder<F>,
    config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    row_vars: &[Var],
    row_vals: &[F],
) -> ([Var; 8], [F; 8])
where
    F: Field + PrimeCharacteristicRing,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    assert_eq!(
        WIDTH, 16,
        "hash_leaf_circuit currently supports WIDTH=16 only"
    );
    assert!(
        row_vars.len() <= 8,
        "hash_leaf_circuit: row_len {} > 8; multi-block absorption not implemented",
        row_vars.len()
    );
    assert_eq!(row_vars.len(), row_vals.len());

    // Width-16 state, first `row_len` = row values, rest = zero.
    // (The `PaddingFreeSponge` treats the unfilled tail as zero in the
    // initial state; no length encoding is appended in the Plonky3
    // implementation used by this repo.)
    let mut state_vars = [builder.alloc_constant(F::ZERO); WIDTH];
    let mut state_vals = [F::ZERO; WIDTH];
    for i in 0..row_vars.len() {
        state_vars[i] = row_vars[i];
        state_vals[i] = row_vals[i];
    }

    let (out_vars, out_vals) = poseidon2_permute_circuit::<F, L, P, WIDTH>(
        builder,
        config,
        perm,
        &state_vars,
        &state_vals,
    );

    let mut digest_vars = [out_vars[0]; 8];
    let mut digest_vals = [F::ZERO; 8];
    for i in 0..8 {
        digest_vars[i] = out_vars[i];
        digest_vals[i] = out_vals[i];
    }
    (digest_vars, digest_vals)
}

/// Verify a Merkle opening inside the circuit.
///
/// Given:
/// - a leaf row (`row_vars`, `row_vals`) of length ≤ 8,
/// - an authentication path (`path_vars`, `path_vals`, one 8-element
///   sibling digest per level),
/// - a position (`position` — the plain `usize`; the bit pattern decides
///   whether the sibling goes on the left or the right at each level),
/// - the expected root (`root_vars`, `root_vals`),
///
/// emits constraints that accept iff hashing the leaf and climbing the
/// path via `poseidon2_compress_circuit` produces `expected_root`.
///
/// The `position` is **public data** (it was sampled via Fiat-Shamir on
/// the verifier side, so it is already known to the circuit's caller).
/// Consequently, the left/right branching at each level is resolved at
/// circuit-synthesis time — no bit-decomposition gadget is needed.
pub fn merkle_verify_path_circuit<F, L, P, const WIDTH: usize>(
    builder: &mut CircuitBuilder<F>,
    config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    row_vars: &[Var],
    row_vals: &[F],
    position: usize,
    path_vars: &[[Var; 8]],
    path_vals: &[[F; 8]],
    root_vars: &[Var; 8],
    root_vals: &[F; 8],
) where
    F: Field + PrimeCharacteristicRing,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    assert_eq!(path_vars.len(), path_vals.len());

    // Step 1: hash the leaf row.
    let (mut cur_vars, mut cur_vals) =
        poseidon2_hash_leaf_circuit::<F, L, P, WIDTH>(builder, config, perm, row_vars, row_vals);

    // Step 2: climb the path.
    for (level, (sibling_vars, sibling_vals)) in path_vars.iter().zip(path_vals.iter()).enumerate()
    {
        let bit = (position >> level) & 1;
        if bit == 0 {
            // current is the left child
            let (next_vars, next_vals) = poseidon2_compress_circuit::<F, L, P, WIDTH>(
                builder,
                config,
                perm,
                &cur_vars,
                &cur_vals,
                sibling_vars,
                sibling_vals,
            );
            cur_vars = next_vars;
            cur_vals = next_vals;
        } else {
            // current is the right child
            let (next_vars, next_vals) = poseidon2_compress_circuit::<F, L, P, WIDTH>(
                builder,
                config,
                perm,
                sibling_vars,
                sibling_vals,
                &cur_vars,
                &cur_vals,
            );
            cur_vars = next_vars;
            cur_vals = next_vals;
        }
    }

    // Step 3: assert the derived root equals the expected root.
    for i in 0..8 {
        assert_eq!(
            cur_vals[i], root_vals[i],
            "merkle_verify_path_circuit: derived root[{i}] does not match expected"
        );
        builder.enforce(
            LinearCombination::from_var(cur_vars[i]),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(root_vars[i]),
        );
    }
}

#[cfg(test)]
mod tests {
    //! Round-trip tests: native Merkle compression + path computation
    //! must match the in-circuit gadget.

    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};
    use p3_symmetric::{PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation};
    use rand::{SeedableRng, rngs::SmallRng};

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
    type NativeHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type NativeCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    fn build_config() -> (Perm, Poseidon2CircuitConfig<F, 16>) {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let (rf, rp) = p3_poseidon2::poseidon2_round_numbers_128::<F>(16, 3)
            .expect("unsupported Poseidon2 parameters");
        let cfg =
            Poseidon2CircuitConfig::<F, 16>::from_rng(rf, rp, 3, &mut SmallRng::seed_from_u64(99));
        (perm, cfg)
    }

    #[test]
    fn compress_circuit_matches_native() {
        let (perm, cfg) = build_config();
        let compress = NativeCompress::new(perm.clone());

        let left: [F; 8] = core::array::from_fn(|i| F::from_u64(1 + i as u64));
        let right: [F; 8] = core::array::from_fn(|i| F::from_u64(100 + i as u64));

        let expected = compress.compress([left, right]);

        let mut builder = CircuitBuilder::<F>::new();
        let left_vars: [Var; 8] = core::array::from_fn(|i| builder.alloc_witness(left[i]));
        let right_vars: [Var; 8] = core::array::from_fn(|i| builder.alloc_witness(right[i]));
        let (_out_vars, out_vals) =
            poseidon2_compress_circuit::<F, GenericPoseidon2LinearLayersKoalaBear, _, 16>(
                &mut builder,
                &cfg,
                &perm,
                &left_vars,
                &left,
                &right_vars,
                &right,
            );

        for i in 0..8 {
            assert_eq!(out_vals[i], expected[i], "compress mismatch at digest[{i}]");
        }

        let (_shape, instance) = builder.build();
        assert!(instance.verify(), "compress circuit must satisfy R1CS");
    }

    #[test]
    fn leaf_hash_circuit_matches_native() {
        use p3_symmetric::CryptographicHasher;
        let (perm, cfg) = build_config();
        let hasher = NativeHash::new(perm.clone());

        // Small row (row_len = 4, fits in one absorption block).
        let row: [F; 4] = core::array::from_fn(|i| F::from_u64(10 + i as u64));
        let expected = hasher.hash_slice(&row);

        let mut builder = CircuitBuilder::<F>::new();
        let row_vars: alloc::vec::Vec<Var> =
            row.iter().map(|&v| builder.alloc_witness(v)).collect();
        let (_out_vars, out_vals) = poseidon2_hash_leaf_circuit::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            16,
        >(&mut builder, &cfg, &perm, &row_vars, &row);

        for i in 0..8 {
            assert_eq!(
                out_vals[i], expected[i],
                "leaf hash mismatch at digest[{i}]"
            );
        }

        let (_shape, instance) = builder.build();
        assert!(instance.verify(), "leaf hash circuit must satisfy R1CS");
    }

    #[test]
    fn merkle_verify_path_circuit_accepts_valid_opening() {
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_merkle_tree::MerkleTreeMmcs;

        let (perm, cfg) = build_config();
        let hasher = NativeHash::new(perm.clone());
        let compress = NativeCompress::new(perm.clone());

        // Build a small tree over 4 rows of width 4 (= 16 leaves total).
        let rows: alloc::vec::Vec<F> = (0..16).map(|i| F::from_u64(i as u64 + 1)).collect();
        let matrix = RowMajorMatrix::new(rows.clone(), 4);
        let mmcs: MerkleTreeMmcs<_, _, _, _, 8> =
            MerkleTreeMmcs::<F, F, _, _, 8>::new(hasher.clone(), compress.clone());
        let (root_hash, tree) = mmcs.commit(alloc::vec![matrix.clone()]);
        let root_arr: [F; 8] = root_hash.into();

        let position: usize = 2;
        let row_at_pos = &rows[position * 4..position * 4 + 4];

        let opening = mmcs.open_batch(position, &tree);
        let (opened, proof) = opening.unpack();
        let leaf_row = opened.into_iter().next().unwrap();
        assert_eq!(leaf_row.as_slice(), row_at_pos);

        // Convert the native path (Vec<[F; 8]>) into the in-circuit form.
        let path_vals: alloc::vec::Vec<[F; 8]> = proof.clone();

        // Wire into the circuit.
        let mut builder = CircuitBuilder::<F>::new();
        let row_vars: alloc::vec::Vec<Var> = row_at_pos
            .iter()
            .map(|&v| builder.alloc_witness(v))
            .collect();
        let path_vars: alloc::vec::Vec<[Var; 8]> = path_vals
            .iter()
            .map(|sib| core::array::from_fn(|i| builder.alloc_witness(sib[i])))
            .collect();
        let root_vars: [Var; 8] = core::array::from_fn(|i| builder.alloc_witness(root_arr[i]));

        merkle_verify_path_circuit::<F, GenericPoseidon2LinearLayersKoalaBear, _, 16>(
            &mut builder,
            &cfg,
            &perm,
            &row_vars,
            row_at_pos,
            position,
            &path_vars,
            &path_vals,
            &root_vars,
            &root_arr,
        );

        let (_shape, instance) = builder.build();
        assert!(
            instance.verify(),
            "honest Merkle-verify circuit must satisfy R1CS"
        );
    }

    #[test]
    #[should_panic(expected = "merkle_verify_path_circuit: derived root")]
    fn merkle_verify_path_circuit_rejects_wrong_root() {
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_merkle_tree::MerkleTreeMmcs;

        let (perm, cfg) = build_config();
        let hasher = NativeHash::new(perm.clone());
        let compress = NativeCompress::new(perm.clone());

        let rows: alloc::vec::Vec<F> = (0..16).map(|i| F::from_u64(i as u64 + 1)).collect();
        let matrix = RowMajorMatrix::new(rows.clone(), 4);
        let mmcs: MerkleTreeMmcs<_, _, _, _, 8> =
            MerkleTreeMmcs::<F, F, _, _, 8>::new(hasher.clone(), compress.clone());
        let (root_hash, tree) = mmcs.commit(alloc::vec![matrix.clone()]);
        let mut root_arr: [F; 8] = root_hash.into();

        // Tamper the expected root.
        root_arr[0] += F::ONE;

        let position: usize = 2;
        let row_at_pos = &rows[position * 4..position * 4 + 4];
        let opening = mmcs.open_batch(position, &tree);
        let (_opened, proof) = opening.unpack();
        let path_vals: alloc::vec::Vec<[F; 8]> = proof;

        let mut builder = CircuitBuilder::<F>::new();
        let row_vars: alloc::vec::Vec<Var> = row_at_pos
            .iter()
            .map(|&v| builder.alloc_witness(v))
            .collect();
        let path_vars: alloc::vec::Vec<[Var; 8]> = path_vals
            .iter()
            .map(|sib| core::array::from_fn(|i| builder.alloc_witness(sib[i])))
            .collect();
        let root_vars: [Var; 8] = core::array::from_fn(|i| builder.alloc_witness(root_arr[i]));

        // This call is expected to panic because cur_vals != root_vals at
        // the derive-equals-expected assertion.
        merkle_verify_path_circuit::<F, GenericPoseidon2LinearLayersKoalaBear, _, 16>(
            &mut builder,
            &cfg,
            &perm,
            &row_vars,
            row_at_pos,
            position,
            &path_vars,
            &path_vals,
            &root_vars,
            &root_arr,
        );
    }
}
