//! Packed sumcheck prover over small fields.
//!
//! Implements the packed sumcheck protocol from "Packed Sumcheck over Small
//! Fields" which eliminates extension field arithmetic by using k independent
//! base-field challenges per round instead of one extension-field challenge.
//!
//! # Parameters
//!
//! - `k`: packing parameter. k=4 gives ~106 bits of security over KoalaBear for degree 3.
//! - `d`: degree of the sumcheck polynomial (d=2 for quadratic, d=3 for Spartan Phase 1).
//! - Evaluation set `W = {0, 1, ..., 2k-1}` used for Lagrange interpolation.
//! - Round polynomial `F(r)` has degree `d*(2k-1)`.
//!
//! # Security
//!
//! Per-round soundness error: `((2k-1)*d / |F|)^k`.
//! For KoalaBear (p ~ 2^31), k=4, d=3: ~2^{-106} per round.

use alloc::{vec, vec::Vec};

use p3_field::Field;

/// Compute Lagrange basis polynomial L_j(r) for the evaluation set {0, 1, ..., n-1}.
///
/// L_j(r) = prod_{m=0, m!=j}^{n-1} (r - m) / (j - m)
///
/// Returns all n basis values [L_0(r), L_1(r), ..., L_{n-1}(r)].
pub fn lagrange_basis_integer_set<F: Field>(n: usize, r: F) -> Vec<F> {
    assert!(n > 0);

    // Precompute barycentric weights: w_j = 1 / prod_{m != j} (j - m)
    // For integer set {0,...,n-1}: w_j = (-1)^{n-1-j} / (j! * (n-1-j)!)
    let mut bary_weights = vec![F::ZERO; n];
    for j in 0..n {
        let mut w = F::ONE;
        for m in 0..n {
            if m != j {
                w *= F::from_u64(j as u64) - F::from_u64(m as u64);
            }
        }
        bary_weights[j] = w.inverse();
    }

    // Compute the "numerator" polynomial: N(r) = prod_{m=0}^{n-1} (r - m)
    let mut numer = F::ONE;
    for m in 0..n {
        numer *= r - F::from_u64(m as u64);
    }

    // L_j(r) = w_j * N(r) / (r - j)
    // Handle the case where r is one of the evaluation points (r - j = 0).
    let mut result = vec![F::ZERO; n];
    let mut is_eval_point = None;
    for j in 0..n {
        let diff = r - F::from_u64(j as u64);
        if diff == F::ZERO {
            is_eval_point = Some(j);
            break;
        }
    }

    if let Some(idx) = is_eval_point {
        // r is exactly one of the evaluation points
        result[idx] = F::ONE;
    } else {
        for j in 0..n {
            result[j] = bary_weights[j] * numer * (r - F::from_u64(j as u64)).inverse();
        }
    }

    result
}

/// Forward difference extrapolation.
///
/// Given evaluations f(0), f(1), ..., f(n-1) of a polynomial of degree < n,
/// compute f(n), f(n+1), ..., f(n+m-1) using only additions.
///
/// The forward difference table Δ^i f(j) = Δ^{i-1} f(j+1) - Δ^{i-1} f(j)
/// has the property that for degree < n polynomials, Δ^{n-1} f(j) is constant.
///
/// Cost: O(n^2) additions to initialize + O(n*m) additions to extrapolate.
pub fn forward_difference_extrapolate<F: Field>(known_evals: &[F], num_extra: usize) -> Vec<F> {
    let n = known_evals.len();
    if num_extra == 0 {
        return vec![];
    }

    // Phase 1: Build the "diagonal" of the forward difference table.
    // D[i] = Δ^i f(n-1-i) for i = 0, ..., n-1
    // We compute this in-place using the difference table.
    let mut d = known_evals.to_vec();

    // Build differences bottom-up: after pass i, d[j] = Δ^i f(j) for j >= 0
    for i in 1..n {
        for j in (i..n).rev() {
            d[j] = d[j] - d[j - 1];
        }
    }
    // Now d[i] = Δ^i f(0) for i = 0, ..., n-1
    // But we need the diagonal: D[i] = Δ^i f(n-1-i)
    // We need to reconstruct. Let's use a different approach.

    // Compute the diagonal D[i] = Δ^i f(n-1-i) via row-by-row construction.
    // Row i of the difference table has entries delta_i[j] = Δ^i f(j) for j = 0..n-1-i.
    let mut diag = vec![F::ZERO; n];
    let mut prev_row = known_evals.to_vec();
    diag[0] = prev_row[n - 1]; // D[0] = Δ^0 f(n-1) = f(n-1)
    for i in 1..n {
        let cur_row: Vec<F> = prev_row.windows(2).map(|w| w[1] - w[0]).collect();
        diag[i] = cur_row[n - 1 - i]; // D[i] = Δ^i f(n-1-i)
        prev_row = cur_row;
    }

    // Phase 2: Extrapolate using the recurrence:
    // f(n-1+t) for t = 1, 2, ..., num_extra
    // Update rule: D[j] += D[j+1] for j = n-2, n-3, ..., 0
    // Then f(n-1+t) = D[0]
    let mut result = Vec::with_capacity(num_extra);
    for _t in 1..=num_extra {
        for j in (0..n - 1).rev() {
            diag[j] = diag[j] + diag[j + 1];
        }
        result.push(diag[0]);
    }

    result
}

/// Compute one round of the packed sumcheck.
///
/// Given 2k sub-tables (each representing a "slice" of d multilinear polynomials),
/// computes the round polynomial F(r) of degree d*(2k-1) and returns its evaluations
/// at points {0, 1, ..., d*(2k-1)}.
///
/// # Arguments
/// - `sub_tables`: 2k groups of d sub-polynomial evaluations, each of size `half_size`.
///   `sub_tables[j][s][x]` = evaluation of the s-th factor of the j-th sub-instance at point x.
/// - `d`: degree of the product polynomial
/// - `k`: packing parameter
///
/// # Returns
/// Evaluations of F(r) at points {0, 1, ..., d*(2k-1)}.
/// Also returns the 2k sub-sums h_i = sum_x prod_s sub_tables[i][s][x].
pub fn packed_round_polynomial<F: Field>(
    sub_tables: &[Vec<Vec<F>>],
    d: usize,
    k: usize,
) -> (Vec<F>, Vec<F>) {
    let two_k = 2 * k;
    assert_eq!(sub_tables.len(), two_k);
    for group in sub_tables {
        assert_eq!(group.len(), d);
    }

    let half_size = sub_tables[0][0].len();
    let poly_degree = d * (two_k - 1);
    let num_eval_points = poly_degree + 1;

    // Compute sub-sums: h_i = sum_{x} prod_{s} sub_tables[i][s][x]
    let mut sub_sums = vec![F::ZERO; two_k];
    for i in 0..two_k {
        for x in 0..half_size {
            let mut prod = F::ONE;
            for s in 0..d {
                prod *= sub_tables[i][s][x];
            }
            sub_sums[i] += prod;
        }
    }

    // Compute F(t) for t = 0, 1, ..., d*(2k-1)
    // F(t) = sum_x prod_s ( sum_j L_j(t) * sub_tables[j][s][x] )
    //
    // For t in {0,...,2k-1}: F(t) = sub_sums[t] (by Lagrange property: L_j(t) = delta_{jt})
    //
    // For t >= 2k: use forward differences to extrapolate each phi_x^(s)(t),
    // then multiply and accumulate.
    let mut f_evals = vec![F::ZERO; num_eval_points];

    // F(t) for t in {0,...,2k-1} = sub_sums
    for t in 0..two_k.min(num_eval_points) {
        f_evals[t] = sub_sums[t];
    }

    // F(t) for t in {2k,...,d*(2k-1)}: per-element computation with forward differences
    if num_eval_points > two_k {
        let num_extra = num_eval_points - two_k;

        for x in 0..half_size {
            // For each factor s, extrapolate phi_x^(s)(t) for t = 2k, ..., d*(2k-1)
            let mut factor_extras: Vec<Vec<F>> = Vec::with_capacity(d);
            for s in 0..d {
                // Known evals at {0,...,2k-1}: sub_tables[j][s][x] for j = 0..2k
                let known: Vec<F> = (0..two_k).map(|j| sub_tables[j][s][x]).collect();
                let extras = forward_difference_extrapolate(&known, num_extra);
                factor_extras.push(extras);
            }

            // For each extra point t = 2k + idx:
            // F(t) += prod_s factor_extras[s][idx]
            for idx in 0..num_extra {
                let mut prod = F::ONE;
                for s in 0..d {
                    prod *= factor_extras[s][idx];
                }
                f_evals[two_k + idx] += prod;
            }
        }
    }

    (f_evals, sub_sums)
}

/// Fold 2k sub-tables into k sub-tables using Lagrange weights at k challenge points.
///
/// For each challenge r_i (i in 0..k), computes:
///   new_tables[i][s][x] = sum_{j=0}^{2k-1} L_j(r_i) * old_tables[j][s][x]
///
/// Then slices each into 2 halves (fixing the first variable to 0 or 1):
///   result[2*i][s] = new_tables[i][s][first half]
///   result[2*i+1][s] = new_tables[i][s][second half]
///
/// This produces 2k sub-tables of half the size, ready for the next round.
pub fn fold_and_slice_tables<F: Field>(
    sub_tables: &[Vec<Vec<F>>],
    challenges: &[F],
    k: usize,
    d: usize,
) -> Vec<Vec<Vec<F>>> {
    let two_k = 2 * k;
    assert_eq!(sub_tables.len(), two_k);
    assert_eq!(challenges.len(), k);

    let half_size = sub_tables[0][0].len();
    let quarter_size = half_size / 2;

    // Precompute Lagrange weights: L[i][j] = L_j(r_i)
    let lagrange_matrix: Vec<Vec<F>> = challenges
        .iter()
        .map(|&r| lagrange_basis_integer_set(two_k, r))
        .collect();

    // Fold: for each challenge i, linear-combine the 2k tables
    // Then slice: split by first variable (first half = var=0, second half = var=1)
    let mut result = Vec::with_capacity(two_k);
    for i in 0..k {
        for half in 0..2 {
            let mut group = Vec::with_capacity(d);
            for s in 0..d {
                let mut new_evals = Vec::with_capacity(quarter_size);
                for x in 0..quarter_size {
                    let src_x = half * quarter_size + x;
                    let mut val = F::ZERO;
                    for j in 0..two_k {
                        val += lagrange_matrix[i][j] * sub_tables[j][s][src_x];
                    }
                    new_evals.push(val);
                }
                group.push(new_evals);
            }
            result.push(group);
        }
    }

    result
}

/// Decompose a set of d multilinear polynomial tables into 2k sub-tables.
///
/// Given d tables each of size N (= 2^num_vars), and packing parameter k,
/// split into 2k groups by partitioning the first log2(2k) bits of the index.
///
/// sub_tables[j][s][x] = tables[s][j * (N / 2k) + x]
pub fn decompose_into_subtables<F: Field>(tables: &[Vec<F>], k: usize) -> Vec<Vec<Vec<F>>> {
    let d = tables.len();
    let n = tables[0].len();
    let two_k = 2 * k;
    let chunk_size = n / two_k;
    assert_eq!(n % two_k, 0, "table size must be divisible by 2k");

    let mut sub_tables = Vec::with_capacity(two_k);
    for j in 0..two_k {
        let mut group = Vec::with_capacity(d);
        for s in 0..d {
            let start = j * chunk_size;
            let end = start + chunk_size;
            group.push(tables[s][start..end].to_vec());
        }
        sub_tables.push(group);
    }

    sub_tables
}

/// Evaluate F(r) at a point using Lagrange interpolation from evaluations at {0,...,deg}.
pub fn evaluate_poly_from_evals<F: Field>(evals: &[F], r: F) -> F {
    lagrange_basis_integer_set(evals.len(), r)
        .iter()
        .zip(evals.iter())
        .map(|(&l, &e)| l * e)
        .sum()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;

    type F = KoalaBear;

    #[test]
    fn lagrange_basis_identity() {
        // L_j(i) = delta_{ij} for integer evaluation set {0,...,n-1}
        for n in 2..=8 {
            for i in 0..n {
                let r = F::from_u64(i as u64);
                let basis = lagrange_basis_integer_set(n, r);
                for j in 0..n {
                    let expected = if i == j { F::ONE } else { F::ZERO };
                    assert_eq!(
                        basis[j],
                        expected,
                        "L_{j}({i}) should be {}, got {:?} for n={n}",
                        if i == j { 1 } else { 0 },
                        basis[j],
                    );
                }
            }
        }
    }

    #[test]
    fn lagrange_basis_partition_of_unity() {
        for n in 2..=8 {
            for r_val in [3u64, 17, 100, 999] {
                let r = F::from_u64(r_val);
                let basis = lagrange_basis_integer_set(n, r);
                let sum: F = basis.iter().copied().sum();
                assert_eq!(
                    sum,
                    F::ONE,
                    "partition of unity failed for n={n}, r={r_val}"
                );
            }
        }
    }

    #[test]
    fn forward_difference_linear() {
        // f(x) = 3x + 5: f(0)=5, f(1)=8, f(2)=11
        let known = vec![F::from_u64(5), F::from_u64(8), F::from_u64(11)];
        let extra = forward_difference_extrapolate(&known, 3);
        // f(3)=14, f(4)=17, f(5)=20
        assert_eq!(extra[0], F::from_u64(14));
        assert_eq!(extra[1], F::from_u64(17));
        assert_eq!(extra[2], F::from_u64(20));
    }

    #[test]
    fn forward_difference_quadratic() {
        // f(x) = x^2 + 1: f(0)=1, f(1)=2, f(2)=5
        let known = vec![F::from_u64(1), F::from_u64(2), F::from_u64(5)];
        let extra = forward_difference_extrapolate(&known, 4);
        // f(3)=10, f(4)=17, f(5)=26, f(6)=37
        assert_eq!(extra[0], F::from_u64(10));
        assert_eq!(extra[1], F::from_u64(17));
        assert_eq!(extra[2], F::from_u64(26));
        assert_eq!(extra[3], F::from_u64(37));
    }

    #[test]
    fn forward_difference_cubic() {
        // f(x) = x^3: f(0)=0, f(1)=1, f(2)=8, f(3)=27
        let known = vec![
            F::from_u64(0),
            F::from_u64(1),
            F::from_u64(8),
            F::from_u64(27),
        ];
        let extra = forward_difference_extrapolate(&known, 3);
        // f(4)=64, f(5)=125, f(6)=216
        assert_eq!(extra[0], F::from_u64(64));
        assert_eq!(extra[1], F::from_u64(125));
        assert_eq!(extra[2], F::from_u64(216));
    }

    #[test]
    fn forward_difference_high_degree() {
        // f(x) = x^7 evaluated at {0,...,7} (degree 7, need 8 known values)
        let known: Vec<F> = (0..8u64).map(|x| F::from_u64(x.pow(7))).collect();
        let extra = forward_difference_extrapolate(&known, 4);
        for (i, &val) in extra.iter().enumerate() {
            let x = 8 + i as u64;
            assert_eq!(val, F::from_u64(x.pow(7)), "f({x}) mismatch");
        }
    }

    #[test]
    fn packed_round_degree2_k2() {
        // Degree-2 sumcheck with k=2 (2k=4 sub-tables)
        // f^(0) and f^(1) are two "factors" of the product f^(0)(x)*f^(1)(x)
        //
        // sub_tables[j][s][x] for j in 0..4, s in 0..2, x in 0..half_size
        let k = 2;
        let d = 2;
        let half_size = 4;

        let sub_tables: Vec<Vec<Vec<F>>> = (0..4)
            .map(|j| {
                (0..2)
                    .map(|s| {
                        (0..half_size)
                            .map(|x| F::from_u64((j * 10 + s * 5 + x + 1) as u64))
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let (f_evals, sub_sums) = packed_round_polynomial(&sub_tables, d, k);

        // F should have degree d*(2k-1) = 2*3 = 6, so 7 evaluation points
        assert_eq!(f_evals.len(), 7);

        // F(j) = sub_sums[j] for j in {0,1,2,3}
        for j in 0..4 {
            assert_eq!(f_evals[j], sub_sums[j], "F({j}) should equal sub_sum[{j}]");
        }

        // Verify sub_sums are correct
        for j in 0..4 {
            let mut expected = F::ZERO;
            for x in 0..half_size {
                expected += sub_tables[j][0][x] * sub_tables[j][1][x];
            }
            assert_eq!(sub_sums[j], expected, "sub_sum[{j}] mismatch");
        }

        // Check that total sum = sum of sub_sums
        let total: F = sub_sums.iter().copied().sum();
        // Also verify via direct computation of F at evaluation points
        // F(0) + F(1) + F(2) + F(3) should equal the total (since L_j(i) = delta_{ij})
        let f_sum_at_ints: F = (0..4).map(|j| f_evals[j]).sum();
        assert_eq!(f_sum_at_ints, total);
    }

    #[test]
    fn decompose_and_fold_roundtrip() {
        // Create 2 factor tables of size 8, decompose with k=2, fold, verify sizes
        let k = 2;
        let d = 2;
        let n = 8;

        let tables: Vec<Vec<F>> = (0..d)
            .map(|s| {
                (0..n)
                    .map(|x| F::from_u64((s * 100 + x + 1) as u64))
                    .collect()
            })
            .collect();

        // Decompose into 2k=4 sub-tables of size n/(2k) = 2
        let sub_tables = decompose_into_subtables(&tables, k);
        assert_eq!(sub_tables.len(), 4);
        for group in &sub_tables {
            assert_eq!(group.len(), d);
            for factor in group {
                assert_eq!(factor.len(), 2);
            }
        }

        // Fold with k=2 challenges, should produce 2k=4 sub-tables of size 1
        let challenges = vec![F::from_u64(5), F::from_u64(7)];
        let folded = fold_and_slice_tables(&sub_tables, &challenges, k, d);
        assert_eq!(folded.len(), 4);
        for group in &folded {
            assert_eq!(group.len(), d);
            for factor in group {
                assert_eq!(factor.len(), 1);
            }
        }
    }

    #[test]
    fn packed_sumcheck_vs_naive_degree2() {
        // Full packed sumcheck vs naive direct computation for degree-2 polynomial.
        // f(y) = a(y) * b(y) where a, b are multilinear over {0,1}^4.
        let k = 2;
        let d = 2;
        let num_vars = 4; // total N = 2^4 = 16
        let n = 1 << num_vars;

        // Create random-ish multilinear polynomials
        let a: Vec<F> = (0..n).map(|i| F::from_u64((3 * i + 7) as u64)).collect();
        let b: Vec<F> = (0..n).map(|i| F::from_u64((5 * i + 11) as u64)).collect();

        // Compute true sum: sum_{y in {0,1}^4} a(y) * b(y)
        let true_sum: F = a.iter().zip(b.iter()).map(|(&ai, &bi)| ai * bi).sum();

        // Decompose into sub-tables
        let tables = vec![a, b];
        let mut sub_tables = decompose_into_subtables(&tables, k);

        // Run packed sumcheck rounds
        let mut claimed_sum = true_sum;
        let challenge_vals = [
            F::from_u64(13),
            F::from_u64(17),
            F::from_u64(23),
            F::from_u64(29),
        ];
        let mut challenge_idx = 0;

        // With k=2, 2k=4, each round processes one variable.
        // After decomposition (which handles log2(2k)=2 variables), we have
        // n/(2k)=4 elements per sub-table. Each round halves this.
        // Rounds: 4 -> 2 -> 1 (then finalize)
        let mut round = 0;
        while sub_tables[0][0].len() > 1 {
            let (f_evals, sub_sums) = packed_round_polynomial(&sub_tables, d, k);

            // Verify: sum of sub_sums = claimed sum
            let sub_total: F = sub_sums.iter().copied().sum();
            assert_eq!(
                sub_total, claimed_sum,
                "round {round}: sub_sums don't sum to claimed value"
            );

            // Verify: F(j) = sub_sums[j] for j in {0,...,2k-1}
            for j in 0..(2 * k) {
                assert_eq!(f_evals[j], sub_sums[j], "round {round}: F({j}) mismatch");
            }

            // Get k challenges (from our predetermined list)
            let chal: Vec<F> = (0..k)
                .map(|i| challenge_vals[(challenge_idx + i) % challenge_vals.len()])
                .collect();
            challenge_idx += k;

            // Update claimed sums: h'_i = F(r_i) for each challenge
            let new_claims: Vec<F> = chal
                .iter()
                .map(|&r| evaluate_poly_from_evals(&f_evals, r))
                .collect();
            claimed_sum = new_claims.iter().copied().sum();

            // Fold and slice
            sub_tables = fold_and_slice_tables(&sub_tables, &chal, k, d);

            round += 1;
        }

        // Final round: each sub-table has size 1
        // The final claimed sum should match the direct evaluation
        let (f_evals_final, sub_sums_final) = packed_round_polynomial(&sub_tables, d, k);
        let final_total: F = sub_sums_final.iter().copied().sum();
        assert_eq!(
            final_total, claimed_sum,
            "final round: sub_sums don't match claimed sum"
        );

        // Verify F at integer points
        for j in 0..(2 * k) {
            assert_eq!(f_evals_final[j], sub_sums_final[j]);
        }
    }

    #[test]
    fn evaluate_poly_from_evals_matches_lagrange() {
        // Verify that evaluate_poly_from_evals correctly interpolates
        // a cubic polynomial f(x) = 2x^3 + x + 3
        let evals: Vec<F> = (0..4u64)
            .map(|x| F::from_u64(2 * x * x * x + x + 3))
            .collect();

        // Check at a non-integer point
        let r = F::from_u64(7);
        let result = evaluate_poly_from_evals(&evals, r);
        let expected = F::from_u64(2 * 343 + 7 + 3); // 2*7^3 + 7 + 3 = 696
        assert_eq!(result, expected);
    }
}
