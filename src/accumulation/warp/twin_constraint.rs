//! Twin-constraint sumcheck for WARP accumulation.
//!
//! The twin-constraint sumcheck simultaneously checks two properties of the
//! accumulated instances via a single sumcheck over the instance-index hypercube:
//!
//! 1. **Codeword proximity**: the folded codeword evaluations are consistent
//!    with a polynomial that evaluates correctly at the claimed point α.
//! 2. **R1CS satisfaction**: the folded witness satisfies Az·Bz = Cz
//!    bundled by the PESAT randomness β.
//!
//! These are combined via a batching challenge ω into a single round polynomial:
//!   h(X) = Σᵢ (f_i(X) + ω·p_i(X)) · eq(τ, i, X)
//!
//! where f_i is the ProtoGalaxy-fold of codeword/alpha evaluations, and p_i is
//! the ProtoGalaxy-fold of bundled R1CS constraint evaluations.
//!
//! After log_l rounds, all tables reduce to single folded vectors at the original size.
//!
//! Reference: EPFL WARP implementation `twin_constraint_round_poly` in lib.rs

use alloc::vec::Vec;

use p3_field::Field;

use crate::accumulation::protogalaxy::{self, UnivariatePoly};
use crate::spartan::r1cs::R1CSShape;

/// R1CS constraint in sparse (row-based) form: (A_row, B_row, C_row).
/// Each component is a list of (coefficient, column_index) pairs.
pub type SparseR1CSConstraint<F> = (Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>);

/// Convert an `R1CSShape` into a list of sparse row-based constraints.
///
/// Each constraint row i is (A_row_i, B_row_i, C_row_i) where entries are
/// (value, column) pairs.
pub fn shape_to_sparse_constraints<F: Field>(shape: &R1CSShape<F>) -> Vec<SparseR1CSConstraint<F>> {
    let num_cons = shape.num_cons();
    let mut constraints: Vec<SparseR1CSConstraint<F>> = (0..num_cons)
        .map(|_| (Vec::new(), Vec::new(), Vec::new()))
        .collect();

    for entry in shape.a().entries() {
        constraints[entry.row].0.push((entry.val, entry.col));
    }
    for entry in shape.b().entries() {
        constraints[entry.row].1.push((entry.val, entry.col));
    }
    for entry in shape.c().entries() {
        constraints[entry.row].2.push((entry.val, entry.col));
    }

    constraints
}

/// Evaluate a single R1CS constraint `(Az·Bz - Cz)` as a degree-2 univariate
/// polynomial from two witness vectors z0 (at X=0) and z1 (at X=1).
///
/// Returns a polynomial p(X) such that:
/// - p(0) = A(z0)·B(z0) - C(z0)
/// - p(1) = A(z1)·B(z1) - C(z1)
///
/// The polynomial is: p(X) = c₀ + c₁·X + c₂·X²
/// where c₀ = a0·b0 - c0, c₁ = a0·Δb + Δa·b0 - Δc, c₂ = Δa·Δb
fn eval_r1cs_constraint_poly<F: Field>(
    constraint: &SparseR1CSConstraint<F>,
    z0: &[F],
    z1: &[F],
) -> UnivariatePoly<F> {
    let eval_lc = |lc: &[(F, usize)], z: &[F]| -> F {
        lc.iter().map(|&(coeff, idx)| coeff * z[idx]).sum()
    };

    let (ref a, ref b, ref c) = *constraint;
    let (a0, b0, c0) = (eval_lc(a, z0), eval_lc(b, z0), eval_lc(c, z0));
    let (da, db, dc) = (
        eval_lc(a, z1) - a0,
        eval_lc(b, z1) - b0,
        eval_lc(c, z1) - c0,
    );

    // p(X) = (a0 + da·X)·(b0 + db·X) - (c0 + dc·X)
    //       = (a0·b0 - c0) + (a0·db + da·b0 - dc)·X + da·db·X²
    UnivariatePoly::from_coeffs(alloc::vec![
        a0 * b0 - c0,
        a0 * db + da * b0 - dc,
        da * db,
    ])
}

/// Compute one round of the twin-constraint sumcheck.
///
/// This is the core computation inside the WARP fold. At each sumcheck round,
/// it processes pairs of table entries and produces a round polynomial h(X)
/// that combines codeword proximity and R1CS satisfaction.
///
/// Arguments:
/// - `codewords`: pairs of codeword evaluation vectors `[u_left, u_right, ...]`
/// - `witnesses`: pairs of full witness vectors `[z_left, z_right, ...]`
/// - `alphas`: pairs of evaluation point vectors `[α_left, α_right, ...]`
/// - `betas`: pairs of PESAT-point vectors `[β_left, β_right, ...]`
/// - `tau_evals`: pairwise eq(τ) evaluations `[τ_left, τ_right, ...]`
/// - `constraints`: the R1CS constraints in sparse row form
/// - `omega`: batching challenge combining codeword and R1CS checks
/// - `expected_num_coeffs`: pad the result to this many coefficients
///
/// Returns h(X) = Σᵢ (f_i(X) + ω·p_i(X)) · t_i(X)
pub fn twin_constraint_round_poly<F: Field>(
    codewords: &[Vec<F>],
    witnesses: &[Vec<F>],
    alphas: &[Vec<F>],
    betas: &[Vec<F>],
    tau_evals: &[F],
    constraints: &[SparseR1CSConstraint<F>],
    omega: F,
    expected_num_coeffs: usize,
) -> UnivariatePoly<F> {
    // Process pairs: each pair (left, right) at indices (2i, 2i+1)
    let num_pairs = codewords.len() / 2;

    let mut h = UnivariatePoly::zero();

    for i in 0..num_pairs {
        let (u_left, u_right) = (&codewords[2 * i], &codewords[2 * i + 1]);
        let (a_left, a_right) = (&alphas[2 * i], &alphas[2 * i + 1]);
        let (z_left, z_right) = (&witnesses[2 * i], &witnesses[2 * i + 1]);
        let (b_left, b_right) = (&betas[2 * i], &betas[2 * i + 1]);
        let (t_left, t_right) = (tau_evals[2 * i], tau_evals[2 * i + 1]);

        // f_i(X) = protogalaxy::fold(alpha_coeffs, codeword_polys)
        // The alpha coeffs are (a_left[j], a_right[j] - a_left[j]) for each position j
        // The codeword polys are linear: lo + (hi-lo)·X for each position j
        let f_i = protogalaxy::fold(
            a_left
                .iter()
                .zip(a_right.iter())
                .map(|(&l, &r)| (l, r - l)),
            u_left
                .iter()
                .zip(u_right.iter())
                .map(|(&l, &r)| UnivariatePoly::from_coeffs(alloc::vec![l, r - l]))
                .collect(),
        );

        // p_i(X) = protogalaxy::fold(beta_coeffs, r1cs_constraint_polys)
        // Each R1CS constraint produces a degree-2 polynomial from (z_left, z_right)
        let p_i = protogalaxy::fold(
            b_left
                .iter()
                .zip(b_right.iter())
                .map(|(&l, &r)| (l, r - l)),
            constraints
                .iter()
                .map(|c| eval_r1cs_constraint_poly(c, z_left, z_right))
                .collect(),
        );

        // t_i(X) = linear interpolation of tau: t_left + (t_right - t_left)·X
        let t_i = UnivariatePoly::from_coeffs(alloc::vec![t_left, t_right - t_left]);

        // h += (f_i + ω·p_i) · t_i
        let fp = f_i.add(&p_i.scale(omega));
        let term = fp.naive_mul(&t_i);
        h = h.add(&term);
    }

    // Pad to expected number of coefficients
    h.pad_to(expected_num_coeffs);
    h
}

/// Reduce tablewise data after a sumcheck round.
///
/// Each pair (left, right) is combined as: left + challenge * (right - left).
/// The table shrinks from 2n to n entries.
pub fn reduce_tablewise<F: Field>(table: &mut Vec<Vec<F>>, challenge: F) {
    let reduced: Vec<Vec<F>> = table
        .chunks(2)
        .map(|pair| {
            pair[0]
                .iter()
                .zip(pair[1].iter())
                .map(|(&l, &r)| l + challenge * (r - l))
                .collect()
        })
        .collect();
    *table = reduced;
}

/// Reduce pairwise (scalar) data after a sumcheck round.
///
/// Each pair (left, right) is combined as: left + challenge * (right - left).
/// The table shrinks from 2n to n entries.
pub fn reduce_pairwise<F: Field>(table: &mut Vec<F>, challenge: F) {
    let reduced: Vec<F> = table
        .chunks(2)
        .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
        .collect();
    *table = reduced;
}

/// Run the full twin-constraint coefficient sumcheck over log_l rounds.
///
/// This is the main entry point for Phase 2 of the WARP fold. It orchestrates:
/// 1. Computing the round polynomial h(X) at each round
/// 2. Absorbing coefficients into the transcript
/// 3. Squeezing a challenge
/// 4. Reducing all tables by the challenge
///
/// Returns (round_polys, challenges) — the sumcheck transcript.
pub fn twin_constraint_sumcheck<F: Field>(
    codewords: &mut Vec<Vec<F>>,
    witnesses: &mut Vec<Vec<F>>,
    alphas: &mut Vec<Vec<F>>,
    betas: &mut Vec<Vec<F>>,
    tau_evals: &mut Vec<F>,
    constraints: &[SparseR1CSConstraint<F>],
    omega: F,
    log_l: usize,
    expected_num_coeffs: usize,
    // Returns (challenge, absorbed round poly coefficients)
    mut transcript_round: impl FnMut(&[F]) -> F,
) -> (Vec<UnivariatePoly<F>>, Vec<F>) {
    let mut round_polys = Vec::with_capacity(log_l);
    let mut challenges = Vec::with_capacity(log_l);

    for _ in 0..log_l {
        // 1. Compute round polynomial
        let h = twin_constraint_round_poly(
            codewords,
            witnesses,
            alphas,
            betas,
            tau_evals,
            constraints,
            omega,
            expected_num_coeffs,
        );

        // 2. Absorb coefficients into transcript and squeeze challenge
        let challenge = transcript_round(&h.coeffs);

        // 3. Reduce all tables by the challenge
        reduce_tablewise(codewords, challenge);
        reduce_tablewise(witnesses, challenge);
        reduce_tablewise(alphas, challenge);
        reduce_tablewise(betas, challenge);
        reduce_pairwise(tau_evals, challenge);

        round_polys.push(h);
        challenges.push(challenge);
    }

    // After log_l rounds, each table should have exactly 1 entry
    debug_assert_eq!(codewords.len(), 1);
    debug_assert_eq!(witnesses.len(), 1);
    debug_assert_eq!(alphas.len(), 1);
    debug_assert_eq!(betas.len(), 1);
    debug_assert_eq!(tau_evals.len(), 1);

    (round_polys, challenges)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    /// Make 4 squaring constraints: x_i * x_i = x_{i+4} for i in 0..4
    /// This gives log_M = 2 fold levels for the beta/PESAT fold.
    fn make_r1cs_constraints() -> Vec<SparseR1CSConstraint<F>> {
        (0..4)
            .map(|i| {
                (
                    vec![(F::ONE, i)],     // A: x_i
                    vec![(F::ONE, i)],     // B: x_i
                    vec![(F::ONE, i + 4)], // C: x_{i+4}
                )
            })
            .collect()
    }

    /// Build a valid witness for the 4-constraint squaring system.
    /// z = [v0, v1, v2, v3, v0², v1², v2², v3²]
    fn make_valid_witness(values: &[u64; 4]) -> Vec<F> {
        let mut z = Vec::with_capacity(8);
        for &v in values {
            z.push(F::from_u64(v));
        }
        for &v in values {
            z.push(F::from_u64(v * v));
        }
        z
    }

    #[test]
    fn eval_r1cs_constraint_poly_at_boolean_points() {
        // Constraint 0: x₀ * x₀ = x₄
        let constraint = (
            vec![(F::ONE, 0)],
            vec![(F::ONE, 0)],
            vec![(F::ONE, 4)],
        );
        // z0: x₀=3, x₄=9 → 3*3=9 ✓
        let z0 = make_valid_witness(&[3, 1, 1, 1]);
        // z1: x₀=5, x₄=25 → 5*5=25 ✓
        let z1 = make_valid_witness(&[5, 1, 1, 1]);

        let p = eval_r1cs_constraint_poly(&constraint, &z0, &z1);

        assert_eq!(p.evaluate(F::ZERO), F::ZERO, "p(0) should be 0 for valid z0");
        assert_eq!(p.evaluate(F::ONE), F::ZERO, "p(1) should be 0 for valid z1");
    }

    #[test]
    fn eval_r1cs_constraint_poly_nonzero_for_invalid() {
        let constraint = (
            vec![(F::ONE, 0)],
            vec![(F::ONE, 0)],
            vec![(F::ONE, 4)],
        );
        // z0: x₀=3, x₄=10 → 3*3=9 ≠ 10 → INVALID
        let mut z0 = make_valid_witness(&[3, 1, 1, 1]);
        z0[4] = F::from_u64(10); // tamper
        let z1 = make_valid_witness(&[5, 1, 1, 1]);

        let p = eval_r1cs_constraint_poly(&constraint, &z0, &z1);

        assert_ne!(p.evaluate(F::ZERO), F::ZERO, "p(0) should be nonzero for invalid z0");
        assert_eq!(p.evaluate(F::ONE), F::ZERO, "p(1) should be 0 for valid z1");
    }

    #[test]
    fn reduce_tablewise_halves_length() {
        let mut table = vec![
            vec![F::from_u64(1), F::from_u64(2)],
            vec![F::from_u64(3), F::from_u64(4)],
            vec![F::from_u64(5), F::from_u64(6)],
            vec![F::from_u64(7), F::from_u64(8)],
        ];
        let challenge = F::from_u64(2);
        reduce_tablewise(&mut table, challenge);

        assert_eq!(table.len(), 2);
        // table[0] = [1,2] + 2*([3,4]-[1,2]) = [1+4, 2+4] = [5, 6]
        assert_eq!(table[0], vec![F::from_u64(5), F::from_u64(6)]);
    }

    #[test]
    fn reduce_pairwise_halves_length() {
        let mut table = vec![F::from_u64(10), F::from_u64(20), F::from_u64(30), F::from_u64(40)];
        let challenge = F::from_u64(3);
        reduce_pairwise(&mut table, challenge);

        assert_eq!(table.len(), 2);
        // table[0] = 10 + 3*(20-10) = 40
        assert_eq!(table[0], F::from_u64(40));
        // table[1] = 30 + 3*(40-30) = 60
        assert_eq!(table[1], F::from_u64(60));
    }

    #[test]
    fn twin_constraint_sumcheck_reduces_to_single() {
        // 4 instances (log_l = 2), 4 squaring constraints (log_M = 2)
        let constraints = make_r1cs_constraints();

        // 4 valid witnesses: z = [v0..v3, v0²..v3²], 8 elements each
        let witnesses: Vec<Vec<F>> = vec![
            make_valid_witness(&[2, 3, 4, 5]),
            make_valid_witness(&[6, 7, 8, 9]),
            make_valid_witness(&[10, 11, 12, 13]),
            make_valid_witness(&[14, 15, 16, 17]),
        ];

        // Codewords = witnesses (identity encoding for testing)
        let mut codewords = witnesses.clone();
        let mut witnesses_mut = witnesses;

        // Alpha points: log_n = 3 variables for code length 8 (= witness size)
        let mut alphas = vec![
            vec![F::from_u64(1), F::from_u64(0), F::from_u64(1)],
            vec![F::from_u64(0), F::from_u64(1), F::from_u64(0)],
            vec![F::from_u64(1), F::from_u64(1), F::from_u64(0)],
            vec![F::from_u64(0), F::from_u64(0), F::from_u64(1)],
        ];

        // Beta points: log_M = 2 variables for 4 constraints
        let mut betas = vec![
            vec![F::from_u64(7), F::from_u64(11)],
            vec![F::from_u64(13), F::from_u64(17)],
            vec![F::from_u64(19), F::from_u64(23)],
            vec![F::from_u64(29), F::from_u64(31)],
        ];

        // Tau eq-evals (4 values)
        let mut tau_evals = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ];

        let omega = F::from_u64(5);
        let log_l = 2;
        let expected_num_coeffs = 8;

        let mut round_counter = 0u64;
        let (round_polys, challenges) = twin_constraint_sumcheck(
            &mut codewords,
            &mut witnesses_mut,
            &mut alphas,
            &mut betas,
            &mut tau_evals,
            &constraints,
            omega,
            log_l,
            expected_num_coeffs,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 100)
            },
        );

        // After 2 rounds, all tables should be reduced to 1 entry
        assert_eq!(codewords.len(), 1, "codewords not reduced to 1");
        assert_eq!(witnesses_mut.len(), 1, "witnesses not reduced to 1");
        assert_eq!(alphas.len(), 1, "alphas not reduced to 1");
        assert_eq!(betas.len(), 1, "betas not reduced to 1");
        assert_eq!(tau_evals.len(), 1, "tau_evals not reduced to 1");

        assert_eq!(round_polys.len(), 2);
        assert_eq!(challenges.len(), 2);

        for poly in &round_polys {
            assert_eq!(poly.coeffs.len(), expected_num_coeffs);
        }
    }

    #[test]
    fn twin_constraint_sumcheck_relation_holds() {
        // Verify the sumcheck relation: h_i(0) + h_i(1) == h_{i-1}(challenge_{i-1})
        let constraints = make_r1cs_constraints();

        let mut witnesses: Vec<Vec<F>> = vec![
            make_valid_witness(&[2, 3, 4, 5]),
            make_valid_witness(&[6, 7, 8, 9]),
            make_valid_witness(&[10, 11, 12, 13]),
            make_valid_witness(&[14, 15, 16, 17]),
        ];
        let mut codewords = witnesses.clone();
        let mut alphas = vec![
            vec![F::from_u64(1), F::from_u64(0), F::from_u64(1)],
            vec![F::from_u64(0), F::from_u64(1), F::from_u64(0)],
            vec![F::from_u64(1), F::from_u64(1), F::from_u64(0)],
            vec![F::from_u64(0), F::from_u64(0), F::from_u64(1)],
        ];
        let mut betas = vec![
            vec![F::from_u64(7), F::from_u64(11)],
            vec![F::from_u64(13), F::from_u64(17)],
            vec![F::from_u64(19), F::from_u64(23)],
            vec![F::from_u64(29), F::from_u64(31)],
        ];
        let mut tau_evals = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ];

        let omega = F::from_u64(5);
        let log_l = 2;
        let expected_num_coeffs = 8;

        let mut round_counter = 0u64;
        let (round_polys, challenges) = twin_constraint_sumcheck(
            &mut codewords,
            &mut witnesses,
            &mut alphas,
            &mut betas,
            &mut tau_evals,
            &constraints,
            omega,
            log_l,
            expected_num_coeffs,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 50)
            },
        );

        // Verify round-by-round: h_i(0) + h_i(1) == h_{i-1}(challenge_{i-1})
        for i in 1..round_polys.len() {
            let prev_at_challenge = round_polys[i - 1].evaluate(challenges[i - 1]);
            let curr_sum =
                round_polys[i].evaluate(F::ZERO) + round_polys[i].evaluate(F::ONE);
            assert_eq!(
                prev_at_challenge, curr_sum,
                "sumcheck relation violated at round {i}"
            );
        }
    }
}
