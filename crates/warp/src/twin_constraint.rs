//! Twin-constraint sumcheck for WARP accumulation.
//!
//! The twin-constraint sumcheck simultaneously checks two properties of the
//! accumulated instances via a single degree-2 sumcheck over the instance-index
//! hypercube {0,1}^{log l}:
//!
//! 1. **Codeword proximity**: μ_i = f̃_i(α_i) — the codeword MLE evaluates
//!    correctly at the claimed evaluation point.
//! 2. **R1CS satisfaction**: η_i = P(β_i, z_i) — the PESAT constraint holds.
//!
//! These are combined via a batching challenge ω into:
//!   Σ_{b ∈ {0,1}^{log l}} eq(τ, b) · (μ̃(b) + ω · η̃(b)) = σ
//!
//! The μ_i and η_i are precomputed in O(l·n), then the sumcheck runs in O(l·log l).
//! After the sumcheck, all tables (codewords, alphas, betas, witnesses) are folded
//! with the challenges in O(l·n).

use alloc::{vec, vec::Vec};

use p3_field::Field;
use p3_maybe_rayon::prelude::*;

use crate::spartan::r1cs::R1CSShape;

/// R1CS constraint in sparse (row-based) form: (A_row, B_row, C_row).
/// Each component is a list of (coefficient, column_index) pairs.
pub type SparseR1CSConstraint<F> = (Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>);

/// Convert an `R1CSShape` into a list of sparse row-based constraints.
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

/// Precompute the codeword evaluation claim μ_i = f̃_i(α_i).
///
/// This evaluates the MLE of the codeword at the alpha point using the O(n)
/// binary tree eq-table expansion.
/// Minimum size before switching to parallel iteration.
const PARALLEL_THRESHOLD: usize = 4096;

fn compute_mu<F: Field>(codeword: &[F], alpha: &[F]) -> F {
    let n = codeword.len();
    let log_n = n.trailing_zeros() as usize;
    assert_eq!(alpha.len(), log_n);

    // Build eq(α, ·) table in O(n) and inner-product with codeword
    let eq_table = compute_eq_table(alpha);
    if n >= PARALLEL_THRESHOLD {
        eq_table
            .par_iter()
            .zip(codeword.par_iter())
            .map(|(&e, &c)| e * c)
            .par_fold_reduce(|| F::ZERO, |a, b| a + b, |a, b| a + b)
    } else {
        let mut mu = F::ZERO;
        for i in 0..n {
            mu += eq_table[i] * codeword[i];
        }
        mu
    }
}

/// Precompute the PESAT target η_i = Σ_row eq(β_i, row) · (Az·Bz - Cz)(row).
fn compute_eta<F: Field>(
    constraints: &[SparseR1CSConstraint<F>],
    beta: &[F],
    z: &[F],
) -> F {
    let num_cons = constraints.len();
    let log_m = num_cons.next_power_of_two().trailing_zeros() as usize;
    assert_eq!(beta.len(), log_m);

    let eval_lc = |lc: &[(F, usize)], z: &[F]| -> F {
        lc.iter().map(|&(coeff, idx)| coeff * z[idx]).sum()
    };

    let eq_table = compute_eq_table(beta);
    if num_cons >= PARALLEL_THRESHOLD {
        constraints
            .par_iter()
            .enumerate()
            .map(|(row, constraint)| {
                let (ref a, ref b, ref c) = *constraint;
                let az: F = a.iter().map(|&(coeff, idx)| coeff * z[idx]).sum();
                let bz: F = b.iter().map(|&(coeff, idx)| coeff * z[idx]).sum();
                let cz: F = c.iter().map(|&(coeff, idx)| coeff * z[idx]).sum();
                eq_table[row] * (az * bz - cz)
            })
            .par_fold_reduce(|| F::ZERO, |a, b| a + b, |a, b| a + b)
    } else {
        let mut eta = F::ZERO;
        for (row, constraint) in constraints.iter().enumerate() {
            let (ref a, ref b, ref c) = *constraint;
            let az = eval_lc(a, z);
            let bz = eval_lc(b, z);
            let cz = eval_lc(c, z);
            eta += eq_table[row] * (az * bz - cz);
        }
        eta
    }
}

/// Build eq(tau, ·) table in O(n) via binary tree expansion (LSB-first convention).
fn compute_eq_table<F: Field>(tau: &[F]) -> Vec<F> {
    let s = tau.len();
    let n = 1usize << s;
    let mut table = vec![F::ZERO; n];
    table[0] = F::ONE;

    for j in (0..s).rev() {
        let tau_j = tau[j];
        let one_minus = F::ONE - tau_j;
        let half = 1usize << (s - 1 - j);
        for i in (0..half).rev() {
            table[2 * i + 1] = table[i] * tau_j;
            table[2 * i] = table[i] * one_minus;
        }
    }
    table
}

/// Run the full twin-constraint sumcheck over log_l rounds.
///
/// This is the main entry point for the WARP fold's algebraic phase:
/// 1. Precompute μ_i and η_i for each instance (O(l·n + l·M))
/// 2. Run a degree-2 table-based sumcheck on eq(τ,b)·(μ̃(b) + ω·η̃(b)) (O(l·log l))
/// 3. Fold all tables (codewords, alphas, betas, witnesses) using eq-weighted
///    combination with the sumcheck challenges (O(l·n))
///
/// Returns (round_evals, challenges) — the sumcheck transcript.
pub fn twin_constraint_sumcheck<F: Field>(
    codewords: &mut Vec<Vec<F>>,
    witnesses: &mut Vec<Vec<F>>,
    alphas: &mut Vec<Vec<F>>,
    betas: &mut Vec<Vec<F>>,
    tau_evals: &mut Vec<F>,
    constraints: &[SparseR1CSConstraint<F>],
    omega: F,
    log_l: usize,
    _expected_num_coeffs: usize,
    mut transcript_round: impl FnMut(&[F]) -> F,
) -> (Vec<Vec<F>>, Vec<F>) {
    let l = codewords.len();
    assert_eq!(l, 1 << log_l);

    // ========================================
    // Step 1: Precompute μ_i and η_i — O(l·n + l·M)
    // ========================================
    let mut mu_table: Vec<F> = Vec::with_capacity(l);
    let mut eta_table: Vec<F> = Vec::with_capacity(l);

    for i in 0..l {
        let mu_i = compute_mu(&codewords[i], &alphas[i]);
        let eta_i = compute_eta(constraints, &betas[i], &witnesses[i]);
        mu_table.push(mu_i);
        eta_table.push(eta_i);
    }

    // Combined target table: target_i = μ_i + ω · η_i
    let mut target_table: Vec<F> = mu_table
        .iter()
        .zip(eta_table.iter())
        .map(|(&mu, &eta)| mu + omega * eta)
        .collect();

    // ========================================
    // Step 2: Degree-2 table-based sumcheck — O(l · log l)
    // ========================================
    // Proving: Σ_{b ∈ {0,1}^{log l}} eq(τ, b) · target(b) = σ
    let initial_claim: F = tau_evals
        .iter()
        .zip(target_table.iter())
        .map(|(&t, &v)| t * v)
        .sum();

    let mut current_claim = initial_claim;
    let mut round_evals_all = Vec::with_capacity(log_l);
    let mut challenges = Vec::with_capacity(log_l);

    for _round in 0..log_l {
        let half = tau_evals.len() / 2;

        // Evaluate degree-2 univariate at points 0, 1, 2
        let compute_pair = |t_pair: &[F], v_pair: &[F]| {
            let t_lo = t_pair[0];
            let t_hi = t_pair[1];
            let v_lo = v_pair[0];
            let v_hi = v_pair[1];

            let t_d = t_hi - t_lo;
            let v_d = v_hi - v_lo;

            [
                t_lo * v_lo,
                t_hi * v_hi,
                (t_lo + t_d.double()) * (v_lo + v_d.double()),
            ]
        };

        let evals = if half >= PARALLEL_THRESHOLD {
            tau_evals
                .par_chunks(2)
                .zip(target_table.par_chunks(2))
                .map(|(t_pair, v_pair)| compute_pair(t_pair, v_pair))
                .par_fold_reduce(
                    || [F::ZERO; 3],
                    |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
                    |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
                )
        } else {
            let mut evals = [F::ZERO; 3];
            for i in 0..half {
                let e = compute_pair(
                    &tau_evals[2 * i..2 * i + 2],
                    &target_table[2 * i..2 * i + 2],
                );
                evals[0] += e[0];
                evals[1] += e[1];
                evals[2] += e[2];
            }
            evals
        };

        let round_evals = evals.to_vec();
        assert_eq!(
            round_evals[0] + round_evals[1],
            current_claim,
            "twin-constraint sumcheck: round claim mismatch"
        );

        let r = transcript_round(&round_evals);
        // Evaluate degree-2 polynomial at r via Lagrange interpolation
        let e0 = round_evals[0];
        let e1 = round_evals[1];
        let e2 = round_evals[2];
        let c0 = e0;
        let c2 = (e2 - e1.double() + e0) * F::TWO.inverse();
        let c1 = e1 - e0 - c2;
        current_claim = c0 + c1 * r + c2 * r * r;

        challenges.push(r);
        round_evals_all.push(round_evals);

        // Bind tau and target tables
        if half >= PARALLEL_THRESHOLD {
            let folded_tau: Vec<F> = tau_evals
                .par_chunks(2)
                .map(|pair| pair[0] + r * (pair[1] - pair[0]))
                .collect();
            let folded_target: Vec<F> = target_table
                .par_chunks(2)
                .map(|pair| pair[0] + r * (pair[1] - pair[0]))
                .collect();
            *tau_evals = folded_tau;
            target_table = folded_target;
        } else {
            for i in 0..half {
                tau_evals[i] =
                    tau_evals[2 * i] + r * (tau_evals[2 * i + 1] - tau_evals[2 * i]);
                target_table[i] =
                    target_table[2 * i] + r * (target_table[2 * i + 1] - target_table[2 * i]);
            }
            tau_evals.truncate(half);
            target_table.truncate(half);
        }
    }

    // ========================================
    // Step 3: Fold all tables using eq-weighted combination — O(l·n)
    // ========================================
    // Compute eq(γ, i) weights from the sumcheck challenges
    let eq_weights = compute_eq_table(&challenges);

    // Fold codewords: folded[j] = Σ_i eq(γ, i) · codewords[i][j]
    let folded_codeword = fold_weighted(codewords, &eq_weights);
    *codewords = vec![folded_codeword];

    // Fold witnesses
    let folded_witness = fold_weighted(witnesses, &eq_weights);
    *witnesses = vec![folded_witness];

    // Fold alphas
    let folded_alpha = fold_weighted(alphas, &eq_weights);
    *alphas = vec![folded_alpha];

    // Fold betas
    let folded_beta = fold_weighted(betas, &eq_weights);
    *betas = vec![folded_beta];

    (round_evals_all, challenges)
}

/// Fold `l` vectors into one via eq-weighted linear combination: folded[j] = Σ_i w[i] · vecs[i][j].
///
/// Parallelizes over the inner dimension (j) when the vector length is large.
fn fold_weighted<F: Field>(vecs: &[Vec<F>], weights: &[F]) -> Vec<F> {
    let len = vecs[0].len();
    if len >= PARALLEL_THRESHOLD {
        let mut folded = vec![F::ZERO; len];
        folded.par_iter_mut().enumerate().for_each(|(j, out)| {
            let mut sum = F::ZERO;
            for (i, v) in vecs.iter().enumerate() {
                sum += weights[i] * v[j];
            }
            *out = sum;
        });
        folded
    } else {
        let mut folded = vec![F::ZERO; len];
        for (i, v) in vecs.iter().enumerate() {
            let w = weights[i];
            for j in 0..len {
                folded[j] += w * v[j];
            }
        }
        folded
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_koala_bear::KoalaBear;
    use p3_field::PrimeCharacteristicRing;

    type F = KoalaBear;

    fn make_r1cs_constraints() -> Vec<SparseR1CSConstraint<F>> {
        (0..4)
            .map(|i| {
                (
                    vec![(F::ONE, i)],
                    vec![(F::ONE, i)],
                    vec![(F::ONE, i + 4)],
                )
            })
            .collect()
    }

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
    fn twin_constraint_sumcheck_reduces_to_single() {
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

        let mut round_counter = 0u64;
        let (round_evals, challenges) = twin_constraint_sumcheck(
            &mut codewords,
            &mut witnesses,
            &mut alphas,
            &mut betas,
            &mut tau_evals,
            &constraints,
            omega,
            log_l,
            8, // unused
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 100)
            },
        );

        assert_eq!(codewords.len(), 1);
        assert_eq!(witnesses.len(), 1);
        assert_eq!(alphas.len(), 1);
        assert_eq!(betas.len(), 1);
        assert_eq!(tau_evals.len(), 1);
        assert_eq!(round_evals.len(), 2);
        assert_eq!(challenges.len(), 2);
    }

    #[test]
    fn twin_constraint_sumcheck_relation_holds() {
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

        let mut round_counter = 0u64;
        let (round_evals, challenges) = twin_constraint_sumcheck(
            &mut codewords,
            &mut witnesses,
            &mut alphas,
            &mut betas,
            &mut tau_evals,
            &constraints,
            omega,
            log_l,
            8,
            |_coeffs| {
                round_counter += 1;
                F::from_u64(round_counter + 50)
            },
        );

        // Verify round-by-round: h_i(0) + h_i(1) == h_{i-1}(challenge_{i-1})
        for i in 1..round_evals.len() {
            let e = &round_evals[i - 1];
            let c0 = e[0];
            let c2 = (e[2] - e[1].double() + e[0]) * F::TWO.inverse();
            let c1 = e[1] - e[0] - c2;
            let r = challenges[i - 1];
            let prev_at_challenge = c0 + c1 * r + c2 * r * r;

            let curr_sum = round_evals[i][0] + round_evals[i][1];
            assert_eq!(
                prev_at_challenge, curr_sum,
                "sumcheck relation violated at round {i}"
            );
        }
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
        assert_eq!(table[0], vec![F::from_u64(5), F::from_u64(6)]);
    }

    #[test]
    fn reduce_pairwise_halves_length() {
        let mut table = vec![F::from_u64(10), F::from_u64(20), F::from_u64(30), F::from_u64(40)];
        let challenge = F::from_u64(3);
        reduce_pairwise(&mut table, challenge);

        assert_eq!(table.len(), 2);
        assert_eq!(table[0], F::from_u64(40));
        assert_eq!(table[1], F::from_u64(60));
    }
}

/// Reduce tablewise data after a sumcheck round.
pub fn reduce_tablewise<F: Field>(table: &mut Vec<Vec<F>>, challenge: F) {
    let reduced: Vec<Vec<F>> = table
        .par_chunks(2)
        .map(|pair| {
            let len = pair[0].len();
            if len >= PARALLEL_THRESHOLD {
                pair[0]
                    .par_iter()
                    .zip(pair[1].par_iter())
                    .map(|(&l, &r)| l + challenge * (r - l))
                    .collect()
            } else {
                pair[0]
                    .iter()
                    .zip(pair[1].iter())
                    .map(|(&l, &r)| l + challenge * (r - l))
                    .collect()
            }
        })
        .collect();
    *table = reduced;
}

/// Reduce pairwise (scalar) data after a sumcheck round.
pub fn reduce_pairwise<F: Field>(table: &mut Vec<F>, challenge: F) {
    let half = table.len() / 2;
    if half >= PARALLEL_THRESHOLD {
        let reduced: Vec<F> = table
            .par_chunks(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();
        *table = reduced;
    } else {
        let reduced: Vec<F> = table
            .chunks(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();
        *table = reduced;
    }
}
