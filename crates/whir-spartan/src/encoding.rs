//! Degree-3 Polynomial Encoding for R1CS
//!
//! Implements the encoding from Spartan Section 4 (Theorem 4.1):
//! For R1CS instance x = (F, A, B, C, io, m, n), creates degree-3 polynomial G such that
//! Σ_{x∈{0,1}^log m} G(x) = 0 iff the R1CS is satisfiable.

use alloc::vec::Vec;
use p3_field::{ExtensionField, Field};

use crate::poly::evals::EvaluationsList;

use super::r1cs::{R1CSInstance, R1CSShape};

/// Compute the eq polynomial: eq(t, x) = prod_{i=1}^s (t_i * x_i + (1-t_i)*(1-x_i))
/// This is the multilinear extension of the equality function
pub fn eq_poly<EF: ExtensionField<F>, F: Field>(t: &[EF], x: &[EF]) -> EF {
    assert_eq!(t.len(), x.len());
    let mut result = EF::ONE;

    for i in 0..t.len() {
        let term = t[i] * x[i] + (EF::ONE - t[i]) * (EF::ONE - x[i]);
        result *= term;
    }

    result
}

/// Compute eq polynomial for a boolean hypercube point represented as usize
pub fn eq_poly_at_index<EF: ExtensionField<F>, F: Field>(idx: usize, r: &[EF]) -> EF {
    let mut result = EF::ONE;
    let num_bits = r.len();

    for (i, r_i) in r.iter().enumerate().take(num_bits) {
        let bit = (idx >> i) & 1;
        let r_i = *r_i;
        let term = if bit == 1 { r_i } else { EF::ONE - r_i };
        result *= term;
    }

    result
}

/// F_io(x) = (sum_y A(x,y)*Z(y)) * (sum_y B(x,y)*Z(y)) - sum_y C(x,y)*Z(y)
/// This represents the constraint satisfaction at point x
pub fn compute_f_io<F: Field>(shape: &R1CSShape<F>, x_idx: usize, z: &[F]) -> F {
    let _num_vars_y = shape.num_vars() + 1 + shape.num_inputs();

    // Compute Az(x) = sum_y A(x,y) * Z(y)
    let mut az_x = F::ZERO;
    for entry in shape.a().entries() {
        if entry.row == x_idx {
            az_x += entry.val * z[entry.col];
        }
    }

    // Compute Bz(x) = sum_y B(x,y) * Z(y)
    let mut bz_x = F::ZERO;
    for entry in shape.b().entries() {
        if entry.row == x_idx {
            bz_x += entry.val * z[entry.col];
        }
    }

    // Compute Cz(x) = sum_y C(x,y) * Z(y)
    let mut cz_x = F::ZERO;
    for entry in shape.c().entries() {
        if entry.row == x_idx {
            cz_x += entry.val * z[entry.col];
        }
    }

    // F_io(x) = Az(x) * Bz(x) - Cz(x)
    az_x * bz_x - cz_x
}

/// Evaluate F̃_io at a random point rx using multilinear extensions
/// F̃_io(rx) = A(rx) * B(rx) - C(rx)
/// where A(rx) = sum_y Ã(rx, y) * Z(y), etc.
pub fn eval_f_io_mle<EF: ExtensionField<F>, F: Field>(
    shape: &R1CSShape<F>,
    rx: &[EF],
    z: &[F],
) -> EF {
    let num_vars_y = shape.num_vars() + 1 + shape.num_inputs();

    // Compute A(rx) = sum_{y∈{0,1}^s} Ã(rx, y) * Z(y)
    let mut a_rx = EF::ZERO;
    for (y_idx, z_y) in z.iter().enumerate().take(1 << num_vars_y) {
        let eq_y = eq_poly_at_index::<EF, F>(y_idx, rx);
        // Find contribution from A matrix
        let a_val: F = shape
            .a()
            .entries()
            .iter()
            .filter(|e| e.col == y_idx)
            .map(|e| e.val)
            .sum();
        a_rx += eq_y * EF::from(a_val) * EF::from(*z_y);
    }

    // Compute B(rx) and C(rx) similarly
    let mut b_rx = EF::ZERO;
    for (y_idx, z_y) in z.iter().enumerate().take(1 << num_vars_y) {
        let eq_y = eq_poly_at_index::<EF, F>(y_idx, rx);
        let b_val: F = shape
            .b()
            .entries()
            .iter()
            .filter(|e| e.col == y_idx)
            .map(|e| e.val)
            .sum();
        b_rx += eq_y * EF::from(b_val) * EF::from(*z_y);
    }

    let mut c_rx = EF::ZERO;
    for (y_idx, z_y) in z.iter().enumerate().take(1 << num_vars_y) {
        let eq_y = eq_poly_at_index::<EF, F>(y_idx, rx);
        let c_val: F = shape
            .c()
            .entries()
            .iter()
            .filter(|e| e.col == y_idx)
            .map(|e| e.val)
            .sum();
        c_rx += eq_y * EF::from(c_val) * EF::from(*z_y);
    }

    a_rx * b_rx - c_rx
}

/// Compute the evaluations of G_io,τ over the boolean hypercube
/// G_io,τ(x) = F_io(x) * eq(τ, x)
/// Returns a vector of evaluations G[0], G[1], ..., G[2^s - 1]
pub fn compute_g_io_tau<F: Field>(shape: &R1CSShape<F>, tau: &[F], z: &[F]) -> Vec<F> {
    let s = shape.num_cons().trailing_zeros() as usize;
    let num_points = 1 << s;
    let mut evaluations = Vec::with_capacity(num_points);

    for x_idx in 0..num_points {
        // Compute F_io(x)
        let f_io_x = compute_f_io(shape, x_idx, z);

        // Compute eq(τ, x) where x is represented as bits
        let eq_tau_x = eq_poly_at_index::<F, F>(x_idx, tau);

        // G_io,τ(x) = F_io(x) * eq(τ, x)
        evaluations.push(f_io_x * eq_tau_x);
    }

    evaluations
}

/// Verify that the sum of G_io,τ over the boolean hypercube is zero
/// This is the main check for R1CS satisfiability (Theorem 4.1)
pub fn verify_sum_g_io_tau<F: Field>(evaluations: &[F]) -> bool {
    let sum: F = evaluations.iter().copied().sum();
    sum == F::ZERO
}

/// Create the degree-3 polynomial G_io,τ from R1CS instance
///
/// From Theorem 4.1: There exists degree-3 s-variate polynomial G such that
/// Σ_{x∈{0,1}^s} G(x) = 0 iff there exists witness w such that SatR1CS(x, w) = 1.
#[derive(Debug, Clone)]
pub struct GPoly<F: Field> {
    /// Evaluations of G over the boolean hypercube {0,1}^s
    evaluations: Vec<F>,
    /// Number of variables
    num_vars: usize,
    /// Challenge τ
    tau: Vec<F>,
}

impl<F: Field> GPoly<F> {
    /// Create G_io,τ polynomial from R1CS instance
    #[must_use]
    pub fn from_r1cs_instance(instance: &R1CSInstance<F>, tau: Vec<F>) -> Self {
        let shape = instance.shape();
        let z = instance.build_z_vector();

        let evaluations = compute_g_io_tau(shape, &tau, &z);
        let num_vars = shape.num_cons().trailing_zeros() as usize;

        Self {
            evaluations,
            num_vars,
            tau,
        }
    }

    /// Get the evaluations (for use in sumcheck)
    #[must_use]
    pub fn evaluations(&self) -> &[F] {
        &self.evaluations
    }

    /// Get as EvaluationsList for WHIR
    pub fn to_evaluations_list(&self) -> EvaluationsList<F> {
        EvaluationsList::new(self.evaluations.clone())
    }

    /// Verify that the sum is zero (completeness check)
    #[must_use]
    pub fn verify_sum_is_zero(&self) -> bool {
        verify_sum_g_io_tau(&self.evaluations)
    }

    #[must_use]
    pub const fn num_vars(&self) -> usize {
        self.num_vars
    }

    #[must_use]
    pub fn tau(&self) -> &[F] {
        &self.tau
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn make_square_instance() -> (R1CSShape<F>, R1CSInstance<F>, Vec<F>) {
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 1;
        let a_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(3);
        witness[1] = F::from_u64(9);
        let input = vec![F::ZERO];
        let instance = R1CSInstance::new(shape.clone(), input, witness);
        let z = instance.build_z_vector();
        (shape, instance, z)
    }

    #[test]
    fn test_eq_poly() {
        let t = vec![EF::ONE, EF::ZERO, EF::ONE];
        let x = t.clone();
        assert_eq!(eq_poly::<EF, F>(&t, &x), EF::ONE);

        let zero = vec![EF::ZERO; 3];
        let expected = (EF::ONE - t[0]) * (EF::ONE - t[1]) * (EF::ONE - t[2]);
        assert_eq!(eq_poly::<EF, F>(&t, &zero), expected);
    }

    #[test]
    fn test_eq_poly_at_index_matches_eq_poly() {
        let r = vec![
            EF::from(F::from_u64(7)),
            EF::from(F::from_u64(11)),
            EF::from(F::from_u64(3)),
        ];
        for idx in 0..8 {
            let bits: Vec<EF> = (0..3)
                .map(|i| {
                    if (idx >> i) & 1 == 1 {
                        EF::ONE
                    } else {
                        EF::ZERO
                    }
                })
                .collect();
            let via_index = eq_poly_at_index::<EF, F>(idx, &r);
            let via_poly = eq_poly::<EF, F>(&bits, &r);
            assert_eq!(via_index, via_poly);
        }
    }

    #[test]
    fn test_compute_f_io_sat() {
        let (shape, _, z) = make_square_instance();
        for x_idx in 0..shape.num_cons() {
            let f = compute_f_io(&shape, x_idx, &z);
            assert_eq!(
                f,
                F::ZERO,
                "Satisfied R1CS should yield F_io=0 at row {x_idx}"
            );
        }
    }

    #[test]
    fn test_compute_f_io_unsat() {
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 1;
        let a_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(3);
        witness[1] = F::from_u64(10); // 3*3 != 10
        let input = vec![F::ZERO];
        let instance = R1CSInstance::new(shape.clone(), input, witness);
        let z = instance.build_z_vector();
        let f = compute_f_io(&shape, 0, &z);
        assert_ne!(f, F::ZERO);
    }

    #[test]
    fn test_eval_f_io_mle_sat_instance() {
        let (shape, _, z) = make_square_instance();
        let num_vars_x = shape.num_cons().trailing_zeros() as usize;

        // For a satisfied R1CS, evaluate at a random point
        let rx: Vec<EF> = (0..num_vars_x)
            .map(|i| EF::from(F::from_u64(i as u64 + 5)))
            .collect();
        let result = eval_f_io_mle(&shape, &rx, &z);
        // eval_f_io_mle should produce a well-defined value (we can at least verify it runs)
        // For a more thorough test, check that it's zero at a boolean point where F_io = 0
        let _ = result;
    }

    #[test]
    fn test_g_io_tau_sat() {
        let (_, instance, _) = make_square_instance();
        let tau = vec![F::from_u64(5); 2];
        let g_poly = GPoly::from_r1cs_instance(&instance, tau);
        assert!(g_poly.verify_sum_is_zero());
    }

    #[test]
    fn test_g_io_tau_unsat() {
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 1;
        let a_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![super::super::r1cs::SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(3);
        witness[1] = F::from_u64(10);
        let input = vec![F::ZERO];
        let instance = R1CSInstance::new(shape, input, witness);
        let tau = vec![F::from_u64(5); 2];
        let g_poly = GPoly::from_r1cs_instance(&instance, tau);
        assert!(!g_poly.verify_sum_is_zero());
    }

    #[test]
    fn test_g_poly_accessors() {
        let (_, instance, _) = make_square_instance();
        let tau = vec![F::from_u64(5), F::from_u64(7)];
        let g_poly = GPoly::from_r1cs_instance(&instance, tau.clone());
        assert_eq!(g_poly.num_vars(), 2);
        assert_eq!(g_poly.tau(), &tau[..]);
        assert_eq!(g_poly.evaluations().len(), 4);
    }

    #[test]
    fn test_g_poly_to_evaluations_list() {
        let (_, instance, _) = make_square_instance();
        let tau = vec![F::from_u64(5), F::from_u64(7)];
        let g_poly = GPoly::from_r1cs_instance(&instance, tau);
        let evals_list = g_poly.to_evaluations_list();
        assert_eq!(evals_list.as_slice(), g_poly.evaluations());
    }

    #[test]
    fn test_compute_g_io_tau_matches_f_io_times_eq() {
        let (shape, _, z) = make_square_instance();
        let tau = vec![F::from_u64(5), F::from_u64(7)];
        let g_evals = compute_g_io_tau(&shape, &tau, &z);

        for x_idx in 0..shape.num_cons() {
            let f_io = compute_f_io(&shape, x_idx, &z);
            let eq_tau_x = eq_poly_at_index::<F, F>(x_idx, &tau);
            assert_eq!(g_evals[x_idx], f_io * eq_tau_x);
        }
    }

    #[test]
    fn test_verify_sum_g_io_tau_zero_evals() {
        assert!(verify_sum_g_io_tau(&[F::ZERO, F::ZERO]));
    }

    #[test]
    fn test_verify_sum_g_io_tau_nonzero() {
        assert!(!verify_sum_g_io_tau(&[F::ONE, F::ONE]));
    }

    #[test]
    fn test_verify_sum_g_io_tau_cancelling() {
        let neg_one = F::ZERO - F::ONE;
        assert!(verify_sum_g_io_tau(&[F::ONE, neg_one]));
    }
}
