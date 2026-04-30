//! R1CS Core Structures and Polynomial Encoding
//!
//! Implements the R1CS to degree-3 polynomial encoding from Spartan Section 4.

use alloc::vec;
use alloc::vec::Vec;
use p3_field::{ExtensionField, Field};
use rand::RngExt;

/// A sparse matrix entry (row, col, value)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseMatEntry<F: Field> {
    pub row: usize,
    pub col: usize,
    pub val: F,
}

impl<F: Field> SparseMatEntry<F> {
    pub const fn new(row: usize, col: usize, val: F) -> Self {
        Self { row, col, val }
    }
}

/// Sparse matrix polynomial representation
/// Represents a sparse matrix as a multilinear polynomial
#[derive(Debug, Clone)]
pub struct SparseMatPolynomial<F: Field> {
    /// Number of variables for row index (log2 of num_rows)
    num_vars_x: usize,
    /// Number of variables for column index (log2 of num_cols)
    num_vars_y: usize,
    /// Non-zero entries
    entries: Vec<SparseMatEntry<F>>,
}

impl<F: Field> SparseMatPolynomial<F> {
    #[must_use]
    pub const fn new(
        num_vars_x: usize,
        num_vars_y: usize,
        entries: Vec<SparseMatEntry<F>>,
    ) -> Self {
        Self {
            num_vars_x,
            num_vars_y,
            entries,
        }
    }

    #[must_use]
    pub const fn num_entries(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn num_vars_x(&self) -> usize {
        self.num_vars_x
    }

    #[must_use]
    pub const fn num_vars_y(&self) -> usize {
        self.num_vars_y
    }

    #[must_use]
    pub fn entries(&self) -> &[SparseMatEntry<F>] {
        &self.entries
    }

    /// Multiply the matrix by a vector
    /// Returns Az, Bz, or Cz depending on which matrix this is
    pub fn multiply_vec(&self, num_rows: usize, num_cols: usize, z: &[F]) -> Vec<F> {
        assert_eq!(z.len(), num_cols);
        let mut result = vec![F::ZERO; num_rows];

        for entry in &self.entries {
            result[entry.row] += entry.val * z[entry.col];
        }

        result
    }

    /// Evaluate the sparse matrix polynomial at points (rx, ry)
    /// From Spartan Section 4: Computes M(rx, ry) = sum_{(i,j,val)} val * eq(i, rx) * eq(j, ry)
    pub fn evaluate<EF: ExtensionField<F>>(&self, rx: &[EF], ry: &[EF]) -> EF {
        assert_eq!(rx.len(), self.num_vars_x);
        assert_eq!(ry.len(), self.num_vars_y);

        let mut result = EF::ZERO;

        for entry in &self.entries {
            // Compute eq polynomial for row
            let eq_row = compute_eq_poly(entry.row, rx);
            // Compute eq polynomial for col
            let eq_col = compute_eq_poly(entry.col, ry);
            // Add val * eq(i, rx) * eq(j, ry)
            result += EF::from(entry.val) * eq_row * eq_col;
        }

        result
    }
}

/// Compute eq(x, r) = prod_{i=1}^m (x_i * r_i + (1-x_i)*(1-r_i))
/// where x is an integer representing bits and r is the evaluation point
fn compute_eq_poly<EF: ExtensionField<F>, F: Field>(x: usize, r: &[EF]) -> EF {
    let mut result = EF::ONE;
    let num_bits = r.len();

    for (i, r_i) in r.iter().enumerate().take(num_bits) {
        let bit = (x >> i) & 1;
        let r_i = *r_i;
        let term = if bit == 1 { r_i } else { EF::ONE - r_i };
        result *= term;
    }

    result
}

/// R1CS Shape: Contains the constraint matrices A, B, C
#[derive(Debug, Clone)]
pub struct R1CSShape<F: Field> {
    /// Number of constraints (rows)
    num_cons: usize,
    /// Number of variables (columns in witness)
    num_vars: usize,
    /// Number of public inputs
    num_inputs: usize,
    /// Matrix A (left side of constraint)
    a: SparseMatPolynomial<F>,
    /// Matrix B (right side of constraint)
    b: SparseMatPolynomial<F>,
    /// Matrix C (output side of constraint)
    c: SparseMatPolynomial<F>,
}

impl<F: Field> R1CSShape<F> {
    /// Create a new R1CS shape from constraint matrices
    #[must_use]
    pub fn new(
        num_cons: usize,
        num_vars: usize,
        num_inputs: usize,
        a_entries: Vec<SparseMatEntry<F>>,
        b_entries: Vec<SparseMatEntry<F>>,
        c_entries: Vec<SparseMatEntry<F>>,
    ) -> Self {
        assert!(num_cons.is_power_of_two(), "num_cons must be power of two");
        assert!(num_vars.is_power_of_two(), "num_vars must be power of two");
        assert!(
            num_inputs < num_vars,
            "num_inputs must be less than num_vars"
        );

        let num_poly_vars_x = num_cons.trailing_zeros() as usize;
        let num_poly_vars_y = ((2 * num_vars).trailing_zeros()) as usize;

        Self {
            num_cons,
            num_vars,
            num_inputs,
            a: SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, a_entries),
            b: SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, b_entries),
            c: SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, c_entries),
        }
    }

    #[must_use]
    pub const fn num_cons(&self) -> usize {
        self.num_cons
    }

    #[must_use]
    pub const fn num_vars(&self) -> usize {
        self.num_vars
    }

    #[must_use]
    pub const fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    /// Number of variables for polynomial x-dimension (log2 of num_cons)
    #[must_use]
    pub const fn num_poly_vars_x(&self) -> usize {
        self.num_cons.trailing_zeros() as usize
    }

    /// Number of variables for polynomial y-dimension (log2 of num_cols)
    #[must_use]
    pub const fn num_poly_vars_y(&self) -> usize {
        ((2 * self.num_vars).trailing_zeros()) as usize
    }

    #[must_use]
    pub const fn a(&self) -> &SparseMatPolynomial<F> {
        &self.a
    }

    #[must_use]
    pub const fn b(&self) -> &SparseMatPolynomial<F> {
        &self.b
    }

    #[must_use]
    pub const fn c(&self) -> &SparseMatPolynomial<F> {
        &self.c
    }

    /// Check if a witness satisfies the R1CS constraints
    /// Returns true if Az * Bz - Cz = 0 for all constraints
    pub fn is_sat(&self, vars: &[F], input: &[F]) -> bool {
        assert_eq!(vars.len(), self.num_vars);
        assert_eq!(input.len(), self.num_inputs);

        // Build the full z vector: [vars, 1, input, padding]
        let size_z = 2 * self.num_vars;
        let mut z = vec![F::ZERO; size_z];
        z[..self.num_vars].copy_from_slice(vars);
        z[self.num_vars] = F::ONE; // constant term
        z[self.num_vars + 1..self.num_vars + 1 + self.num_inputs].copy_from_slice(input);

        // Compute Az, Bz, Cz
        let az = self.a.multiply_vec(self.num_cons, size_z, &z);
        let bz = self.b.multiply_vec(self.num_cons, size_z, &z);
        let cz = self.c.multiply_vec(self.num_cons, size_z, &z);

        // Check Az * Bz - Cz = 0 for all constraints
        for i in 0..self.num_cons {
            if az[i] * bz[i] != cz[i] {
                return false;
            }
        }

        true
    }

    /// Evaluate all three matrices at points (rx, ry)
    /// Returns (A(rx, ry), B(rx, ry), C(rx, ry))
    pub fn evaluate<EF: ExtensionField<F>>(&self, rx: &[EF], ry: &[EF]) -> (EF, EF, EF) {
        (
            self.a.evaluate(rx, ry),
            self.b.evaluate(rx, ry),
            self.c.evaluate(rx, ry),
        )
    }

    /// Multiply the constraint matrices by the witness vector
    /// Returns (Az, Bz, Cz) as dense polynomials
    pub fn multiply_vec(&self, z: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
        let size_z = self.num_vars + 1 + self.num_inputs;
        (
            self.a.multiply_vec(self.num_cons, size_z, z),
            self.b.multiply_vec(self.num_cons, size_z, z),
            self.c.multiply_vec(self.num_cons, size_z, z),
        )
    }
}

/// Represents an R1CS instance with a satisfying assignment
/// Z = (io, 1, w) where w is the witness
#[derive(Debug, Clone)]
pub struct R1CSInstance<F: Field> {
    /// The R1CS shape (constraint matrices)
    shape: R1CSShape<F>,
    /// Public input
    input: Vec<F>,
    /// Witness (private input)
    witness: Vec<F>,
}

impl<F: Field> R1CSInstance<F> {
    #[must_use]
    pub fn new(shape: R1CSShape<F>, input: Vec<F>, witness: Vec<F>) -> Self {
        assert_eq!(witness.len(), shape.num_vars());
        assert_eq!(input.len(), shape.num_inputs());
        Self {
            shape,
            input,
            witness,
        }
    }

    #[must_use]
    pub const fn shape(&self) -> &R1CSShape<F> {
        &self.shape
    }

    #[must_use]
    pub fn input(&self) -> &[F] {
        &self.input
    }

    #[must_use]
    pub fn witness(&self) -> &[F] {
        &self.witness
    }

    /// Build the full Z vector: [witness, 1, input]
    pub fn build_z_vector(&self) -> Vec<F> {
        // We need the Z vector to be a power of two to use with EvaluationsList
        // The number of variables in the polynomial representation is determined by
        // num_poly_vars_y which is log2(2 * num_vars)
        let size_z = 2 * self.shape.num_vars();
        let mut z = vec![F::ZERO; size_z];
        z[..self.shape.num_vars()].copy_from_slice(&self.witness);
        z[self.shape.num_vars()] = F::ONE;
        z[self.shape.num_vars() + 1..self.shape.num_vars() + 1 + self.shape.num_inputs()]
            .copy_from_slice(&self.input);
        z
    }

    /// Verify that the witness satisfies the constraints
    #[must_use]
    /// Produces a synthetic R1CS instance for benchmarking.

    pub fn verify(&self) -> bool {
        self.shape.is_sat(&self.witness, &self.input)
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

    fn make_square_shape() -> (R1CSShape<F>, Vec<F>, Vec<F>) {
        let num_cons = 4;
        let num_vars = 4;
        let num_inputs = 1;
        let a_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(2);
        witness[1] = F::from_u64(4);
        let input = vec![F::ZERO];
        (shape, witness, input)
    }

    #[test]
    fn test_sparse_mat_multiply() {
        let entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let mat = SparseMatPolynomial::new(2, 2, entries);

        let z = vec![F::ONE, F::ZERO, F::ZERO, F::ZERO];
        let result = mat.multiply_vec(4, 4, &z);

        assert_eq!(result[0], F::ONE);
        assert_eq!(result[1], F::ZERO);
        assert_eq!(result[2], F::ZERO);
        assert_eq!(result[3], F::ZERO);
    }

    #[test]
    fn test_sparse_mat_multiply_multiple_entries() {
        let entries = vec![
            SparseMatEntry::new(0, 0, F::from_u64(2)),
            SparseMatEntry::new(0, 1, F::from_u64(3)),
            SparseMatEntry::new(1, 0, F::ONE),
        ];
        let mat = SparseMatPolynomial::new(1, 1, entries);

        let z = vec![F::from_u64(5), F::from_u64(7)];
        let result = mat.multiply_vec(2, 2, &z);

        // row 0: 2*5 + 3*7 = 31
        assert_eq!(result[0], F::from_u64(31));
        // row 1: 1*5 = 5
        assert_eq!(result[1], F::from_u64(5));
    }

    #[test]
    fn test_sparse_mat_evaluate() {
        let entries = vec![SparseMatEntry::new(0, 0, F::from_u64(3))];
        let mat = SparseMatPolynomial::new(1, 1, entries);

        let rx = vec![EF::ONE];
        let ry = vec![EF::ONE];
        let result = mat.evaluate(&rx, &ry);
        // eq(0, [1]) = 1-1 = 0 → but entry at row=0 so eq(0, rx=[1]) = 1 - 1 = 0
        // Actually, bit 0 of row=0 is 0, so eq = (1 - rx[0]) = (1 - 1) = 0.
        // Let's try rx = [0.5]
        let half = EF::from(F::from_u64(2)).inverse();
        let rx2 = vec![half];
        let ry2 = vec![half];
        let result2 = mat.evaluate(&rx2, &ry2);
        // eq(0, [0.5]) = (1 - 0.5) = 0.5, eq(0, [0.5]) = 0.5
        // result = 3 * 0.5 * 0.5 = 0.75
        let expected = EF::from(F::from_u64(3)) * half * half;
        assert_eq!(result2, expected);
        // At rx=[1], ry=[1]: eq(0, [1]) = 0, so result should be 0
        assert_eq!(result, EF::ZERO);
    }

    #[test]
    fn test_sparse_mat_num_entries() {
        let entries = vec![
            SparseMatEntry::new(0, 0, F::ONE),
            SparseMatEntry::new(1, 1, F::ONE),
        ];
        let mat = SparseMatPolynomial::new(1, 1, entries);
        assert_eq!(mat.num_entries(), 2);
        assert_eq!(mat.num_vars_x(), 1);
        assert_eq!(mat.num_vars_y(), 1);
    }

    #[test]
    fn test_r1cs_shape_sat() {
        let (shape, witness, input) = make_square_shape();
        assert!(shape.is_sat(&witness, &input));
    }

    #[test]
    fn test_r1cs_shape_unsat() {
        let (shape, mut witness, input) = make_square_shape();
        witness[1] = F::from_u64(5); // 2*2 != 5
        assert!(!shape.is_sat(&witness, &input));
    }

    #[test]
    fn test_r1cs_shape_accessors() {
        let (shape, _, _) = make_square_shape();
        assert_eq!(shape.num_cons(), 4);
        assert_eq!(shape.num_vars(), 4);
        assert_eq!(shape.num_inputs(), 1);
        assert_eq!(shape.num_poly_vars_x(), 2);
        assert_eq!(shape.num_poly_vars_y(), 3); // log2(2 * 4) = 3
        assert_eq!(shape.a().num_entries(), 1);
        assert_eq!(shape.b().num_entries(), 1);
        assert_eq!(shape.c().num_entries(), 1);
    }

    #[test]
    fn test_r1cs_shape_evaluate() {
        let (shape, _, _) = make_square_shape();
        let rx = vec![EF::ZERO; shape.num_poly_vars_x()];
        let ry = vec![EF::ZERO; shape.num_poly_vars_y()];
        let (a_eval, b_eval, c_eval) = shape.evaluate(&rx, &ry);
        // At rx=0, ry=0: eq(0,[0,0]) = 1*1 = 1 for all entries at row=0, col=0
        assert_eq!(a_eval, EF::ONE);
        assert_eq!(b_eval, EF::ONE);
        // C has entry at (0,1), eq(1, [0,0,0]) for col=1: bit0=1 → ry[0]=0, so eq=0
        assert_eq!(c_eval, EF::ZERO);
    }

    #[test]
    fn test_r1cs_shape_multiply_vec() {
        let (shape, witness, input) = make_square_shape();
        let mut z = vec![F::ZERO; 2 * shape.num_vars()];
        z[..shape.num_vars()].copy_from_slice(&witness);
        z[shape.num_vars()] = F::ONE;
        z[shape.num_vars() + 1..shape.num_vars() + 1 + shape.num_inputs()].copy_from_slice(&input);

        let (az, bz, cz) = shape.multiply_vec(&z[..shape.num_vars() + 1 + shape.num_inputs()]);
        // For constraint 0: A*z = w[0] = 2, B*z = w[0] = 2, C*z = w[1] = 4
        assert_eq!(az[0], F::from_u64(2));
        assert_eq!(bz[0], F::from_u64(2));
        assert_eq!(cz[0], F::from_u64(4));
        // A*z * B*z = C*z → 2*2 = 4 ✓
        assert_eq!(az[0] * bz[0], cz[0]);
    }

    #[test]
    fn test_r1cs_instance_new_and_verify() {
        let (shape, witness, input) = make_square_shape();
        let instance = R1CSInstance::new(shape, input.clone(), witness.clone());

        assert_eq!(instance.input(), &input[..]);
        assert_eq!(instance.witness(), &witness[..]);
        assert!(instance.verify());
    }

    #[test]
    fn test_r1cs_instance_build_z_vector() {
        let (shape, witness, input) = make_square_shape();
        let instance = R1CSInstance::new(shape, input.clone(), witness.clone());
        let z = instance.build_z_vector();

        assert_eq!(z.len(), 8); // 2 * num_vars = 2 * 4
        assert_eq!(&z[..4], &witness[..]);
        assert_eq!(z[4], F::ONE); // constant term
        assert_eq!(z[5], input[0]); // public input
    }

    #[test]
    fn test_r1cs_instance_unsat_verify() {
        let (shape, mut witness, input) = make_square_shape();
        witness[1] = F::from_u64(99);
        let instance = R1CSInstance::new(shape, input, witness);
        assert!(!instance.verify());
    }

    #[test]
    fn test_produce_synthetic_r1cs() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(42);

        let (shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(4, 4, 1, &mut rng);
        assert_eq!(shape.num_cons(), 4);
        assert_eq!(shape.num_vars(), 4);
        assert_eq!(shape.num_inputs(), 1);
        assert!(instance.verify());
    }

    #[test]
    fn test_produce_synthetic_r1cs_larger() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(123);

        let (shape, instance) = R1CSInstance::<F>::produce_synthetic_r1cs(16, 8, 3, &mut rng);
        assert_eq!(shape.num_cons(), 16);
        assert_eq!(shape.num_vars(), 8);
        assert_eq!(shape.num_inputs(), 3);
        assert!(instance.verify());
    }

    #[test]
    fn test_compute_eq_poly() {
        // eq(0, [r]) = 1 - r for each bit
        let r = vec![EF::from(F::from_u64(3))];
        let eq_0 = compute_eq_poly::<EF, F>(0, &r);
        assert_eq!(eq_0, EF::ONE - EF::from(F::from_u64(3)));

        let eq_1 = compute_eq_poly::<EF, F>(1, &r);
        assert_eq!(eq_1, EF::from(F::from_u64(3)));

        // eq(x, x) on boolean hypercube = 1
        let bits = vec![EF::ONE, EF::ZERO, EF::ONE];
        let eq_self = compute_eq_poly::<EF, F>(0b101, &bits);
        assert_eq!(eq_self, EF::ONE);
    }
}

impl<F: p3_field::Field> R1CSInstance<F>
where
    rand::distr::StandardUniform: rand::distr::Distribution<F>,
{
    /// Produces a synthetic R1CS instance for benchmarking.
    pub fn produce_synthetic_r1cs(
        num_cons: usize,
        num_vars: usize,
        num_inputs: usize,
        rng: &mut impl rand::Rng,
    ) -> (R1CSShape<F>, Self) {
        assert!(
            num_cons.is_power_of_two(),
            "num_cons must be a power of two"
        );
        assert!(
            num_vars.is_power_of_two(),
            "num_vars must be a power of two"
        );
        assert!(
            num_inputs < num_vars,
            "num_inputs must be less than num_vars"
        );

        let mut witness = vec![F::ZERO; num_vars];
        let mut input = vec![F::ZERO; num_inputs];

        for i in 0..num_vars {
            witness[i] = rng.random();
        }
        for i in 0..num_inputs {
            input[i] = rng.random();
        }

        let size_z = 2 * num_vars;
        let mut z = vec![F::ZERO; size_z];
        z[..num_vars].copy_from_slice(&witness);
        z[num_vars] = F::ONE;
        z[num_vars + 1..num_vars + 1 + num_inputs].copy_from_slice(&input);

        let mut a_entries = Vec::new();
        let mut b_entries = Vec::new();
        let mut c_entries = Vec::new();

        let one = F::ONE;
        let max_idx = num_vars + 1 + num_inputs;

        for i in 0..num_cons {
            let a_idx = i % max_idx;
            let b_idx = (i + 2) % max_idx;

            a_entries.push(SparseMatEntry::new(i, a_idx, one));
            b_entries.push(SparseMatEntry::new(i, b_idx, one));

            let ab_val = z[a_idx] * z[b_idx];

            let c_idx = (i + 3) % max_idx;
            let c_val = z[c_idx];

            if c_val == F::ZERO {
                c_entries.push(SparseMatEntry::new(i, num_vars, ab_val));
            } else {
                let coeff = ab_val * c_val.inverse();
                c_entries.push(SparseMatEntry::new(i, c_idx, coeff));
            }
        }

        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );
        let instance = Self::new(shape.clone(), input, witness);
        (shape, instance)
    }
}
