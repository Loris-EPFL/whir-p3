//! R1CS Core Structures and Polynomial Encoding
//!
//! Implements the R1CS to degree-3 polynomial encoding from Spartan Section 4.

use alloc::vec;
use alloc::vec::Vec;
use p3_field::{ExtensionField, Field};

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
    pub fn new(num_vars_x: usize, num_vars_y: usize, entries: Vec<SparseMatEntry<F>>) -> Self {
        Self {
            num_vars_x,
            num_vars_y,
            entries,
        }
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn num_vars_x(&self) -> usize {
        self.num_vars_x
    }

    pub fn num_vars_y(&self) -> usize {
        self.num_vars_y
    }

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
            let eq_row = compute_eq_poly(&entry.row, rx);
            // Compute eq polynomial for col
            let eq_col = compute_eq_poly(&entry.col, ry);
            // Add val * eq(i, rx) * eq(j, ry)
            result += EF::from(entry.val) * eq_row * eq_col;
        }

        result
    }
}

/// Compute eq(x, r) = prod_{i=1}^m (x_i * r_i + (1-x_i)*(1-r_i))
/// where x is an integer representing bits and r is the evaluation point
fn compute_eq_poly<EF: ExtensionField<F>, F: Field>(x: &usize, r: &[EF]) -> EF {
    let mut result = EF::ONE;
    let num_bits = r.len();

    for i in 0..num_bits {
        let bit = (*x >> i) & 1;
        let r_i = r[i];
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

    pub fn num_cons(&self) -> usize {
        self.num_cons
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    /// Number of variables for polynomial x-dimension (log2 of num_cons)
    pub fn num_poly_vars_x(&self) -> usize {
        self.num_cons.trailing_zeros() as usize
    }

    /// Number of variables for polynomial y-dimension (log2 of num_cols)
    pub fn num_poly_vars_y(&self) -> usize {
        ((2 * self.num_vars).trailing_zeros()) as usize
    }

    pub fn a(&self) -> &SparseMatPolynomial<F> {
        &self.a
    }

    pub fn b(&self) -> &SparseMatPolynomial<F> {
        &self.b
    }

    pub fn c(&self) -> &SparseMatPolynomial<F> {
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
    pub fn new(shape: R1CSShape<F>, input: Vec<F>, witness: Vec<F>) -> Self {
        assert_eq!(witness.len(), shape.num_vars());
        assert_eq!(input.len(), shape.num_inputs());
        Self {
            shape,
            input,
            witness,
        }
    }

    pub fn shape(&self) -> &R1CSShape<F> {
        &self.shape
    }

    pub fn input(&self) -> &[F] {
        &self.input
    }

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
    pub fn verify(&self) -> bool {
        self.shape.is_sat(&self.witness, &self.input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn test_sparse_mat_multiply() {
        type F = BabyBear;

        // Simple test: matrix with single entry at (0, 0) = 1
        let entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let mat = SparseMatPolynomial::new(2, 2, entries); // 4x4 matrix

        let z = vec![F::ONE, F::ZERO, F::ZERO, F::ZERO];
        let result = mat.multiply_vec(4, 4, &z);

        assert_eq!(result[0], F::ONE);
        assert_eq!(result[1], F::ZERO);
        assert_eq!(result[2], F::ZERO);
        assert_eq!(result[3], F::ZERO);
    }

    #[test]
    fn test_r1cs_shape_sat() {
        type F = BabyBear;

        // Create a simple R1CS: x * x = x^2
        // One constraint, one variable
        let num_cons = 2usize.pow(2); // Must be power of 2
        let num_vars = 2usize.pow(2); // Must be power of 2
        let num_inputs = 1;

        // Constraint: w[0] * w[0] = w[1]
        // A = [1 at (0,0)]
        // B = [1 at (0,0)]
        // C = [1 at (0,1)]
        let a_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![SparseMatEntry::new(0, 1, F::ONE)];

        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );

        // Witness: w[0] = 2, w[1] = 4 (since 2*2 = 4)
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(2);
        witness[1] = F::from_u64(4);

        let input = vec![F::ZERO];

        assert!(shape.is_sat(&witness, &input));
    }
}
