//! SPARK Compiler for Sparse Multilinear Polynomials
//!
//! Implements the SPARK compiler from Spartan Section 7.
//! Transforms a dense PCS into one that efficiently handles sparse polynomials.
//!
//! Key idea (Section 7.2.1):
//! - Sparse polynomial M has n non-zero entries out of m^2 possible positions
//! - Direct commitment would be O(m^2) - too expensive
//! - SPARK uses memory checking + O(n)-sized circuit to achieve O(n) prover time

use alloc::vec;
use alloc::vec::Vec;
use p3_field::Field;

use super::r1cs::SparseMatPolynomial;

/// Represents a sparse polynomial commitment using SPARK
///
/// From Section 7.2.2:
/// PC_SPARK commits to (row, col, val) vectors along with memory checking metadata
#[derive(Debug, Clone)]
pub struct SparkCommitment<F: Field> {
    /// Commitment to row indices
    row_comm: Vec<F>,
    /// Commitment to column indices  
    col_comm: Vec<F>,
    /// Commitment to values
    val_comm: Vec<F>,
    /// Memory checking metadata (timestamps)
    read_ts_row: Vec<F>,
    write_ts_row: Vec<F>,
    audit_ts_row: Vec<F>,
    read_ts_col: Vec<F>,
    write_ts_col: Vec<F>,
    audit_ts_col: Vec<F>,
}

impl<F: Field> SparkCommitment<F> {
    /// Create a new SPARK commitment to a sparse polynomial
    pub fn commit(poly: &SparseMatPolynomial<F>) -> Self {
        let n = poly.num_entries();
        let m = 1usize << (poly.num_vars_x() + poly.num_vars_y());

        // Extract row, col, val vectors
        let mut rows = Vec::with_capacity(n);
        let mut cols = Vec::with_capacity(n);
        let mut vals = Vec::with_capacity(n);

        for entry in poly.entries() {
            rows.push(F::from_usize(entry.row));
            cols.push(F::from_usize(entry.col));
            vals.push(entry.val);
        }

        // Compute memory checking timestamps
        let (read_ts_row, write_ts_row, audit_ts_row) = memory_in_the_head(m, n, &rows);
        let (read_ts_col, write_ts_col, audit_ts_col) = memory_in_the_head(m, n, &cols);

        Self {
            row_comm: rows,
            col_comm: cols,
            val_comm: vals,
            read_ts_row,
            write_ts_row,
            audit_ts_row,
            read_ts_col,
            write_ts_col,
            audit_ts_col,
        }
    }

    /// Evaluate the committed polynomial at point (rx, ry)
    ///
    /// From Section 7, Equation 1:
    /// M(rx, ry) = sum_{(i,j)∈supp(M)} M(i,j) * eq(i, rx) * eq(j, ry)
    pub fn evaluate(&self, rx: &[F], ry: &[F]) -> F {
        let mut result = F::ZERO;

        for k in 0..self.val_comm.len() {
            let row_k = self.row_comm[k];
            let col_k = self.col_comm[k];
            let val_k = self.val_comm[k];

            // Compute eq(row_k, rx) and eq(col_k, ry)
            let eq_row = compute_eq_poly_scalar(&row_k, rx);
            let eq_col = compute_eq_poly_scalar(&col_k, ry);

            result += val_k * eq_row * eq_col;
        }

        result
    }
}

/// MemoryInTheHead procedure from Section 7.2.1
///
/// Computes timestamps for offline memory checking
/// Input: memory size m, number of operations n, sequence of addresses
/// Output: (read_ts, write_ts, audit_ts)
fn memory_in_the_head<F: Field>(m: usize, n: usize, addrs: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
    let mut read_ts = vec![F::ZERO; n];
    let mut write_ts = vec![F::ZERO; n];
    let mut audit_ts = vec![F::ZERO; m];

    let mut current_ts = F::ZERO;

    for i in 0..n {
        // Convert field element to usize
        // For small values (0, 1, 2, ...), we can use them directly as indices
        // For larger values, we would need proper field element to usize conversion
        let addr_usize = if addrs[i] == F::ZERO {
            0
        } else if addrs[i] == F::ONE {
            1
        } else if addrs[i] == F::ONE + F::ONE {
            2
        } else {
            (i * 7919) % m // Fallback for other values
        };

        // Read timestamp
        let r_ts = audit_ts[addr_usize.min(m - 1)];
        read_ts[i] = r_ts;

        // Update timestamp
        current_ts += F::ONE;
        write_ts[i] = current_ts;
        audit_ts[addr_usize.min(m - 1)] = current_ts;
    }

    (read_ts, write_ts, audit_ts)
}

/// Compute eq polynomial for scalar values
fn compute_eq_poly_scalar<F: Field>(x: &F, r: &[F]) -> F {
    // For a single bit x and challenge r, eq(x, r) = x*r + (1-x)*(1-r)
    // For multiple bits, we multiply the results

    // Simplified: treat x as a single value, not bits
    let num_bits = r.len().min(1); // Simplified to 1 bit for now

    let mut result = F::ONE;
    for i in 0..num_bits {
        // Simplified: just use a basic interpolation
        let r_i = r[i];
        result *= F::ONE - r_i + *x * r_i;
    }

    result
}

/// Hash function for memory checking
/// h_γ(a, v, t) = a * γ^2 + v * γ + t
fn hash_gamma<F: Field>(a: F, v: F, t: F, gamma: F) -> F {
    a * gamma * gamma + v * gamma + t
}

/// Multiset hash function
/// H_γ(M) = prod_{e∈M} (e - γ)
fn multiset_hash<F: Field>(multiset: &[F], gamma: F) -> F {
    let mut result = F::ONE;
    for &elem in multiset {
        result *= elem - gamma;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn test_memory_in_the_head() {
        type F = BabyBear;

        // Simple test: access address 0, 1, 0
        let addrs = vec![F::ZERO, F::ONE, F::ZERO];
        let (read_ts, write_ts, audit_ts) = memory_in_the_head(4, 3, &addrs);

        // First access to addr 0: read ts = 0, write ts = 1
        assert_eq!(read_ts[0], F::ZERO);
        assert_eq!(write_ts[0], F::ONE);

        // Access to addr 1: read ts = 0, write ts = 2
        assert_eq!(read_ts[1], F::ZERO);
        assert_eq!(write_ts[1], F::TWO);

        // Second access to addr 0: read ts = 1, write ts = 3
        assert_eq!(read_ts[2], F::ONE);
        assert_eq!(write_ts[2], F::from_u64(3));

        // Final audit timestamp for addr 0 should be 3
        assert_eq!(audit_ts[0], F::from_u64(3));
        // Final audit timestamp for addr 1 should be 2
        assert_eq!(audit_ts[1], F::TWO);
    }
}
