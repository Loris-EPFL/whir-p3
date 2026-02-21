//! SPARK Compiler for Sparse Multilinear Polynomials
//!
//! Implements a soundness-oriented SPARK artifact for sparse matrix openings.
//! This module keeps prover/verifier checks explicit and deterministic.

use alloc::vec;
use alloc::vec::Vec;
use p3_field::Field;

use super::r1cs::SparseMatPolynomial;

/// Represents a sparse polynomial commitment using SPARK.
#[derive(Debug, Clone)]
pub struct SparkCommitment<F: Field> {
    /// Row indices.
    row_indices: Vec<usize>,
    /// Column indices.
    col_indices: Vec<usize>,
    /// Committed values.
    val_comm: Vec<F>,
    /// Row/column domain sizes.
    num_rows: usize,
    num_cols: usize,
    /// Memory checking metadata (timestamps).
    read_ts_row: Vec<F>,
    write_ts_row: Vec<F>,
    audit_ts_row: Vec<F>,
    read_ts_col: Vec<F>,
    write_ts_col: Vec<F>,
    audit_ts_col: Vec<F>,
}

/// Transcript-derived compression challenges for SPARK payload binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparkCompressionChallenges<F: Field> {
    pub gamma: F,
    pub eta: F,
}

/// Batched opening values for matrix evaluations at (rx, ry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparkBatchOpening<F: Field> {
    pub a_eval: F,
    pub b_eval: F,
    pub c_eval: F,
    pub batched_eval: F,
}

/// Prover-reported complexity profile for SPARK proof materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparkCostProfile {
    pub non_zero_entries: usize,
    pub row_timestamp_entries: usize,
    pub col_timestamp_entries: usize,
    pub field_mul_estimate: usize,
    pub field_add_estimate: usize,
    pub serialized_field_elements: usize,
}

/// Standalone SPARK proof artifact.
///
/// Carries full matrix commitment payload plus compressed digests and batched opening.
#[derive(Debug, Clone)]
pub struct SparkProof<F: Field> {
    pub a_comm: SparkCommitment<F>,
    pub b_comm: SparkCommitment<F>,
    pub c_comm: SparkCommitment<F>,
    pub compression_challenges: SparkCompressionChallenges<F>,
    pub a_digest: F,
    pub b_digest: F,
    pub c_digest: F,
    pub batch_opening: SparkBatchOpening<F>,
    pub cost_profile: SparkCostProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparkEvaluations<F: Field> {
    pub a_eval: F,
    pub b_eval: F,
    pub c_eval: F,
}

impl<F: Field> SparkCommitment<F> {
    /// Create a new SPARK commitment to a sparse polynomial.
    #[must_use] 
    pub fn commit(poly: &SparseMatPolynomial<F>) -> Self {
        let n = poly.num_entries();
        let num_rows = 1usize << poly.num_vars_x();
        let num_cols = 1usize << poly.num_vars_y();

        let mut rows = Vec::with_capacity(n);
        let mut cols = Vec::with_capacity(n);
        let mut vals = Vec::with_capacity(n);

        for entry in poly.entries() {
            rows.push(entry.row);
            cols.push(entry.col);
            vals.push(entry.val);
        }

        let (read_ts_row, write_ts_row, audit_ts_row) = memory_in_the_head(num_rows, n, &rows);
        let (read_ts_col, write_ts_col, audit_ts_col) = memory_in_the_head(num_cols, n, &cols);

        Self {
            row_indices: rows,
            col_indices: cols,
            val_comm: vals,
            num_rows,
            num_cols,
            read_ts_row,
            write_ts_row,
            audit_ts_row,
            read_ts_col,
            write_ts_col,
            audit_ts_col,
        }
    }

    /// Evaluate the committed polynomial at point (rx, ry).
    pub fn evaluate(&self, rx: &[F], ry: &[F]) -> F {
        let mut result = F::ZERO;

        for k in 0..self.val_comm.len() {
            let row_k = self.row_indices[k];
            let col_k = self.col_indices[k];
            let val_k = self.val_comm[k];

            let eq_row = compute_eq_poly_index(row_k, rx);
            let eq_col = compute_eq_poly_index(col_k, ry);

            result += val_k * eq_row * eq_col;
        }

        result
    }

    /// Verifies memory-checking metadata consistency for row/col access streams.
    #[must_use] 
    pub fn verify_structure(&self) -> bool {
        verify_memory_in_the_head(
            self.num_rows,
            self.row_indices.len(),
            &self.row_indices,
            &self.read_ts_row,
            &self.write_ts_row,
            &self.audit_ts_row,
        ) && verify_memory_in_the_head(
            self.num_cols,
            self.col_indices.len(),
            &self.col_indices,
            &self.read_ts_col,
            &self.write_ts_col,
            &self.audit_ts_col,
        )
    }

    /// Compressed digest that binds row/col/value and memory-check metadata.
    pub fn compressed_digest(&self, gamma: F) -> F {
        let mut elems = Vec::with_capacity(
            self.val_comm.len() * 6 + self.audit_ts_row.len() + self.audit_ts_col.len(),
        );

        for k in 0..self.val_comm.len() {
            let row = F::from_usize(self.row_indices[k]);
            let col = F::from_usize(self.col_indices[k]);
            let val = self.val_comm[k];
            elems.push(hash_gamma(row, val, self.read_ts_row[k], gamma));
            elems.push(hash_gamma(row, val, self.write_ts_row[k], gamma));
            elems.push(hash_gamma(col, val, self.read_ts_col[k], gamma));
            elems.push(hash_gamma(col, val, self.write_ts_col[k], gamma));
            elems.push(hash_gamma(row, col, val, gamma));
            elems.push(hash_gamma(val, row, col, gamma));
        }

        for &ts in &self.audit_ts_row {
            elems.push(hash_gamma(F::ZERO, F::ONE, ts, gamma));
        }
        for &ts in &self.audit_ts_col {
            elems.push(hash_gamma(F::ONE, F::ZERO, ts, gamma));
        }

        multiset_hash(&elems, gamma)
    }

    const fn cost_profile(&self) -> SparkCostProfile {
        let n = self.val_comm.len();
        let row_t = self.read_ts_row.len() + self.write_ts_row.len() + self.audit_ts_row.len();
        let col_t = self.read_ts_col.len() + self.write_ts_col.len() + self.audit_ts_col.len();
        let serialized_field_elements = n + row_t + col_t;

        SparkCostProfile {
            non_zero_entries: n,
            row_timestamp_entries: row_t,
            col_timestamp_entries: col_t,
            field_mul_estimate: 12 * n + self.audit_ts_row.len() + self.audit_ts_col.len(),
            field_add_estimate: 10 * n + self.audit_ts_row.len() + self.audit_ts_col.len(),
            serialized_field_elements,
        }
    }
}

impl<F: Field> SparkProof<F> {
    pub fn from_matrices(
        a: &SparseMatPolynomial<F>,
        b: &SparseMatPolynomial<F>,
        c: &SparseMatPolynomial<F>,
        rx: &[F],
        ry: &[F],
        challenges: SparkCompressionChallenges<F>,
    ) -> Self {
        let a_comm = SparkCommitment::commit(a);
        let b_comm = SparkCommitment::commit(b);
        let c_comm = SparkCommitment::commit(c);

        let a_eval = a_comm.evaluate(rx, ry);
        let b_eval = b_comm.evaluate(rx, ry);
        let c_eval = c_comm.evaluate(rx, ry);
        let batched_eval = a_eval + challenges.eta * b_eval + challenges.eta.square() * c_eval;

        let a_digest = a_comm.compressed_digest(challenges.gamma);
        let b_digest = b_comm.compressed_digest(challenges.gamma);
        let c_digest = c_comm.compressed_digest(challenges.gamma);

        let a_cost = a_comm.cost_profile();
        let b_cost = b_comm.cost_profile();
        let c_cost = c_comm.cost_profile();

        Self {
            a_comm,
            b_comm,
            c_comm,
            compression_challenges: challenges,
            a_digest,
            b_digest,
            c_digest,
            batch_opening: SparkBatchOpening {
                a_eval,
                b_eval,
                c_eval,
                batched_eval,
            },
            cost_profile: SparkCostProfile {
                non_zero_entries: a_cost.non_zero_entries
                    + b_cost.non_zero_entries
                    + c_cost.non_zero_entries,
                row_timestamp_entries: a_cost.row_timestamp_entries
                    + b_cost.row_timestamp_entries
                    + c_cost.row_timestamp_entries,
                col_timestamp_entries: a_cost.col_timestamp_entries
                    + b_cost.col_timestamp_entries
                    + c_cost.col_timestamp_entries,
                field_mul_estimate: a_cost.field_mul_estimate
                    + b_cost.field_mul_estimate
                    + c_cost.field_mul_estimate,
                field_add_estimate: a_cost.field_add_estimate
                    + b_cost.field_add_estimate
                    + c_cost.field_add_estimate,
                serialized_field_elements: a_cost.serialized_field_elements
                    + b_cost.serialized_field_elements
                    + c_cost.serialized_field_elements
                    + 8,
            },
        }
    }

    pub fn verify(
        &self,
        rx: &[F],
        ry: &[F],
        expected_challenges: SparkCompressionChallenges<F>,
    ) -> Result<SparkEvaluations<F>, &'static str> {
        if self.compression_challenges != expected_challenges {
            return Err("SPARK challenge mismatch");
        }

        if !self.a_comm.verify_structure() {
            return Err("SPARK structure check failed: A");
        }
        if !self.b_comm.verify_structure() {
            return Err("SPARK structure check failed: B");
        }
        if !self.c_comm.verify_structure() {
            return Err("SPARK structure check failed: C");
        }

        let gamma = expected_challenges.gamma;
        if self.a_comm.compressed_digest(gamma) != self.a_digest {
            return Err("SPARK digest mismatch: A");
        }
        if self.b_comm.compressed_digest(gamma) != self.b_digest {
            return Err("SPARK digest mismatch: B");
        }
        if self.c_comm.compressed_digest(gamma) != self.c_digest {
            return Err("SPARK digest mismatch: C");
        }

        let a_eval = self.a_comm.evaluate(rx, ry);
        let b_eval = self.b_comm.evaluate(rx, ry);
        let c_eval = self.c_comm.evaluate(rx, ry);
        if a_eval != self.batch_opening.a_eval {
            return Err("SPARK opening mismatch: A");
        }
        if b_eval != self.batch_opening.b_eval {
            return Err("SPARK opening mismatch: B");
        }
        if c_eval != self.batch_opening.c_eval {
            return Err("SPARK opening mismatch: C");
        }

        let eta = expected_challenges.eta;
        let expected_batch = a_eval + eta * b_eval + eta.square() * c_eval;
        if expected_batch != self.batch_opening.batched_eval {
            return Err("SPARK opening mismatch: batched");
        }

        let expected_cost = {
            let a = self.a_comm.cost_profile();
            let b = self.b_comm.cost_profile();
            let c = self.c_comm.cost_profile();
            SparkCostProfile {
                non_zero_entries: a.non_zero_entries + b.non_zero_entries + c.non_zero_entries,
                row_timestamp_entries: a.row_timestamp_entries
                    + b.row_timestamp_entries
                    + c.row_timestamp_entries,
                col_timestamp_entries: a.col_timestamp_entries
                    + b.col_timestamp_entries
                    + c.col_timestamp_entries,
                field_mul_estimate: a.field_mul_estimate
                    + b.field_mul_estimate
                    + c.field_mul_estimate,
                field_add_estimate: a.field_add_estimate
                    + b.field_add_estimate
                    + c.field_add_estimate,
                serialized_field_elements: a.serialized_field_elements
                    + b.serialized_field_elements
                    + c.serialized_field_elements
                    + 8,
            }
        };
        if expected_cost != self.cost_profile {
            return Err("SPARK cost profile mismatch");
        }

        Ok(SparkEvaluations {
            a_eval,
            b_eval,
            c_eval,
        })
    }
}

/// MemoryInTheHead procedure from Section 7.2.1.
fn memory_in_the_head<F: Field>(m: usize, n: usize, addrs: &[usize]) -> (Vec<F>, Vec<F>, Vec<F>) {
    let mut read_ts = vec![F::ZERO; n];
    let mut write_ts = vec![F::ZERO; n];
    let mut audit_ts = vec![F::ZERO; m];

    let mut current_ts = F::ZERO;

    for i in 0..n {
        let addr_usize = addrs[i];
        assert!(addr_usize < m, "address out of bounds in memory trace");

        let r_ts = audit_ts[addr_usize];
        read_ts[i] = r_ts;

        current_ts += F::ONE;
        write_ts[i] = current_ts;
        audit_ts[addr_usize] = current_ts;
    }

    (read_ts, write_ts, audit_ts)
}

fn verify_memory_in_the_head<F: Field>(
    m: usize,
    n: usize,
    addrs: &[usize],
    read_ts: &[F],
    write_ts: &[F],
    audit_ts: &[F],
) -> bool {
    let (exp_read, exp_write, exp_audit) = memory_in_the_head::<F>(m, n, addrs);
    read_ts == exp_read && write_ts == exp_write && audit_ts == exp_audit
}

/// Compute eq(index, r) = ∏_i (bit_i(index)*r_i + (1-bit_i(index))*(1-r_i)).
fn compute_eq_poly_index<F: Field>(x: usize, r: &[F]) -> F {
    let mut result = F::ONE;
    for (i, r_i) in r.iter().enumerate() {
        let bit = (x >> i) & 1;
        let term = if bit == 1 { *r_i } else { F::ONE - *r_i };
        result *= term;
    }
    result
}

/// Hash function for memory checking.
/// h_γ(a, v, t) = a * γ^2 + v * γ + t
fn hash_gamma<F: Field>(a: F, v: F, t: F, gamma: F) -> F {
    a * gamma * gamma + v * gamma + t
}

/// Multiset hash function.
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

        let addrs = vec![0usize, 1usize, 0usize];
        let (read_ts, write_ts, audit_ts) = memory_in_the_head::<F>(4, 3, &addrs);

        assert_eq!(read_ts[0], F::ZERO);
        assert_eq!(write_ts[0], F::ONE);
        assert_eq!(read_ts[1], F::ZERO);
        assert_eq!(write_ts[1], F::TWO);
        assert_eq!(read_ts[2], F::ONE);
        assert_eq!(write_ts[2], F::from_u64(3));
        assert_eq!(audit_ts[0], F::from_u64(3));
        assert_eq!(audit_ts[1], F::TWO);
    }

    #[test]
    fn test_compute_eq_poly_index_full_bits() {
        type F = BabyBear;
        let r = vec![F::from_u64(7), F::from_u64(11)];
        let eq = compute_eq_poly_index(2, &r);
        assert_eq!(eq, (F::ONE - r[0]) * r[1]);
    }

    #[test]
    fn test_spark_proof_verify_and_detect_tamper() {
        type F = BabyBear;

        let entries = vec![
            super::super::r1cs::SparseMatEntry::new(0, 0, F::ONE),
            super::super::r1cs::SparseMatEntry::new(1, 1, F::TWO),
        ];
        let mat = SparseMatPolynomial::new(2, 2, entries.clone());
        let mat_b = SparseMatPolynomial::new(2, 2, entries.clone());
        let mat_c = SparseMatPolynomial::new(2, 2, entries);
        let rx = vec![F::from_u64(5), F::from_u64(9)];
        let ry = vec![F::from_u64(2), F::from_u64(3)];

        let challenges = SparkCompressionChallenges {
            gamma: F::from_u64(17),
            eta: F::from_u64(23),
        };

        let proof = SparkProof::from_matrices(&mat, &mat_b, &mat_c, &rx, &ry, challenges);
        let verified = proof
            .verify(&rx, &ry, challenges)
            .expect("valid spark proof");
        assert_eq!(verified.a_eval, proof.batch_opening.a_eval);

        let mut tampered = proof.clone();
        tampered.a_digest += F::ONE;
        assert!(tampered.verify(&rx, &ry, challenges).is_err());

        let mut tampered_batch = proof.clone();
        tampered_batch.batch_opening.batched_eval += F::ONE;
        assert!(tampered_batch.verify(&rx, &ry, challenges).is_err());

        let mut tampered_cost = proof;
        tampered_cost.cost_profile.field_mul_estimate += 1;
        assert!(tampered_cost.verify(&rx, &ry, challenges).is_err());
    }
}
