//! R1CS circuit builder for constructing constraint systems programmatically.
//!
//! Provides a high-level API for building R1CS constraints that produces
//! `R1CSShape` and `R1CSInstance` compatible with the Spartan prover.

use alloc::{vec, vec::Vec};

use p3_field::Field;

use crate::spartan::r1cs::{R1CSInstance, R1CSShape, SparseMatEntry};

/// A variable in the circuit, identified by its index in the z-vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Var(pub usize);

impl Var {
    /// Returns the raw index of this variable in the z-vector.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// A linear combination of variables: `constant + Σ (coeff * var)`.
#[derive(Clone, Debug)]
pub struct LinearCombination<F: Field> {
    terms: Vec<(Var, F)>,
    constant: F,
}

impl<F: Field> LinearCombination<F> {
    /// Create a linear combination consisting of a single variable with coefficient 1.
    #[must_use]
    pub fn from_var(var: Var) -> Self {
        Self {
            terms: vec![(var, F::ONE)],
            constant: F::ZERO,
        }
    }

    /// Create a linear combination that is a single constant.
    #[must_use]
    pub fn from_constant(c: F) -> Self {
        Self {
            terms: Vec::new(),
            constant: c,
        }
    }

    /// Create a linear combination `coeff * var`.
    #[must_use]
    pub fn from_scaled(var: Var, coeff: F) -> Self {
        Self {
            terms: vec![(var, coeff)],
            constant: F::ZERO,
        }
    }

    /// Add a term `coeff * var` to this linear combination.
    pub fn add_term(&mut self, var: Var, coeff: F) {
        self.terms.push((var, coeff));
    }

    /// Add a constant to this linear combination.
    pub fn add_constant(&mut self, c: F) {
        self.constant += c;
    }

    /// Evaluate this linear combination given the full z-vector.
    #[must_use]
    pub fn evaluate(&self, z: &[F]) -> F {
        let mut result = self.constant;
        for &(var, coeff) in &self.terms {
            result += coeff * z[var.0];
        }
        result
    }
}

impl<F: Field> core::ops::Add for LinearCombination<F> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.terms.extend(rhs.terms);
        self.constant += rhs.constant;
        self
    }
}

impl<F: Field> core::ops::Sub for LinearCombination<F> {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        for (var, coeff) in rhs.terms {
            self.terms.push((var, -coeff));
        }
        self.constant -= rhs.constant;
        self
    }
}

/// Circuit builder that accumulates R1CS constraints.
///
/// # Z-vector layout
///
/// The z-vector for R1CS is: `[witness_0..witness_n | 1 | input_0..input_k | padding]`
/// where total size = `2 * num_vars` (power of two).
///
/// Variables are allocated in two pools:
/// - **Witness variables** (private): indices `0..num_witness_vars`
/// - **Public inputs**: indices `num_vars+1..num_vars+1+num_public_inputs`
///   (after the constant-1 slot at index `num_vars`)
///
/// The `one()` variable always points to index `num_vars` (the constant-1 slot).
#[derive(Debug)]
pub struct CircuitBuilder<F: Field> {
    /// Values for witness variables (private).
    witness_values: Vec<F>,
    /// Values for public inputs.
    public_input_values: Vec<F>,
    /// Constraints as (A, B, C) linear combinations, where A*B = C.
    constraints: Vec<(LinearCombination<F>, LinearCombination<F>, LinearCombination<F>)>,
}

impl<F: Field> CircuitBuilder<F> {
    /// Create a new, empty circuit builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            witness_values: Vec::new(),
            public_input_values: Vec::new(),
            constraints: Vec::new(),
        }
    }

    /// Allocate a private witness variable with the given value.
    pub fn alloc_witness(&mut self, value: F) -> Var {
        let idx = self.witness_values.len();
        self.witness_values.push(value);
        Var(idx)
    }

    /// Allocate a public input variable with the given value.
    ///
    /// Note: The actual z-vector index depends on `num_vars` which is finalized at build time.
    /// We track public inputs separately and map them during `build()`.
    pub fn alloc_public_input(&mut self, value: F) -> Var {
        let idx = self.public_input_values.len();
        self.public_input_values.push(value);
        // Use a sentinel: public inputs get indices starting after all possible witness vars.
        // We'll remap in build(). Use usize::MAX - idx as a distinguishable sentinel.
        Var(usize::MAX - idx)
    }

    /// Returns the number of allocated witness variables.
    #[must_use]
    pub fn num_witness_vars(&self) -> usize {
        self.witness_values.len()
    }

    /// Returns the number of allocated public inputs.
    #[must_use]
    pub fn num_public_inputs(&self) -> usize {
        self.public_input_values.len()
    }

    /// Returns the number of constraints added so far.
    #[must_use]
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Add an R1CS constraint: `a * b = c`.
    pub fn enforce(
        &mut self,
        a: LinearCombination<F>,
        b: LinearCombination<F>,
        c: LinearCombination<F>,
    ) {
        self.constraints.push((a, b, c));
    }

    /// Convenience: allocate a new witness variable constrained to `a * b`.
    pub fn mul(&mut self, a: Var, b: Var, product_value: F) -> Var {
        let c = self.alloc_witness(product_value);
        self.enforce(
            LinearCombination::from_var(a),
            LinearCombination::from_var(b),
            LinearCombination::from_var(c),
        );
        c
    }

    /// Convenience: allocate a new witness variable constrained to `a + b`.
    /// Encoded as `(a + b) * 1 = c`.
    pub fn add(&mut self, a: Var, b: Var, sum_value: F) -> Var {
        let c = self.alloc_witness(sum_value);
        let one_var = self.one_lc();
        self.enforce(
            LinearCombination::from_var(a) + LinearCombination::from_var(b),
            one_var,
            LinearCombination::from_var(c),
        );
        c
    }

    /// Convenience: constrain `a == b`. Encoded as `(a - b) * 1 = 0`.
    pub fn enforce_equal(&mut self, a: Var, b: Var) {
        let one_var = self.one_lc();
        self.enforce(
            LinearCombination::from_var(a) - LinearCombination::from_var(b),
            one_var,
            LinearCombination::from_constant(F::ZERO),
        );
    }

    /// Convenience: constrain `a * b = c` where a, b, c are all existing variables.
    pub fn enforce_mul(&mut self, a: Var, b: Var, c: Var) {
        self.enforce(
            LinearCombination::from_var(a),
            LinearCombination::from_var(b),
            LinearCombination::from_var(c),
        );
    }

    /// Convenience: allocate a constant value as a witness variable.
    /// The value is not constrained — use `enforce_constant` if needed.
    pub fn alloc_constant(&mut self, value: F) -> Var {
        self.alloc_witness(value)
    }

    /// Constrain a variable to equal a constant: `var * 1 = constant`.
    pub fn enforce_constant(&mut self, var: Var, value: F) {
        let one_var = self.one_lc();
        self.enforce(
            LinearCombination::from_var(var),
            one_var,
            LinearCombination::from_constant(value),
        );
    }

    /// A linear combination representing the constant 1.
    fn one_lc(&self) -> LinearCombination<F> {
        LinearCombination::from_constant(F::ONE)
    }

    /// Build the `R1CSShape` and `R1CSInstance` from the accumulated constraints.
    ///
    /// Pads `num_vars` and `num_cons` to the next power of two as required by `R1CSShape`.
    #[must_use]
    pub fn build(self) -> (R1CSShape<F>, R1CSInstance<F>) {
        let raw_num_vars = self.witness_values.len().max(1);
        let num_vars = raw_num_vars.next_power_of_two();
        let num_inputs = self.public_input_values.len();
        let raw_num_cons = self.constraints.len().max(1);
        let num_cons = raw_num_cons.next_power_of_two();

        // The constant-1 slot is at index `num_vars` in the z-vector.
        let one_index = num_vars;

        // Remap variable indices: witness vars stay as-is, public inputs get remapped,
        // and the constant in LCs gets converted to a reference to the one-slot.
        let remap = |lc: &LinearCombination<F>| -> Vec<(usize, F)> {
            let mut entries: Vec<(usize, F)> = Vec::new();
            for &(var, coeff) in &lc.terms {
                let idx = if var.0 >= usize::MAX - num_inputs {
                    // This is a public input sentinel
                    let pi_idx = usize::MAX - var.0;
                    one_index + 1 + pi_idx
                } else {
                    var.0
                };
                entries.push((idx, coeff));
            }
            // Handle the constant term via the one-slot
            if lc.constant != F::ZERO {
                entries.push((one_index, lc.constant));
            }
            entries
        };

        let mut a_entries = Vec::new();
        let mut b_entries = Vec::new();
        let mut c_entries = Vec::new();

        for (row, (a, b, c)) in self.constraints.iter().enumerate() {
            for (col, val) in remap(a) {
                if val != F::ZERO {
                    a_entries.push(SparseMatEntry::new(row, col, val));
                }
            }
            for (col, val) in remap(b) {
                if val != F::ZERO {
                    b_entries.push(SparseMatEntry::new(row, col, val));
                }
            }
            for (col, val) in remap(c) {
                if val != F::ZERO {
                    c_entries.push(SparseMatEntry::new(row, col, val));
                }
            }
        }

        let shape = R1CSShape::new(num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries);

        // Pad witness to num_vars
        let mut witness = self.witness_values;
        witness.resize(num_vars, F::ZERO);

        let instance = R1CSInstance::new(shape.clone(), self.public_input_values, witness);
        (shape, instance)
    }
}

impl<F: Field> Default for CircuitBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    type F = KoalaBear;

    #[test]
    fn simple_multiplication_constraint() {
        // Prove: x * x = y where x=3, y=9
        let mut builder = CircuitBuilder::<F>::new();
        let x = builder.alloc_witness(F::from_u64(3));
        let _y = builder.mul(x, x, F::from_u64(9));

        let (shape, instance) = builder.build();
        assert!(instance.verify(), "simple multiplication should satisfy R1CS");
        assert!(shape.is_sat(instance.witness(), instance.input()));
    }

    #[test]
    fn addition_constraint() {
        // Prove: a + b = c where a=5, b=7, c=12
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.alloc_witness(F::from_u64(5));
        let b = builder.alloc_witness(F::from_u64(7));
        let _c = builder.add(a, b, F::from_u64(12));

        let (shape, instance) = builder.build();
        assert!(instance.verify(), "addition should satisfy R1CS");
        assert!(shape.is_sat(instance.witness(), instance.input()));
    }

    #[test]
    fn equality_constraint() {
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.alloc_witness(F::from_u64(42));
        let b = builder.alloc_witness(F::from_u64(42));
        builder.enforce_equal(a, b);

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }

    #[test]
    fn equality_constraint_fails_on_mismatch() {
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.alloc_witness(F::from_u64(42));
        let b = builder.alloc_witness(F::from_u64(43));
        builder.enforce_equal(a, b);

        let (_, instance) = builder.build();
        assert!(!instance.verify());
    }

    #[test]
    fn public_input_constraint() {
        // Prove: witness * witness = product, product == public_input
        // where witness=5, product=25, public=25
        // Need at least 2 witness vars so num_inputs < num_vars
        let mut builder = CircuitBuilder::<F>::new();
        let w = builder.alloc_witness(F::from_u64(5));
        let product = builder.mul(w, w, F::from_u64(25));
        let pi = builder.alloc_public_input(F::from_u64(25));
        builder.enforce_equal(product, pi);

        let (shape, instance) = builder.build();
        assert!(instance.verify(), "public input constraint should satisfy R1CS");
        assert!(shape.is_sat(instance.witness(), instance.input()));
    }

    #[test]
    fn chain_of_multiplications() {
        // x=2, x^2=4, x^4=16, x^8=256
        let mut builder = CircuitBuilder::<F>::new();
        let x = builder.alloc_witness(F::from_u64(2));
        let x2 = builder.mul(x, x, F::from_u64(4));
        let x4 = builder.mul(x2, x2, F::from_u64(16));
        let _x8 = builder.mul(x4, x4, F::from_u64(256));

        let (shape, instance) = builder.build();
        assert!(instance.verify(), "chain of muls should satisfy R1CS");
        assert!(shape.is_sat(instance.witness(), instance.input()));
    }

    #[test]
    fn constant_constraint() {
        let mut builder = CircuitBuilder::<F>::new();
        let v = builder.alloc_witness(F::from_u64(7));
        builder.enforce_constant(v, F::from_u64(7));

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }

    #[test]
    fn linear_combination_in_constraint() {
        // Prove: (2*a + 3*b) * 1 = c where a=4, b=5, c=23
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.alloc_witness(F::from_u64(4));
        let b = builder.alloc_witness(F::from_u64(5));
        let c = builder.alloc_witness(F::from_u64(23));

        let mut lhs = LinearCombination::from_scaled(a, F::from_u64(2));
        lhs.add_term(b, F::from_u64(3));

        builder.enforce(
            lhs,
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(c),
        );

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }

    #[test]
    fn spartan_integration() {
        use p3_koala_bear::Poseidon2KoalaBear;
        use p3_challenger::DuplexChallenger;
        use p3_field::extension::BinomialExtensionField;
        use rand::{rngs::SmallRng, SeedableRng};

        type EF = BinomialExtensionField<F, 4>;
        type Perm = Poseidon2KoalaBear<16>;
        type Challenger = DuplexChallenger<F, Perm, 16, 8>;

        // Build circuit: x * x = y
        let mut builder = CircuitBuilder::<F>::new();
        let x = builder.alloc_witness(F::from_u64(5));
        let _y = builder.mul(x, x, F::from_u64(25));

        let (shape, instance) = builder.build();
        assert!(instance.verify());

        // Prove with Spartan
        let spartan = crate::spartan::r1cs_prover::R1CSProver::new();
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
        let mut challenger = Challenger::new(perm);
        let proof = spartan.prove::<EF, _>(&instance, &mut challenger);

        // Verify with Spartan
        let perm2 = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
        let mut verifier_challenger = Challenger::new(perm2);
        let result = crate::spartan::r1cs_prover::R1CSVerifier::new().verify::<EF, _>(
            &shape,
            instance.input(),
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_ok(), "Spartan verification failed: {result:?}");
    }
}
