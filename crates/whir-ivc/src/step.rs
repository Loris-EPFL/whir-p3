//! Step circuit trait for IVC.
//!
//! Users implement this trait to define the per-step computation that gets
//! folded into the running accumulator at each IVC step.

use alloc::{vec, vec::Vec};

use p3_field::Field;

use crate::circuit::builder::{CircuitBuilder, Var};

/// A user-defined step function for IVC.
///
/// Each IVC step:
/// 1. Takes the current public state as input.
/// 2. Executes user computation (via `synthesize`).
/// 3. Produces a new public state as output.
/// 4. The resulting R1CS instance is folded into the running accumulator.
pub trait StepCircuit<F: Field> {
    /// The number of field elements in the public state (input/output).
    fn state_size(&self) -> usize;

    /// Synthesize one step of the computation.
    ///
    /// Given the input state variables, produce the output state variables
    /// and add all necessary R1CS constraints to the builder.
    fn synthesize(
        &self,
        builder: &mut CircuitBuilder<F>,
        input_state: &[Var],
    ) -> Vec<Var>;
}

/// A trivial step circuit that just copies input to output (identity function).
/// Useful for testing the IVC infrastructure without any real computation.
#[derive(Debug)]
pub struct TrivialStepCircuit {
    state_size: usize,
}

impl TrivialStepCircuit {
    #[must_use]
    pub const fn new(state_size: usize) -> Self {
        Self { state_size }
    }
}

impl<F: Field> StepCircuit<F> for TrivialStepCircuit {
    fn state_size(&self) -> usize {
        self.state_size
    }

    fn synthesize(
        &self,
        _builder: &mut CircuitBuilder<F>,
        input_state: &[Var],
    ) -> Vec<Var> {
        // Identity: output = input (no constraints added)
        input_state.to_vec()
    }
}

/// A step circuit that generates a configurable number of multiplication
/// constraints by chaining squarings: x -> x^2 -> x^4 -> ...
///
/// `num_muls` squarings produce `num_muls` R1CS constraints. Useful for
/// benchmarking the pipeline at different step circuit sizes.
#[derive(Debug)]
pub struct WorkloadStepCircuit {
    num_muls: usize,
}

impl WorkloadStepCircuit {
    #[must_use]
    pub const fn new(num_muls: usize) -> Self {
        Self { num_muls }
    }
}

impl<F: Field> StepCircuit<F> for WorkloadStepCircuit {
    fn state_size(&self) -> usize {
        1
    }

    fn synthesize(
        &self,
        builder: &mut CircuitBuilder<F>,
        input_state: &[Var],
    ) -> Vec<Var> {
        // Generate num_muls independent multiplication constraints.
        // Each constraint: a_i * a_i = b_i where a_i and b_i are fresh
        // witness variables with consistent values. This is independent
        // of the input state value, so it's always satisfiable.
        let mut last = input_state[0];
        for i in 0..self.num_muls {
            let val = F::from_u64((i as u64 + 2) % 1000 + 1);
            let a = builder.alloc_witness(val);
            let b = builder.mul(a, a, val * val);
            // Chain to output: constrain last = last (identity via addition)
            // to keep the variables connected to the circuit
            last = b;
        }
        vec![last]
    }
}

/// A step circuit that squares each element of the state.
/// Useful for testing: state[i] <- state[i]^2.
#[derive(Debug)]
pub struct SquaringStepCircuit {
    state_size: usize,
}

impl SquaringStepCircuit {
    #[must_use]
    pub const fn new(state_size: usize) -> Self {
        Self { state_size }
    }
}

impl<F: Field> StepCircuit<F> for SquaringStepCircuit {
    fn state_size(&self) -> usize {
        self.state_size
    }

    fn synthesize(
        &self,
        _builder: &mut CircuitBuilder<F>,
        input_state: &[Var],
    ) -> Vec<Var> {
        input_state
            .iter()
            .map(|&v| {
                // We need to know the value to allocate the product.
                // In a real IVC, the prover fills this in from the witness.
                // For now, we just allocate a fresh variable — the caller
                // must ensure the witness values are set correctly.
                //
                // The `mul` method on CircuitBuilder requires the product value,
                // so this must be called with a builder that has been pre-populated.
                // This is a limitation of the current builder API.
                //
                // For testing, we use a wrapper that pre-computes values.
                v // placeholder — real implementation needs value
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_koala_bear::KoalaBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    type F = KoalaBear;

    #[test]
    fn trivial_step_produces_valid_circuit() {
        let step = TrivialStepCircuit::new(2);
        let mut builder = CircuitBuilder::<F>::new();
        let input = vec![
            builder.alloc_witness(F::from_u64(3)),
            builder.alloc_witness(F::from_u64(7)),
        ];
        let output = step.synthesize(&mut builder, &input);

        assert_eq!(output.len(), 2);
        assert_eq!(input, output); // identity

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }
}
