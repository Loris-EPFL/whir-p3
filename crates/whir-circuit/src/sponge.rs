//! Duplex sponge challenger as R1CS constraints.
//!
//! Exactly mirrors `DuplexChallenger<F, Perm, WIDTH, RATE>` behavior:
//! - `observe(val)`: push to input buffer; when full, add to state and permute
//! - `sample()`: pop from output buffer; if empty, duplex first
//! - `sample_ext()`: call sample() D times to construct an EF element
//!
//! The key difference from a native challenger: all state updates are tracked as
//! circuit variables with R1CS constraints.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use super::{
    builder::{CircuitBuilder, Var},
    ext_field::{ExtVal, ExtVar},
    poseidon2::{Poseidon2CircuitConfig, poseidon2_permute_circuit},
};

/// Circuit-level duplex sponge challenger.
///
/// Exactly matches the behavior of `DuplexChallenger<F, Perm, WIDTH, RATE>`.
#[derive(Debug)]
pub struct CircuitChallenger<F: Field, const WIDTH: usize, const RATE: usize> {
    sponge_state_vars: [Var; WIDTH],
    sponge_state_vals: [F; WIDTH],
    input_buffer_vars: Vec<Var>,
    input_buffer_vals: Vec<F>,
    output_buffer_vars: Vec<Var>,
    output_buffer_vals: Vec<F>,
}

impl<F: Field + PrimeCharacteristicRing, const WIDTH: usize, const RATE: usize>
    CircuitChallenger<F, WIDTH, RATE>
{
    /// Create a new challenger with zero-initialized state.
    pub fn new(builder: &mut CircuitBuilder<F>) -> Self {
        let sponge_state_vars: [Var; WIDTH] =
            core::array::from_fn(|_| builder.alloc_witness(F::ZERO));
        Self {
            sponge_state_vars,
            sponge_state_vals: [F::ZERO; WIDTH],
            input_buffer_vars: Vec::new(),
            input_buffer_vals: Vec::new(),
            output_buffer_vars: Vec::new(),
            output_buffer_vals: Vec::new(),
        }
    }

    /// Perform duplexing: add input buffer to sponge state, permute, fill output buffer.
    fn duplexing<L, P>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
    ) where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
    {
        // Overwrite state with input buffer: state[i] = input[i]
        for (i, (var, val)) in self
            .input_buffer_vars
            .drain(..)
            .zip(self.input_buffer_vals.drain(..))
            .enumerate()
        {
            self.sponge_state_vars[i] = var;
            self.sponge_state_vals[i] = val;
        }

        // Permute
        let (new_vars, new_vals) = poseidon2_permute_circuit::<F, L, P, WIDTH>(
            builder,
            config,
            perm,
            &self.sponge_state_vars,
            &self.sponge_state_vals,
        );
        self.sponge_state_vars = new_vars;
        self.sponge_state_vals = new_vals;

        // Fill output buffer with state[0..RATE]
        self.output_buffer_vars.clear();
        self.output_buffer_vals.clear();
        for i in 0..RATE {
            self.output_buffer_vars.push(self.sponge_state_vars[i]);
            self.output_buffer_vals.push(self.sponge_state_vals[i]);
        }
    }

    /// Absorb a base field element.
    pub fn observe<L, P>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
        var: Var,
        val: F,
    ) where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
    {
        // Clear output buffer (invalidates old outputs)
        self.output_buffer_vars.clear();
        self.output_buffer_vals.clear();

        // Push to input buffer
        self.input_buffer_vars.push(var);
        self.input_buffer_vals.push(val);

        // If input buffer is full, duplex
        if self.input_buffer_vars.len() == RATE {
            self.duplexing::<L, P>(builder, config, perm);
        }
    }

    /// Absorb multiple base field elements.
    pub fn observe_slice<L, P>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
        vars: &[Var],
        vals: &[F],
    ) where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
    {
        assert_eq!(vars.len(), vals.len());
        for (&v, &val) in vars.iter().zip(vals.iter()) {
            self.observe::<L, P>(builder, config, perm, v, val);
        }
    }

    /// Squeeze one base field element.
    pub fn sample<L, P>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
    ) -> (Var, F)
    where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
    {
        if !self.input_buffer_vars.is_empty() || self.output_buffer_vals.is_empty() {
            self.duplexing::<L, P>(builder, config, perm);
        }

        let val = self.output_buffer_vals.pop().expect("output buffer empty after duplexing");
        let var = self.output_buffer_vars.pop().expect("output buffer empty after duplexing");
        (var, val)
    }

    /// Squeeze an extension field element (D base field samples).
    pub fn sample_ext<L, P, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
    ) -> (ExtVar<D>, ExtVal<F, D>)
    where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
    {
        let mut vars = [Var(0); D];
        let mut vals = [F::ZERO; D];
        for i in 0..D {
            let (v, f) = self.sample::<L, P>(builder, config, perm);
            vars[i] = v;
            vals[i] = f;
        }
        (ExtVar::new(vars), ExtVal::new(vals))
    }

    /// Absorb an extension field element (D base field observations).
    pub fn observe_ext<L, P, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
        ext: &ExtVar<D>,
        ext_val: &ExtVal<F, D>,
    ) where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
    {
        for i in 0..D {
            self.observe::<L, P>(builder, config, perm, ext.vars[i], ext_val.vals[i]);
        }
    }

    /// Sample and return only the value (discarding the var) for bits extraction.
    pub fn sample_bits<L, P>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        config: &Poseidon2CircuitConfig<F, WIDTH>,
        perm: &P,
        bits: usize,
    ) -> (Var, F, usize)
    where
        L: GenericPoseidon2LinearLayers<WIDTH>,
        P: Permutation<[F; WIDTH]>,
        F: p3_field::PrimeField64,
    {
        let (var, val) = self.sample::<L, P>(builder, config, perm);
        let val_u64 = val.as_canonical_u64();
        let index = (val_u64 as usize) & ((1 << bits) - 1);
        (var, val, index)
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::{KoalaBear, GenericPoseidon2LinearLayersKoalaBear, Poseidon2KoalaBear};
    use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
    type L = GenericPoseidon2LinearLayersKoalaBear;

    fn make_perm_and_config() -> (Perm, Poseidon2CircuitConfig<F, 16>) {
        let mut rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut rng);
        let mut rng2 = SmallRng::seed_from_u64(42);
        let config = Poseidon2CircuitConfig::<F, 16>::from_rng(8, 20, 3, &mut rng2);
        (perm, config)
    }

    #[test]
    fn circuit_challenger_matches_duplex_challenger_observe_sample() {
        let (perm, config) = make_perm_and_config();

        // Real challenger
        let mut real_challenger = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());

        // Circuit challenger
        let mut builder = CircuitBuilder::<F>::new();
        let mut circuit_challenger = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        // Observe 8 values to trigger duplexing
        for i in 0..8u64 {
            let val = F::from_u64(i + 1);
            real_challenger.observe(val);
            let var = builder.alloc_witness(val);
            circuit_challenger.observe::<L, _>(&mut builder, &config, &perm, var, val);
        }

        // Sample and compare
        let real_sample: F = real_challenger.sample();
        let (_, circuit_sample) =
            circuit_challenger.sample::<L, _>(&mut builder, &config, &perm);

        assert_eq!(
            real_sample, circuit_sample,
            "circuit challenger sample doesn't match real challenger"
        );

        // Verify R1CS
        let (_, instance) = builder.build();
        assert!(instance.verify(), "circuit challenger R1CS not satisfied");
    }

    #[test]
    fn circuit_challenger_matches_multiple_samples() {
        let (perm, config) = make_perm_and_config();

        let mut real = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());
        let mut builder = CircuitBuilder::<F>::new();
        let mut circuit = CircuitChallenger::<F, 16, 8>::new(&mut builder);

        // Observe some values
        for i in 0..5u64 {
            let val = F::from_u64(i * 7 + 3);
            real.observe(val);
            let var = builder.alloc_witness(val);
            circuit.observe::<L, _>(&mut builder, &config, &perm, var, val);
        }

        // Sample multiple times
        for _ in 0..4 {
            let real_s: F = real.sample();
            let (_, circuit_s) = circuit.sample::<L, _>(&mut builder, &config, &perm);
            assert_eq!(real_s, circuit_s, "sample mismatch");
        }

        // Observe more, then sample again
        for i in 0..3u64 {
            let val = F::from_u64(i + 100);
            real.observe(val);
            let var = builder.alloc_witness(val);
            circuit.observe::<L, _>(&mut builder, &config, &perm, var, val);
        }

        let real_s: F = real.sample();
        let (_, circuit_s) = circuit.sample::<L, _>(&mut builder, &config, &perm);
        assert_eq!(real_s, circuit_s, "sample after re-observe mismatch");

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }
}
